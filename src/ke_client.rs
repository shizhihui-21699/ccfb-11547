//! NTS-KE client (RFC 8915 §4): performs the TLS 1.3 handshake, negotiates the
//! AEAD algorithm, collects cookies and the NTP server/port hints, and
//! derives the C2S/S2C working keys from the TLS exporter.

use std::io::BufReader;
use std::net::TcpStream;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use rustls::client::ClientConfig;
use rustls::pki_types::ServerName;
use rustls::ClientConnection;

use crate::aead::AeadAlg;
use crate::constants::*;
use crate::ke::{read_until_eom, write_records, KeRecord};
use crate::keyderive::derive_working_keys;
use crate::{Error, Result};

/// Everything a protected NTP exchange needs, obtained from one KE session.
#[derive(Clone)]
pub struct KeSession {
    pub alg: AeadAlg,
    pub c2s_key: Vec<u8>,
    pub s2c_key: Vec<u8>,
    pub cookies: Vec<Vec<u8>>,
    pub ntp_server: Option<String>,
    pub ntp_port: u16,
}

pub struct KeClient {
    tls: Arc<ClientConfig>,
}

impl KeClient {
    pub fn new(tls: Arc<ClientConfig>) -> Self {
        Self { tls }
    }

    /// Run a full KE exchange against `host:port`.
    pub fn negotiate(&self, host: &str, port: u16) -> Result<KeSession> {
        let addr = format!("{host}:{port}");
        let mut tcp = TcpStream::connect(&addr)?;
        tcp.set_nodelay(true)?;
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| Error::Tls(format!("invalid server name: {e}")))?;
        let mut conn = ClientConnection::new(self.tls.clone(), server_name)?;

        let mut sock = rustls::Stream::new(&mut conn, &mut tcp);
        // ---- client request (§4.1): Next Protocol (NTPv4), AEAD offers, EOM ----
        let offers: Vec<u16> = SUPPORTED_AEAD_IDS.to_vec();
        write_records(
            &mut sock,
            &[
                KeRecord::next_protocol(&[NEXT_PROTOCOL_NTPV4]),
                KeRecord::algo_negotiation(&offers),
                KeRecord::end_of_message(),
            ],
        )?;

        let mut reader = BufReader::new(sock);
        let records = read_until_eom(&mut reader)?;
        let stream = reader.into_inner();
        stream.conn.send_close_notify();

        // ---- TLS version must be 1.3 (§4) ----
        let version = stream
            .conn
            .protocol_version()
            .ok_or_else(|| Error::ke("handshake produced no protocol version"))?;
        if version != rustls::ProtocolVersion::TLSv1_3 {
            return Err(Error::ke(format!(
                "NTS-KE requires TLS 1.3, negotiated {version:?}"
            )));
        }
        // ---- ALPN must be ntske/1 (§4) ----
        match stream.conn.alpn_protocol() {
            Some(p) if p == crate::cert::NTS_KE_ALPN => {}
            other => {
                return Err(Error::ke(format!(
                    "NTS-KE ALPN mismatch: expected ntske/1, got {:?}",
                    other.map(String::from_utf8_lossy)
                )))
            }
        }

        // ---- interpret response records ----
        let mut alg: Option<AeadAlg> = None;
        let mut cookies = Vec::new();
        let mut ntp_server = None;
        let mut ntp_port = DEFAULT_NTP_PORT;
        let mut saw_eom = false;
        let mut alg_seen = 0u8;

        for rec in &records {
            match rec.r#type {
                KE_RECORD_ERROR => {
                    let code = rec
                        .body
                        .get(..2)
                        .map(BigEndian::read_u16)
                        .unwrap_or(0);
                    return Err(Error::KeServerError {
                        code,
                        message: ke_error_text(code).into(),
                    });
                }
                KE_RECORD_WARNING => continue,
                KE_RECORD_NEXT_PROTOCOL => {
                    // Server must echo NTPv4 (id 0); ignore other ids if any.
                    let offers_ntpv4 = rec.body.len() >= 2
                        && (0..rec.body.len() / 2)
                            .any(|i| BigEndian::read_u16(&rec.body[i * 2..i * 2 + 2]) == 0);
                    if !offers_ntpv4 {
                        return Err(Error::ke("server did not select NTPv4"));
                    }
                }
                KE_RECORD_ALGO_NEGOTIATION => {
                    alg_seen += 1;
                    if rec.body.len() != 2 {
                        return Err(Error::ke("algorithm negotiation body must be one u16"));
                    }
                    let id = BigEndian::read_u16(&rec.body);
                    if !SUPPORTED_AEAD_IDS.contains(&id) {
                        return Err(Error::UnsupportedAead(id));
                    }
                    alg = Some(AeadAlg::from_id(id)?);
                }
                KE_RECORD_NEW_COOKIE => {
                    if rec.body.is_empty() {
                        return Err(Error::ke("empty New Cookie record"));
                    }
                    cookies.push(rec.body.clone());
                }
                KE_RECORD_SERVER_NEGOTIATION => {
                    ntp_server = Some(
                        String::from_utf8(rec.body.clone())
                            .map_err(|_| Error::ke("server negotiation not UTF-8"))?,
                    );
                }
                KE_RECORD_PORT_NEGOTIATION => {
                    if rec.body.len() != 2 {
                        return Err(Error::ke("port negotiation body must be one u16"));
                    }
                    ntp_port = BigEndian::read_u16(&rec.body);
                }
                KE_RECORD_END_OF_MESSAGE => saw_eom = true,
                other => {
                    if rec.critical {
                        return Err(Error::ke(format!(
                            "unrecognized critical record 0x{other:04x}"
                        )));
                    }
                }
            }
        }
        if !saw_eom {
            return Err(Error::ke("server response missing End-of-Message"));
        }
        if alg_seen != 1 {
            return Err(Error::ke(
                "server must send exactly one algorithm negotiation record",
            ));
        }
        let alg = alg.ok_or_else(|| Error::ke("no negotiated AEAD in response"))?;
        if cookies.is_empty() {
            return Err(Error::ke("server provided no cookies"));
        }

        // ---- two TLS exporters → C2S / S2C working keys (RFC 8915 §5.1) ----
        let conn = &stream.conn;
        let keys = derive_working_keys(
            |label, ctx, len| {
                let mut out = vec![0u8; len];
                conn.export_keying_material(&mut out, label.as_bytes(), Some(ctx))
                    .map_err(|e| Error::ke(format!("TLS exporter failed: {e}")))?;
                Ok(out)
            },
            alg,
        )?;

        Ok(KeSession {
            alg,
            c2s_key: keys.c2s,
            s2c_key: keys.s2c,
            cookies,
            ntp_server,
            ntp_port,
        })
    }
}

pub fn ke_error_text(code: u16) -> &'static str {
    match code {
        KE_ERR_UNRECOGNIZED_CRITICAL_RECORD => "unrecognized critical record",
        KE_ERR_BAD_REQUEST => "bad request",
        KE_ERR_INTERNAL_SERVER_ERROR => "internal server error",
        _ => "unknown error",
    }
}
