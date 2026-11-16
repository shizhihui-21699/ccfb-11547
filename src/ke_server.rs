//! NTS-KE server (RFC 8915 §4).
//!
//! Accepts TLS 1.3 connections, requires one critical Algorithm Negotiation
//! record followed by End-of-Message, derives the same exporter/working keys
//! as the client, mints [`DEFAULT_COOKIES_PER_KE`] cookies under the current
//! master key, and returns them with optional NTP server/port hints.

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use rustls::server::ServerConnection;
use rustls::ServerConfig;

use crate::aead::AeadAlg;
use crate::constants::*;
use crate::cookie::{mint_cookie, KeyStore};
use crate::ke::{read_until_eom, write_records, KeRecord};
use crate::keyderive::derive_working_keys;
use crate::{Error, Result};

#[derive(Clone)]
pub struct KeServerConfig {
    pub tls: Arc<ServerConfig>,
    pub key_store: KeyStore,
    pub ntp_server_hint: Option<String>,
    pub ntp_port_hint: u16,
    pub cookies_per_handshake: usize,
    pub cookie_ttl_secs: u64,
}

pub struct KeServer {
    listener: TcpListener,
    cfg: KeServerConfig,
}

impl KeServer {
    pub fn bind(addr: &str, cfg: KeServerConfig) -> Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        Ok(Self { listener, cfg })
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accept and fully serve one KE connection (blocking).
    pub fn handle_one(&self) -> Result<()> {
        let (tcp, _peer) = self.listener.accept()?;
        tcp.set_nodelay(true)?;
        match self.serve_conn(tcp) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Protocol-level failures already attempted an Error record;
                // connection errors just surface to the caller's log.
                Err(e)
            }
        }
    }

    fn serve_conn(&self, mut tcp: TcpStream) -> Result<()> {
        let mut conn = ServerConnection::new(self.cfg.tls.clone())?;
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);

        let mut reader = BufReader::new(&mut stream);
        let request = read_until_eom(&mut reader)?;

        // Validate request shape: exactly one critical algo record, then EOM.
        let offered = parse_client_request(&request)?;
        let alg = AeadAlg::negotiate(&offered)?;

        let mut writer = reader.into_inner();

        let version = writer
            .conn
            .protocol_version()
            .ok_or_else(|| Error::ke("no negotiated version"))?;
        if version != rustls::ProtocolVersion::TLSv1_3 {
            return Err(Error::ke("only TLS 1.3 is permitted"));
        }

        // Two TLS exporters produce the C2S/S2C keys directly (RFC 8915 §5.1).
        let keys = {
            let conn = &writer.conn;
            derive_working_keys(
                |label, ctx, len| {
                    let mut out = vec![0u8; len];
                    conn.export_keying_material(&mut out, label.as_bytes(), Some(ctx))
                        .map_err(|e| Error::ke(format!("exporter: {e}")))?;
                    Ok(out)
                },
                alg,
            )?
        };

        // Mint cookies. Each cookie independently binds a fresh UID; the
        // working keys inside are identical across the batch (one TLS session).
        let master = self.cfg.key_store.current();
        let mut records = Vec::with_capacity(self.cfg.cookies_per_handshake + 5);
        records.push(KeRecord::next_protocol(&[NEXT_PROTOCOL_NTPV4]));
        records.push(KeRecord::algo_negotiation(&[alg.id()]));
        for _ in 0..self.cfg.cookies_per_handshake {
            let cookie = mint_cookie(
                &master,
                alg,
                &keys.c2s,
                &keys.s2c,
                self.cfg.cookie_ttl_secs,
            )?;
            records.push(KeRecord::new_cookie(cookie));
        }
        if let Some(name) = &self.cfg.ntp_server_hint {
            records.push(KeRecord::server_negotiation(name));
        }
        if self.cfg.ntp_port_hint != 0 {
            records.push(KeRecord::port_negotiation(self.cfg.ntp_port_hint));
        }
        records.push(KeRecord::end_of_message());

        write_records(&mut writer, &records)?;
        writer.flush()?;
        writer.conn.send_close_notify();
        let _ = writer.flush();
        Ok(())
    }
}

fn parse_client_request(records: &[KeRecord]) -> Result<Vec<u16>> {
    let mut offered: Option<Vec<u16>> = None;
    let mut saw_ntpv4 = false;
    let mut eom = false;
    for rec in records {
        match rec.r#type {
            KE_RECORD_NEXT_PROTOCOL => {
                if !rec.critical || rec.body.len() % 2 != 0 || rec.body.is_empty() {
                    return Err(Error::ke("malformed next-protocol record"));
                }
                // We only protect NTPv4 (protocol id 0).
                let protocols: Vec<u16> = (0..rec.body.len() / 2)
                    .map(|i| BigEndian::read_u16(&rec.body[i * 2..i * 2 + 2]))
                    .collect();
                if !protocols.contains(&NEXT_PROTOCOL_NTPV4) {
                    return Err(Error::ke("client did not offer NTPv4"));
                }
                saw_ntpv4 = true;
            }
            KE_RECORD_ALGO_NEGOTIATION => {
                if rec.body.len() % 2 != 0 || rec.body.is_empty() {
                    return Err(Error::ke("malformed algorithm negotiation record"));
                }
                let ids = (0..rec.body.len() / 2)
                    .map(|i| BigEndian::read_u16(&rec.body[i * 2..i * 2 + 2]))
                    .collect();
                if offered.is_some() {
                    return Err(Error::ke("duplicate algorithm negotiation record"));
                }
                offered = Some(ids);
            }
            KE_RECORD_END_OF_MESSAGE => {
                eom = true;
            }
            // Optional, client-permitted records we simply accept.
            KE_RECORD_SERVER_NEGOTIATION | KE_RECORD_PORT_NEGOTIATION => {}
            other => {
                if rec.critical {
                    return Err(Error::ke(format!(
                        "unrecognized critical record 0x{other:04x}"
                    )));
                }
            }
        }
    }
    if !eom {
        return Err(Error::ke("request missing End-of-Message"));
    }
    if !saw_ntpv4 {
        return Err(Error::ke("request missing NTS Next Protocol Negotiation"));
    }
    offered.ok_or_else(|| Error::ke("request missing algorithm negotiation"))
}

/// Send an Error record then close; used by a front-end that catches
/// [`Error::ke`] failures before the response path runs.
pub fn send_error(mut w: impl Write, code: u16) -> Result<()> {
    write_records(&mut w, &[KeRecord::error(code), KeRecord::end_of_message()])
}
