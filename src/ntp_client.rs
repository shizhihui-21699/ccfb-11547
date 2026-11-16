//! NTS-protected NTP client (RFC 8915 §5).
//!
//! Per request the client:
//!   1. builds an NTPv4 client header with a fresh transmit timestamp,
//!   2. generates a 32-byte Unique Identifier and consumes one cookie,
//!   3. serializes [UID, Cookie, N cookie placeholders] as the *plaintext*,
//!      AEAD-seals it with the C2S key (AAD = 48-byte NTP header), and
//!      appends a single NTS Authenticator extension field,
//!   4. verifies the response with the S2C key, echoes the UID, and runs the
//!      standard on-wire offset/RTT calculation.
//!
//! Cookies are consumed one per request; placeholders ask the server to
//! replenish the jar in the same round trip, so a steady-state client keeps
//! the same count without another KE handshake until the server refuses.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use byteorder::ByteOrder;

use crate::aead::AeadAlg;
use crate::cookie::fresh_uid;
use crate::constants::*;
use crate::ke_client::KeSession;
use crate::ntp::{
    ef_cookie, ef_cookie_placeholder, ef_unique_id, parse_nts_packet, write_extension_fields, AuthenticatorBody, ExtensionField, NtpHeader,
    NtpTimestamp, NtsPacket, LI_NO_WARNING, MODE_CLIENT,
};
use crate::time_util::{on_wire_calculation, Clock, SystemClock};
use crate::{Error, Result};

/// One authenticated time sample plus bookkeeping for the cookie jar.
#[derive(Debug, Clone)]
pub struct TimeSample {
    pub offset_nanos: i128,
    pub rtt_nanos: u128,
    pub t1: NtpTimestamp,
    pub t2: NtpTimestamp,
    pub t3: NtpTimestamp,
    pub t4: NtpTimestamp,
    pub stratum: u8,
    pub cookies_remaining: usize,
}

pub struct NtsNtpClient {
    session: KeSession,
    socket: UdpSocket,
    server: SocketAddr,
    clock: Box<dyn Clock>,
    /// Desired steady-state jar size; placeholders request back to this.
    jar_target: usize,
}

impl NtsNtpClient {
    pub fn connect(session: KeSession, server: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", 0))?;
        socket.set_read_timeout(Some(Duration::from_millis(800)))?;
        socket.connect(server)?;
        Ok(Self {
            session,
            socket,
            server,
            clock: Box::new(SystemClock::default()),
            jar_target: DEFAULT_COOKIES_PER_KE,
        })
    }

    pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn cookies_left(&self) -> usize {
        self.session.cookies.len()
    }

    /// Address of the NTS NTP server this client exchanges with.
    pub fn server_addr(&self) -> SocketAddr {
        self.server
    }

    pub fn alg(&self) -> AeadAlg {
        self.session.alg
    }

    /// Perform one authenticated NTP exchange, consuming one cookie.
    ///
    /// A lost datagram is retried a few times with a fresh UID but the same
    /// cookie (cookies are reusable tokens), so a transient timeout does not
    /// drain the jar.
    pub fn query(&mut self) -> Result<TimeSample> {
        let cookie = self
            .session
            .cookies
            .pop()
            .ok_or(Error::NoCookies)?;

        let max_attempts = 4;
        let mut last_err = None;
        for _ in 0..max_attempts {
            match self.exchange_once(&cookie) {
                Ok(sample) => return Ok(sample),
                Err(Error::Io(e))
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    last_err = Some(Error::Io(e));
                    continue; // fresh UID, same cookie
                }
                Err(e) => {
                    // Authentication/parsing errors are not retryable; return
                    // the cookie so the jar is not charged for a failed probe.
                    self.session.cookies.push(cookie.clone());
                    return Err(e);
                }
            }
        }
        self.session.cookies.push(cookie);
        Err(last_err.unwrap_or_else(|| Error::ntp("exchanges exhausted without a response")))
    }

    fn exchange_once(&mut self, cookie: &[u8]) -> Result<TimeSample> {
        let uid = fresh_uid();
        // AEAD nonce, independent of the Unique Identifier per RFC 8915:
        // 16 octets for GCM (RFC 5116), 32 for SIV-CMAC (RFC 5297).
        let nonce: Vec<u8> = match self.session.alg {
            AeadAlg::Aes128Gcm => fresh_uid()[..16].to_vec(),
            AeadAlg::AesSivCmac256 => fresh_uid().to_vec(),
        };

        // ---- header ----
        let t1 = self.clock.now_ntp();
        let header = NtpHeader {
            li: LI_NO_WARNING,
            version: 4,
            mode: MODE_CLIENT,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: [0; 4],
            reference_timestamp: NtpTimestamp(0),
            origin_timestamp: NtpTimestamp(0),
            receive_timestamp: NtpTimestamp(0),
            transmit_timestamp: t1,
        };

        // ---- RFC 8915 §5.6 request layout ----
        // Cleartext outer fields: Unique Identifier and the NTS Cookie (the
        // server needs the cookie to recover the working keys). Only the
        // Cookie Placeholder requests go inside the encrypted authenticator.
        let placeholders = self.jar_target.saturating_sub(self.session.cookies.len());
        let mut inner_fields: Vec<ExtensionField> = Vec::new();
        for _ in 0..placeholders {
            inner_fields.push(ef_cookie_placeholder(cookie.len()));
        }
        // The authenticator's encrypted body must still be authenticated;
        // with no placeholders, seal an empty field list.
        let plaintext = write_extension_fields(&inner_fields);

        // ---- AEAD seal ----
        // AAD is the whole packet prefix preceding the authenticator: the
        // 48-byte NTP header plus the cleartext Unique Identifier and Cookie
        // extension fields (RFC 8915 §5.4 / chrony NNA_GenerateAuthEF).
        let header_bytes = header.to_bytes();
        let outer = [ef_unique_id(&uid), ef_cookie(cookie)];
        let outer_wire = write_extension_fields(&outer);
        let mut aad = Vec::with_capacity(header_bytes.len() + outer_wire.len());
        aad.extend_from_slice(&header_bytes);
        aad.extend_from_slice(&outer_wire);

        let sealed = self.session.alg.seal(
            &self.session.c2s_key,
            &nonce,
            &aad,
            &plaintext,
        )?;
        let auth = ExtensionField::new(
            EF_NTS_AUTHENTICATOR,
            AuthenticatorBody {
                nonce: nonce.clone(),
                ciphertext: sealed,
            }
            .encode(),
        );
        // Outer fields first, authenticator always last (§5.4.3).
        let mut packet = aad;
        packet.extend_from_slice(&write_extension_fields(&[auth]));

        // ---- exchange ----
        let recv_mono = self.clock.instant_nanos();
        self.socket.send(&packet)?;
        let mut buf = vec![0u8; 2048];
        let n = self.socket.recv(&mut buf)?;
        buf.truncate(n);
        let t4 = self.clock.now_ntp();

        let sample = self.verify_response(&buf, &header, &uid, &nonce, t1, t4, recv_mono)?;
        Ok(sample)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_response(
        &mut self,
        buf: &[u8],
        req_header: &NtpHeader,
        uid: &[u8],
        nonce: &[u8],
        t1: NtpTimestamp,
        t4: NtpTimestamp,
        _recv_mono: u128,
    ) -> Result<TimeSample> {
        let NtsPacket {
            header,
            fields,
            authenticator,
        } = parse_nts_packet(buf)?;

        if header.version != 4 || header.mode != crate::ntp::MODE_SERVER {
            return Err(Error::ntp(format!(
                "expected NTPv4 server response, got v{} mode {}",
                header.version, header.mode
            )));
        }
        // The server copies our transmit timestamp into origin (§5.6).
        if header.origin_timestamp != t1 {
            return Err(Error::AuthFailed(
                "response origin timestamp does not match request".into(),
            ));
        }
        let (auth_body, auth_idx) = authenticator
            .ok_or_else(|| Error::AuthFailed("response has no NTS authenticator".into()))?;

        // Authenticator must be the final extension field (§5.4.3).
        if auth_idx != fields.len() - 1 {
            return Err(Error::ntp("authenticator is not the last extension field"));
        }

        // ---- S2C open ----
        // AAD is the full packet prefix before the authenticator: response
        // header plus the cleartext outer extension fields.
        let resp_prefix_len = NTP_HEADER_LEN
            + fields
                .iter()
                .take(auth_idx)
                .map(ExtensionField::wire_len)
                .sum::<usize>();
        if resp_prefix_len > buf.len() {
            return Err(Error::ntp("response authenticator offset beyond packet"));
        }
        let inner_bytes = self.session.alg.open(
            &self.session.s2c_key,
            nonce,
            &buf[..resp_prefix_len],
            &auth_body.ciphertext,
        )?;
        let inner = parse_nts_packet(&{
            let mut h = [0u8; NTP_HEADER_LEN];
            req_header.write(&mut h);
            let mut full = h.to_vec();
            full.extend_from_slice(&inner_bytes);
            full
        })?;

        // The Unique Identifier is echoed as a cleartext outer EF (§5.7).
        let outer_uid = fields
            .iter()
            .find(|f| f.r#type == EF_UNIQUE_IDENTIFIER)
            .ok_or_else(|| Error::AuthFailed("response missing outer Unique Identifier".into()))?;
        if outer_uid.value != uid {
            return Err(Error::AuthFailed("Unique Identifier mismatch".into()));
        }
        // The encrypted inner fields must not contain another authenticator.
        if inner
            .fields
            .iter()
            .any(|f| f.r#type == EF_NTS_AUTHENTICATOR)
        {
            return Err(Error::AuthFailed("nested authenticator in response".into()));
        }
        // Negotiated AEAD, if present, must equal the KE-negotiated algorithm.
        if let Some(neg) = inner.fields.iter().find(|f| f.r#type == EF_NTS_NEGOTIATED_AEAD) {
            if neg.value.len() >= 2 {
                let id = byteorder::BigEndian::read_u16(&neg.value);
                if id != self.session.alg.id() {
                    return Err(Error::AuthFailed(format!(
                        "server changed AEAD to {id} mid-session"
                    )));
                }
            }
        }

        // ---- replenish the cookie jar from New Cookie fields ----
        for f in inner.fields.iter().filter(|f| f.r#type == EF_NTS_COOKIE) {
            self.session.cookies.push(f.value.clone());
        }

        let (offset_nanos, rtt_nanos) =
            on_wire_calculation(t1, header.receive_timestamp, header.transmit_timestamp, t4)?;

        Ok(TimeSample {
            offset_nanos,
            rtt_nanos,
            t1,
            t2: header.receive_timestamp,
            t3: header.transmit_timestamp,
            t4,
            stratum: header.stratum,
            cookies_remaining: self.session.cookies.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time_util::testutil::FakeClock;

    fn session_for(alg: AeadAlg) -> KeSession {
        KeSession {
            alg,
            c2s_key: vec![3u8; alg.key_len()],
            s2c_key: vec![4u8; alg.key_len()],
            cookies: vec![vec![0xaa; 40], vec![0xbb; 40]],
            ntp_server: None,
            ntp_port: 4123,
        }
    }

    #[test]
    fn no_cookie_is_error() {
        let mut s = session_for(AeadAlg::Aes128Gcm);
        s.cookies.clear();
        let client = NtsNtpClient::connect(s, "127.0.0.1:4123".parse().unwrap()).unwrap();
        let mut c = client.with_clock(Box::new(FakeClock::new(1_700_000_000)));
        assert!(matches!(c.query(), Err(Error::NoCookies)));
    }
}
