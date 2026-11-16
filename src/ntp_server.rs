//! NTS-protected NTP server (RFC 8915 §5).
//!
//! Per datagram the server:
//!   1. parses header + the single NTS Authenticator EF, which must be last,
//!   2. opens the authenticator with the C2S key recovered from the (outer)
//!      NTS Cookie EF, binding the 32-byte UID and the 48-byte header,
//!   3. cross-checks inner and outer extension fields, counts Cookie
//!      Placeholders, and mints replacements under the current master key,
//!   4. builds the NTP server header (origin = client transmit, receive/
//!      transmit = local clock), seals [UID, new cookies…, negotiated AEAD]
//!      with the S2C key and sends it back.

use std::net::{SocketAddr, UdpSocket};

use crate::constants::{
    EF_NTS_AUTHENTICATOR, EF_NTS_COOKIE, EF_NTS_COOKIE_PLACEHOLDER, EF_UNIQUE_IDENTIFIER,
    NTP_HEADER_LEN, UNIQUE_ID_LEN,
};
use crate::cookie::{mint_cookie, verify_cookie, KeyStore};
use crate::ntp::{
    ef_cookie, ef_negotiated_aead, ef_unique_id, parse_extension_fields, parse_nts_packet,
    write_extension_fields, AuthenticatorBody,
    ExtensionField, NtpHeader, NtpTimestamp, LI_NO_WARNING, MODE_SERVER,
};
use crate::time_util::{Clock, SystemClock};
use crate::{Error, Result};

pub struct NtsNtpServerConfig {
    pub key_store: KeyStore,
    pub cookie_ttl_secs: u64,
    pub stratum: u8,
    pub reference_id: [u8; 4],
}

pub struct NtsNtpServer {
    socket: UdpSocket,
    cfg: NtsNtpServerConfig,
    clock: Box<dyn Clock>,
}

impl NtsNtpServer {
    pub fn bind(addr: &str, cfg: NtsNtpServerConfig) -> Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            cfg,
            clock: Box::new(SystemClock::default()),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Bound a blocking `recv_from` so the front-end can periodically reload
    /// the shared key store. A timeout surfaces as
    /// [`std::io::ErrorKind::WouldBlock`] / `TimedOut`.
    pub fn set_recv_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        self.socket.set_read_timeout(Some(timeout))?;
        Ok(())
    }

    /// Serve one datagram, returning the peer address on success.
    pub fn serve_one(&self) -> Result<SocketAddr> {
        let mut buf = vec![0u8; 2048];
        let (n, peer) = self.socket.recv_from(&mut buf)?;
        buf.truncate(n);
        match self.handle(&buf) {
            Ok(resp) => {
                self.socket.send_to(&resp, peer)?;
                Ok(peer)
            }
            Err(e) => {
                // NTS has no error channel over UDP; invalid packets are
                // dropped silently (§5.8). Surface the reason for logging.
                Err(e)
            }
        }
    }

    /// Process one request and return the serialized response packet.
    pub fn handle(&self, request: &[u8]) -> Result<Vec<u8>> {
        let packet = parse_nts_packet(request)?;
        if packet.header.version != 4 || packet.header.mode != crate::ntp::MODE_CLIENT {
            return Err(Error::ntp("expected NTPv4 client mode 3"));
        }
        let (auth_body, auth_idx) = packet
            .authenticator
            .ok_or_else(|| Error::AuthFailed("request has no authenticator".into()))?;
        if auth_idx != packet.fields.len() - 1 {
            return Err(Error::ntp("authenticator must be the last EF"));
        }

        // ---- outer cleartext fields: UID and the NTS Cookie ----
        let outer_uid = packet
            .fields
            .iter()
            .find(|f| f.r#type == EF_UNIQUE_IDENTIFIER)
            .ok_or_else(|| Error::AuthFailed("request has no Unique Identifier EF".into()))?;
        if outer_uid.value.len() != UNIQUE_ID_LEN {
            return Err(Error::AuthFailed(
                "Unique Identifier must be 32 octets".into(),
            ));
        }
        let uid = outer_uid.value.clone();
        // The authenticator nonce is the AEAD nonce: 16 octets for GCM
        // (RFC 5116) and 32 for SIV-CMAC (RFC 5297). Per RFC 8915 it is an
        // independent random value, not derived from the Unique Identifier.
        match auth_body.nonce.len() {
            16 | 32 => {}
            n => {
                return Err(Error::AuthFailed(format!(
                    "unexpected authenticator nonce length {n}"
                )))
            }
        };
        let outer_cookie = packet
            .fields
            .iter()
            .find(|f| f.r#type == EF_NTS_COOKIE)
            .ok_or_else(|| Error::AuthFailed("request has no cookie EF".into()))?;
        let verified = verify_cookie(&self.cfg.key_store, &outer_cookie.value)?;

        // ---- C2S open ----
        // AAD is every byte preceding the authenticator EF: the NTP header
        // plus the cleartext outer fields (Unique Identifier, Cookie).
        let auth_prefix_len = NTP_HEADER_LEN
            + packet
                .fields
                .iter()
                .take(auth_idx)
                .map(crate::ntp::ExtensionField::wire_len)
                .sum::<usize>();
        if auth_prefix_len > request.len() {
            return Err(Error::ntp("authenticator offset beyond packet"));
        }
        let plaintext = verified.alg.open(
            &verified.c2s_key,
            &auth_body.nonce,
            &request[..auth_prefix_len],
            &auth_body.ciphertext,
        )?;
        // The encrypted body may be empty (no placeholders); an empty wire
        // means zero inner extension fields.
        let inner_fields = if plaintext.is_empty() {
            Vec::new()
        } else {
            parse_extension_fields(&plaintext)?
        };

        // ---- inner fields may only contain cookie placeholders ----
        if inner_fields
            .iter()
            .any(|f| f.r#type != EF_NTS_COOKIE_PLACEHOLDER)
        {
            return Err(Error::AuthFailed(
                "unexpected non-placeholder field inside authenticator".into(),
            ));
        }
        let placeholders = inner_fields.len();

        // ---- timestamps: receive now, transmit now (after processing) ----
        let t2 = self.clock.now_ntp();
        let t3 = self.clock.now_ntp();
        let resp_header = NtpHeader {
            li: LI_NO_WARNING,
            version: 4,
            mode: MODE_SERVER,
            stratum: self.cfg.stratum,
            poll: packet.header.poll,
            precision: -24, // ~60 ns nominal
            root_delay: 0,
            root_dispersion: 0,
            reference_id: self.cfg.reference_id,
            reference_timestamp: t2,
            origin_timestamp: packet.header.transmit_timestamp,
            receive_timestamp: t2,
            transmit_timestamp: t3,
        };

        // ---- response layout (RFC 8915 §5.7) ----
        // The Unique Identifier is echoed as a cleartext outer EF; only the
        // replacement cookies and the negotiated-AEAD EF go inside the
        // S2C-encrypted authenticator.
        let mut resp_inner: Vec<ExtensionField> = Vec::new();
        let master = self.cfg.key_store.current();
        for _ in 0..placeholders {
            let new_cookie = mint_cookie(
                &master,
                verified.alg,
                &verified.c2s_key,
                &verified.s2c_key,
                self.cfg.cookie_ttl_secs,
            )?;
            resp_inner.push(ef_cookie(&new_cookie));
        }
        // Always hand back at least one cookie even without placeholders,
        // so a simple client never empties its jar.
        if placeholders == 0 {
            let new_cookie = mint_cookie(
                &master,
                verified.alg,
                &verified.c2s_key,
                &verified.s2c_key,
                self.cfg.cookie_ttl_secs,
            )?;
            resp_inner.push(ef_cookie(&new_cookie));
        }
        resp_inner.push(ef_negotiated_aead(verified.alg.id()));

        let inner_wire = write_extension_fields(&resp_inner);
        let header_bytes = resp_header.to_bytes();
        // Echo the request's AEAD nonce (16B for GCM/SIV in NTS practice).
        let resp_nonce = auth_body.nonce.clone();
        // AAD = header + cleartext outer UID EF, everything before the auth.
        let outer_uid_wire = write_extension_fields(&[ef_unique_id(&uid)]);
        let mut resp_aad = Vec::with_capacity(header_bytes.len() + outer_uid_wire.len());
        resp_aad.extend_from_slice(&header_bytes);
        resp_aad.extend_from_slice(&outer_uid_wire);
        let sealed = verified.alg.seal(
            &verified.s2c_key,
            &resp_nonce,
            &resp_aad,
            &inner_wire,
        )?;
        let auth = ExtensionField::new(
            EF_NTS_AUTHENTICATOR,
            AuthenticatorBody {
                nonce: resp_nonce,
                ciphertext: sealed,
            }
            .encode(),
        );
        // Outer cleartext UID first, then the authenticator (always last).
        let mut out = resp_aad;
        out.extend_from_slice(&write_extension_fields(&[auth]));
        Ok(out)
    }
}

/// Convenience for tests / the demo: round-trip one packet in-process.
pub fn process_inproc(
    cfg: &NtsNtpServerConfig,
    request: &[u8],
    clock: &dyn Clock,
) -> Result<Vec<u8>> {
    let srv = NtsNtpServer {
        socket: UdpSocket::bind("127.0.0.1:0").unwrap(),
        cfg: NtsNtpServerConfig {
            key_store: cfg.key_store.clone(),
            cookie_ttl_secs: cfg.cookie_ttl_secs,
            stratum: cfg.stratum,
            reference_id: cfg.reference_id,
        },
        clock: Box::new(InprocClock(clock.instant_nanos(), clock.now_ntp())),
    };
    srv.handle(request)
}

struct InprocClock(u128, NtpTimestamp);
impl Clock for InprocClock {
    fn now_ntp(&self) -> NtpTimestamp {
        self.1
    }
    fn instant_nanos(&self) -> u128 {
        self.0
    }
}
