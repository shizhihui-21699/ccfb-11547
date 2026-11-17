//! NTS server: NTS-KE endpoint plus an NTS-protected NTPv4 responder.
//!
//! The server keeps no per-client state. Everything needed to answer a request
//! is in the cookie the client returns, encrypted under a rotating master key
//! (see `nts_core::cookie`). That is what makes key rotation cheap and what
//! lets an NTP node be restarted, or load-balanced across nodes sharing a
//! master key, without invalidating clients' cookies.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nts_core::aead::AeadAlg;
use nts_core::auth;
use nts_core::cookie::KeyRing;
use nts_core::ke::{self as ke_records, Record, RecordType, PROTOCOL_NTPV4};
use nts_core::ntp::{
    self, ExtensionField, Packet, EF_NTS_COOKIE, EF_NTS_COOKIE_PLACEHOLDER,
    EF_UNIQUE_IDENTIFIER, MODE_CLIENT, MODE_SERVER,
};
use nts_ke::{self as ke};
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// Cookies handed out per NTS-KE exchange. RFC 8915 §4.1.6 says "SHOULD send
/// eight"; chrony's client keeps a pool of eight.
pub const COOKIES_PER_KE: usize = 8;

/// Algorithms this server accepts, in preference order. 15 is mandatory to
/// implement; 30 is smaller on the wire and preferred when both sides allow it.
pub const DEFAULT_ALGS: [AeadAlg; 2] = [AeadAlg::AesSivCmac256, AeadAlg::Aes128GcmSiv];

#[derive(Debug)]
pub struct ServerConfig {
    pub ke_bind: SocketAddr,
    pub ntp_bind: SocketAddr,
    /// Cert chain, leaf first.
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// Name advertised in the NTPv4 Server Negotiation record. If `None` the
    /// record is omitted and clients use the KE server's address (§4.1.7).
    pub ntp_server_name: Option<String>,
    /// Port advertised in the NTPv4 Port Negotiation record; omitted when 123.
    pub ntp_port: u16,
    pub algorithms: Vec<AeadAlg>,
    /// Master keys retained after rotation (in addition to the current one).
    pub key_retain: usize,
    /// Maximum age of a cookie, in seconds.
    pub cookie_max_age: Duration,
    /// Stratum to advertise. This implementation has no clock discipline of
    /// its own, so it reports a high stratum rather than claiming accuracy it
    /// does not have.
    pub stratum: u8,
    /// Also answer plain, unprotected NTP requests. Off by default: serving
    /// unauthenticated time from a server that advertises NTS is a downgrade
    /// path. Enabled only for benchmark comparisons.
    pub allow_plain_ntp: bool,
}

/// Live counters, exported for the stats endpoint and for tests.
#[derive(Default)]
pub struct ServerStats {
    pub ke_requests: AtomicU64,
    pub ke_failures: AtomicU64,
    pub ntp_requests: AtomicU64,
    pub ntp_bad_cookie: AtomicU64,
    pub ntp_auth_failures: AtomicU64,
    pub cookies_minted: AtomicU64,
    pub rotations: AtomicU64,
}

pub struct NtsServer {
    cfg: ServerConfig,
    ring: KeyRing,
    stats: Arc<ServerStats>,
    start: Instant,
}

impl NtsServer {
    pub fn new(cfg: ServerConfig) -> Self {
        let ring = KeyRing::new(cfg.key_retain, cfg.cookie_max_age.as_secs());
        Self {
            cfg,
            ring,
            stats: Arc::new(ServerStats::default()),
            start: Instant::now(),
        }
    }

    pub fn stats(&self) -> Arc<ServerStats> {
        self.stats.clone()
    }

    pub fn key_ring(&self) -> KeyRing {
        self.ring.clone()
    }

    pub fn uptime(&self) -> Duration {
        self.start.elapsed()
    }

    /// Rotate the cookie master key. New cookies use the new key immediately;
    /// cookies from the previous `key_retain` generations keep working.
    pub fn rotate(&self) -> u32 {
        let id = self.ring.rotate();
        self.stats.rotations.fetch_add(1, Ordering::Relaxed);
        info!(key_id = id, generations = self.ring.generations(), "rotated cookie master key");
        id
    }

    /// Start the periodic rotation task. Returns a handle that stops it on drop.
    pub fn spawn_rotation(self: &Arc<Self>, every: Duration) -> RotationTask {
        let server = self.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            ticker.tick().await; // first tick fires immediately; skip it
            loop {
                ticker.tick().await;
                server.rotate();
            }
        });
        RotationTask { handle: Some(handle) }
    }

    /// Serve both NTS-KE (TCP) and NTP (UDP) until the future is dropped.
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let tls_cfg = Arc::new(self.tls_config()?);
        let acceptor = TlsAcceptor::from(tls_cfg);

        let ke_listener = TcpListener::bind(self.cfg.ke_bind)
            .await
            .with_context(|| format!("binding NTS-KE listener on {}", self.cfg.ke_bind))?;
        let ntp_socket = UdpSocket::bind(self.cfg.ntp_bind)
            .await
            .with_context(|| format!("binding NTP socket on {}", self.cfg.ntp_bind))?;
        let ntp_socket = Arc::new(ntp_socket);

        info!(
            ke = %self.cfg.ke_bind,
            ntp = %ntp_socket.local_addr()?,
            algs = ?self.cfg.algorithms,
            "NTS server listening"
        );

        let ke_task = {
            let server = self.clone();
            tokio::spawn(async move {
                loop {
                    match ke_listener.accept().await {
                        Ok((stream, peer)) => {
                            let acceptor = acceptor.clone();
                            let server = server.clone();
                            tokio::spawn(async move {
                                server.stats.ke_requests.fetch_add(1, Ordering::Relaxed);
                                if let Err(e) = server.handle_ke(acceptor, stream, peer).await {
                                    server.stats.ke_failures.fetch_add(1, Ordering::Relaxed);
                                    debug!(%peer, error = %e, "NTS-KE session failed");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "NTS-KE accept failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            })
        };

        let ntp_task = {
            let server = self.clone();
            let socket = ntp_socket.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; ntp::MAX_PACKET_LEN];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((n, peer)) => {
                            server.stats.ntp_requests.fetch_add(1, Ordering::Relaxed);
                            debug!(%peer, len = n, "NTP packet received");
                            if std::env::var("NTS_DUMP").is_ok() {
                                tracing::debug!("rx hex: {}", hex::encode(&buf[..n]));
                            }
                            let request = buf[..n].to_vec();
                            let socket = socket.clone();
                            let server = server.clone();
                            tokio::spawn(async move {
                                if let Some(reply) = server.handle_ntp(&request, peer) {
                                    if let Err(e) = socket.send_to(&reply, peer).await {
                                        debug!(%peer, error = %e, "NTP send failed");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "NTP recv failed");
                        }
                    }
                }
            })
        };

        tokio::select! {
            r = ke_task => r.context("NTS-KE task panicked")?,
            r = ntp_task => r.context("NTP task panicked")?,
        }
        Ok(())
    }

    fn tls_config(&self) -> Result<rustls::ServerConfig> {
        let provider = rustls::crypto::ring::default_provider();
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("configuring TLS 1.3")?
            .with_no_client_auth()
            .with_single_cert(self.cfg.cert_chain.clone(), self.cfg.key.clone_key())
            .context("loading server certificate and key")?;
        cfg.alpn_protocols = vec![ke::ALPN.to_vec()];
        Ok(cfg)
    }

    async fn handle_ke(
        &self,
        acceptor: TlsAcceptor,
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
    ) -> Result<()> {
        let mut tls = acceptor.accept(stream).await.context("TLS accept")?;

        let records = ke::read_message(&mut tls).await.context("reading KE request")?;
        let request = match parse_request(&records) {
            Ok(r) => r,
            Err(KeFailure::Error(code)) => {
                        let resp = ke::build_response(Some(code), None, None, None, &[], false);
                ke::write_message(&mut tls, &resp).await.ok();
                tls.shutdown().await.ok();
                return Ok(());
            }
        };

        // Pick the first algorithm we support that the client offered.
        let algorithm = request
            .offered
            .iter()
            .copied()
            .find(|a| self.cfg.algorithms.contains(a));

        let Some(alg) = algorithm else {
            let resp = ke::build_response(None, None, None, None, &[], false);
            ke::write_message(&mut tls, &resp).await.ok();
            tls.shutdown().await.ok();
            return Ok(());
        };

        // Derive keys from the exporter and mint cookies. The exporter needs
        // the connection immutably; the ring mints under the current key.
        //
        // Historical quirk: when AES-128-GCM-SIV (30) was added, chrony and
        // some other implementations derived the exporter context with the
        // AES-SIV-CMAC-256 identifier (15) instead of the negotiated one. A
        // client that did not send record 1024 will do that, so we must too, or
        // our C2S key will not match the key it is using.
        let exporter_alg = if alg == AeadAlg::Aes128GcmSiv && !request.compliant_128gcm {
            debug!("client did not send record 1024; using legacy exporter context");
            AeadAlg::AesSivCmac256
        } else {
            alg
        };
        let cookies = {
            let (_, conn) = tls.get_ref();
            let keys = ke::derive_keys(conn, alg, exporter_alg, PROTOCOL_NTPV4)
                .map_err(|e| anyhow::anyhow!("exporter: {e}"))?;
            let mut cookies = Vec::with_capacity(COOKIES_PER_KE);
            for _ in 0..COOKIES_PER_KE {
                let c = self
                    .ring
                    .seal(alg, &keys.c2s, &keys.s2c)
                    .map_err(|e| anyhow::anyhow!("minting cookie: {e}"))?;
                cookies.push(c);
            }
            self.stats
                .cookies_minted
                .fetch_add(cookies.len() as u64, Ordering::Relaxed);
            cookies
        };

        let ntp_name = self.cfg.ntp_server_name.as_deref();
        let ntp_port = if self.cfg.ntp_port == 123 {
            None
        } else {
            Some(self.cfg.ntp_port)
        };
        let compliant = request.compliant_128gcm && alg == AeadAlg::Aes128GcmSiv;
        let resp = ke::build_response(None, Some(alg), ntp_name, ntp_port, &cookies, compliant);
        ke::write_message(&mut tls, &resp).await.context("writing KE response")?;
        tls.shutdown().await.ok();

        info!(%peer, %alg, "NTS-KE served");
        Ok(())
    }

    /// Handle one NTS-protected NTP request. Returns the reply to send, or
    /// `None` to stay silent.
    pub fn handle_ntp(&self, request: &[u8], peer: SocketAddr) -> Option<Vec<u8>> {
        let packet = match Packet::parse(request) {
            Ok(p) => p,
            Err(e) => {
                debug!(%peer, error = %e, "dropping malformed NTP packet");
                return None;
            }
        };
        if packet.mode() != MODE_CLIENT {
            debug!(%peer, mode = packet.mode(), "ignoring non-client-mode NTP packet");
            return None;
        }

        let cookie = match packet.find_field(EF_NTS_COOKIE) {
            Some(ef) => ef.body.clone(),
            None => {
                // A request with no NTS EFs at all is plain NTP. Answering it
                // is only enabled explicitly, because a server that advertises
                // NTS should not silently serve unauthenticated time: doing so
                // would let an on-path attacker downgrade a client by simply
                // stripping the extension fields. The flag exists so the
                // benchmark can measure protocol overhead on the same host.
                if self.cfg.allow_plain_ntp && packet.extension_fields.is_empty() {
                    return Some(self.plain_reply(&packet));
                }
                debug!(%peer, "request without cookie");
                return None;
            }
        };

        // Recover keys from the cookie. A failure here is expected during
        // rotation to a new key set, so it is a NAK, not a dropped packet.
        let (alg, c2s, s2c) = match self.ring.open(&cookie) {
            Ok(v) => v,
            Err(e) => {
                self.stats.ntp_bad_cookie.fetch_add(1, Ordering::Relaxed);
                debug!(%peer, error = %e, "rejecting cookie");
                return Some(self.nak_reply(&packet));
            }
        };

        let (verified, _plaintext) = match auth::open_packet(alg, &c2s, request) {
            Ok(v) => v,
            Err(e) => {
                self.stats.ntp_auth_failures.fetch_add(1, Ordering::Relaxed);
                debug!(%peer, error = %e, "request authentication failed");
                return Some(self.nak_reply(&packet));
            }
        };

        let uniq_id = match verified.find_field(EF_UNIQUE_IDENTIFIER) {
            Some(ef) if ef.body.len() >= 32 => ef.body.clone(),
            _ => {
                debug!(%peer, "request lacks a valid Unique Identifier");
                return Some(self.nak_reply(&packet));
            }
        };

        // One fresh cookie per valid Placeholder, plus one for the cookie the
        // client just spent (RFC 8915 §5.7).
        let placeholders = verified
            .find_fields(EF_NTS_COOKIE_PLACEHOLDER)
            .filter(|ef| ef.body.len() == cookie.len())
            .count();
        let n_cookies = (1 + placeholders).min(8);
        let mut new_cookies = Vec::with_capacity(n_cookies);
        for _ in 0..n_cookies {
            match self.ring.seal(alg, &c2s, &s2c) {
                Ok(c) => new_cookies.push(c),
                Err(e) => {
                    warn!(error = %e, "failed to mint cookie");
                    return Some(self.nak_reply(&packet));
                }
            }
        }
        self.stats
            .cookies_minted
            .fetch_add(new_cookies.len() as u64, Ordering::Relaxed);

        // Build the response prefix: header, Unique Identifier echo, then the
        // Authenticator EF wrapping the new cookies.
        let mut response = Packet::new(MODE_SERVER);
        response.set_stratum(self.stratum());
        response.set_originate_timestamp(packet.transmit_timestamp());
        response.set_receive_timestamp(ntp::now_ntp_timestamp());
        response.set_transmit_timestamp(ntp::now_ntp_timestamp());
        // Reference id identifies our clock source; "NTS" plus a version byte.
        response.set_reference_id(*b"NTS0");

        response
            .extension_fields
            .push(ExtensionField::new(EF_UNIQUE_IDENTIFIER, uniq_id));
        let prefix = response.encode();

        let encrypted: Vec<ExtensionField> = new_cookies
            .into_iter()
            .map(|c| ExtensionField::new(EF_NTS_COOKIE, c))
            .collect();

        let mut nonce = vec![0u8; alg.nonce_len()];
        rand::thread_rng().fill_bytes(&mut nonce);

        match auth::seal_packet(alg, &s2c, &prefix, &encrypted, &nonce) {
            Ok(reply) => {
                if std::env::var("NTS_DUMP").is_ok() {
                    tracing::debug!("tx hex: {}", hex::encode(&reply));
                }
                Some(reply)
            }
            Err(e) => {
                warn!(error = %e, "failed to seal response");
                None
            }
        }
    }

    /// Unauthenticated NTPv4 reply, used only when plain NTP is enabled.
    fn plain_reply(&self, request: &Packet) -> Vec<u8> {
        let mut p = Packet::new(MODE_SERVER);
        p.set_stratum(self.stratum());
        p.set_originate_timestamp(request.transmit_timestamp());
        p.set_receive_timestamp(ntp::now_ntp_timestamp());
        p.set_transmit_timestamp(ntp::now_ntp_timestamp());
        p.set_reference_id(*b"NTS0");
        p.encode()
    }

    /// Reply with an NTS NAK: an unauthenticated KoD carrying the client's
    /// Unique Identifier (RFC 8915 §5.7).
    fn nak_reply(&self, request: &Packet) -> Vec<u8> {
        let mut p = Packet::new(MODE_SERVER);
        p.set_stratum(0);
        p.set_reference_id(*b"NTSN");
        p.set_originate_timestamp(request.transmit_timestamp());
        if let Some(uniq) = request.find_field(EF_UNIQUE_IDENTIFIER) {
            p.extension_fields
                .push(ExtensionField::new(EF_UNIQUE_IDENTIFIER, uniq.body.clone()));
        }
        p.encode()
    }

    fn stratum(&self) -> u8 {
        self.cfg.stratum
    }
}

/// Why an NTS-KE request was refused.
///
/// Every rejection maps to an RFC 8915 §4.1.3 error code, so there is no
/// "close silently" variant: a client that gets no reply cannot distinguish a
/// buggy server from a wrong request, and §4.2 tells it to back off either way.
enum KeFailure {
    /// Reply with this NTS-KE error code and close.
    Error(u16),
}

struct KeRequest {
    offered: Vec<AeadAlg>,
    /// True when the client sent chrony's private record 1024, meaning it will
    /// derive AES-128-GCM-SIV exporter keys with the spec-compliant context.
    compliant_128gcm: bool,
}

fn parse_request(records: &[Record]) -> std::result::Result<KeRequest, KeFailure> {
    let mut protocol_seen = false;
    let mut protocol_ok = false;
    let mut offered: Option<Vec<AeadAlg>> = None;
    let mut compliant_128gcm = false;

    for rec in records {
        match rec.record_type {
            RecordType::EndOfMessage => {}
            RecordType::NextProtocol => {
                if protocol_seen {
                    return Err(KeFailure::Error(ke_records::RECORD_ERROR));
                }
                protocol_seen = true;
                protocol_ok = rec
                    .u16_list()
                    .map(|l| l.contains(&PROTOCOL_NTPV4))
                    .unwrap_or(false);
            }
            RecordType::AeadAlgorithm => {
                if offered.is_some() {
                    return Err(KeFailure::Error(1)); // Bad Request
                }
                let ids = rec.u16_list().map_err(|_| KeFailure::Error(1))?;
                let algs: Vec<AeadAlg> = ids.iter().filter_map(|id| AeadAlg::from_id(*id)).collect();
                // Keep the client's preference order, but only for algorithms
                // we know; unknown ones are ignored per §4.1.5.
                offered = Some(algs);
            }
            RecordType::Error | RecordType::Warning | RecordType::Cookie => {
                return Err(KeFailure::Error(1));
            }
            RecordType::Unknown(t) => {
                if t == ke_records::RECORD_CHRONY_COMPLIANT_128GCM {
                    // chrony-specific: an empty, non-critical record confirming
                    // the client will use the RFC-conformant exporter context
                    // for AEAD 30. We honour it below when deriving keys.
                    if !rec.body.is_empty() {
                        return Err(KeFailure::Error(1));
                    }
                    compliant_128gcm = true;
                    continue;
                }
                if rec.critical {
                    debug!(record_type = t, "unrecognized critical record");
                    return Err(KeFailure::Error(0)); // Unrecognized Critical Record
                }
            }
            RecordType::Ntpv4Server | RecordType::Ntpv4Port => {
                // We honour these only insofar as we advertise our own; a
                // client's preference here is optional to follow (§4.1.7).
            }
        }
    }

    if !protocol_seen {
        return Err(KeFailure::Error(1));
    }
    if !protocol_ok {
        return Err(KeFailure::Error(1));
    }
    let offered = offered.ok_or(KeFailure::Error(1))?;
    if offered.is_empty() {
        return Err(KeFailure::Error(1));
    }
    Ok(KeRequest {
        offered,
        compliant_128gcm,
    })
}

/// Stops the rotation task when dropped, so tests do not leak it.
pub struct RotationTask {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for RotationTask {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}
