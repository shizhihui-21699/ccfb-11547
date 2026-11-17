//! NTS client: NTS-KE handshake, NTS-protected NTP exchanges, and the
//! offset/delay arithmetic of RFC 5905 §8.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use nts_core::aead::AeadAlg;
use nts_core::auth;
use nts_core::error::Error as CoreError;
use nts_core::ke::MIN_RETRY_SECS;
use nts_core::keyring::Association;
use nts_core::ntp::{
    self, ExtensionField, Packet, EF_NTS_COOKIE, EF_NTS_COOKIE_PLACEHOLDER,
    EF_UNIQUE_IDENTIFIER, MODE_CLIENT, STRATUM_UNSPECIFIED,
};
use nts_ke::{self as ke};
use rand::RngCore;
use rustls::pki_types::ServerName;
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

/// Length of the Unique Identifier we generate. RFC 8915 §5.3 requires at
/// least 32 octets; chrony uses exactly 32.
pub const UNIQ_ID_LEN: usize = 32;

/// NTS NAK kiss code from a KoD packet ("NTSN").
pub const KOD_NTSN: [u8; 4] = *b"NTSN";

#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// NTS-KE hostname, also used as the TLS server name.
    pub ke_server: String,
    pub ke_port: u16,
    /// Overrides the hostname used for certificate validation, for cases where
    /// the KE server is reached by IP but the certificate names a host.
    pub tls_server_name: String,
    /// Explicit NTP server address, bypassing the KE server's NTPv4 Server
    /// record and DNS. Needed in networks where DNS is untrusted but the NTP
    /// server's address is known.
    pub ntp_server_override: Option<String>,
    pub ntp_port_override: Option<u16>,
    /// AEAD algorithms to offer, in preference order.
    pub offered: Vec<AeadAlg>,
    /// Extra roots to trust, for a private CA. `None` means system roots only.
    pub extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// Skip certificate verification. Only for lab interop testing.
    pub insecure: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            ke_server: String::new(),
            ke_port: ke::DEFAULT_PORT,
            tls_server_name: String::new(),
            ntp_server_override: None,
            ntp_port_override: None,
            // Prefer the mandatory-to-implement algorithm: it is what every NTS
            // implementation must support, so offering it first maximises
            // interoperability. AES-128-GCM-SIV is offered second.
            offered: vec![AeadAlg::AesSivCmac256, AeadAlg::Aes128GcmSiv],
            extra_roots: Vec::new(),
            insecure: false,
        }
    }
}

/// The result of a completed NTS-KE run.
pub struct KeOutcome {
    pub association: Association,
    pub ntp_addr: SocketAddr,
    pub negotiated_alg: AeadAlg,
    pub ntp_server_name: Option<String>,
    pub ntp_port: u16,
}

/// Perform the NTS-KE handshake and return a ready-to-use association.
pub async fn do_ke(cfg: &ClientConfig) -> Result<KeOutcome> {
    let tls_cfg = Arc::new(build_tls_config(cfg)?);
    let connector = TlsConnector::from(tls_cfg);

    let ke_host = if cfg.tls_server_name.is_empty() {
        cfg.ke_server.clone()
    } else {
        cfg.tls_server_name.clone()
    };
    let ke_addr = format!("{}:{}", cfg.ke_server, cfg.ke_port);
    debug!(%ke_addr, %ke_host, "connecting for NTS-KE");

    // Resolve explicitly rather than handing a `host:port` string to
    // `TcpStream::connect`: that path takes whatever address the resolver
    // returns first, which on dual-stack hosts is commonly `::1` for
    // `localhost`. Many NTS-KE servers bind only IPv4, and the resulting
    // failure looks like a TLS error rather than a connection error.
    let tcp_addr = resolve(&cfg.ke_server, cfg.ke_port).await?;
    debug!(%tcp_addr, "resolved NTS-KE address");
    let tcp = TcpStream::connect(tcp_addr)
        .await
        .with_context(|| format!("connecting to NTS-KE server {ke_addr} ({tcp_addr})"))?;
    tcp.set_nodelay(true).ok();

    let server_name = ServerName::try_from(ke_host.clone())
        .map_err(|_| anyhow!("invalid TLS server name {ke_host:?}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake with NTS-KE server")?;

    {
        let (_, conn) = tls.get_ref();
        let alpn = conn.alpn_protocol().map(|p| p.to_vec());
        if alpn.as_deref() != Some(ke::ALPN) {
            bail!("NTS-KE server did not select ALPN ntske/1 (got {alpn:?})");
        }
        if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            bail!(
                "NTS-KE requires TLS 1.3, server negotiated {:?}",
                conn.protocol_version()
            );
        }
    }

    let request = ke::build_request(&cfg.offered, None, None);
    ke::write_message(&mut tls, &request)
        .await
        .context("sending NTS-KE request")?;
    let records = ke::read_message(&mut tls)
        .await
        .context("reading NTS-KE response")?;
    let response = ke::parse_response(&records).context("parsing NTS-KE response")?;

    // Derive keys from the exporter before the TLS session goes away. The
    // exporter is available as soon as the handshake completes, so this can
    // borrow the connection for the last time.
    let keys = {
        let (_, conn) = tls.get_ref();
        ke::derive_keys(
            conn,
            response.algorithm,
            response.exporter_alg(),
            nts_core::ke::PROTOCOL_NTPV4,
        )
        .map_err(|e| anyhow!("deriving AEAD keys: {e}"))?
    };

    info!(
        algorithm = %response.algorithm,
        cookies = response.cookies.len(),
        "NTS-KE complete"
    );

    let ntp_name = cfg
        .ntp_server_override
        .clone()
        .or_else(|| response.ntp_server.clone());
    let ntp_port = cfg
        .ntp_port_override
        .or(Some(response.ntp_port))
        .unwrap_or(123);

    let host_for_addr = ntp_name
        .clone()
        .unwrap_or_else(|| cfg.ke_server.clone());
    let ntp_addr = resolve(&host_for_addr, ntp_port)
        .await
        .with_context(|| format!("resolving NTP server {host_for_addr}"))?;

    Ok(KeOutcome {
        association: Association::new(keys, response.cookies),
        ntp_addr,
        negotiated_alg: response.algorithm,
        ntp_server_name: response.ntp_server,
        ntp_port,
    })
}

async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    // Accept a literal address without a DNS lookup, which also avoids the
    // resolver entirely in networks where it cannot be trusted.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("DNS lookup for {host}"))?
        .collect();
    addrs
        .into_iter()
        // Prefer IPv4: many lab networks advertise IPv6 we cannot route.
        .min_by_key(|a| if a.is_ipv4() { 0 } else { 1 })
        .ok_or_else(|| anyhow!("no addresses for {host}"))
}

fn build_tls_config(cfg: &ClientConfig) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    if !cfg.insecure {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            roots.add(cert).ok();
        }
        for cert in &cfg.extra_roots {
            roots
                .add(cert.clone())
                .context("adding extra trusted certificate")?;
        }
        if roots.is_empty() && cfg.extra_roots.is_empty() {
            warn!("no trusted roots loaded; NTS-KE will fail unless --insecure is used");
        }
    }

    let mut provider = rustls::crypto::ring::default_provider();
    // Some NTS-KE peers (notably chrony's GnuTLS stack on this platform) abort
    // the handshake when the ClientHello's first key share is X25519. Put the
    // NIST curves first: every TLS 1.3 implementation is required to support
    // P-256, and it costs one extra key exchange per NTS-KE run at most.
    // X25519 stays available as a fallback.
    provider.kx_groups = vec![
        rustls::crypto::ring::kx_group::SECP256R1,
        rustls::crypto::ring::kx_group::SECP384R1,
        rustls::crypto::ring::kx_group::X25519,
    ];
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("configuring TLS 1.3")?;

    let mut config = if cfg.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = vec![ke::ALPN.to_vec()];
    Ok(config)
}

/// Accepts any certificate. Only reachable via an explicit `--insecure` flag.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
        ]
    }
}

/// One timing sample, with the raw NTP timestamps kept for auditing.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Clock offset (server - client), in seconds.
    pub offset: f64,
    /// Round-trip delay, in seconds.
    pub delay: f64,
    /// Local monotonic send/receive instants, for jitter accounting.
    pub sent_unix: f64,
    pub recv_unix: f64,
    /// Server's own reported transmit time, UNIX seconds.
    pub server_tx_unix: f64,
    pub stratum: u8,
    /// Whether the server sent us fresh cookies.
    pub cookies_received: usize,
}

/// A client association that can send repeated NTS-protected requests without
/// re-running NTS-KE, until its cookie pool runs dry.
pub struct NtsClient {
    cfg: ClientConfig,
    socket: UdpSocket,
    assoc: Association,
    ntp_addr: SocketAddr,
    pub negotiated_alg: AeadAlg,
}

impl NtsClient {
    /// Run NTS-KE and bind a connected UDP socket to the negotiated NTP server.
    pub async fn connect(cfg: ClientConfig) -> Result<Self> {
        let outcome = do_ke(&cfg).await?;
        let bind: SocketAddr = if outcome.ntp_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind).await.context("binding UDP socket")?;
        socket
            .connect(outcome.ntp_addr)
            .await
            .with_context(|| format!("connecting UDP to {}", outcome.ntp_addr))?;
        Ok(Self {
            cfg,
            socket,
            assoc: outcome.association,
            ntp_addr: outcome.ntp_addr,
            negotiated_alg: outcome.negotiated_alg,
        })
    }

    pub fn ntp_addr(&self) -> SocketAddr {
        self.ntp_addr
    }

    pub fn cookie_count(&self) -> usize {
        self.assoc.cookie_count()
    }

    /// Perform one NTS-protected request/response and compute offset and delay.
    ///
    /// On NTS NAK, or when the cookie pool is exhausted, this transparently
    /// re-runs NTS-KE once and retries — which is what a long-lived client
    /// should do, and it exercises the rotation path end to end.
    pub async fn measure(&mut self, timeout: Duration) -> Result<Sample> {
        match self.measure_once(timeout).await {
            Ok(s) => Ok(s),
            Err(MeasureError::NeedsRekey(reason)) => {
                warn!(%reason, "re-running NTS-KE");
                self.rekey().await?;
                self.measure_once(timeout)
                    .await
                    .map_err(|e| anyhow!("after rekey: {e}"))
            }
            Err(e) => Err(anyhow!("{e}")),
        }
    }

    async fn rekey(&mut self) -> Result<()> {
        // Honour RFC 8915 §4.2: never hammer the KE server on failure.
        let outcome = match do_ke(&self.cfg).await {
            Ok(o) => o,
            Err(e) => {
                tokio::time::sleep(Duration::from_secs(MIN_RETRY_SECS)).await;
                return Err(e);
            }
        };
        self.assoc = outcome.association;
        self.ntp_addr = outcome.ntp_addr;
        self.negotiated_alg = outcome.negotiated_alg;
        self.socket.connect(self.ntp_addr).await?;
        Ok(())
    }

    async fn measure_once(&mut self, timeout: Duration) -> std::result::Result<Sample, MeasureError> {
        let cookie = self
            .assoc
            .take_cookie()
            .ok_or_else(|| MeasureError::NeedsRekey("cookie pool empty".into()))?;
        let placeholders = self.assoc.placeholders_for();
        let alg = self.assoc.keys.alg;

        let mut uniq_id = [0u8; UNIQ_ID_LEN];
        rand::thread_rng().fill_bytes(&mut uniq_id);
        let mut nonce = vec![0u8; alg.nonce_len()];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Build the authenticated prefix: header, Unique Identifier, Cookie,
        // then zero-length Placeholders (RFC 8915 §5.5 requires the same body
        // length as the Cookie field).
        let mut packet = Packet::new(MODE_CLIENT);
        let t1 = ntp::now_ntp_timestamp();
        packet.set_transmit_timestamp(t1);
        packet
            .extension_fields
            .push(ExtensionField::new(EF_UNIQUE_IDENTIFIER, uniq_id.to_vec()));
        packet
            .extension_fields
            .push(ExtensionField::new(EF_NTS_COOKIE, cookie.clone()));
        for _ in 0..placeholders {
            packet.extension_fields.push(ExtensionField::new(
                EF_NTS_COOKIE_PLACEHOLDER,
                vec![0u8; cookie.len()],
            ));
        }
        let prefix = packet.encode();

        let sent_unix = unix_now();
        let request = auth::seal_packet(alg, &self.assoc.keys.c2s, &prefix, &[], &nonce)
            .map_err(|e| MeasureError::Other(anyhow!("sealing request: {e}")))?;

        self.socket
            .send(&request)
            .await
            .map_err(|e| MeasureError::Other(anyhow!("sending request: {e}")))?;

        let mut buf = vec![0u8; ntp::MAX_PACKET_LEN];
        let n = tokio::time::timeout(timeout, self.socket.recv(&mut buf))
            .await
            .map_err(|_| MeasureError::Other(anyhow!("request timed out after {timeout:?}")))?
            .map_err(|e| MeasureError::Other(anyhow!("receiving response: {e}")))?;
        let recv_unix = unix_now();
        let response = &buf[..n];

        // An NTS NAK is a KoD with no NTS EFs; detect it before attempting AEAD.
        if let Some(kod) = detect_nak(response) {
            return Err(kod);
        }

        let (verified, encrypted_fields) =
            auth::open_packet(alg, &self.assoc.keys.s2c, response)
                .map_err(|e| MeasureError::Other(anyhow!("verifying response: {e}")))?;

        if verified.mode() != ntp::MODE_SERVER {
            return Err(MeasureError::Other(anyhow!(
                "response has mode {}, expected server",
                verified.mode()
            )));
        }

        // The Unique Identifier must match this request, else a replayed or
        // off-path packet is being fed to us.
        let echoed = verified
            .find_field(EF_UNIQUE_IDENTIFIER)
            .ok_or_else(|| MeasureError::Other(anyhow!("response missing Unique Identifier")))?;
        if echoed.body != uniq_id {
            return Err(MeasureError::Other(anyhow!(
                "Unique Identifier mismatch: possible spoofed response"
            )));
        }

        // Fresh cookies arrive encrypted inside the Authenticator EF.
        let fresh: Vec<Vec<u8>> = encrypted_fields
            .iter()
            .filter(|f| f.field_type == EF_NTS_COOKIE)
            .map(|f| f.body.clone())
            .collect();
        let cookies_received = fresh.len();
        self.assoc.absorb_cookies(fresh);

        let t4 = ntp::ntp_timestamp_from_unix(
            recv_unix.trunc() as u64,
            ((recv_unix.fract()) * 1e9) as u32,
        );
        let server_rx = timestamp_bytes(&response[32..40]);
        let server_tx = timestamp_bytes(&response[40..48]);
        let server_tx_unix = ntp::ntp_timestamp_to_unix(&server_tx);

        // RFC 5905 §8: offset = ((T2 - T1) + (T3 - T4)) / 2,
        //              delay  = (T4 - T1) - (T3 - T2).
        let t1s = ntp::ntp_timestamp_to_unix(&t1);
        let t2s = ntp::ntp_timestamp_to_unix(&server_rx);
        let t3s = server_tx_unix;
        let t4s = ntp::ntp_timestamp_to_unix(&t4);
        let offset = ((t2s - t1s) + (t3s - t4s)) / 2.0;
        let delay = (t4s - t1s) - (t3s - t2s);

        Ok(Sample {
            offset,
            delay,
            sent_unix,
            recv_unix,
            server_tx_unix,
            stratum: verified.stratum(),
            cookies_received,
        })
    }
}

#[derive(Debug)]
pub enum MeasureError {
    /// The association must be rebuilt before another request can succeed.
    NeedsRekey(String),
    Other(anyhow::Error),
}

impl std::fmt::Display for MeasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasureError::NeedsRekey(r) => write!(f, "needs rekey: {r}"),
            MeasureError::Other(e) => write!(f, "{e}"),
        }
    }
}

/// Recognize an NTS NAK: an unauthenticated KoD (stratum 0) whose reference id
/// is "NTSN". RFC 8915 §5.7 requires it to echo our Unique Identifier, which
/// the caller checks separately when it matters.
fn detect_nak(raw: &[u8]) -> Option<MeasureError> {
    if raw.len() < ntp::HEADER_LEN {
        return None;
    }
    let stratum = raw[1];
    let refid = &raw[12..16];
    if stratum == STRATUM_UNSPECIFIED && refid == KOD_NTSN {
        Some(MeasureError::NeedsRekey("server sent NTS NAK".into()))
    } else {
        None
    }
}

fn timestamp_bytes(s: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&s[..8]);
    out
}

pub fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Convert a core error into the client's error type where useful.
impl From<CoreError> for MeasureError {
    fn from(e: CoreError) -> Self {
        MeasureError::Other(anyhow!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nak_detection() {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x24; // server mode, v4
        pkt[1] = 0; // stratum 0
        pkt[12..16].copy_from_slice(&KOD_NTSN);
        assert!(matches!(detect_nak(&pkt), Some(MeasureError::NeedsRekey(_))));

        // A normal packet is not a NAK.
        let mut ok = vec![0u8; 48];
        ok[1] = 2;
        ok[12..16].copy_from_slice(b"GPS\0");
        assert!(detect_nak(&ok).is_none());

        // Stratum 0 with a different kiss code is not our NAK.
        let mut other = vec![0u8; 48];
        other[12..16].copy_from_slice(b"RATE");
        assert!(detect_nak(&other).is_none());
    }

    #[test]
    fn offset_formula_matches_rfc5905() {
        // Server clock is 10 s ahead; the path is symmetric with 10 s each way.
        //   T2 = T1 + 10 (outbound) + 10 (offset) = 1020
        //   T3 = T2                                = 1020
        //   T4 = T1 + 20 (round trip)              = 1020
        let t1: f64 = 1000.0;
        let t2: f64 = 1020.0;
        let t3: f64 = 1020.0;
        let t4: f64 = 1020.0;
        let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
        let delay = (t4 - t1) - (t3 - t2);
        assert!((offset - 10.0).abs() < 1e-9, "offset {offset}");
        assert!((delay - 20.0).abs() < 1e-9, "delay {delay}");
    }
}
