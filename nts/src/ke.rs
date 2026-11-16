//! The NTS Key Establishment protocol, RFC 8915 section 4.
//!
//! A request and a response are each a sequence of records terminated by an
//! End of Message record.  There is exactly one request and one response per
//! TLS connection, on TCP 4460, with ALPN "ntske/1" and TLS 1.3 or later.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroize;

use crate::aead::Aead;

/// ALPN identifier, RFC 8915 section 7.2.
pub const ALPN_NTSKE: &[u8] = b"ntske/1";
/// TLS exporter label, RFC 8915 section 4.3.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";

pub const DEFAULT_KE_PORT: u16 = 4460;
pub const DEFAULT_NTP_PORT: u16 = 123;

// Record types, RFC 8915 section 4.1.
pub const REC_END_OF_MESSAGE: u16 = 0;
pub const REC_NEXT_PROTOCOL: u16 = 1;
pub const REC_ERROR: u16 = 2;
pub const REC_WARNING: u16 = 3;
pub const REC_AEAD_ALGORITHM: u16 = 4;
pub const REC_NEW_COOKIE: u16 = 5;
pub const REC_NTPV4_SERVER: u16 = 6;
pub const REC_NTPV4_PORT: u16 = 7;
/// chrony's extension: says the server derives exporter keys with the algorithm
/// ID it actually negotiated, rather than the legacy misspelling of it.
pub const REC_COMPLIANT_128GCM_EXPORT: u16 = 1024;

/// Next Protocol ID for NTPv4, RFC 8915 section 7.7.
pub const NEXT_PROTOCOL_NTPV4: u16 = 0;

pub const ERROR_UNRECOGNIZED_CRITICAL_RECORD: u16 = 0;
pub const ERROR_BAD_REQUEST: u16 = 1;
pub const ERROR_INTERNAL_SERVER_ERROR: u16 = 2;

/// Servers must accept requests of at least 1024 octets; we accept more.
pub const MAX_REQUEST_LEN: usize = 16384;
/// Clients should accept responses of at least 65536 octets.
pub const MAX_RESPONSE_LEN: usize = 65536;

const CRITICAL: u16 = 1 << 15;

#[derive(Debug, thiserror::Error)]
pub enum KeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("no address found for {0}")]
    NoAddress(String),
    #[error("malformed NTS-KE message: {0}")]
    Malformed(String),
    #[error("server reported NTS-KE error {code}: {meaning}")]
    ServerError { code: u16, meaning: &'static str },
    #[error("server returned no {0}")]
    MissingRecord(&'static str),
    #[error("server offered AEAD algorithm {0}, which we did not request or do not support")]
    UnsupportedAead(u16),
    #[error("server negotiated next protocol {0}, not NTPv4")]
    UnsupportedNextProtocol(u16),
    #[error("certificate validation failed: {0}")]
    Certificate(String),
    #[error("unexpected TLS version or ALPN result")]
    TlsProfile,
    #[error("timed out during the NTS-KE exchange")]
    Timeout,
}

/// One NTS-KE record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub critical: bool,
    pub typ: u16,
    pub body: Vec<u8>,
}

impl Record {
    pub fn new(critical: bool, typ: u16, body: Vec<u8>) -> Self {
        Self {
            critical,
            typ,
            body,
        }
    }

    pub fn u16_value(critical: bool, typ: u16, v: u16) -> Self {
        Self::new(critical, typ, v.to_be_bytes().to_vec())
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut t = self.typ & 0x7fff;
        if self.critical {
            t |= CRITICAL;
        }
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
    }
}

/// Decode a complete message.  Returns the records in order, including the
/// End of Message record.
pub fn decode_message(mut buf: &[u8]) -> Result<Vec<Record>, KeError> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(KeError::Malformed(format!(
                "truncated record header ({} octets left)",
                buf.len()
            )));
        }
        let raw_type = u16::from_be_bytes([buf[0], buf[1]]);
        let body_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 4 + body_len {
            return Err(KeError::Malformed("record body truncated".into()));
        }
        out.push(Record {
            critical: raw_type & CRITICAL != 0,
            typ: raw_type & 0x7fff,
            body: buf[4..4 + body_len].to_vec(),
        });
        buf = &buf[4 + body_len..];
    }
    if out.is_empty() {
        return Err(KeError::Malformed("empty message".into()));
    }
    Ok(out)
}

fn parse_u16_list(body: &[u8]) -> Result<Vec<u16>, KeError> {
    if body.len() % 2 != 0 {
        return Err(KeError::Malformed("odd-length u16 list".into()));
    }
    Ok(body
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

fn error_meaning(code: u16) -> &'static str {
    match code {
        ERROR_UNRECOGNIZED_CRITICAL_RECORD => "unrecognized critical record",
        ERROR_BAD_REQUEST => "bad request",
        ERROR_INTERNAL_SERVER_ERROR => "internal server error",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Requests and responses
// ---------------------------------------------------------------------------

/// What a client asks for.
#[derive(Debug, Clone)]
pub struct KeRequest {
    pub next_protocols: Vec<u16>,
    /// In decreasing preference order.
    pub aeads: Vec<Aead>,
    pub ntp_server: Option<String>,
    pub ntp_port: Option<u16>,
    /// Announce support for the corrected exporter context (chrony record 1024).
    pub compliant_128gcm_export: bool,
}

impl KeRequest {
    /// A request for NTPv4 with the given algorithms in preference order.
    pub fn ntpv4(aeads: &[Aead]) -> Self {
        Self {
            next_protocols: vec![NEXT_PROTOCOL_NTPV4],
            aeads: aeads.to_vec(),
            ntp_server: None,
            ntp_port: None,
            compliant_128gcm_export: true,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut protos = Vec::new();
        for p in &self.next_protocols {
            protos.extend_from_slice(&p.to_be_bytes());
        }
        Record::new(true, REC_NEXT_PROTOCOL, protos).encode(&mut out);

        let mut algos = Vec::new();
        for a in &self.aeads {
            algos.extend_from_slice(&a.id().to_be_bytes());
        }
        Record::new(false, REC_AEAD_ALGORITHM, algos).encode(&mut out);

        if self.compliant_128gcm_export {
            Record::new(false, REC_COMPLIANT_128GCM_EXPORT, Vec::new()).encode(&mut out);
        }
        if let Some(s) = &self.ntp_server {
            Record::new(false, REC_NTPV4_SERVER, s.as_bytes().to_vec()).encode(&mut out);
        }
        if let Some(p) = self.ntp_port {
            Record::u16_value(false, REC_NTPV4_PORT, p).encode(&mut out);
        }
        Record::new(true, REC_END_OF_MESSAGE, Vec::new()).encode(&mut out);
        out
    }

    /// Parse a request in a server.  Rejects anything this server would not
    /// understand if it were marked critical.
    pub fn decode(buf: &[u8]) -> Result<Self, KeError> {
        let records = decode_message(buf)?;
        let mut req = KeRequest {
            next_protocols: Vec::new(),
            aeads: Vec::new(),
            ntp_server: None,
            ntp_port: None,
            compliant_128gcm_export: false,
        };
        let mut seen_next = false;
        let mut seen_eom = false;

        for r in &records {
            if seen_eom {
                return Err(KeError::Malformed("record after End of Message".into()));
            }
            match r.typ {
                REC_END_OF_MESSAGE => {
                    if !r.critical || !r.body.is_empty() {
                        return Err(KeError::Malformed(
                            "End of Message must be critical and empty".into(),
                        ));
                    }
                    seen_eom = true;
                }
                REC_NEXT_PROTOCOL => {
                    if seen_next {
                        return Err(KeError::Malformed(
                            "more than one Next Protocol record".into(),
                        ));
                    }
                    seen_next = true;
                    req.next_protocols = parse_u16_list(&r.body)?;
                    if req.next_protocols.is_empty() {
                        return Err(KeError::Malformed(
                            "Next Protocol record must offer at least one protocol".into(),
                        ));
                    }
                }
                REC_AEAD_ALGORITHM => {
                    req.aeads = parse_u16_list(&r.body)?
                        .into_iter()
                        .map(|id| {
                            Aead::from_id(id).ok_or(KeError::UnsupportedAead(id))
                        })
                        .collect::<Result<_, _>>()?;
                }
                REC_COMPLIANT_128GCM_EXPORT => {
                    if !r.body.is_empty() {
                        return Err(KeError::Malformed("non-empty record 1024".into()));
                    }
                    req.compliant_128gcm_export = true;
                }
                REC_NTPV4_SERVER => {
                    req.ntp_server = Some(
                        String::from_utf8(r.body.clone())
                            .map_err(|_| KeError::Malformed("non-UTF-8 server name".into()))?,
                    );
                }
                REC_NTPV4_PORT => {
                    let v = parse_u16_list(&r.body)?;
                    if v.len() != 1 {
                        return Err(KeError::Malformed("bad NTPv4 port record".into()));
                    }
                    req.ntp_port = Some(v[0]);
                }
                REC_ERROR | REC_WARNING => {
                    return Err(KeError::Malformed(
                        "client must not send Error or Warning records".into(),
                    ));
                }
                other => {
                    if r.critical {
                        return Err(KeError::ServerError {
                            code: ERROR_UNRECOGNIZED_CRITICAL_RECORD,
                            meaning: "unrecognized critical record",
                        });
                    }
                    // Non-critical unknown records are ignored (RFC 8915 4.1).
                    let _ = other;
                }
            }
        }
        if !seen_eom {
            return Err(KeError::Malformed("missing End of Message".into()));
        }
        if !seen_next {
            return Err(KeError::Malformed("missing Next Protocol record".into()));
        }
        Ok(req)
    }
}

/// What a server agreed to.
#[derive(Debug, Clone)]
pub struct KeResponse {
    pub next_protocol: u16,
    /// `None` means the server supports none of the offered algorithms.
    pub aead: Option<Aead>,
    pub ntp_server: Option<String>,
    pub ntp_port: Option<u16>,
    pub cookies: Vec<Vec<u8>>,
    pub compliant_128gcm_export: bool,
    pub warnings: Vec<u16>,
}

impl KeResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        Record::u16_value(true, REC_NEXT_PROTOCOL, self.next_protocol).encode(&mut out);
        let algos: Vec<u8> = match self.aead {
            Some(a) => a.id().to_be_bytes().to_vec(),
            None => Vec::new(),
        };
        Record::new(false, REC_AEAD_ALGORITHM, algos).encode(&mut out);
        if self.compliant_128gcm_export && self.aead == Some(Aead::Aes128GcmSiv) {
            Record::new(false, REC_COMPLIANT_128GCM_EXPORT, Vec::new()).encode(&mut out);
        }
        if let Some(p) = self.ntp_port {
            Record::u16_value(true, REC_NTPV4_PORT, p).encode(&mut out);
        }
        if let Some(s) = &self.ntp_server {
            Record::new(true, REC_NTPV4_SERVER, s.as_bytes().to_vec()).encode(&mut out);
        }
        for w in &self.warnings {
            Record::u16_value(true, REC_WARNING, *w).encode(&mut out);
        }
        for c in &self.cookies {
            // The Critical bit SHOULD NOT be set (RFC 8915 4.1.6).
            Record::new(false, REC_NEW_COOKIE, c.clone()).encode(&mut out);
        }
        Record::new(true, REC_END_OF_MESSAGE, Vec::new()).encode(&mut out);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, KeError> {
        let records = decode_message(buf)?;
        let mut next_protocol: Option<u16> = None;
        let mut aead: Option<Aead> = None;
        let mut ntp_server = None;
        let mut ntp_port = None;
        let mut cookies = Vec::new();
        let mut compliant = false;
        let mut warnings = Vec::new();
        let mut seen_eom = false;

        for r in &records {
            if seen_eom {
                return Err(KeError::Malformed("record after End of Message".into()));
            }
            match r.typ {
                REC_END_OF_MESSAGE => seen_eom = true,
                REC_NEXT_PROTOCOL => {
                    let v = parse_u16_list(&r.body)?;
                    if v.len() > 1 {
                        return Err(KeError::Malformed(
                            "response must name at most one next protocol".into(),
                        ));
                    }
                    next_protocol = v.first().copied();
                }
                REC_AEAD_ALGORITHM => {
                    let v = parse_u16_list(&r.body)?;
                    if v.len() > 1 {
                        return Err(KeError::Malformed(
                            "response must name at most one AEAD".into(),
                        ));
                    }
                    aead = match v.first() {
                        None => None,
                        Some(id) => Some(
                            Aead::from_id(*id).ok_or(KeError::UnsupportedAead(*id))?,
                        ),
                    };
                }
                REC_ERROR => {
                    let v = parse_u16_list(&r.body)?;
                    if v.len() != 1 {
                        return Err(KeError::Malformed("bad Error record".into()));
                    }
                    return Err(KeError::ServerError {
                        code: v[0],
                        meaning: error_meaning(v[0]),
                    });
                }
                REC_WARNING => {
                    let v = parse_u16_list(&r.body)?;
                    if v.len() != 1 {
                        return Err(KeError::Malformed("bad Warning record".into()));
                    }
                    warnings.push(v[0]);
                }
                REC_NEW_COOKIE => cookies.push(r.body.clone()),
                REC_NTPV4_SERVER => {
                    ntp_server = Some(
                        String::from_utf8(r.body.clone())
                            .map_err(|_| KeError::Malformed("non-UTF-8 server name".into()))?,
                    );
                }
                REC_NTPV4_PORT => {
                    let v = parse_u16_list(&r.body)?;
                    if v.len() != 1 {
                        return Err(KeError::Malformed("bad NTPv4 port record".into()));
                    }
                    ntp_port = Some(v[0]);
                }
                REC_COMPLIANT_128GCM_EXPORT => compliant = true,
                _ => {
                    if r.critical {
                        return Err(KeError::Malformed(format!(
                            "unrecognized critical record {}",
                            r.typ
                        )));
                    }
                }
            }
        }
        if !seen_eom {
            return Err(KeError::Malformed("missing End of Message".into()));
        }
        // Unrecognized warning codes must be treated as errors (RFC 8915 4.1.4).
        // This memo defines none, so any warning we cannot interpret is fatal.
        if let Some(w) = warnings.first() {
            return Err(KeError::Malformed(format!("unrecognized warning {w}")));
        }
        Ok(Self {
            next_protocol: next_protocol.ok_or(KeError::MissingRecord("Next Protocol"))?,
            aead,
            ntp_server,
            ntp_port,
            cookies,
            compliant_128gcm_export: compliant,
            warnings,
        })
    }
}

// ---------------------------------------------------------------------------
// Key extraction
// ---------------------------------------------------------------------------

/// The two NTPv4 keys established by a successful NTS-KE run.
pub struct Keys {
    pub c2s: Vec<u8>,
    pub s2c: Vec<u8>,
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.c2s.zeroize();
        self.s2c.zeroize();
    }
}

/// Per-association context for the TLS exporter: Protocol ID (2 octets),
/// AEAD ID (2 octets), direction (1 octet, 0 = C2S, 1 = S2C).  See RFC 8915
/// section 5.1.
fn exporter_context(aead: Aead, s2c: bool, compliant: bool) -> [u8; 5] {
    let mut ctx = [0u8; 5];
    ctx[0..2].copy_from_slice(&NEXT_PROTOCOL_NTPV4.to_be_bytes());
    // chrony (and servers built before the erratum was clarified) derive the
    // exporter for AEAD_AES_128_GCM_SIV using the AES-SIV ID, hence the
    // compliant-128gcm negotiation record.  Only use the real ID once the peer
    // has confirmed it, otherwise interop breaks against older servers.
    let exporter_id = if aead == Aead::Aes128GcmSiv && !compliant {
        crate::aead::AEAD_AES_SIV_CMAC_256
    } else {
        aead.id()
    };
    ctx[2..4].copy_from_slice(&exporter_id.to_be_bytes());
    ctx[4] = u8::from(s2c);
    ctx
}

/// Extract the C2S and S2C keys from an established TLS session.
pub fn extract_keys<T: rustls::SideData>(
    conn: &rustls::ConnectionCommon<T>,
    aead: Aead,
    compliant_128gcm: bool,
) -> Result<Keys, KeError> {
    let extract = |s2c: bool| -> Result<Vec<u8>, KeError> {
        let ctx = exporter_context(aead, s2c, compliant_128gcm);
        let out = conn
            .export_keying_material(vec![0u8; aead.key_len()], EXPORTER_LABEL, Some(&ctx))
            .map_err(|e| KeError::Certificate(e.to_string()))?;
        Ok(out)
    };
    Ok(Keys {
        c2s: extract(false)?,
        s2c: extract(true)?,
    })
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Result of a successful key establishment.
pub struct KeOutcome {
    pub aead: Aead,
    pub cookies: Vec<Vec<u8>>,
    pub ntp_server: Option<String>,
    pub ntp_port: u16,
    pub keys: Keys,
}

pub struct ClientConfig {
    /// Addresses to try, in order.
    pub addrs: Vec<SocketAddr>,
    /// Server name for SNI and certificate validation.
    pub server_name: String,
    pub root_store: Arc<rustls::RootCertStore>,
    pub timeout: Duration,
    /// TLS exporter compatibility mode; see `exporter_context`.
    pub compliant_128gcm_export: bool,
}

impl ClientConfig {
    pub fn new(host: &str, port: u16) -> Result<Self, KeError> {
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|e| {
                KeError::NoAddress(format!("{host}:{port}: {e}"))
            })?
            .collect();
        if addrs.is_empty() {
            return Err(KeError::NoAddress(host.to_string()));
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(Self {
            addrs,
            server_name: host.to_string(),
            root_store: Arc::new(roots),
            timeout: Duration::from_secs(10),
            compliant_128gcm_export: true,
        })
    }

    pub fn with_roots(mut self, roots: rustls::RootCertStore) -> Self {
        self.root_store = Arc::new(roots);
        self
    }
}

fn client_tls_config(cfg: &ClientConfig) -> Result<Arc<rustls::ClientConfig>, KeError> {
    // RFC 8915 section 3: TLS 1.3 or later only.  Restricting here (rather than
    // trusting the peer) means a downgrade attempt fails the handshake.
    let mut tls = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(cfg.root_store.clone())
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_NTSKE.to_vec()];
    Ok(Arc::new(tls))
}

fn do_handshake(
    conn: &mut rustls::ClientConnection,
    sock: &mut TcpStream,
    roots_ok: &dyn Fn(&rustls::ClientConnection) -> bool,
) -> Result<(), KeError> {
    while conn.is_handshaking() {
        let mut progressed = false;
        if conn.wants_write() {
            conn.write_tls(sock)?;
            progressed = true;
        }
        if conn.wants_read() {
            match conn.read_tls(sock) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(KeError::Timeout);
                }
                Err(e) => return Err(KeError::Io(e)),
            }
            progressed = true;
            conn.process_new_packets()
                .map_err(|e| KeError::Certificate(format!("{e}")))?;
        }
        // A handshaking connection that wants neither to read nor to write can
        // never make progress; without this the loop would spin at full CPU
        // until the socket timeout, which a hostile peer could exploit.
        if !progressed {
            return Err(KeError::TlsProfile);
        }
    }
    if !roots_ok(conn) {
        return Err(KeError::TlsProfile);
    }
    Ok(())
}

/// Run NTS-KE against one server.
pub fn run_client(cfg: &ClientConfig, request: &KeRequest) -> Result<KeOutcome, KeError> {
    let tls = client_tls_config(cfg)?;
    let server_name = rustls_pki_types::ServerName::try_from(cfg.server_name.clone())
        .map_err(|e| KeError::Certificate(format!("invalid server name: {e}")))?;

    let mut last_err = None;
    if std::env::var_os("NTS_DEBUG").is_some() {
        eprintln!("ke: trying {:?}", cfg.addrs);
    }
    for addr in &cfg.addrs {
        match TcpStream::connect_timeout(addr, cfg.timeout) {
            Ok(s) => {
                s.set_read_timeout(Some(cfg.timeout))?;
                s.set_write_timeout(Some(cfg.timeout))?;
                let mut sock = s;
                match negotiate(&tls, server_name.clone(), &mut sock, request) {
                    Ok(o) => return Ok(o),
                    Err(e) => {
                        if std::env::var_os("NTS_DEBUG").is_some() {
                            eprintln!("ke: {addr} failed: {e:?}");
                        }
                        last_err = Some(e)
                    }
                }
            }
            Err(e) => last_err = Some(KeError::Io(e)),
        }
    }
    Err(last_err.unwrap_or_else(|| KeError::NoAddress(cfg.server_name.clone())))
}

fn negotiate(
    tls: &Arc<rustls::ClientConfig>,
    server_name: rustls_pki_types::ServerName<'static>,
    sock: &mut TcpStream,
    request: &KeRequest,
) -> Result<KeOutcome, KeError> {
    let mut conn = rustls::ClientConnection::new(tls.clone(), server_name)?;
    do_handshake(&mut conn, sock, &|c| {
        // Both checks are redundant with the configuration above, but they
        // make a misconfiguration fail closed instead of silently downgrading.
        c.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
            && c.alpn_protocol() == Some(ALPN_NTSKE)
    })?;

    conn.writer().write_all(&request.encode())?;
    conn.write_tls(sock)?;

    // Read until the response's End of Message record arrives.  The TLS records
    // must be pulled off the socket before plaintext can be read out of the
    // buffer, so read_tls/process_new_packets always runs first.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if conn.wants_read() {
            conn.read_tls(sock)?;
            conn.process_new_packets()
                .map_err(|e| KeError::Certificate(format!("{e}")))?;
        }
        match conn.reader().read(&mut chunk) {
            Ok(0) => {
                return Err(KeError::Malformed(
                    "connection closed before a complete response".into(),
                ))
            }
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_RESPONSE_LEN {
                    return Err(KeError::Malformed("response too long".into()));
                }
                // Records are self-delimiting, so a complete message can be
                // recognised without waiting for the peer to close.  A prefix
                // that simply has not arrived in full yet is not an error.
                match decode_message(&buf) {
                    Ok(records) => {
                        if records.last().map(|r| r.typ) == Some(REC_END_OF_MESSAGE) {
                            break;
                        }
                    }
                    Err(_) if is_incomplete(&buf) => {}
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(KeError::Io(e)),
        }
    };
    // `buf` holds exactly one complete message; decode it in place rather than
    // round-tripping through the records a second time.
    let mut response = KeResponse::decode(&buf)?;

    if response.next_protocol != NEXT_PROTOCOL_NTPV4 {
        return Err(KeError::UnsupportedNextProtocol(response.next_protocol));
    }
    let aead = match response.aead {
        Some(a) if request.aeads.contains(&a) => a,
        Some(a) => return Err(KeError::UnsupportedAead(a.id())),
        None => {
            return Err(KeError::MissingRecord(
                "AEAD algorithm that we offered",
            ))
        }
    };
    if response.cookies.is_empty() {
        return Err(KeError::MissingRecord("cookie"));
    }

    // The server's record 1024 confirmation only matters for the GCM-SIV
    // exporter quirk; the request is only advisory for every other algorithm.
    let compliant = if aead == Aead::Aes128GcmSiv {
        response.compliant_128gcm_export
    } else {
        true
    };
    let keys = extract_keys(&conn, aead, compliant)?;
    // RFC 8915 section 4: both sides send close_notify once the exchange is
    // done.  Nothing depends on the peer acting on it.
    send_close_notify(&mut conn, sock);

    Ok(KeOutcome {
        aead,
        cookies: std::mem::take(&mut response.cookies),
        ntp_server: response.ntp_server,
        ntp_port: response.ntp_port.unwrap_or(DEFAULT_NTP_PORT),
        keys,
    })
}

/// Server side: run the TLS handshake for one accepted connection and return
/// the request bytes.  The caller decodes, decides, and calls
/// [`server_reply`].  Kept separate so policy (which algorithms to accept, how
/// many cookies) lives with the server, not in the wire code.
pub fn server_handshake(
    tls: &rustls::ServerConfig,
    sock: &mut TcpStream,
    timeout: Duration,
) -> Result<(rustls::ServerConnection, KeRequest), KeError> {
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    let mut conn = rustls::ServerConnection::new(Arc::new(tls.clone()))?;

    while conn.is_handshaking() {
        let mut progressed = false;
        if conn.wants_write() {
            conn.write_tls(sock)?;
            progressed = true;
        }
        if conn.wants_read() {
            conn.read_tls(sock)?;
            progressed = true;
            conn.process_new_packets()
                .map_err(|e| KeError::Certificate(format!("{e}")))?;
        }
        // As on the client side: no read and no write while handshaking means
        // no progress is possible, so fail instead of spinning.
        if !progressed {
            return Err(KeError::TlsProfile);
        }
    }
    // RFC 8915 section 3: refuse anything that is not TLS 1.3 with ntske/1.
    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || conn.alpn_protocol() != Some(ALPN_NTSKE)
    {
        send_close_notify(&mut conn, sock);
        return Err(KeError::TlsProfile);
    }

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if conn.wants_read() {
            conn.read_tls(sock)?;
            conn.process_new_packets()
                .map_err(|e| KeError::Certificate(format!("{e}")))?;
        }
        match conn.reader().read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_REQUEST_LEN {
                    return Err(KeError::Malformed("request too long".into()));
                }
                if let Ok(records) = decode_message(&buf) {
                    if records.last().map(|r| r.typ) == Some(REC_END_OF_MESSAGE) {
                        break;
                    }
                }
            }
            Err(e) => return Err(KeError::Io(e)),
        }
    }

    let request = KeRequest::decode(&buf)?;
    Ok((conn, request))
}

/// Send the response and close the TLS session.
pub fn server_reply(
    conn: &mut rustls::ServerConnection,
    sock: &mut TcpStream,
    response: &KeResponse,
) -> Result<(), KeError> {
    conn.writer().write_all(&response.encode())?;
    conn.write_tls(sock)?;
    send_close_notify(conn, sock);
    Ok(())
}

/// Server-side helper: pick the AEAD to use from the client's ordered list.
/// Honouring the client's preference is optional (RFC 8915 4.1.5); doing so
/// keeps behaviour predictable and matches chrony.
pub fn choose_aead(offered: &[Aead], supported: &[Aead]) -> Option<Aead> {
    offered.iter().copied().find(|a| supported.contains(a))
}

#[cfg(test)]
fn encode_records(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        r.encode(&mut out);
    }
    out
}

/// Split `host:port`, `[v6]:port` or a bare host, defaulting the port.
///
/// Shared by the binaries so an IPv6 literal in `--server` is never mistaken
/// for `host:port` just because it contains colons.
pub fn split_host_port(spec: &str, default_port: u16) -> (String, u16) {
    if let Some(inner) = spec.strip_prefix('[') {
        if let Some((h, rest)) = inner.split_once(']') {
            let port = rest
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return (h.to_string(), port);
        }
    }
    if spec.matches(':').count() == 1 {
        if let Some((h, p)) = spec.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h.to_string(), port);
            }
        }
    }
    (spec.to_string(), default_port)
}

/// Whether `buf` holds a valid prefix of a message whose remaining records have
/// simply not arrived yet.
fn is_incomplete(buf: &[u8]) -> bool {
    let mut rest = buf;
    while !rest.is_empty() {
        if rest.len() < 4 {
            return true;
        }
        let body_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() < 4 + body_len {
            return true;
        }
        rest = &rest[4 + body_len..];
    }
    false
}

/// Send a TLS close_notify.  Failures are not interesting: the NTS-KE exchange
/// has already completed and everything the client needs is in hand.
pub fn send_close_notify<T: rustls::SideData>(
    conn: &mut rustls::ConnectionCommon<T>,
    sock: &mut TcpStream,
) {
    conn.send_close_notify();
    let _ = conn.write_tls(sock);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_roundtrip_preserves_critical_bit() {
        let records = vec![
            Record::u16_value(true, REC_NEXT_PROTOCOL, NEXT_PROTOCOL_NTPV4),
            Record::new(false, REC_AEAD_ALGORITHM, vec![0, 15, 0, 30]),
            Record::new(true, REC_END_OF_MESSAGE, Vec::new()),
        ];
        let enc = encode_records(&records);
        assert_eq!(decode_message(&enc).unwrap(), records);
    }

    #[test]
    fn request_has_exactly_one_next_protocol_and_ends_with_eom() {
        let req = KeRequest::ntpv4(&[Aead::AesSivCmac256]);
        let records = decode_message(&req.encode()).unwrap();
        assert_eq!(
            records.iter().filter(|r| r.typ == REC_NEXT_PROTOCOL).count(),
            1
        );
        assert_eq!(records.last().unwrap().typ, REC_END_OF_MESSAGE);
        assert!(records.last().unwrap().critical);
        let back = KeRequest::decode(&req.encode()).unwrap();
        assert_eq!(back.aeads, vec![Aead::AesSivCmac256]);
    }

    #[test]
    fn request_rejects_unknown_critical_record() {
        let records = vec![
            Record::u16_value(true, REC_NEXT_PROTOCOL, NEXT_PROTOCOL_NTPV4),
            Record::new(true, REC_AEAD_ALGORITHM, vec![0, 15]),
            Record::new(true, 9999, Vec::new()),
            Record::new(true, REC_END_OF_MESSAGE, Vec::new()),
        ];
        assert!(matches!(
            KeRequest::decode(&encode_records(&records)),
            Err(KeError::ServerError { code: 0, .. })
        ));
    }

    #[test]
    fn request_ignores_unknown_noncritical_record() {
        let records = vec![
            Record::u16_value(true, REC_NEXT_PROTOCOL, NEXT_PROTOCOL_NTPV4),
            Record::new(false, REC_AEAD_ALGORITHM, vec![0, 15]),
            Record::new(false, 9999, vec![1, 2, 3]),
            Record::new(true, REC_END_OF_MESSAGE, Vec::new()),
        ];
        let req = KeRequest::decode(&encode_records(&records)).unwrap();
        assert_eq!(req.aeads, vec![Aead::AesSivCmac256]);
    }

    #[test]
    fn missing_end_of_message_is_rejected() {
        let records = vec![
            Record::u16_value(true, REC_NEXT_PROTOCOL, NEXT_PROTOCOL_NTPV4),
            Record::new(false, REC_AEAD_ALGORITHM, vec![0, 15]),
        ];
        assert!(KeRequest::decode(&encode_records(&records)).is_err());
    }

    #[test]
    fn error_record_surfaces_code() {
        let records = vec![
            Record::new(true, REC_ERROR, vec![0, 1]),
            Record::new(true, REC_END_OF_MESSAGE, Vec::new()),
        ];
        match KeResponse::decode(&encode_records(&records)) {
            Err(KeError::ServerError { code: 1, .. }) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn response_decode_collects_cookies() {
        let resp = KeResponse {
            next_protocol: NEXT_PROTOCOL_NTPV4,
            aead: Some(Aead::AesSivCmac256),
            ntp_server: Some("time.example".into()),
            ntp_port: Some(123),
            cookies: vec![vec![1; 100], vec![2; 100]],
            compliant_128gcm_export: false,
            warnings: vec![],
        };
        let back = KeResponse::decode(&resp.encode()).unwrap();
        assert_eq!(back.cookies.len(), 2);
        assert_eq!(back.aead, Some(Aead::AesSivCmac256));
        assert_eq!(back.ntp_server.as_deref(), Some("time.example"));
    }

    #[test]
    fn exporter_context_matches_rfc_layout() {
        let ctx = exporter_context(Aead::AesSivCmac256, false, true);
        assert_eq!(ctx, [0, 0, 0, 15, 0]);
        let ctx = exporter_context(Aead::AesSivCmac256, true, true);
        assert_eq!(ctx, [0, 0, 0, 15, 1]);
        // Legacy servers: GCM-SIV keys are derived under the AES-SIV ID.
        let ctx = exporter_context(Aead::Aes128GcmSiv, false, false);
        assert_eq!(ctx, [0, 0, 0, 15, 0]);
        let ctx = exporter_context(Aead::Aes128GcmSiv, false, true);
        assert_eq!(ctx, [0, 0, 0, 30, 0]);
    }

    #[test]
    fn split_host_port_variants() {
        assert_eq!(split_host_port("a.example", 4460), ("a.example".into(), 4460));
        assert_eq!(split_host_port("a.example:5000", 4460), ("a.example".into(), 5000));
        assert_eq!(split_host_port("::1", 4460), ("::1".into(), 4460));
        assert_eq!(split_host_port("[::1]:5000", 4460), ("::1".into(), 5000));
        assert_eq!(split_host_port("[::1]", 4460), ("::1".into(), 4460));
    }

    #[test]
    fn huge_body_length_is_rejected_without_allocating() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x01, 0xff, 0xff]);
        // No body at all.
        assert!(decode_message(&buf).is_err());
    }
}
