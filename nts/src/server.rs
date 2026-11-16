//! An NTS server: an NTS-KE listener on TCP and an NTS-protected NTP responder
//! on UDP, sharing one rotating cookie key ring.
//!
//! The two halves can be run on separate hosts, which is the deployment RFC 8915
//! section 8.3 recommends: an attacker who exhausts the TCP/asymmetric side
//! cannot interrupt time service for clients that already hold cookies.  Here
//! they share a process for simplicity, but the only state they share is the
//! key ring, so splitting them is a matter of running two processes from the
//! same seed.
//!
//! The NTP side never writes the clock: it reports its own time and lets the
//! client decide.  That keeps the test server harmless to the machine it runs
//! on and makes it usable without privileges.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::aead::Aead;
use crate::cookie::{CookieContents, KeyRing, SharedKeyRing};
use crate::ke::{self, choose_aead, KeResponse, DEFAULT_NTP_PORT, NEXT_PROTOCOL_NTPV4};
use crate::ntp::{self, Packet};
use crate::nts_ntp::{self, TARGET_COOKIE_STOCK};

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_ntp: SocketAddr,
    pub listen_ke: Option<SocketAddr>,
    /// AEADs this server is willing to negotiate, most preferred first.
    pub supported_aeads: Vec<Aead>,
    /// Stratum to advertise.
    pub stratum: u8,
    /// Precision log2 seconds, as an NTP signed 8-bit value.
    pub precision: i8,
    /// Root delay and dispersion in seconds.
    pub root_delay: f64,
    pub root_dispersion: f64,
    /// Reference ID, four ASCII octets.
    pub reference_id: [u8; 4],
    /// How many cookie generations to retain for decryption.
    pub max_retired_cookie_keys: usize,
    /// How many cookies to hand out per NTS-KE run (RFC 8915 suggests eight).
    pub cookies_per_ke: usize,
    /// Address advertised to clients, if it differs from the listening one.
    pub advertised_ntp: Option<String>,
    pub max_ke_connections: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_ntp: "127.0.0.1:12300".parse().unwrap(),
            listen_ke: None,
            supported_aeads: vec![Aead::AesSivCmac256, Aead::Aes128GcmSiv],
            stratum: 1,
            precision: -20,
            root_delay: 0.0,
            root_dispersion: 0.000_5,
            reference_id: *b"NTSR",
            max_retired_cookie_keys: 2,
            cookies_per_ke: TARGET_COOKIE_STOCK,
            advertised_ntp: None,
            max_ke_connections: 0,
        }
    }
}

/// Shared state between the two listeners.
pub struct ServerState {
    pub config: ServerConfig,
    pub key_ring: SharedKeyRing,
    pub aead: Aead,
    pub requests: AtomicU64,
    pub responses: AtomicU64,
    pub naks: AtomicU64,
    pub ke_sessions: AtomicU64,
    pub ke_errors: AtomicU64,
    pub cookies_minted: AtomicU64,
    pub bad_packets: AtomicU64,
    pub rotation_count: AtomicU64,
    pub running: AtomicBool,
}

impl ServerState {
    pub fn new(config: ServerConfig, seed: &[u8]) -> Arc<Self> {
        let ring = KeyRing::from_seed(seed, config.max_retired_cookie_keys);
        let aead = config.supported_aeads.first().copied().unwrap_or(Aead::AesSivCmac256);
        Arc::new(Self {
            config,
            key_ring: Arc::new(std::sync::RwLock::new(ring)),
            aead,
            requests: AtomicU64::new(0),
            responses: AtomicU64::new(0),
            naks: AtomicU64::new(0),
            ke_sessions: AtomicU64::new(0),
            ke_errors: AtomicU64::new(0),
            cookies_minted: AtomicU64::new(0),
            bad_packets: AtomicU64::new(0),
            rotation_count: AtomicU64::new(0),
            running: AtomicBool::new(true),
        })
    }

    /// Rotate the cookie key.  Old cookies keep working for
    /// `max_retired_cookie_keys` further rotations.
    pub fn rotate(&self) {
        let mut ring = self.key_ring.write().expect("key ring lock");
        ring.rotate();
        self.rotation_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mint_cookies(&self, aead: Aead, c2s: &[u8], s2c: &[u8], count: usize) -> Vec<Vec<u8>> {
        let ring = self.key_ring.read().expect("key ring lock");
        let contents = CookieContents {
            aead,
            c2s_key: c2s.to_vec(),
            s2c_key: s2c.to_vec(),
        };
        let out = (0..count).map(|_| ring.mint(&contents)).collect();
        self.cookies_minted.fetch_add(count as u64, Ordering::Relaxed);
        out
    }

    pub fn ring_stats(&self) -> crate::cookie::RingStats {
        self.key_ring.read().expect("key ring lock").stats()
    }
}

/// Build the NTP header fields that describe this server.
///
/// `poll` is echoed from the client's request, as RFC 5905 section 7.3
/// prescribes for a server reply.
fn server_header(cfg: &ServerConfig, poll: i8) -> Packet {
    let mut p = Packet::new();
    p.set_mode(ntp::MODE_SERVER);
    p.set_stratum(cfg.stratum);
    p.set_reference_id(u32::from_be_bytes(cfg.reference_id));
    p.header[2] = poll as u8;
    p.header[3] = cfg.precision as u8;
    let root_delay = (cfg.root_delay * 65_536.0) as i32;
    let root_disp = (cfg.root_dispersion * 65_536.0) as u32;
    p.header[4..8].copy_from_slice(&root_delay.to_be_bytes());
    p.header[8..12].copy_from_slice(&root_disp.to_be_bytes());
    // Reference timestamp: when the reference clock was last updated.  A real
    // server tracks this; a host that is its own reference reports the time at
    // which it last read its clock, which is now.
    p.set_reference_ts(ntp::ntp_now());
    p
}

/// Handle one UDP datagram.  Returns the reply, or `None` if the packet should
/// be silently dropped.
pub fn handle_ntp_datagram(state: &ServerState, data: &[u8]) -> Option<Vec<u8>> {
    let request = match Packet::parse(data) {
        Ok(p) => p,
        Err(_) => {
            state.bad_packets.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    state.requests.fetch_add(1, Ordering::Relaxed);

    let receive_ntp = ntp::ntp_now();
    let receive_unix = ntp::system_unix_f64();
    let _ = receive_unix;

    let ring = state.key_ring.read().expect("key ring lock");
    let verified = match nts_ntp::verify_request(&request, &ring) {
        Ok(v) => v,
        Err(_) => {
            drop(ring);
            // RFC 8915 section 5.7: reply to an unverifiable request with an
            // NTS NAK, but only if it echoes a unique identifier we can mirror
            // and do not include any cookie or authenticator.
            state.naks.fetch_add(1, Ordering::Relaxed);
            return nak_for(&request);
        }
    };

    let poll = request.header[2] as i8;
    let mut response = server_header(&state.config, poll);
    response.set_receive_ts(receive_ntp);
    response.set_transmit_ts(ntp::ntp_now());

    // One cookie for the one consumed, plus one per placeholder, capped by what
    // the request can carry (RFC 8915 section 5.7).
    let wanted = (verified.placeholder_count + 1).min(TARGET_COOKIE_STOCK);
    let cookies = {
        let contents = &verified.contents;
        let minted = {
            let ring = state.key_ring.read().expect("key ring lock");
            let c = CookieContents {
                aead: contents.aead,
                c2s_key: contents.c2s_key.clone(),
                s2c_key: contents.s2c_key.clone(),
            };
            (0..wanted).map(|_| ring.mint(&c)).collect::<Vec<_>>()
        };
        state
            .cookies_minted
            .fetch_add(minted.len() as u64, Ordering::Relaxed);
        minted
    };
    drop(ring);

    if nts_ntp::build_response(&verified, &mut response, &cookies).is_err() {
        state.bad_packets.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let _ = receive_unix;
    state.responses.fetch_add(1, Ordering::Relaxed);
    Some(response.encode())
}

/// Build an NTS NAK: stratum 0, reference ID "NTSN", echoing the unique
/// identifier.  No cookie and no authenticator (RFC 8915 section 5.7).
fn nak_for(request: &Packet) -> Option<Vec<u8>> {
    let uid = request.find(ntp::EF_UNIQUE_ID)?.body.clone();
    let mut p = Packet::new();
    p.set_mode(ntp::MODE_SERVER);
    p.set_stratum(0);
    p.set_reference_id(ntp::KOD_NTSN);
    p.push(ntp::ExtField::new(ntp::EF_UNIQUE_ID, uid));
    let now = ntp::ntp_now();
    p.set_receive_ts(now);
    p.set_transmit_ts(now);
    Some(p.encode())
}

/// Verify a response the way a client would; used by the interop harness to
/// check its own servers without a second implementation.
pub fn check_response(
    response: &[u8],
    contents: &CookieContents,
    uid: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let p = Packet::parse(response).map_err(|e| e.to_string())?;
    let v = nts_ntp::verify_response(&p, contents, uid).map_err(|e| e.to_string())?;
    Ok(v.cookies)
}

/// Serve NTS-KE connections until `running` is cleared.
pub fn run_ke_listener(state: Arc<ServerState>, tls: Arc<rustls::ServerConfig>, listener: TcpListener) {
    listener.set_nonblocking(true).ok();
    loop {
        if !state.running.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((mut sock, _peer)) => {
                // On BSD/macOS an accepted socket inherits the listener's
                // non-blocking flag, so reset it before handing it to the
                // blocking handshake.
                let _ = sock.set_nonblocking(false);
                let s = state.clone();
                let t = tls.clone();
                std::thread::spawn(move || {
                    s.ke_sessions.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = serve_ke_session(&s, &t, &mut sock) {
                        s.ke_errors.fetch_add(1, Ordering::Relaxed);
                        eprintln!("NTS-KE session failed: {e}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return,
        }
    }
}

fn serve_ke_session(
    state: &ServerState,
    tls: &rustls::ServerConfig,
    sock: &mut std::net::TcpStream,
) -> Result<(), ke::KeError> {
    let (mut conn, request) = ke::server_handshake(tls, sock, Duration::from_secs(10))?;

    // Negotiate.  Errors are reported in-band, which is how a client learns why
    // its request was unacceptable.
    let protocol_ok = request.next_protocols.contains(&NEXT_PROTOCOL_NTPV4);
    let aead = if protocol_ok {
        choose_aead(&request.aeads, &state.config.supported_aeads)
    } else {
        None
    };

    if !protocol_ok || aead.is_none() {
        let response = KeResponse {
            next_protocol: NEXT_PROTOCOL_NTPV4,
            aead: None,
            ntp_server: state.config.advertised_ntp.clone(),
            ntp_port: Some(state.config.listen_ntp.port()),
            cookies: vec![],
            compliant_128gcm_export: false,
            warnings: vec![],
        };
        // An empty AEAD record means "none supported"; the client gives up.
        let mut resp = response;
        resp.aead = None;
        ke::server_reply(&mut conn, sock, &resp)?;
        return Ok(());
    }
    let aead = aead.unwrap();

    let compliant = request.compliant_128gcm_export;
    let keys = ke::extract_keys(&conn, aead, compliant)?;
    let cookies = state.mint_cookies(aead, &keys.c2s, &keys.s2c, state.config.cookies_per_ke);

    let response = KeResponse {
        next_protocol: NEXT_PROTOCOL_NTPV4,
        aead: Some(aead),
        ntp_server: state.config.advertised_ntp.clone(),
        // Always state the port: an unprivileged server does not use 123, and
        // omitting the record would make the client assume it does.
        ntp_port: Some(state.config.listen_ntp.port()),
        cookies,
        compliant_128gcm_export: compliant && aead == Aead::Aes128GcmSiv,
        warnings: vec![],
    };
    ke::server_reply(&mut conn, sock, &response)?;
    Ok(())
}

/// Serve NTP datagrams until `running` is cleared.
pub fn run_ntp_listener(state: Arc<ServerState>, sock: UdpSocket) {
    sock.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let mut buf = [0u8; 2048];
    loop {
        if !state.running.load(Ordering::Relaxed) {
            return;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if let Some(reply) = handle_ntp_datagram(&state, &buf[..n]) {
                    let _ = sock.send_to(&reply, peer);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return,
        }
    }
}

/// Load an NTS-KE server TLS configuration from PEM files.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    use std::io::BufReader;
    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("no private key in {key_path}"))?;

    let mut cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![ke::ALPN_NTSKE.to_vec()];
    Ok(Arc::new(cfg))
}

/// A one-line description of the server's time base, for logs and reports.
pub fn time_base_description() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "system clock at {} (unix {}), offset unmanaged",
        humantime_like(now.as_secs()),
        now.as_secs()
    )
}

fn humantime_like(unix_secs: u64) -> String {
    // Minimal RFC 3339 rendering without pulling in a date library.
    let days = unix_secs / 86_400;
    let rem = unix_secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's days-from-civil inverse.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Port used for the NTP responder if none was given.
pub const DEFAULT_SERVER_NTP_PORT: u16 = DEFAULT_NTP_PORT;

/// Resolve `host:port`, `[v6]:port`, or a bare address with a default port.
pub fn resolve_addr(spec: &str) -> anyhow::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    if let Ok(a) = spec.parse::<SocketAddr>() {
        return Ok(a);
    }
    let (host, port) = crate::ke::split_host_port(spec, DEFAULT_SERVER_NTP_PORT);
    let with_port = format!("{host}:{port}");
    let mut addrs = with_port.to_socket_addrs()?;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {spec}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> Arc<ServerState> {
        ServerState::new(
            ServerConfig {
                listen_ntp: "127.0.0.1:12300".parse().unwrap(),
                supported_aeads: vec![Aead::AesSivCmac256],
                ..Default::default()
            },
            &[42u8; 32],
        )
    }

    fn client_request_for(state: &ServerState, aead: Aead) -> (Vec<u8>, CookieContents, Vec<u8>) {
        let n = aead.key_len();
        let contents = CookieContents {
            aead,
            c2s_key: vec![1u8; n],
            s2c_key: vec![2u8; n],
        };
        let cookie = state.key_ring.read().unwrap().mint(&contents);
        let mut req = Packet::new();
        req.set_transmit_ts(ntp::ntp_now());
        nts_ntp::build_request(&mut req, &contents, &cookie, 3).unwrap();
        let uid = req.find(ntp::EF_UNIQUE_ID).unwrap().body.clone();
        (req.encode(), contents, uid)
    }

    #[test]
    fn answered_correctly_and_cookies_returned() {
        let s = state();
        let (wire, contents, uid) = client_request_for(&s, Aead::AesSivCmac256);
        let reply = handle_ntp_datagram(&s, &wire).expect("server should reply");
        let cookies = check_response(&reply, &contents, &uid).unwrap();
        assert_eq!(cookies.len(), 4, "one for the consumed cookie plus three placeholders");
        assert_eq!(s.responses.load(Ordering::Relaxed), 1);
        assert_eq!(s.naks.load(Ordering::Relaxed), 0);
        // Response must not exceed the request.
        assert!(reply.len() <= wire.len() + 3, "{} vs {}", reply.len(), wire.len());
    }

    #[test]
    fn header_fields_are_populated() {
        let s = state();
        let (wire, contents, uid) = client_request_for(&s, Aead::AesSivCmac256);
        let orig_tx = Packet::parse(&wire).unwrap().transmit_ts();
        let reply = handle_ntp_datagram(&s, &wire).unwrap();
        let p = Packet::parse(&reply).unwrap();
        assert_eq!(p.mode(), ntp::MODE_SERVER);
        assert_eq!(p.stratum(), 1);
        assert_eq!(p.origin_ts(), orig_tx);
        assert_ne!(p.receive_ts(), 0);
        assert_ne!(p.transmit_ts(), 0);
        // The returned cookies decode under the current ring.
        let ring = s.key_ring.read().unwrap();
        for c in check_response(&reply, &contents, &uid).unwrap() {
            let got = ring.open(&c).unwrap();
            assert_eq!(got.c2s_key, contents.c2s_key);
        }
    }

    #[test]
    fn bad_cookie_gets_a_nak() {
        let s = state();
        let n = Aead::AesSivCmac256.key_len();
        let contents = CookieContents {
            aead: Aead::AesSivCmac256,
            c2s_key: vec![1u8; n],
            s2c_key: vec![2u8; n],
        };
        let bogus = vec![7u8; crate::cookie::cookie_len(Aead::AesSivCmac256)];
        let mut req = Packet::new();
        req.set_transmit_ts(ntp::ntp_now());
        nts_ntp::build_request(&mut req, &contents, &bogus, 0).unwrap();
        let uid = req.find(ntp::EF_UNIQUE_ID).unwrap().body.clone();
        let reply = handle_ntp_datagram(&s, &req.encode()).unwrap();
        let p = Packet::parse(&reply).unwrap();
        assert_eq!(p.stratum(), 0);
        assert_eq!(p.reference_id(), ntp::KOD_NTSN);
        assert_eq!(p.find(ntp::EF_UNIQUE_ID).unwrap().body, uid);
        assert!(p.find(ntp::EF_COOKIE).is_none());
        assert!(p.find(ntp::EF_NTS_AUTH).is_none());
        assert_eq!(s.naks.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unauthenticated_request_is_dropped_without_reply() {
        let s = state();
        let mut p = Packet::new();
        p.set_transmit_ts(ntp::ntp_now());
        assert!(handle_ntp_datagram(&s, &p.encode()).is_none());
    }

    #[test]
    fn garbage_is_dropped() {
        let s = state();
        assert!(handle_ntp_datagram(&s, &[0u8; 5]).is_none());
        assert!(handle_ntp_datagram(&s, b"not an ntp packet at all").is_none());
    }

    #[test]
    fn rotation_keeps_old_cookies_working_then_retires_them() {
        let s = state();
        let (wire_a, contents, uid) = client_request_for(&s, Aead::AesSivCmac256);
        let old_cookies = {
            let reply = handle_ntp_datagram(&s, &wire_a).unwrap();
            check_response(&reply, &contents, &uid).unwrap()
        };

        s.rotate();
        // A cookie minted before rotation still authenticates a request.
        let mut req = Packet::new();
        req.set_transmit_ts(ntp::ntp_now());
        nts_ntp::build_request(&mut req, &contents, &old_cookies[0], 0).unwrap();
        let uid2 = req.find(ntp::EF_UNIQUE_ID).unwrap().body.clone();
        let reply = handle_ntp_datagram(&s, &req.encode()).unwrap();
        assert!(check_response(&reply, &contents, &uid2).is_ok());

        // Retire it by rotating past the retention window.
        for _ in 0..state().config.max_retired_cookie_keys {
            s.rotate();
        }
        let mut req = Packet::new();
        req.set_transmit_ts(ntp::ntp_now());
        nts_ntp::build_request(&mut req, &contents, &old_cookies[0], 0).unwrap();
        let reply = handle_ntp_datagram(&s, &req.encode()).unwrap();
        assert_eq!(Packet::parse(&reply).unwrap().reference_id(), ntp::KOD_NTSN);
    }

    #[test]
    fn ke_negotiation_prefers_client_order() {
        // Client prefers GCM-SIV; both are supported, so GCM-SIV must win.
        assert_eq!(
            choose_aead(
                &[Aead::Aes128GcmSiv, Aead::AesSivCmac256],
                &[Aead::AesSivCmac256, Aead::Aes128GcmSiv]
            ),
            Some(Aead::Aes128GcmSiv)
        );
        // Disjoint sets negotiate nothing.
        assert_eq!(choose_aead(&[Aead::Aes128GcmSiv], &[Aead::AesSivCmac256]), None);
    }

    #[test]
    fn civil_date_conversion() {
        assert_eq!(humantime_like(0), "1970-01-01T00:00:00Z");
        assert_eq!(humantime_like(1_767_225_600), "2026-01-01T00:00:00Z");
    }
}
