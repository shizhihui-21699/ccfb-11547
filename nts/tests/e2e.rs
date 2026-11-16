//! End-to-end tests: real TCP/TLS for NTS-KE and real UDP for NTP, all on
//! loopback with ephemeral ports.
//!
//! These exercise the full stack the way a deployment would: certificate
//! validation against a private CA, ALPN negotiation, exporter key extraction,
//! cookie minting, packet authentication, cookie stock replenishment, and
//! rotation.  Unit tests cover the formats; these cover the wiring.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use nts::aead::Aead;
use nts::client::{Client, ClientError};
use nts::cookie::CookieContents;
use nts::ke::ClientConfig;
use nts::nts_ntp::NtsError;
use nts::server::{handle_ntp_datagram, ServerConfig, ServerState};
use nts::{ntp, nts_ntp};

struct TestServer {
    state: Arc<ServerState>,
    ntp_addr: SocketAddr,
    ke_addr: SocketAddr,
    ca_pem: Vec<u8>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.state.running.store(false, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn make_ca_and_leaf() -> (rcgen::Certificate, rcgen::KeyPair, rcgen::Certificate, rcgen::KeyPair) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "NTS test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    (ca_cert, ca_key, leaf_cert, leaf_key)
}

fn start_server(aeads: Vec<Aead>, seed: [u8; 32], keep_old: usize) -> TestServer {
    let (ca_cert, _ca_key, leaf_cert, leaf_key) = make_ca_and_leaf();

    // Ephemeral ports: bind to 0 and read back what the OS chose.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ntp_addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let ke_addr = tcp.local_addr().unwrap();

    let cfg = ServerConfig {
        listen_ntp: ntp_addr,
        listen_ke: Some(ke_addr),
        supported_aeads: aeads,
        max_retired_cookie_keys: keep_old,
        stratum: 2,
        ..Default::default()
    };
    let state = ServerState::new(cfg, &seed);

    // Build the rustls server config directly from rcgen output.
    let cert_der = rustls_pki_types::CertificateDer::from(leaf_cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    tls.alpn_protocols = vec![nts::ke::ALPN_NTSKE.to_vec()];
    let tls = Arc::new(tls);

    let s = state.clone();
    let t = tls.clone();
    let ke_thread = std::thread::spawn(move || nts::server::run_ke_listener(s, t, tcp));

    let s = state.clone();
    let ntp_thread = std::thread::spawn(move || nts::server::run_ntp_listener(s, udp));

    // Give the listeners a moment to be ready (they are pre-bound, so the
    // first accept/recv would block rather than fail; this is belt and braces).
    std::thread::sleep(Duration::from_millis(50));

    TestServer {
        state,
        ntp_addr,
        ke_addr,
        ca_pem: ca_cert.pem().into_bytes(),
        threads: vec![ke_thread, ntp_thread],
    }
}

fn client_for(ts: &TestServer, aeads: Vec<Aead>) -> Client {
    let mut roots = rustls::RootCertStore::empty();
    let mut reader = std::io::BufReader::new(&ts.ca_pem[..]);
    for c in rustls_pemfile::certs(&mut reader) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut ke_cfg = ClientConfig::new("localhost", ts.ke_addr.port()).unwrap();
    ke_cfg.addrs = vec![ts.ke_addr];
    ke_cfg.timeout = Duration::from_secs(5);
    let ke_cfg = ke_cfg.with_roots(roots);
    Client::new(ke_cfg, ts.ntp_addr, aeads)
}

#[test]
fn full_session_with_both_algorithms() {
    for aead in [Aead::AesSivCmac256, Aead::Aes128GcmSiv] {
        let ts = start_server(vec![Aead::AesSivCmac256, Aead::Aes128GcmSiv], [1u8; 32], 2);
        let mut c = client_for(&ts, vec![aead]);
        c.key_establish().unwrap_or_else(|e| panic!("{aead:?} key_establish: {e}"));
        assert_eq!(c.aead(), Some(aead));
        assert_eq!(c.cookie_count(), 8, "NTS-KE provides eight cookies");

        for i in 0..20 {
            let s = c.poll().unwrap_or_else(|e| panic!("{aead:?} poll {i}: {e}"));
            assert!(s.offset.abs() < 0.5, "loopback offset {} too large", s.offset);
            assert!(s.delay >= 0.0);
            assert_eq!(s.stratum, 2);
            // The stock is topped up to eight on every successful volley.
            assert_eq!(c.cookie_count(), 8, "{aead:?} poll {i} stock");
        }
        // Twenty polls out of eight initial cookies, and one KE run: the rest
        // came from the responses, which is the whole point of the design.
        assert_eq!(c.stats.ke_runs, 1);
        assert_eq!(c.stats.responses, 20);
        assert_eq!(c.stats.auth_failures, 0);
        assert_eq!(c.stats.naks, 0);
    }
}

#[test]
fn cookies_survive_a_single_rotation_and_then_expire() {
    let ts = start_server(vec![Aead::AesSivCmac256], [9u8; 32], 1);
    let mut c = client_for(&ts, vec![Aead::AesSivCmac256]);
    c.key_establish().unwrap();
    c.poll().unwrap();
    let before = c.cookie_count();
    assert!(before > 0);

    // One rotation: the client's existing cookies must still be accepted, so
    // polling continues without any NTS-KE rerun.
    ts.state.rotate();
    let ke_before = c.stats.ke_runs;
    for _ in 0..before {
        let s = c.poll().expect("cookie must survive one rotation");
        assert!(s.offset.abs() < 0.5);
    }
    assert_eq!(c.stats.ke_runs, ke_before, "must not re-run NTS-KE");

    // Rotate past the retention window (keep_old = 1): now the stock left over
    // from before the first rotation is dead, and the client must recover by
    // re-running NTS-KE rather than silently failing.
    ts.state.rotate();
    ts.state.rotate();
    let mut recovered = false;
    for _ in 0..12 {
        match c.poll() {
            Ok(_) => recovered = true,
            Err(ClientError::Nts(NtsError::NtsNak)) => {
                // Expected for cookies minted under the expired key; the client
                // has already re-established by this point.
                continue;
            }
            Err(e) => panic!("unexpected error {e}"),
        }
    }
    assert!(recovered, "client never recovered after key retirement");
    assert!(c.stats.naks > 0, "expected at least one NAK");
    assert!(c.stats.ke_runs > ke_before, "expected an NTS-KE rerun");
    // And it is healthy again afterwards.
    assert!(c.poll().is_ok());
}

#[test]
fn client_uses_each_cookie_once() {
    let ts = start_server(vec![Aead::AesSivCmac256], [3u8; 32], 2);
    let mut c = client_for(&ts, vec![Aead::AesSivCmac256]);
    c.key_establish().unwrap();
    for _ in 0..5 {
        c.poll().unwrap();
    }
    assert_eq!(c.stats.cookies_consumed, 5);
    // Eight from KE plus one per response, minus five consumed.
    assert_eq!(c.stats.cookies_received, 8 + 5);
}

#[test]
fn rejects_server_with_untrusted_certificate() {
    let ts = start_server(vec![Aead::AesSivCmac256], [4u8; 32], 2);
    // Client that trusts only the system roots, not our CA.
    let mut ke_cfg = ClientConfig::new("localhost", ts.ke_addr.port()).unwrap();
    ke_cfg.addrs = vec![ts.ke_addr];
    ke_cfg.timeout = Duration::from_secs(5);
    let mut c = Client::new(ke_cfg, ts.ntp_addr, vec![Aead::AesSivCmac256]);
    let err = c.key_establish().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("certificate") || msg.contains("Certificate"),
        "unexpected error: {msg}"
    );
}

#[test]
fn tampered_server_response_is_rejected() {
    let ts = start_server(vec![Aead::AesSivCmac256], [5u8; 32], 2);

    // Build a request by hand so the response can be inspected and mangled.
    let ring = ts.state.key_ring.read().unwrap();
    let contents = CookieContents {
        aead: Aead::AesSivCmac256,
        c2s_key: vec![0xaa; 32],
        s2c_key: vec![0xbb; 32],
    };
    let cookie = ring.mint(&contents);
    drop(ring);

    let mut req = ntp::Packet::new();
    req.set_transmit_ts(ntp::ntp_now());
    nts_ntp::build_request(&mut req, &contents, &cookie, 2).unwrap();
    let uid = req.find(ntp::EF_UNIQUE_ID).unwrap().body.clone();
    let req_wire = req.encode();

    let reply = handle_ntp_datagram(&ts.state, &req_wire).unwrap();
    // Sanity: it verifies when untouched.
    let p = ntp::Packet::parse(&reply).unwrap();
    assert!(nts_ntp::verify_response(&p, &contents, &uid).is_ok());

    // Flip a bit inside the authenticator: the client must reject it.
    let mut bad = reply.clone();
    let last = bad.len() - 8;
    bad[last] ^= 0x01;
    let p = ntp::Packet::parse(&bad).unwrap();
    assert!(matches!(
        nts_ntp::verify_response(&p, &contents, &uid),
        Err(NtsError::AuthFailed)
    ));

    // And flipping a header bit (part of the AD) must also fail.
    let mut bad = reply.clone();
    bad[40] ^= 0x01;
    let p = ntp::Packet::parse(&bad).unwrap();
    assert!(matches!(
        nts_ntp::verify_response(&p, &contents, &uid),
        Err(NtsError::AuthFailed)
    ));
}

#[test]
fn unauthenticated_reply_never_reaches_the_client() {
    // A plain NTP server that answers without NTS must not be able to move the
    // client's clock: the response has no authenticator, so verification fails
    // before any timestamp is used.
    let contents = CookieContents {
        aead: Aead::AesSivCmac256,
        c2s_key: vec![1u8; 32],
        s2c_key: vec![2u8; 32],
    };
    let mut plain = ntp::Packet::new();
    plain.set_mode(ntp::MODE_SERVER);
    plain.set_stratum(1);
    let now = ntp::ntp_now();
    plain.set_receive_ts(now);
    plain.set_transmit_ts(now);
    let wire = plain.encode();
    let parsed = ntp::Packet::parse(&wire).unwrap();
    assert!(matches!(
        nts_ntp::verify_response(&parsed, &contents, &[0u8; 32]),
        Err(NtsError::NotProtected(_))
    ));
}

#[test]
fn seed_determinism_across_server_instances() {
    // Two servers from the same seed must accept each other's cookies.  This is
    // what makes rotation work across a load-balanced fleet without shared
    // storage.
    let a = ServerState::new(ServerConfig::default(), &[11u8; 32]);
    let b = ServerState::new(ServerConfig::default(), &[11u8; 32]);
    let contents = CookieContents {
        aead: Aead::AesSivCmac256,
        c2s_key: vec![7u8; 32],
        s2c_key: vec![8u8; 32],
    };
    let cookie = a.key_ring.read().unwrap().mint(&contents);
    assert!(b.key_ring.read().unwrap().open(&cookie).is_ok());

    // Different seed: no.
    let c = ServerState::new(ServerConfig::default(), &[12u8; 32]);
    assert!(c.key_ring.read().unwrap().open(&cookie).is_err());

    // Both rotated the same number of times: still in step.
    a.rotate();
    b.rotate();
    let cookie2 = a.key_ring.read().unwrap().mint(&contents);
    assert!(b.key_ring.read().unwrap().open(&cookie2).is_ok());
    assert_eq!(
        a.ring_stats().primary_id,
        b.ring_stats().primary_id,
        "ratchet must stay synchronised"
    );
}
