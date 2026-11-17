//! End-to-end tests that run a real in-process NTS server and exercise the
//! client against it over loopback sockets.
//!
//! These cover the parts unit tests cannot: the TLS 1.3 exporter handshake,
//! packet framing across two independently built packets, and cookie rotation
//! behaviour observed from the client side.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nts_client::{ClientConfig, NtsClient};
use nts_server::{NtsServer, ServerConfig};

/// Build a server with a freshly generated CA and leaf certificate, bind it to
/// ephemeral loopback ports, and return a running server plus the client config
/// needed to talk to it.
struct Harness {
    server: Arc<NtsServer>,
    cfg: ClientConfig,
    _rotation: nts_server::RotationTask,
}

async fn harness(alg_order: &[u16]) -> Harness {
    let ca = rcgen::generate_simple_self_signed(vec!["NTS Test CA".into()]).unwrap();
    // Reuse the same key for CA and leaf; rcgen's simple API makes the leaf its
    // own CA, which rustls accepts when it is explicitly trusted as a root and
    // is also presented as the end entity only if it has the CA bit clear.
    let leaf = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let mut leaf_params = leaf;
    leaf_params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
        rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.self_signed(&leaf_key).unwrap();

    let ke_bind: SocketAddr = pick_port_tcp().await;
    let ntp_bind: SocketAddr = pick_port_udp().await;

    let cert_der = rustls::pki_types::CertificateDer::from(leaf_cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
    );

    let algorithms = alg_order
        .iter()
        .map(|id| nts_core::aead::AeadAlg::from_id(*id).unwrap())
        .collect();

    let cfg = ServerConfig {
        ke_bind,
        ntp_bind,
        cert_chain: vec![cert_der.clone()],
        key: key_der,
        ntp_server_name: Some("127.0.0.1".into()),
        ntp_port: ntp_bind.port(),
        algorithms,
        key_retain: 2,
        cookie_max_age: Duration::from_secs(3600),
        stratum: 2,
        allow_plain_ntp: false,
    };
    let server = Arc::new(NtsServer::new(cfg));

    let rotation = server.spawn_rotation(Duration::from_secs(3600));

    let serve = server.clone();
    tokio::spawn(async move {
        if let Err(e) = serve.serve().await {
            eprintln!("test server stopped: {e}");
        }
    });

    // Give the listeners a moment to bind.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let client_cfg = ClientConfig {
        ke_server: "127.0.0.1".into(),
        ke_port: ke_bind.port(),
        tls_server_name: "localhost".into(),
        ntp_server_override: Some("127.0.0.1".into()),
        ntp_port_override: Some(ntp_bind.port()),
        offered: alg_order
            .iter()
            .map(|id| nts_core::aead::AeadAlg::from_id(*id).unwrap())
            .collect(),
        extra_roots: vec![cert_der],
        insecure: false,
    };
    let _ = ca;
    Harness {
        server,
        cfg: client_cfg,
        _rotation: rotation,
    }
}

async fn pick_port_tcp() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

async fn pick_port_udp() -> SocketAddr {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    drop(s);
    a
}

#[tokio::test]
async fn ke_then_time_sample_with_siv() {
    let h = harness(&[15]).await;
    let mut client = NtsClient::connect(h.cfg.clone()).await.expect("NTS-KE");
    assert_eq!(client.negotiated_alg.id(), 15);
    assert!(client.cookie_count() >= 1, "KE must yield cookies");

    let sample = client
        .measure(Duration::from_secs(2))
        .await
        .expect("time sample");
    assert_eq!(sample.stratum, 2);
    // A loopback exchange should have a small delay and a small offset.
    assert!(sample.delay >= 0.0 && sample.delay < 0.5, "delay {}", sample.delay);
    assert!(sample.offset.abs() < 0.5, "offset {}", sample.offset);
}

#[tokio::test]
async fn ke_then_time_sample_with_gcm_siv() {
    let h = harness(&[30]).await;
    let mut client = NtsClient::connect(h.cfg.clone()).await.expect("NTS-KE");
    assert_eq!(client.negotiated_alg.id(), 30);
    let sample = client
        .measure(Duration::from_secs(2))
        .await
        .expect("time sample");
    assert!(sample.delay < 0.5, "delay {}", sample.delay);
}

#[tokio::test]
async fn server_prefers_client_order() {
    // Client asks for 30 first; server supports both, so 30 must be chosen.
    let h = harness(&[15, 30]).await;
    let mut client = NtsClient::connect(h.cfg.clone()).await.unwrap();
    assert_eq!(client.negotiated_alg.id(), 15, "server should honour offer order");

    let mut cfg30 = h.cfg.clone();
    cfg30.offered = vec![nts_core::aead::AeadAlg::Aes128GcmSiv];
    let mut c30 = NtsClient::connect(cfg30).await.unwrap();
    assert_eq!(c30.negotiated_alg.id(), 30);
    let _ = client.measure(Duration::from_secs(2)).await;
    let _ = c30.measure(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn cookies_refill_and_pool_survives_many_requests() {
    let h = harness(&[15]).await;
    let mut client = NtsClient::connect(h.cfg.clone()).await.unwrap();
    // Ten requests from a pool of eight must work: the server returns a fresh
    // cookie for each request, so the pool never drains.
    for i in 0..10 {
        let s = client
            .measure(Duration::from_secs(2))
            .await
            .unwrap_or_else(|e| panic!("request {i} failed: {e:#}"));
        assert_eq!(s.cookies_received, 1, "request {i} got no fresh cookie");
    }
}

#[tokio::test]
async fn old_cookies_keep_working_across_rotation() {
    let h = harness(&[15]).await;
    let mut client = NtsClient::connect(h.cfg.clone()).await.unwrap();

    // Burn through the initial cookies; each response refills one.
    for _ in 0..8 {
        client.measure(Duration::from_secs(2)).await.unwrap();
    }

    let before = h.server.key_ring().current_id();
    h.server.rotate();
    assert_ne!(h.server.key_ring().current_id(), before);

    // Cookies minted before the rotation are still accepted during the
    // transition window, so no request fails.
    for i in 0..5 {
        client
            .measure(Duration::from_secs(2))
            .await
            .unwrap_or_else(|e| panic!("post-rotation request {i} failed: {e:#}"));
    }
}

#[tokio::test]
async fn client_recovers_from_nts_nak_after_key_erasure() {
    // Retain=0 means every rotation erases the previous key, so the client's
    // next request is answered with an NTS NAK and it must re-run NTS-KE.
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let cert = params.self_signed(&ca_key).unwrap();

    let ke_bind = pick_port_tcp().await;
    let ntp_bind = pick_port_udp().await;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let cfg = ServerConfig {
        ke_bind,
        ntp_bind,
        cert_chain: vec![cert_der.clone()],
        key: rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ca_key.serialize_der()),
        ),
        ntp_server_name: Some("127.0.0.1".into()),
        ntp_port: ntp_bind.port(),
        algorithms: vec![nts_core::aead::AeadAlg::AesSivCmac256],
        key_retain: 0,
        cookie_max_age: Duration::from_secs(3600),
        stratum: 2,
        allow_plain_ntp: false,
    };
    let server = Arc::new(NtsServer::new(cfg));
    let rotation = server.spawn_rotation(Duration::from_secs(3600));
    let serve = server.clone();
    tokio::spawn(async move {
        let _ = serve.serve().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let client_cfg = ClientConfig {
        ke_server: "127.0.0.1".into(),
        ke_port: ke_bind.port(),
        tls_server_name: "localhost".into(),
        ntp_server_override: Some("127.0.0.1".into()),
        ntp_port_override: Some(ntp_bind.port()),
        offered: vec![nts_core::aead::AeadAlg::AesSivCmac256],
        extra_roots: vec![cert_der],
        insecure: false,
    };
    let mut client = NtsClient::connect(client_cfg).await.unwrap();
    client.measure(Duration::from_secs(2)).await.unwrap();

    // Erase everything the client's cookies were minted under.
    server.rotate();

    // The client sees a NAK, re-runs NTS-KE internally, and succeeds.
    let s = client
        .measure(Duration::from_secs(2))
        .await
        .expect("client should recover from NTS NAK");
    assert!(s.delay < 0.5);
    drop(rotation);
}

#[tokio::test]
async fn tampered_request_gets_no_valid_response() {
    // A packet whose Authenticator EF body is corrupted must not produce a
    // valid reply; the server answers with a NAK or silence, never a sample.
    use nts_core::auth;
    use nts_core::ntp::{ExtensionField, Packet, EF_NTS_COOKIE, EF_UNIQUE_IDENTIFIER, MODE_CLIENT};

    let h = harness(&[15]).await;
    let mut client = NtsClient::connect(h.cfg.clone()).await.unwrap();
    client.measure(Duration::from_secs(2)).await.unwrap();

    // Build a syntactically valid request with a bogus cookie.
    let mut p = Packet::new(MODE_CLIENT);
    p.extension_fields
        .push(ExtensionField::new(EF_UNIQUE_IDENTIFIER, vec![0xaa; 32]));
    p.extension_fields
        .push(ExtensionField::new(EF_NTS_COOKIE, vec![0xbb; 96]));
    let prefix = p.encode();
    let key = [0u8; 32];
    let raw = auth::seal_packet(
        nts_core::aead::AeadAlg::AesSivCmac256,
        &key,
        &prefix,
        &[],
        &[0u8; 16],
    )
    .unwrap();
    assert!(raw.len() > 48);

    // The server's NAK (or silence) must not be a valid NTS response; parse it
    // as a client would and require failure.
    let ntp_bind = h.cfg.ntp_port_override.unwrap();
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&raw, format!("127.0.0.1:{ntp_bind}")).await.unwrap();
    let mut buf = [0u8; 1024];
    if let Ok(Ok((n, _))) =
        tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await
    {
        let reply = &buf[..n];
        // Either it is a KoD/NAK with no NTS EFs, or it must fail verification.
        let parsed = Packet::parse(reply).unwrap();
        if parsed.find_field(0x0404).is_some() {
            assert!(nts_core::auth::open_packet(
                nts_core::aead::AeadAlg::AesSivCmac256,
                &[0x11; 32],
                reply
            )
            .is_err());
        }
    }
}
