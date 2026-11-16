//! Certificate generation and rustls TLS-1.3 configuration for NTS-KE.
//!
//! Production servers should use a publicly trusted certificate (the KE
//! channel is ordinary TLS, validated against WebPKI). For labs and the
//! interop tests here we generate a self-signed certificate with rcgen and
//! either pin it directly or run a local "trust anchor" verifier.

use std::io::BufReader;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::ServerConfig;
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::{Error, Result};

/// A generated certificate chain + private key, PEM and DER forms.
pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a self-signed ECDSA P-256 certificate for `common_name`.
///
/// The name is interpreted as an IP address when it parses as one (rcgen
/// then emits an iPAddress SAN), otherwise a DNS SAN. Standard TLS server
/// extensions are included: BasicConstraints CA:FALSE, digitalSignature /
/// keyAgreement key usage, and the serverAuth extended key usage, which
/// strict verifiers (e.g. chrony over GnuTLS) expect on an NTS-KE endpoint.
pub fn generate_self_signed(common_name: &str) -> Result<Identity> {
    use rcgen::{
        CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
        date_time_ymd,
    };

    let mut params = CertificateParams::new(vec![common_name.to_string()])
        .map_err(|e| Error::Certificate(e.to_string()))?;
    params.not_before = date_time_ymd(2025, 1, 1);
    params.not_after = date_time_ymd(2035, 1, 1);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyAgreement,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().map_err(|e| Error::Certificate(e.to_string()))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| Error::Certificate(e.to_string()))?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    let cert_der = cert.der().to_vec();
    let key_der = key.serialize_der();
    Ok(Identity {
        cert_der,
        key_der,
        cert_pem,
        key_pem,
    })
}

/// ALPN protocol identifier for NTS-KE, mandated by RFC 8915 §4 ("ntske/1").
pub const NTS_KE_ALPN: &[u8] = b"ntske/1";

/// Server TLS config: TLS 1.3 only with the mandatory NTS-KE ALPN,
/// self-signed or supplied identity.
pub fn server_config(identity: &Identity) -> Result<ServerConfig> {
    let cert_chain = vec![CertificateDer::from(identity.cert_der.clone())];
    let key = load_private_key(&identity.key_der)?;
    let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    let mut config = builder;
    config.alpn_protocols = vec![NTS_KE_ALPN.to_vec()];
    Ok(config)
}

/// Client config validating against the WebPKI roots (production use).
pub fn client_config_webpki() -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![NTS_KE_ALPN.to_vec()];
    Ok(config)
}

/// Client config that trusts exactly the DER certificate in `trusted_der`
/// (lab/interop use). Hostname is still checked against the cert SAN/CN.
pub fn client_config_pinned(trusted_der: &[u8]) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(trusted_der.to_vec()))
        .map_err(|e| Error::Certificate(e.to_string()))?;
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![NTS_KE_ALPN.to_vec()];
    Ok(config)
}

/// Insecure verifier used ONLY by the demo client's `--insecure` flag.
/// Accepts any certificate but still requires TLS 1.3 upstream.
#[derive(Debug)]
pub struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

pub fn client_config_insecure() -> ClientConfig {
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![NTS_KE_ALPN.to_vec()];
    config
}

fn load_private_key(der: &[u8]) -> Result<PrivateKeyDer<'static>> {
    // rcgen emits SEC1 ECDSA keys; rustls accepts them wrapped as PKCS8/SEC1.
    let pk = rustls::pki_types::PrivateKeyDer::try_from(der.to_vec())
        .map_err(|e| Error::Certificate(format!("private key DER: {e}")))?;
    Ok(pk)
}

/// Parse a PEM private key (helper for externally supplied server identities).
pub fn private_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    let item = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Error::Certificate(e.to_string()))?
        .ok_or_else(|| Error::Certificate("no private key in PEM".into()))?;
    Ok(item)
}

pub fn cert_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Certificate(e.to_string()))
}
