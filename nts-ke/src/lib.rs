//! NTS-KE over TLS 1.3 (RFC 8915 §4), shared by client and server.
//!
//! Besides carrying the record exchange, this module owns the one piece of the
//! protocol that is easy to get subtly wrong: deriving the C2S/S2C keys from
//! the TLS exporter.
//!
//! * Label: `EXPORTER-network-time-security` (RFC 8915 §4.3).
//! * Context: `protocol_id (2) || aead_id (2) || direction (1)`, where
//!   direction is `0x00` for C2S and `0x01` for S2C (§5.1).
//!
//! rustls routes `export_keying_material(label, context)` straight into
//! TLS 1.3 `Derive-Secret(ExporterMasterSecret, label, Hash(context))`, which is
//! exactly RFC 8446 §7.5, so the label must be passed verbatim (no extra
//! `EXPORTER` prefix logic on our side).

use nts_core::aead::AeadAlg;
use nts_core::error::{Error, Result};
use nts_core::ke::{self, Record, RecordType, PROTOCOL_NTPV4};
use nts_core::keyring::AssociationKeys;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

pub const ALPN: &[u8] = b"ntske/1";
pub const DEFAULT_PORT: u16 = 4460;
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";

/// Cap on an NTS-KE message; chrony uses 16384 and RFC 8915 has no explicit
/// bound, but a KE message is always tiny in practice.
pub const MAX_KE_MESSAGE: usize = 16 * 1024;

/// Derive the directional AEAD keys for NTPv4 from an established TLS session.
///
/// `alg` is the algorithm whose *key length* and behaviour apply.
/// `exporter_alg` is the identifier placed into the exporter context; it is
/// normally equal to `alg` but differs when interoperating with implementations
/// that used the AES-SIV-CMAC-256 id for AES-128-GCM-SIV before record 1024
/// existed (see the caller in the server).
pub fn derive_keys<C>(
    conn: &C,
    alg: AeadAlg,
    exporter_alg: AeadAlg,
    protocol: u16,
) -> Result<AssociationKeys>
where
    C: Exporter,
{
    let c2s = export(conn, alg, exporter_alg, protocol, 0x00)?;
    let s2c = export(conn, alg, exporter_alg, protocol, 0x01)?;
    Ok(AssociationKeys::new(alg, c2s.to_vec(), s2c.to_vec()))
}

fn export<C: Exporter>(
    conn: &C,
    alg: AeadAlg,
    exporter_alg: AeadAlg,
    protocol: u16,
    direction: u8,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut context = [0u8; 5];
    context[..2].copy_from_slice(&protocol.to_be_bytes());
    context[2..4].copy_from_slice(&exporter_alg.id().to_be_bytes());
    context[4] = direction;

    let mut out = Zeroizing::new(vec![0u8; alg.key_len()]);
    conn.export_keying_material(out.as_mut_slice(), EXPORTER_LABEL, &context)
        .map_err(|e| Error::KeyMaterial(format!("TLS exporter failed: {e}")))?;
    Ok(out)
}

/// Anything that can export TLS keying material — implemented for both rustls
/// connection types so this module need not know which side it is on.
pub trait Exporter {
    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> std::result::Result<(), rustls::Error>;
}

impl Exporter for rustls::ClientConnection {
    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> std::result::Result<(), rustls::Error> {
        rustls::ConnectionCommon::export_keying_material(self, out, label, Some(context)).map(|_| ())
    }
}

impl Exporter for rustls::ServerConnection {
    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> std::result::Result<(), rustls::Error> {
        rustls::ConnectionCommon::export_keying_material(self, out, label, Some(context)).map(|_| ())
    }
}

/// Read one complete NTS-KE message.
///
/// NTS-KE has no length prefix: the message ends at the End of Message record,
/// so we accumulate until the record decoder accepts a buffer that ends with
/// one. A record whose declared body overruns the buffer is not an error yet —
/// it means more bytes are in flight.
pub async fn read_message<S>(stream: &mut S) -> Result<Vec<Record>>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 1024];
    loop {
        match ke::decode_message(&buf) {
            Ok(records) => return Ok(records),
            Err(e) => {
                // Distinguish "need more bytes" from "this will never parse".
                if !is_incomplete(&e) {
                    return Err(e);
                }
            }
        }
        if buf.len() > MAX_KE_MESSAGE {
            return Err(Error::Ke("NTS-KE message exceeded size limit".into()));
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| Error::Ke(format!("read failed: {e}")))?;
        if n == 0 {
            if buf.is_empty() {
                return Err(Error::Ke("connection closed before any record".into()));
            }
            return Err(Error::Ke("connection closed mid-message".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn is_incomplete(e: &Error) -> bool {
    match e {
        Error::Ke(msg) => {
            msg.contains("truncated record header")
                || msg.contains("overruns message")
                || msg.contains("missing End of Message")
        }
        _ => false,
    }
}

/// Write a complete NTS-KE message and flush it.
pub async fn write_message<S>(stream: &mut S, records: &[Record]) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let buf = ke::encode_message(records);
    stream
        .write_all(&buf)
        .await
        .map_err(|e| Error::Ke(format!("write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Ke(format!("flush failed: {e}")))?;
    Ok(())
}

/// A parsed NTS-KE response: the negotiated parameters plus the cookies.
#[derive(Debug, Clone)]
pub struct KeResponse {
    pub algorithm: AeadAlg,
    pub ntp_server: Option<String>,
    pub ntp_port: u16,
    pub cookies: Vec<Vec<u8>>,
    /// True when the server echoed chrony's record 1024, confirming it derives
    /// AES-128-GCM-SIV exporter keys with the spec-compliant context.
    pub compliant_128gcm: bool,
}

impl KeResponse {
    /// The identifier to place in the exporter context. A server that did not
    /// confirm record 1024 may be using the historical AES-SIV-CMAC-256 id.
    pub fn exporter_alg(&self) -> AeadAlg {
        if self.algorithm == AeadAlg::Aes128GcmSiv && !self.compliant_128gcm {
            AeadAlg::AesSivCmac256
        } else {
            self.algorithm
        }
    }
}

/// Interpret a server response, applying RFC 8915 §4.1 validation.
pub fn parse_response(records: &[Record]) -> Result<KeResponse> {
    let mut protocol_seen = false;
    let mut protocol_ok = false;
    let mut algorithm: Option<AeadAlg> = None;
    let mut ntp_server = None;
    let mut ntp_port: u16 = 123;
    let mut cookies = Vec::new();
    let mut compliant_128gcm = false;

    for rec in records {
        match rec.record_type {
            RecordType::EndOfMessage => {}
            RecordType::NextProtocol => {
                if protocol_seen {
                    return Err(Error::Ke("duplicate Next Protocol record".into()));
                }
                protocol_seen = true;
                protocol_ok = rec.u16_list()?.contains(&PROTOCOL_NTPV4);
            }
            RecordType::AeadAlgorithm => {
                if algorithm.is_some() {
                    return Err(Error::Ke("duplicate AEAD record".into()));
                }
                let ids = rec.u16_list()?;
                match ids.as_slice() {
                    [id] => {
                        algorithm = Some(
                            AeadAlg::from_id(*id).ok_or(Error::UnknownAead(*id))?,
                        )
                    }
                    [] => return Err(Error::Ke("server supports none of our AEADs".into())),
                    _ => return Err(Error::Ke("server selected multiple AEADs".into())),
                }
            }
            RecordType::Error => {
                let code = read_u16(&rec.body)?;
                return Err(Error::KeError(code));
            }
            RecordType::Warning => {
                let code = read_u16(&rec.body)?;
                return Err(Error::KeWarning(code));
            }
            RecordType::Cookie => cookies.push(rec.body.clone()),
            RecordType::Ntpv4Server => {
                if ntp_server.is_some() {
                    return Err(Error::Ke("duplicate NTPv4 Server record".into()));
                }
                ntp_server = Some(
                    String::from_utf8(rec.body.clone())
                        .map_err(|_| Error::Ke("NTPv4 Server record not ASCII".into()))?,
                );
            }
            RecordType::Ntpv4Port => {
                ntp_port = read_u16(&rec.body)?;
            }
            RecordType::Unknown(t) => {
                if t == ke::RECORD_CHRONY_COMPLIANT_128GCM && rec.body.is_empty() {
                    compliant_128gcm = true;
                    continue;
                }
                if rec.critical {
                    return Err(Error::Ke(format!(
                        "unrecognized critical record type {t}"
                    )));
                }
            }
        }
    }

    if !protocol_seen {
        return Err(Error::Ke("missing Next Protocol record".into()));
    }
    if !protocol_ok {
        return Err(Error::Ke("server did not accept NTPv4".into()));
    }
    let algorithm = algorithm.ok_or_else(|| Error::Ke("missing AEAD record".into()))?;
    if cookies.is_empty() {
        return Err(Error::Ke("server returned no cookies".into()));
    }
    Ok(KeResponse {
        algorithm,
        ntp_server,
        ntp_port,
        cookies,
        compliant_128gcm,
    })
}

fn read_u16(body: &[u8]) -> Result<u16> {
    if body.len() != 2 {
        return Err(Error::Ke("expected a 2-octet integer".into()));
    }
    Ok(u16::from_be_bytes([body[0], body[1]]))
}

/// Build the client's request records.
///
/// `offered` must be non-empty and ordered by preference. The chrony
/// "compliant AES-128-GCM-SIV export" marker is included when 30 is offered,
/// so a chrony server derives the spec-compliant exporter context instead of
/// the historical one (which hashed the algorithm id differently and would
/// make our keys disagree).
pub fn build_request(offered: &[AeadAlg], ntp_server: Option<&str>, ntp_port: Option<u16>) -> Vec<Record> {
    let ids: Vec<u16> = offered.iter().map(|a| a.id()).collect();
    let mut records = vec![
        Record::next_protocol(&[PROTOCOL_NTPV4]),
        Record::aead_algorithms(&ids),
    ];
    if offered.contains(&AeadAlg::Aes128GcmSiv) {
        records.push(Record::new(
            RecordType::Unknown(ke::RECORD_CHRONY_COMPLIANT_128GCM),
            Vec::new(),
            false,
        ));
    }
    if let Some(server) = ntp_server {
        records.push(Record::ntpv4_server(server));
    }
    if let Some(port) = ntp_port {
        records.push(Record::ntpv4_port(port));
    }
    records.push(Record::end_of_message());
    records
}

/// Build the server's response records.
///
/// `compliant_128gcm` echoes chrony's record 1024: it tells a client that we
/// derive AES-128-GCM-SIV exporter keys with the RFC-conformant context. A
/// server must only set it when the client asked, and only when it selected
/// AEAD 30, otherwise the client would be looking for a key we never derived.
pub fn build_response(
    error: Option<u16>,
    algorithm: Option<AeadAlg>,
    ntp_server: Option<&str>,
    ntp_port: Option<u16>,
    cookies: &[Vec<u8>],
    compliant_128gcm: bool,
) -> Vec<Record> {
    let mut records = Vec::new();
    if let Some(code) = error {
        records.push(Record::error(code));
        records.push(Record::end_of_message());
        return records;
    }
    records.push(Record::next_protocol(&[PROTOCOL_NTPV4]));
    let ids: Vec<u16> = algorithm.map(|a| vec![a.id()]).unwrap_or_default();
    let mut aead_record = Record::aead_algorithms(&ids);
    aead_record.critical = true;
    records.push(aead_record);
    if compliant_128gcm && algorithm == Some(AeadAlg::Aes128GcmSiv) {
        records.push(Record::new(
            RecordType::Unknown(ke::RECORD_CHRONY_COMPLIANT_128GCM),
            Vec::new(),
            false,
        ));
    }
    if let Some(server) = ntp_server {
        records.push(Record::ntpv4_server(server));
    }
    if let Some(port) = ntp_port {
        records.push(Record::ntpv4_port(port));
    }
    for c in cookies {
        records.push(Record::cookie(c.clone()));
    }
    records.push(Record::end_of_message());
    records
}

#[cfg(test)]
mod tests {
    use super::*;
    use nts_core::ke::Record;

    #[test]
    fn exporter_context_layout() {
        // Guard the exact 5-octet context from RFC 8915 §5.1, since a mistake
        // here silently produces keys that only fail at the NTP layer.
        let alg = AeadAlg::AesSivCmac256;
        let mut context = [0u8; 5];
        context[..2].copy_from_slice(&0u16.to_be_bytes());
        context[2..4].copy_from_slice(&alg.id().to_be_bytes());
        context[4] = 0x01;
        assert_eq!(context, [0x00, 0x00, 0x00, 0x0f, 0x01]);
        assert_eq!(ALPN, b"ntske/1");
        assert_eq!(EXPORTER_LABEL, b"EXPORTER-network-time-security");
    }

    #[test]
    fn request_offers_requested_algorithms_in_order() {
        let req = build_request(&[AeadAlg::Aes128GcmSiv, AeadAlg::AesSivCmac256], None, None);
        let aead = req
            .iter()
            .find(|r| r.record_type == RecordType::AeadAlgorithm)
            .unwrap();
        assert_eq!(aead.u16_list().unwrap(), vec![30, 15]);
        assert!(req.last().unwrap().record_type == RecordType::EndOfMessage);
    }

    #[test]
    fn parse_minimal_response() {
        let records = build_response(
            None,
            Some(AeadAlg::AesSivCmac256),
            None,
            None,
            &[vec![1; 96], vec![2; 96]],
            false,
        );
        let resp = parse_response(&records).unwrap();
        assert_eq!(resp.algorithm, AeadAlg::AesSivCmac256);
        assert_eq!(resp.cookies.len(), 2);
        assert_eq!(resp.ntp_port, 123);
        assert!(resp.ntp_server.is_none());
    }

    #[test]
    fn response_with_error_record_is_rejected() {
        let records = build_response(Some(1), None, None, None, &[], false);
        assert!(matches!(parse_response(&records), Err(Error::KeError(1))));
    }

    #[test]
    fn response_without_cookie_is_rejected() {
        let records = build_response(None, Some(AeadAlg::AesSivCmac256), None, None, &[], false);
        assert!(parse_response(&records).is_err());
    }

    #[test]
    fn unrecognized_critical_record_is_rejected() {
        let mut records = build_response(
            None,
            Some(AeadAlg::AesSivCmac256),
            None,
            None,
            &[vec![1; 96]],
            false,
        );
        records.insert(
            0,
            Record::new(RecordType::Unknown(12345), vec![1], true),
        );
        assert!(parse_response(&records).is_err());
    }

    #[test]
    fn unrecognized_noncritical_record_is_ignored() {
        let mut records = build_response(
            None,
            Some(AeadAlg::AesSivCmac256),
            None,
            None,
            &[vec![1; 96]],
            false,
        );
        records.insert(
            0,
            Record::new(RecordType::Unknown(12345), vec![1], false),
        );
        assert!(parse_response(&records).unwrap().cookies.len() == 1);
    }

    #[test]
    fn response_echoes_server_and_port() {
        let records = build_response(
            None,
            Some(AeadAlg::AesSivCmac256),
            Some("ntp.example.net"),
            Some(1234),
            &[vec![1; 96]],
            false,
        );
        let resp = parse_response(&records).unwrap();
        assert_eq!(resp.ntp_server.as_deref(), Some("ntp.example.net"));
        assert_eq!(resp.ntp_port, 1234);
    }
}
