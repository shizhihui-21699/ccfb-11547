//! NTS Key Establishment record encoding and decoding (RFC 8915 §4.1).
//!
//! An NTS-KE message is a sequence of records carried inside a TLS 1.3
//! application-data stream. Each record is:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |C|       Record Type           |          Body Length          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! .                         Record Body                           .
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Note the length field counts the *body* only — unlike an NTP extension
//! field, which counts the 4-octet prefix too. This asymmetry is the single
//! most common interop bug in NTS-KE implementations, so it is called out here
//! and covered by tests.

use crate::error::{Error, Result};

pub const RECORD_END_OF_MESSAGE: u16 = 0;
pub const RECORD_NEXT_PROTOCOL: u16 = 1;
pub const RECORD_ERROR: u16 = 2;
pub const RECORD_WARNING: u16 = 3;
pub const RECORD_AEAD_ALGORITHM: u16 = 4;
pub const RECORD_COOKIE: u16 = 5;
pub const RECORD_NTPV4_SERVER: u16 = 6;
pub const RECORD_NTPV4_PORT: u16 = 7;

/// Private record chrony uses to confirm it will derive the AES-128-GCM-SIV
/// exporter context per spec rather than the historical quirk. Not in IANA's
/// registry; see chrony's `NKE_RECORD_COMPLIANT_128GCM_EXPORT`. We advertise
/// it when offering 30 so that a chrony server derives the compliant key.
pub const RECORD_CHRONY_COMPLIANT_128GCM: u16 = 1024;

pub const PROTOCOL_NTPV4: u16 = 0;

/// RFC 8915 §4.2 minimum retry interval.
pub const MIN_RETRY_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    EndOfMessage,
    NextProtocol,
    Error,
    Warning,
    AeadAlgorithm,
    Ntpv4Server,
    Ntpv4Port,
    Cookie,
    /// Any type we do not know; retained so the critical bit can be honoured.
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            RECORD_END_OF_MESSAGE => RecordType::EndOfMessage,
            RECORD_NEXT_PROTOCOL => RecordType::NextProtocol,
            RECORD_ERROR => RecordType::Error,
            RECORD_WARNING => RecordType::Warning,
            RECORD_AEAD_ALGORITHM => RecordType::AeadAlgorithm,
            RECORD_COOKIE => RecordType::Cookie,
            RECORD_NTPV4_SERVER => RecordType::Ntpv4Server,
            RECORD_NTPV4_PORT => RecordType::Ntpv4Port,
            other => RecordType::Unknown(other),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::EndOfMessage => RECORD_END_OF_MESSAGE,
            RecordType::NextProtocol => RECORD_NEXT_PROTOCOL,
            RecordType::Error => RECORD_ERROR,
            RecordType::Warning => RECORD_WARNING,
            RecordType::AeadAlgorithm => RECORD_AEAD_ALGORITHM,
            RecordType::Cookie => RECORD_COOKIE,
            RecordType::Ntpv4Server => RECORD_NTPV4_SERVER,
            RecordType::Ntpv4Port => RECORD_NTPV4_PORT,
            RecordType::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub critical: bool,
    pub record_type: RecordType,
    pub body: Vec<u8>,
}

impl Record {
    pub fn new(record_type: RecordType, body: Vec<u8>, critical: bool) -> Self {
        Self {
            critical,
            record_type,
            body,
        }
    }

    pub fn end_of_message() -> Self {
        Self::new(RecordType::EndOfMessage, Vec::new(), true)
    }

    pub fn next_protocol(protocols: &[u16]) -> Self {
        let mut body = Vec::with_capacity(protocols.len() * 2);
        for p in protocols {
            body.extend_from_slice(&p.to_be_bytes());
        }
        Self::new(RecordType::NextProtocol, body, true)
    }

    pub fn aead_algorithms(algs: &[u16]) -> Self {
        let mut body = Vec::with_capacity(algs.len() * 2);
        for a in algs {
            body.extend_from_slice(&a.to_be_bytes());
        }
        // Critical bit MAY be set; chrony sets it in requests.
        Self::new(RecordType::AeadAlgorithm, body, true)
    }

    pub fn error(code: u16) -> Self {
        Self::new(RecordType::Error, code.to_be_bytes().to_vec(), true)
    }

    pub fn cookie(body: Vec<u8>) -> Self {
        // RFC 8915 §4.1.6: critical bit SHOULD NOT be set for cookies.
        Self::new(RecordType::Cookie, body, false)
    }

    pub fn ntpv4_server(name: &str) -> Self {
        Self::new(RecordType::Ntpv4Server, name.as_bytes().to_vec(), true)
    }

    pub fn ntpv4_port(port: u16) -> Self {
        Self::new(RecordType::Ntpv4Port, port.to_be_bytes().to_vec(), true)
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut ty = self.record_type.to_u16();
        if self.critical {
            ty |= 0x8000;
        }
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
    }

    /// Interpret a body as a list of 16-bit identifiers.
    pub fn u16_list(&self) -> Result<Vec<u16>> {
        if self.body.len() % 2 != 0 {
            return Err(Error::Ke(format!(
                "record type {:?} has odd-length body",
                self.record_type
            )));
        }
        Ok(self
            .body
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect())
    }
}

/// Decode a complete NTS-KE message. Enforces that End of Message is present
/// exactly once and is last (RFC 8915 §4.1.1).
pub fn decode_message(buf: &[u8]) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos == buf.len() {
            break;
        }
        if buf.len() - pos < 4 {
            return Err(Error::Ke("truncated record header".into()));
        }
        let raw_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let body_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if buf.len() - pos < body_len {
            return Err(Error::Ke("record body overruns message".into()));
        }
        let critical = raw_type & 0x8000 != 0;
        let record_type = RecordType::from_u16(raw_type & 0x7fff);
        let body = buf[pos..pos + body_len].to_vec();
        pos += body_len;
        let is_end = record_type == RecordType::EndOfMessage;
        records.push(Record {
            critical,
            record_type,
            body,
        });
        if is_end {
            if pos != buf.len() {
                return Err(Error::Ke("records after End of Message".into()));
            }
            break;
        }
    }
    match records.last() {
        Some(r) if r.record_type == RecordType::EndOfMessage => {}
        _ => return Err(Error::Ke("missing End of Message record".into())),
    }
    if records
        .iter()
        .take(records.len() - 1)
        .any(|r| r.record_type == RecordType::EndOfMessage)
    {
        return Err(Error::Ke("duplicate End of Message record".into()));
    }
    Ok(records)
}

pub fn encode_message(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for r in records {
        r.encode_into(&mut out);
    }
    if !records
        .iter()
        .any(|r| r.record_type == RecordType::EndOfMessage)
    {
        Record::end_of_message().encode_into(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_length_excludes_header() {
        let rec = Record::new(RecordType::NextProtocol, vec![0, 0], true);
        let mut buf = Vec::new();
        rec.encode_into(&mut buf);
        assert_eq!(buf.len(), 6);
        // Type word: critical bit + type 1.
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x8001);
        // Body length 2, not 6.
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 2);
    }

    #[test]
    fn message_roundtrip() {
        let records = vec![
            Record::next_protocol(&[PROTOCOL_NTPV4]),
            Record::aead_algorithms(&[15, 30]),
            Record::end_of_message(),
        ];
        let buf = encode_message(&records);
        let decoded = decode_message(&buf).unwrap();
        assert_eq!(decoded, records);
        assert_eq!(decoded[0].u16_list().unwrap(), vec![0]);
        assert_eq!(decoded[1].u16_list().unwrap(), vec![15, 30]);
    }

    #[test]
    fn missing_end_of_message_is_rejected() {
        let mut buf = Vec::new();
        Record::next_protocol(&[0]).encode_into(&mut buf);
        assert!(decode_message(&buf).is_err());
    }

    #[test]
    fn records_after_end_of_message_are_rejected() {
        let mut buf = Vec::new();
        Record::end_of_message().encode_into(&mut buf);
        Record::next_protocol(&[0]).encode_into(&mut buf);
        assert!(decode_message(&buf).is_err());
    }

    #[test]
    fn cookie_record_has_critical_bit_clear() {
        let rec = Record::cookie(vec![0xaa; 96]);
        let mut buf = Vec::new();
        rec.encode_into(&mut buf);
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), RECORD_COOKIE);
    }

    #[test]
    fn unknown_critical_record_is_representable() {
        let rec = Record::new(RecordType::Unknown(9999), vec![1], true);
        let mut buf = Vec::new();
        rec.encode_into(&mut buf);
        let decoded = decode_message(&{
            let mut m = buf.clone();
            Record::end_of_message().encode_into(&mut m);
            m
        })
        .unwrap();
        assert_eq!(decoded[0].record_type, RecordType::Unknown(9999));
        assert!(decoded[0].critical);
    }

    #[test]
    fn odd_length_identifier_list_is_rejected() {
        let rec = Record::new(RecordType::NextProtocol, vec![0, 0, 0], true);
        assert!(rec.u16_list().is_err());
    }
}
