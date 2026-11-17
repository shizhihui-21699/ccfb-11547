//! NTPv4 packet and extension-field handling (RFC 5905 + RFC 7822 framing),
//! restricted to the parts NTS needs.
//!
//! Field layout follows RFC 8915 §5:
//!
//! ```text
//! +-------------------------------+  \
//! |  48-octet NTP header          |   |-- AEAD associated data (A)
//! +-------------------------------+  /
//! | Unique Identifier EF          |  authenticated, in the clear
//! | NTS Cookie EF (+ placeholders)|  authenticated, in the clear
//! +-------------------------------+
//! | NTS Authenticator EF          |  A = everything above; P = encrypted EFs
//! +-------------------------------+
//! | optional trailing EFs         |  unauthenticated, discarded
//! +-------------------------------+
//! ```

use crate::error::{Error, Result};

/// Length of the bare NTPv4 header.
pub const HEADER_LEN: usize = 48;

/// Minimum legal extension-field length per RFC 7822. NTS EFs that are
/// encrypted inside the Authenticator EF may be shorter (RFC 8915 §5.6).
pub const MIN_EF_LEN: usize = 16;

/// Smallest legal NTP packet we will look at.
pub const MIN_PACKET_LEN: usize = HEADER_LEN;

/// Largest packet we will parse. Comfortably above the 1280-octet guidance in
/// RFC 8915 §5.7, and bounded so a hostile peer cannot make us allocate wildly.
pub const MAX_PACKET_LEN: usize = 4096;

pub const EF_UNIQUE_IDENTIFIER: u16 = 0x0104;
pub const EF_NTS_COOKIE: u16 = 0x0204;
pub const EF_NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;
pub const EF_NTS_AUTH_AND_EEF: u16 = 0x0404;

pub const MODE_CLIENT: u8 = 3;
pub const MODE_SERVER: u8 = 4;
pub const VERSION_4: u8 = 4;

pub const STRATUM_UNSPECIFIED: u8 = 0;

/// NTP short / timestamp formats are 16.16 and 32.32 fixed point of seconds.
pub const NTP_UNIX_EPOCH_DELTA: u64 = 2_208_988_800;

/// A parsed (or to-be-built) NTP packet.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Raw header bytes, exactly [`HEADER_LEN`] long.
    pub header: [u8; HEADER_LEN],
    /// Extension fields, in wire order, each framed as `type || length || body`.
    pub extension_fields: Vec<ExtensionField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionField {
    pub field_type: u16,
    pub body: Vec<u8>,
}

impl ExtensionField {
    pub fn new(field_type: u16, body: Vec<u8>) -> Self {
        Self { field_type, body }
    }

    /// Length including the 4-octet type/length prefix, i.e. the value that
    /// goes in the length subfield (RFC 7822).
    pub fn wire_len(&self) -> usize {
        4 + self.body.len()
    }

    /// Append this field to `out`, framed as RFC 7822 requires.
    ///
    /// `pad_to_min` lifts the field to the 16-octet minimum length; pass
    /// `false` only for the fields that live inside the Authenticator EF,
    /// where RFC 8915 §5.6 waives that minimum.
    pub fn encode_into(&self, out: &mut Vec<u8>, pad_to_min: bool) {
        let mut len = self.wire_len();
        if pad_to_min && len < MIN_EF_LEN {
            len = MIN_EF_LEN;
        }
        debug_assert_eq!(len % 4, 0, "extension field must be word-aligned");
        out.extend_from_slice(&self.field_type.to_be_bytes());
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
        // Zero padding up to the declared length (used for min-length EFs).
        out.resize(out.len() + (len - self.wire_len()), 0);
    }
}

impl Packet {
    pub fn new(mode: u8) -> Self {
        let mut header = [0u8; HEADER_LEN];
        // LI = 0 (no warning), VN = 4, Mode.
        header[0] = (VERSION_4 << 3) | (mode & 0x7);
        Self {
            header,
            extension_fields: Vec::new(),
        }
    }

    pub fn mode(&self) -> u8 {
        self.header[0] & 0x7
    }

    pub fn version(&self) -> u8 {
        (self.header[0] >> 3) & 0x7
    }

    pub fn stratum(&self) -> u8 {
        self.header[1]
    }

    pub fn set_stratum(&mut self, s: u8) {
        self.header[1] = s;
    }

    pub fn transmit_timestamp(&self) -> [u8; 8] {
        let mut t = [0u8; 8];
        t.copy_from_slice(&self.header[40..48]);
        t
    }

    pub fn set_transmit_timestamp(&mut self, ts: [u8; 8]) {
        self.header[40..48].copy_from_slice(&ts);
    }

    pub fn originate_timestamp(&self) -> [u8; 8] {
        let mut t = [0u8; 8];
        t.copy_from_slice(&self.header[24..32]);
        t
    }

    pub fn set_originate_timestamp(&mut self, ts: [u8; 8]) {
        self.header[24..32].copy_from_slice(&ts);
    }

    pub fn set_receive_timestamp(&mut self, ts: [u8; 8]) {
        self.header[32..40].copy_from_slice(&ts);
    }

    pub fn reference_id(&self) -> [u8; 4] {
        let mut r = [0u8; 4];
        r.copy_from_slice(&self.header[12..16]);
        r
    }

    pub fn set_reference_id(&mut self, id: [u8; 4]) {
        self.header[12..16].copy_from_slice(&id);
    }

    /// Encode header plus every extension field, with RFC 7822 minimum-length
    /// padding applied to each field.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.extend_from_slice(&self.header);
        for ef in &self.extension_fields {
            ef.encode_into(&mut out, true);
        }
        out
    }

    /// Encode only the extension fields, without the RFC 7822 minimum-length
    /// padding. Used for the plaintext of the Authenticator EF, where
    /// RFC 8915 §5.6 explicitly permits short fields.
    pub fn encode_encrypted_fields(fields: &[ExtensionField]) -> Vec<u8> {
        let mut out = Vec::new();
        for ef in fields {
            ef.encode_into(&mut out, false);
        }
        out
    }

    /// Split a raw packet into header and extension fields without attempting
    /// to interpret NTS semantics.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < MIN_PACKET_LEN {
            return Err(Error::Ntp(format!("packet too short: {} bytes", raw.len())));
        }
        if raw.len() > MAX_PACKET_LEN {
            return Err(Error::Ntp(format!("packet too long: {} bytes", raw.len())));
        }
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&raw[..HEADER_LEN]);

        let mut extension_fields = Vec::new();
        let mut pos = HEADER_LEN;
        while pos < raw.len() {
            if raw.len() - pos < 4 {
                return Err(Error::Ntp("trailing bytes shorter than EF header".into()));
            }
            let field_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
            let length = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
            if length < 4 || length % 4 != 0 {
                return Err(Error::Ntp(format!("bad EF length {length}")));
            }
            if pos + length > raw.len() {
                return Err(Error::Ntp(format!(
                    "EF length {length} overruns packet at offset {pos}"
                )));
            }
            extension_fields.push(ExtensionField {
                field_type,
                body: raw[pos + 4..pos + length].to_vec(),
            });
            pos += length;
        }
        Ok(Self {
            header,
            extension_fields,
        })
    }

    /// Byte offset, relative to the start of the packet, at which the
    /// Authenticator EF begins — this is exactly `len(A)` for AEAD.
    ///
    /// Returns `None` if no Authenticator EF is present.
    pub fn authenticator_offset(&self) -> Option<usize> {
        let mut pos = HEADER_LEN;
        for ef in &self.extension_fields {
            if ef.field_type == EF_NTS_AUTH_AND_EEF {
                return Some(pos);
            }
            pos += ef.wire_len();
        }
        None
    }

    pub fn find_field(&self, field_type: u16) -> Option<&ExtensionField> {
        self.extension_fields
            .iter()
            .find(|ef| ef.field_type == field_type)
    }

    pub fn find_fields(&self, field_type: u16) -> impl Iterator<Item = &ExtensionField> {
        self.extension_fields
            .iter()
            .filter(move |ef| ef.field_type == field_type)
    }
}

/// Format an NTP timestamp (seconds since 1900) from a UNIX timestamp.
pub fn ntp_timestamp_from_unix(unix_secs: u64, nanos: u32) -> [u8; 8] {
    let secs = unix_secs.wrapping_add(NTP_UNIX_EPOCH_DELTA);
    let frac = ((nanos as u64) << 32) / 1_000_000_000;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(secs as u32).to_be_bytes());
    out[4..].copy_from_slice(&(frac as u32).to_be_bytes());
    out
}

/// Convert an NTP timestamp into UNIX seconds (fractional).
pub fn ntp_timestamp_to_unix(ts: &[u8; 8]) -> f64 {
    let secs = u32::from_be_bytes([ts[0], ts[1], ts[2], ts[3]]) as f64;
    let frac = u32::from_be_bytes([ts[4], ts[5], ts[6], ts[7]]) as f64 / 4294967296.0;
    secs - NTP_UNIX_EPOCH_DELTA as f64 + frac
}

/// Current time as an NTP timestamp.
pub fn now_ntp_timestamp() -> [u8; 8] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    ntp_timestamp_from_unix(now.as_secs(), now.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_and_version_roundtrip() {
        let p = Packet::new(MODE_CLIENT);
        assert_eq!(p.version(), 4);
        assert_eq!(p.mode(), MODE_CLIENT);
        assert_eq!(p.header[0], 0x23);
    }

    #[test]
    fn extension_fields_roundtrip() {
        let mut p = Packet::new(MODE_CLIENT);
        p.extension_fields
            .push(ExtensionField::new(EF_UNIQUE_IDENTIFIER, vec![0xaa; 32]));
        p.extension_fields
            .push(ExtensionField::new(EF_NTS_COOKIE, vec![0xbb; 96]));
        let raw = p.encode();
        assert_eq!(raw.len(), HEADER_LEN + 4 + 32 + 4 + 96);
        let parsed = Packet::parse(&raw).unwrap();
        assert_eq!(parsed.extension_fields.len(), 2);
        assert_eq!(parsed.extension_fields[0].field_type, EF_UNIQUE_IDENTIFIER);
        assert_eq!(parsed.extension_fields[1].body.len(), 96);
    }

    #[test]
    fn short_ef_is_padded_to_rfc7822_minimum() {
        let mut p = Packet::new(MODE_CLIENT);
        p.extension_fields
            .push(ExtensionField::new(0x1234, vec![1, 2, 3, 4]));
        let raw = p.encode();
        assert_eq!(raw.len(), HEADER_LEN + MIN_EF_LEN);
        // length field advertises the padded length
        assert_eq!(u16::from_be_bytes([raw[50], raw[51]]) as usize, MIN_EF_LEN);
        let parsed = Packet::parse(&raw).unwrap();
        assert_eq!(parsed.extension_fields[0].body.len(), MIN_EF_LEN - 4);
    }

    #[test]
    fn authenticator_offset_points_at_auth_field() {
        let mut p = Packet::new(MODE_CLIENT);
        p.extension_fields
            .push(ExtensionField::new(EF_UNIQUE_IDENTIFIER, vec![0; 32]));
        p.extension_fields
            .push(ExtensionField::new(EF_NTS_COOKIE, vec![0; 96]));
        p.extension_fields
            .push(ExtensionField::new(EF_NTS_AUTH_AND_EEF, vec![0; 16]));
        let expected = HEADER_LEN + 4 + 32 + 4 + 96;
        assert_eq!(p.authenticator_offset(), Some(expected));
        let raw = p.encode();
        assert_eq!(
            u16::from_be_bytes([raw[expected], raw[expected + 1]]),
            EF_NTS_AUTH_AND_EEF
        );
    }

    #[test]
    fn rejects_bad_ef_length() {
        let mut raw = Packet::new(MODE_CLIENT).encode();
        // type 0x1234, length 0 (illegal)
        raw.extend_from_slice(&[0x12, 0x34, 0x00, 0x00]);
        assert!(Packet::parse(&raw).is_err());
    }

    #[test]
    fn rejects_overrunning_ef() {
        let mut raw = Packet::new(MODE_CLIENT).encode();
        // Declares 1024 bytes but supplies 8.
        raw.extend_from_slice(&[0x12, 0x34, 0x04, 0x00, 1, 2, 3, 4]);
        assert!(Packet::parse(&raw).is_err());
    }

    #[test]
    fn timestamp_conversion() {
        let ts = ntp_timestamp_from_unix(1_700_000_000, 500_000_000);
        let back = ntp_timestamp_to_unix(&ts);
        assert!((back - 1_700_000_000.5).abs() < 1e-6);
    }
}
