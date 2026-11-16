//! NTPv4 packet and NTS extension-field wire handling.
//!
//! * 48-byte NTP header (RFC 5905 §7.3 / RFC 7822)
//! * 16-bit aligned extension fields (RFC 5905 §7.5), including the four
//!   NTS extension fields defined in RFC 8915 §5.1.2:
//!
//!   * 0x0104 Unique Identifier, 0x0204 Cookie, 0x0304 Cookie Placeholder,
//!   * 0x0404 NTS Authenticator and Encrypted Extension Fields,
//!   * 0x0504 Negotiated AEAD Algorithm.
//!
//! Extension fields are padded with zero octets out to a multiple of four.
//! The most-significant bit of the type word (0x8000) marks the last
//! extension field (RFC 7822).

use byteorder::{BigEndian, ByteOrder};

use crate::constants::*;
use crate::{Error, Result};

// ---------------------------------------------------------------- NTP header

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpHeader {
    pub li: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: [u8; 4],
    pub reference_timestamp: NtpTimestamp,
    pub origin_timestamp: NtpTimestamp,
    pub receive_timestamp: NtpTimestamp,
    pub transmit_timestamp: NtpTimestamp,
}

/// NTP short-format 64-bit timestamp (seconds since 1900-01-01, frac 2^-32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NtpTimestamp(pub u64);

/// NTP mode values (RFC 5905 §8.4).
pub const MODE_CLIENT: u8 = 3;
pub const MODE_SERVER: u8 = 4;

/// Leap indicator values.
pub const LI_NO_WARNING: u8 = 0;
pub const LI_NOT_SYNCED: u8 = 3;

impl NtpHeader {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < NTP_HEADER_LEN {
            return Err(Error::TooShort {
                got: buf.len(),
                need: NTP_HEADER_LEN,
            });
        }
        let b = &buf[..NTP_HEADER_LEN];
        let li = b[0] >> 6;
        let version = (b[0] >> 3) & 0x07;
        let mode = b[0] & 0x07;
        if version != 4 {
            return Err(Error::ntp(format!("unsupported NTP version {version}")));
        }
        Ok(Self {
            li,
            version,
            mode,
            stratum: b[1],
            poll: b[2] as i8,
            precision: b[3] as i8,
            root_delay: BigEndian::read_u32(&b[4..8]),
            root_dispersion: BigEndian::read_u32(&b[8..12]),
            reference_id: b[12..16].try_into().unwrap(),
            reference_timestamp: NtpTimestamp(BigEndian::read_u64(&b[16..24])),
            origin_timestamp: NtpTimestamp(BigEndian::read_u64(&b[24..32])),
            receive_timestamp: NtpTimestamp(BigEndian::read_u64(&b[32..40])),
            transmit_timestamp: NtpTimestamp(BigEndian::read_u64(&b[40..48])),
        })
    }

    /// Serialize exactly the 48-byte header.
    pub fn write(&self, out: &mut [u8]) {
        assert!(out.len() >= NTP_HEADER_LEN);
        out[0] = (self.li << 6) | ((self.version & 0x07) << 3) | (self.mode & 0x07);
        out[1] = self.stratum;
        out[2] = self.poll as u8;
        out[3] = self.precision as u8;
        BigEndian::write_u32(&mut out[4..8], self.root_delay);
        BigEndian::write_u32(&mut out[8..12], self.root_dispersion);
        out[12..16].copy_from_slice(&self.reference_id);
        BigEndian::write_u64(&mut out[16..24], self.reference_timestamp.0);
        BigEndian::write_u64(&mut out[24..32], self.origin_timestamp.0);
        BigEndian::write_u64(&mut out[32..40], self.receive_timestamp.0);
        BigEndian::write_u64(&mut out[40..48], self.transmit_timestamp.0);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![0u8; NTP_HEADER_LEN];
        self.write(&mut v);
        v
    }
}

// ----------------------------------------------------------- extension fields

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionField {
    pub r#type: u16,
    pub value: Vec<u8>,
}

impl ExtensionField {
    pub fn new(r#type: u16, value: Vec<u8>) -> Self {
        Self { r#type, value }
    }

    /// On-wire length of one extension field, padded to a multiple of four
    /// and never below the 16-octet minimum (RFC 5905 §7.5).
    pub fn wire_len(&self) -> usize {
        ef_wire_len(self.value.len())
    }
}

pub fn ef_wire_len(value_len: usize) -> usize {
    let l = 4 + value_len;
    let padded = (l + 3) & !3;
    padded.max(16)
}

/// Parse every extension field following the 48-byte header.
pub fn parse_extension_fields(mut buf: &[u8]) -> Result<Vec<ExtensionField>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(Error::ntp("trailing bytes shorter than EF header"));
        }
        let raw_type = BigEndian::read_u16(&buf[0..2]);
        let field_len = BigEndian::read_u16(&buf[2..4]) as usize;
        if field_len < 16 || !field_len.is_multiple_of(4) || field_len > buf.len() {
            return Err(Error::ntp(format!(
                "bad extension field length {field_len} (have {} bytes)",
                buf.len()
            )));
        }
        let r#type = raw_type & 0x7fff;
        let value = buf[4..field_len].to_vec();
        out.push(ExtensionField {
            r#type,
            value: trim_zero_pad(&value),
        });
        let last = raw_type & 0x8000 != 0;
        buf = &buf[field_len..];
        if last {
            if !buf.is_empty() {
                return Err(Error::ntp("data after last-extension-field marker"));
            }
            break;
        }
    }
    Ok(out)
}

/// Serialize extension fields. NTS extension fields are length-delimited and
/// peers (e.g. chrony) never set the RFC 7822 last-field marker, so all type
/// words are emitted with the high bit clear.
pub fn write_extension_fields(fields: &[ExtensionField]) -> Vec<u8> {
    let total: usize = fields.iter().map(|f| f.wire_len()).sum();
    let mut out = Vec::with_capacity(total);
    for f in fields {
        let wire_len = f.wire_len();
        let mut buf = vec![0u8; wire_len];
        BigEndian::write_u16(&mut buf[0..2], f.r#type & 0x7fff);
        BigEndian::write_u16(&mut buf[2..4], wire_len as u16);
        buf[4..4 + f.value.len()].copy_from_slice(&f.value);
        out.extend_from_slice(&buf);
    }
    out
}

fn trim_zero_pad(v: &[u8]) -> Vec<u8> {
    let mut end = v.len();
    while end > 0 && v[end - 1] == 0 {
        end -= 1;
    }
    v[..end].to_vec()
}

// ----------------------------------------------------- NTS-specific EF values

/// Negotiated AEAD Algorithm EF body (§5.4.2): one 16-bit algorithm id.
pub fn ef_negotiated_aead(alg_id: u16) -> ExtensionField {
    let mut v = vec![0u8; 2];
    BigEndian::write_u16(&mut v, alg_id);
    ExtensionField::new(EF_NTS_NEGOTIATED_AEAD, v)
}

/// Unique Identifier EF body: 32-octet nonce.
pub fn ef_unique_id(uid: &[u8]) -> ExtensionField {
    assert_eq!(uid.len(), UNIQUE_ID_LEN);
    ExtensionField::new(EF_UNIQUE_IDENTIFIER, uid.to_vec())
}

pub fn ef_cookie(cookie: &[u8]) -> ExtensionField {
    ExtensionField::new(EF_NTS_COOKIE, cookie.to_vec())
}

pub fn ef_cookie_placeholder(len: usize) -> ExtensionField {
    ExtensionField::new(EF_NTS_COOKIE_PLACEHOLDER, vec![0u8; len])
}

/// NTS Authenticator EF body (§5.4.3):
/// `u16 nonce_len | u16 ct_len | nonce(padded) | ciphertext+tag(padded)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorBody {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl AuthenticatorBody {
    pub fn encode(&self) -> Vec<u8> {
        let nonce_padded = (self.nonce.len() + 3) & !3;
        let ct_padded = (self.ciphertext.len() + 3) & !3;
        let mut buf = vec![0u8; 4 + nonce_padded + ct_padded];
        BigEndian::write_u16(&mut buf[0..2], self.nonce.len() as u16);
        BigEndian::write_u16(&mut buf[2..4], self.ciphertext.len() as u16);
        buf[4..4 + self.nonce.len()].copy_from_slice(&self.nonce);
        let off = 4 + nonce_padded;
        buf[off..off + self.ciphertext.len()].copy_from_slice(&self.ciphertext);
        buf
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        if value.len() < 4 {
            return Err(Error::ntp("authenticator EF shorter than 4 octets"));
        }
        let nonce_len = BigEndian::read_u16(&value[0..2]) as usize;
        let ct_len = BigEndian::read_u16(&value[2..4]) as usize;
        let nonce_padded = (nonce_len + 3) & !3;
        let ct_padded = (ct_len + 3) & !3;
        let need = 4 + nonce_padded + ct_padded;
        if value.len() < need {
            return Err(Error::ntp(format!(
                "authenticator EF truncated: have {}, need {need}",
                value.len()
            )));
        }
        Ok(Self {
            nonce: value[4..4 + nonce_len].to_vec(),
            ciphertext: value[4 + nonce_padded..4 + nonce_padded + ct_len].to_vec(),
        })
    }
}

/// A fully parsed NTS-protected NTP packet.
#[derive(Debug)]
pub struct NtsPacket {
    pub header: NtpHeader,
    pub fields: Vec<ExtensionField>,
    pub authenticator: Option<(AuthenticatorBody, usize)>,
}

pub fn parse_nts_packet(buf: &[u8]) -> Result<NtsPacket> {
    let header = NtpHeader::parse(buf)?;
    let fields = parse_extension_fields(&buf[NTP_HEADER_LEN..])?;
    let authenticator = fields
        .iter()
        .position(|f| f.r#type == EF_NTS_AUTHENTICATOR)
        .map(|idx| {
            AuthenticatorBody::decode(&fields[idx].value).map(|b| (b, idx))
        })
        .transpose()?;
    Ok(NtsPacket {
        header,
        fields,
        authenticator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = NtpHeader {
            li: LI_NO_WARNING,
            version: 4,
            mode: MODE_CLIENT,
            stratum: 0,
            poll: 6,
            precision: -20,
            root_delay: 1,
            root_dispersion: 2,
            reference_id: *b"NTS1",
            reference_timestamp: NtpTimestamp(0x11223344_55667788),
            origin_timestamp: NtpTimestamp(1),
            receive_timestamp: NtpTimestamp(2),
            transmit_timestamp: NtpTimestamp(3),
        };
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 48);
        let back = NtpHeader::parse(&bytes).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn extension_field_alignment_without_last_bit() {
        // 32-byte UID: 4 + 32 = 36 (already aligned)
        let uid = ef_unique_id(&[0xaau8; 32]);
        assert_eq!(uid.wire_len(), 36);
        // 20-byte cookie: 4+20 = 24
        let ck = ef_cookie(&[1u8; 20]);
        assert_eq!(ck.wire_len(), 24);
        // short value gets padded up to the 16-octet minimum
        let alg = ef_negotiated_aead(16);
        assert_eq!(alg.wire_len(), 16);

        let wire = write_extension_fields(&[uid, ck, alg]);
        // NTS extension fields never set the RFC 7822 last-field marker.
        let t0 = BigEndian::read_u16(&wire[0..2]);
        assert_eq!(t0, EF_UNIQUE_IDENTIFIER);
        let last_word = BigEndian::read_u16(&wire[wire.len() - 16..wire.len() - 14]);
        assert_eq!(last_word, EF_NTS_NEGOTIATED_AEAD);
        assert_eq!(last_word & 0x8000, 0);

        let parsed = parse_extension_fields(&wire).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].r#type, EF_UNIQUE_IDENTIFIER);
        assert_eq!(parsed[0].value, vec![0xaau8; 32]);
        assert_eq!(parsed[1].r#type, EF_NTS_COOKIE);
        assert_eq!(parsed[2].r#type, EF_NTS_NEGOTIATED_AEAD);
    }

    #[test]
    fn authenticator_body_roundtrip() {
        let body = AuthenticatorBody {
            nonce: vec![7u8; 32],
            ciphertext: vec![9u8; 41], // deliberately unaligned
        };
        let enc = body.encode();
        assert_eq!(enc.len() % 4, 0);
        let dec = AuthenticatorBody::decode(&enc).unwrap();
        assert_eq!(body, dec);
    }

    #[test]
    fn rejects_non_v4_and_truncated() {
        let mut h = NtpHeader {
            li: 0,
            version: 4,
            mode: MODE_CLIENT,
            stratum: 0,
            poll: 6,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: [0; 4],
            reference_timestamp: NtpTimestamp(0),
            origin_timestamp: NtpTimestamp(0),
            receive_timestamp: NtpTimestamp(0),
            transmit_timestamp: NtpTimestamp(0),
        };
        let mut bytes = h.to_bytes();
        bytes[0] = (3 << 3) | MODE_CLIENT; // version 3
        assert!(NtpHeader::parse(&bytes).is_err());
        assert!(NtpHeader::parse(&bytes[..40]).is_err());
        h.version = 4;
        let _ = h;
    }
}
