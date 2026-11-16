//! NTPv4 packet encoding and the NTS extension fields of RFC 8915 section 5.
//!
//! Only what NTS needs is modelled: the 48-octet header, extension fields, and
//! the Authenticator-and-Encrypted-EF field.  Extension field parsing is
//! deliberately strict because everything before the authenticator is fed to
//! the AEAD as associated data; a lenient parser here would let an attacker
//! move the authenticated boundary.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch.
pub const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

pub const NTP_HEADER_LEN: usize = 48;

/// RFC 8915 section 5.3.
pub const EF_UNIQUE_ID: u16 = 0x0104;
/// RFC 8915 section 5.4.
pub const EF_COOKIE: u16 = 0x0204;
/// RFC 8915 section 5.5.
pub const EF_COOKIE_PLACEHOLDER: u16 = 0x0304;
/// RFC 8915 section 5.6.
pub const EF_NTS_AUTH: u16 = 0x0404;

/// RFC 7822: an extension field is at least 16 octets long.
pub const MIN_EF_LEN: usize = 16;

pub const MODE_CLIENT: u8 = 3;
pub const MODE_SERVER: u8 = 4;

pub const NTP_VERSION: u8 = 4;

/// Kiss code "NTSN" (RFC 8915 section 7.4), carried in the reference ID of a
/// stratum-0 packet.
pub const KOD_NTSN: u32 = u32::from_be_bytes(*b"NTSN");

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet too short: {0} octets, need at least {NTP_HEADER_LEN}")]
    TooShort(usize),
    #[error("truncated extension field at offset {0}")]
    TruncatedExtField(usize),
    #[error("extension field at offset {offset} has illegal length {len}")]
    BadExtFieldLength { offset: usize, len: usize },
    #[error("packet is too long")]
    TooLong,
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Current time as an NTP 64-bit timestamp (32.32 fixed point), in the era
/// whose representation is closest to the real current time.
pub fn ntp_now() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    unix_to_ntp(now.as_secs(), now.subsec_nanos())
}

pub fn unix_to_ntp(unix_secs: u64, nanos: u32) -> u64 {
    // Truncating to 32 bits drops the era; the receiver recovers it by picking
    // the era nearest its own clock, which is unambiguous for ±68 years.
    let secs = unix_secs.wrapping_add(NTP_UNIX_OFFSET) & 0xffff_ffff;
    let frac = ((nanos as u64) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// Convert an NTP timestamp back to Unix seconds.
///
/// `pivot` is an estimate of the correct time (normally the local clock at
/// receive time).  Because an NTP timestamp only carries 32 bits of seconds,
/// the era must be reconstructed; picking the era closest to `pivot` is the
/// standard approach and is correct as long as the clock is within 68 years of
/// the server.
pub fn ntp_to_unix(ts: u64, pivot: f64) -> f64 {
    let secs = (ts >> 32) as u32 as f64;
    let frac = (ts & 0xffff_ffff) as f64 / 4_294_967_296.0;
    let base = secs - (NTP_UNIX_OFFSET as f64) + frac;
    let era_shift = ((pivot - base) / 4_294_967_296.0).round();
    base + era_shift * 4_294_967_296.0
}

pub fn system_unix_f64() -> f64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    d.as_secs_f64()
}

// ---------------------------------------------------------------------------
// Extension fields
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtField {
    pub typ: u16,
    pub body: Vec<u8>,
}

impl ExtField {
    pub fn new(typ: u16, body: Vec<u8>) -> Self {
        debug_assert!(body.len() % 4 == 0, "EF body must be a multiple of 4");
        Self { typ, body }
    }

    /// Total on-the-wire length including the 4-octet header.
    pub fn encoded_len(&self) -> usize {
        4 + self.body.len()
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.typ.to_be_bytes());
        out.extend_from_slice(&((4 + self.body.len()) as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
    }

    /// Append this field to a buffer (used for the encrypted inner fields).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.encode(out);
    }
}

/// The NTS Authenticator and Encrypted Extension Fields extension field,
/// RFC 8915 section 5.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthField {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

fn pad4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

impl AuthField {
    pub fn encoded_len(&self) -> usize {
        4 + 4 + pad4(self.nonce.len()) + pad4(self.ciphertext.len())
    }

    /// Build the field body.  `additional_padding` is the extra zero padding
    /// described in RFC 8915 section 5.6; clients use it to reserve room so the
    /// server's response can carry more cookies without growing the packet.
    pub fn encode(&self, additional_padding: usize) -> ExtField {
        let nonce_padded = pad4(self.nonce.len());
        let ct_padded = pad4(self.ciphertext.len());
        let mut body = Vec::with_capacity(
            4 + nonce_padded + ct_padded + additional_padding,
        );
        body.extend_from_slice(&(self.nonce.len() as u16).to_be_bytes());
        body.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.nonce);
        body.resize(4 + nonce_padded, 0);
        body.extend_from_slice(&self.ciphertext);
        body.resize(4 + nonce_padded + ct_padded, 0);
        body.resize(body.len() + additional_padding, 0);
        debug_assert_eq!(body.len() % 4, 0);
        ExtField::new(EF_NTS_AUTH, body)
    }

    /// Parse an auth field body.  Enforces the length and padding rules a
    /// server must apply (RFC 8915 section 5.6), so a packet that under-pads
    /// its nonce is rejected rather than silently accepted.
    pub fn parse(body: &[u8], max_nonce_len: usize, tag_len: usize) -> Option<Self> {
        if body.len() < 4 {
            return None;
        }
        let nonce_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        let ct_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        let nonce_padded = pad4(nonce_len);
        let ct_padded = pad4(ct_len);
        if 4 + nonce_padded + ct_padded > body.len() {
            return None;
        }
        if nonce_len == 0 || nonce_len > max_nonce_len {
            return None;
        }
        if ct_len < tag_len {
            return None;
        }
        // RFC 8915 5.6: a sender that uses a nonce shorter than min(16, N_MAX)
        // must pad the field so the nonce region plus Additional Padding reaches
        // that length.  This is what stops a client from shrinking its request
        // below the response a server would send (DDoS amplification).
        let n_req = pad4(std::cmp::min(16, max_nonce_len));
        if nonce_padded < n_req {
            let required = 4 + ct_padded + n_req;
            if body.len() < required {
                return None;
            }
        }
        let nonce = body[4..4 + nonce_len].to_vec();
        let ct_off = 4 + nonce_padded;
        let ciphertext = body[ct_off..ct_off + ct_len].to_vec();
        Some(Self { nonce, ciphertext })
    }
}

// ---------------------------------------------------------------------------
// Packet
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Packet {
    pub header: [u8; NTP_HEADER_LEN],
    pub efs: Vec<ExtField>,
}

impl Default for Packet {
    fn default() -> Self {
        Self::new()
    }
}

impl Packet {
    pub fn new() -> Self {
        let mut header = [0u8; NTP_HEADER_LEN];
        const LEAP_NONE: u8 = 0;
        header[0] = (LEAP_NONE << 6) | (NTP_VERSION << 3) | MODE_CLIENT;
        Self {
            header,
            efs: Vec::new(),
        }
    }

    pub fn version(&self) -> u8 {
        (self.header[0] >> 3) & 0x07
    }

    pub fn mode(&self) -> u8 {
        self.header[0] & 0x07
    }

    pub fn set_mode(&mut self, mode: u8) {
        self.header[0] = (self.header[0] & !0x07) | (mode & 0x07);
    }

    pub fn stratum(&self) -> u8 {
        self.header[1]
    }

    pub fn set_stratum(&mut self, s: u8) {
        self.header[1] = s;
    }

    pub fn reference_id(&self) -> u32 {
        u32::from_be_bytes([self.header[12], self.header[13], self.header[14], self.header[15]])
    }

    pub fn set_reference_id(&mut self, id: u32) {
        self.header[12..16].copy_from_slice(&id.to_be_bytes());
    }

    fn ts_at(&self, off: usize) -> u64 {
        u64::from_be_bytes(self.header[off..off + 8].try_into().unwrap())
    }

    fn set_ts_at(&mut self, off: usize, v: u64) {
        self.header[off..off + 8].copy_from_slice(&v.to_be_bytes());
    }

    /// Reference timestamp (header offset 16).
    pub fn reference_ts(&self) -> u64 {
        self.ts_at(16)
    }
    pub fn set_reference_ts(&mut self, v: u64) {
        self.set_ts_at(16, v)
    }

    /// Origin (client transmit) timestamp, offset 24.
    pub fn origin_ts(&self) -> u64 {
        self.ts_at(24)
    }
    pub fn set_origin_ts(&mut self, v: u64) {
        self.set_ts_at(24, v)
    }

    /// Receive timestamp, offset 32.
    pub fn receive_ts(&self) -> u64 {
        self.ts_at(32)
    }
    pub fn set_receive_ts(&mut self, v: u64) {
        self.set_ts_at(32, v)
    }

    /// Transmit timestamp, offset 40.
    pub fn transmit_ts(&self) -> u64 {
        self.ts_at(40)
    }
    pub fn set_transmit_ts(&mut self, v: u64) {
        self.set_ts_at(40, v)
    }

    pub fn push(&mut self, ef: ExtField) {
        self.efs.push(ef);
    }

    /// Current length of the encoded packet.
    pub fn encoded_len(&self) -> usize {
        NTP_HEADER_LEN + self.efs.iter().map(ExtField::encoded_len).sum::<usize>()
    }

    /// Serialize header plus all extension fields.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            NTP_HEADER_LEN + self.efs.iter().map(ExtField::encoded_len).sum::<usize>(),
        );
        out.extend_from_slice(&self.header);
        for ef in &self.efs {
            ef.encode(&mut out);
        }
        out
    }

    /// Byte offset at which the extension fields begin.
    pub const fn efs_offset(&self) -> usize {
        NTP_HEADER_LEN
    }

    pub fn parse(buf: &[u8]) -> Result<Self, PacketError> {
        if buf.len() < NTP_HEADER_LEN {
            return Err(PacketError::TooShort(buf.len()));
        }
        let mut header = [0u8; NTP_HEADER_LEN];
        header.copy_from_slice(&buf[..NTP_HEADER_LEN]);
        let mut efs = Vec::new();
        let mut off = NTP_HEADER_LEN;
        while off < buf.len() {
            if buf.len() - off < 4 {
                return Err(PacketError::TruncatedExtField(off));
            }
            let typ = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            if len < 4 || len % 4 != 0 || off + len > buf.len() {
                return Err(PacketError::BadExtFieldLength { offset: off, len });
            }
            efs.push(ExtField {
                typ,
                body: buf[off + 4..off + len].to_vec(),
            });
            off += len;
        }
        Ok(Self { header, efs })
    }

    /// The associated data for an authenticator that starts at byte
    /// `auth_offset`: the whole packet from the first header octet up to, but
    /// not including, the authenticator extension field.
    pub fn associated_data(&self, auth_offset: usize) -> Vec<u8> {
        self.encode()[..auth_offset].to_vec()
    }

    pub fn find(&self, typ: u16) -> Option<&ExtField> {
        self.efs.iter().find(|e| e.typ == typ)
    }

    pub fn find_all(&self, typ: u16) -> impl Iterator<Item = &ExtField> {
        self.efs.iter().filter(move |e| e.typ == typ)
    }

    /// Index of the authenticator extension field, which RFC 8915 requires to
    /// be the last one.
    pub fn auth_index(&self) -> Option<usize> {
        self.efs.iter().position(|e| e.typ == EF_NTS_AUTH)
    }

    /// Byte offset of the authenticator field within the encoded packet.
    pub fn ef_offset(&self, index: usize) -> usize {
        NTP_HEADER_LEN + self.efs[..index].iter().map(ExtField::encoded_len).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_roundtrip() {
        let now = system_unix_f64();
        let ts = ntp_now();
        let back = ntp_to_unix(ts, now);
        assert!((back - now).abs() < 0.001, "{back} vs {now}");
    }

    #[test]
    fn era_reconstruction_after_2036() {
        // 2042-01-01T00:00:00Z is past the first NTP era rollover.
        let unix = 2_272_070_400.0_f64;
        let ts = unix_to_ntp(unix as u64, 0);
        assert_eq!(ntp_to_unix(ts, unix), unix);
        // A clock still in 2026 must not read this as 1909.
        let recovered = ntp_to_unix(ts, 1_763_000_000.0);
        assert_eq!(recovered, unix);
    }

    #[test]
    fn auth_field_roundtrip() {
        let af = AuthField {
            nonce: vec![7u8; 16],
            ciphertext: vec![9u8; 16],
        };
        let ef = af.encode(0);
        let parsed = AuthField::parse(&ef.body, 16, 16).unwrap();
        assert_eq!(parsed, af);
    }

    #[test]
    fn auth_field_rejects_short_nonce_without_padding() {
        // nonce_len 4 must be padded to 16; here the field only holds 8 octets
        // after the header, so it must be rejected.
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(&[1, 2, 3, 4]);
        body.resize(body.len() + 16, 0);
        assert!(AuthField::parse(&body, 16, 16).is_none());
    }

    #[test]
    fn packet_roundtrip() {
        let mut p = Packet::new();
        p.set_mode(MODE_SERVER);
        p.set_transmit_ts(0xdead_beef_1234_5678);
        p.push(ExtField::new(EF_UNIQUE_ID, vec![0xaa; 32]));
        let enc = p.encode();
        let back = Packet::parse(&enc).unwrap();
        assert_eq!(back.mode(), MODE_SERVER);
        assert_eq!(back.transmit_ts(), 0xdead_beef_1234_5678);
        assert_eq!(back.find(EF_UNIQUE_ID).unwrap().body, vec![0xaa; 32]);
    }

    #[test]
    fn rejects_unaligned_ext_field() {
        let mut buf = vec![0u8; NTP_HEADER_LEN];
        buf.extend_from_slice(&[0x01, 0x04, 0x00, 0x11]); // length 17
        buf.resize(NTP_HEADER_LEN + 20, 0);
        assert!(Packet::parse(&buf).is_err());
    }
}
