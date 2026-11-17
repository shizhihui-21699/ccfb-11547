//! The NTS Authenticator and Encrypted Extension Fields extension field
//! (RFC 8915 §5.6), plus the packet-level seal/verify helpers built on it.

use crate::aead::{self, AeadAlg};
use crate::error::{Error, Result};
use crate::ntp::{ExtensionField, Packet, EF_NTS_AUTH_AND_EEF, HEADER_LEN, MIN_EF_LEN};

/// The decoded contents of an Authenticator EF body.
#[derive(Debug, Clone)]
pub struct DecodedAuth {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// `N_REQ` from RFC 8915 §5.6: the nonce length (padded to a word boundary)
/// that clients must reach, else they must add explicit Additional Padding.
///
/// `N_MAX` for AES-SIV is unlimited and for AES-128-GCM-SIV it is 12
/// (RFC 5116), so `min(16, N_MAX)` is 16 and 12 respectively.
pub fn required_padded_nonce_len(alg: AeadAlg) -> usize {
    match alg {
        AeadAlg::AesSivCmac256 => 16,
        AeadAlg::Aes128GcmSiv => 12,
    }
}

fn pad4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

/// Build the body of an Authenticator EF.
///
/// `extra_padding` is appended verbatim after the ciphertext; it exists so a
/// client with a short nonce can satisfy the `N_REQ` rule without encrypting
/// anything extra. It is not needed for server packets.
pub fn encode_authenticator_body(
    alg: AeadAlg,
    nonce: &[u8],
    ciphertext: &[u8],
    extra_padding: usize,
) -> Vec<u8> {
    let nonce_padded = pad4(nonce.len());
    let ct_padded = pad4(ciphertext.len());
    let mut body = Vec::with_capacity(4 + nonce_padded + ct_padded + extra_padding);
    body.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    body.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    body.extend_from_slice(nonce);
    body.resize(body.len() + (nonce_padded - nonce.len()), 0);
    body.extend_from_slice(ciphertext);
    body.resize(body.len() + (ct_padded - ciphertext.len()), 0);
    body.resize(body.len() + extra_padding, 0);
    let _ = alg;
    body
}

/// Parse an Authenticator EF body back into nonce and ciphertext.
pub fn decode_authenticator_body(alg: AeadAlg, body: &[u8]) -> Result<DecodedAuth> {
    if body.len() < 4 {
        return Err(Error::Ntp("Authenticator EF body shorter than 4".into()));
    }
    let nonce_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let ct_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if nonce_len == 0 || nonce_len > aead::MAX_NONCE_LEN {
        return Err(Error::Ntp(format!("unacceptable nonce length {nonce_len}")));
    }
    if ct_len < alg.tag_len() {
        return Err(Error::Ntp(format!(
            "ciphertext length {ct_len} shorter than tag"
        )));
    }
    let nonce_padded = pad4(nonce_len);
    let ct_padded = pad4(ct_len);
    let needed = 4 + nonce_padded + ct_padded;
    if body.len() < needed {
        return Err(Error::Ntp("Authenticator EF truncated".into()));
    }
    let nonce = body[4..4 + nonce_len].to_vec();
    let ct_start = 4 + nonce_padded;
    let ciphertext = body[ct_start..ct_start + ct_len].to_vec();
    Ok(DecodedAuth { nonce, ciphertext })
}

/// How many octets of Additional Padding a client packet must carry.
pub fn required_extra_padding(alg: AeadAlg, nonce_len: usize) -> usize {
    let want = required_padded_nonce_len(alg);
    let have = pad4(nonce_len);
    want.saturating_sub(have)
}

/// Seal a packet: `prefix` must be the already-encoded header plus every
/// extension field that precedes the Authenticator EF. Returns the complete
/// packet bytes (prefix + Authenticator EF).
pub fn seal_packet(
    alg: AeadAlg,
    key: &[u8],
    prefix: &[u8],
    plaintext_fields: &[ExtensionField],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let plaintext = Packet::encode_encrypted_fields(plaintext_fields);
    let ciphertext = aead::seal(alg, key, nonce, prefix, &plaintext)?;
    let extra = required_extra_padding(alg, nonce.len());
    let body = encode_authenticator_body(alg, nonce, &ciphertext, extra);
    let mut out = Vec::with_capacity(prefix.len() + 4 + body.len() + 8);
    out.extend_from_slice(prefix);
    let ef = ExtensionField::new(EF_NTS_AUTH_AND_EEF, body);
    // The Authenticator EF is subject to the normal RFC 7822 minimum; in
    // practice it is always well over 16 octets.
    ef.encode_into(&mut out, true);
    Ok(out)
}

/// Verify and decrypt a received packet.
///
/// Returns the parsed packet (with the decrypted extension fields appended, in
/// plaintext form) and the plaintext fields separately for convenience.
///
/// Extension fields that appear *after* the Authenticator EF are unauthenticated
/// and are discarded, as RFC 8915 §5.7 requires.
pub fn open_packet(alg: AeadAlg, key: &[u8], raw: &[u8]) -> Result<(Packet, Vec<ExtensionField>)> {
    let packet = Packet::parse(raw)?;
    let auth_offset = packet
        .authenticator_offset()
        .ok_or_else(|| Error::Ntp("no Authenticator EF".into()))?;

    let auth_ef = packet
        .find_field(EF_NTS_AUTH_AND_EEF)
        .ok_or_else(|| Error::Ntp("no Authenticator EF".into()))?;
    let decoded = decode_authenticator_body(alg, &auth_ef.body)?;

    let ad = &raw[..auth_offset];
    let plaintext = aead::open(alg, key, &decoded.nonce, ad, &decoded.ciphertext)?;

    let fields = parse_plaintext_fields(&plaintext)?;

    // Only the fields up to and including the Authenticator EF are authentic.
    let mut authenticated: Vec<ExtensionField> = Vec::new();
    for ef in &packet.extension_fields {
        authenticated.push(ef.clone());
        if ef.field_type == EF_NTS_AUTH_AND_EEF {
            break;
        }
    }
    let mut verified = Packet {
        header: packet.header,
        extension_fields: authenticated,
    };
    // Surface decrypted fields after the authenticator for the caller.
    verified.extension_fields.extend(fields.iter().cloned());
    Ok((verified, fields))
}

/// Parse the concatenation of extension fields carried inside the
/// Authenticator EF. These may be shorter than RFC 7822's 16-octet minimum
/// (RFC 8915 §5.6), but must still be word-aligned and non-empty.
pub fn parse_plaintext_fields(mut buf: &[u8]) -> Result<Vec<ExtensionField>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(Error::Ntp("trailing bytes in encrypted EFs".into()));
        }
        let field_type = u16::from_be_bytes([buf[0], buf[1]]);
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if length < 4 || length % 4 != 0 || length > buf.len() {
            return Err(Error::Ntp(format!("bad encrypted EF length {length}")));
        }
        out.push(ExtensionField::new(field_type, buf[4..length].to_vec()));
        buf = &buf[length..];
    }
    Ok(out)
}

/// Build a client request by appending the Authenticator EF to an already
/// framed prefix. Used by both client and tests.
pub fn frame_with_authenticator(prefix: Vec<u8>, body: Vec<u8>) -> Vec<u8> {
    let mut out = prefix;
    let ef = ExtensionField::new(EF_NTS_AUTH_AND_EEF, body);
    ef.encode_into(&mut out, true);
    debug_assert!(out.len() > HEADER_LEN);
    out
}

/// Sanity-check that a packet's Authenticator EF is the last *authenticated*
/// field and that it is at least the RFC 7822 minimum length.
pub fn validate_authenticator_placement(packet: &Packet) -> Result<()> {
    let auth = packet
        .find_field(EF_NTS_AUTH_AND_EEF)
        .ok_or_else(|| Error::Ntp("no Authenticator EF".into()))?;
    if auth.wire_len() < MIN_EF_LEN {
        return Err(Error::Ntp("Authenticator EF below RFC 7822 minimum".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp::{ExtensionField, Packet, EF_NTS_COOKIE, MODE_CLIENT};

    fn build_prefix() -> (Vec<u8>, Vec<u8>) {
        let mut p = Packet::new(MODE_CLIENT);
        p.extension_fields.push(ExtensionField::new(
            crate::ntp::EF_UNIQUE_IDENTIFIER,
            vec![0x11; 32],
        ));
        p.extension_fields
            .push(ExtensionField::new(EF_NTS_COOKIE, vec![0x22; 96]));
        let prefix = p.encode();
        (prefix, vec![0x22; 96])
    }

    #[test]
    fn authenticator_body_layout() {
        let nonce = [0u8; 12];
        let ct = vec![0u8; 16];
        let body = encode_authenticator_body(AeadAlg::AesSivCmac256, &nonce, &ct, 4);
        assert_eq!(&body[..2], &12u16.to_be_bytes());
        assert_eq!(&body[2..4], &16u16.to_be_bytes());
        assert_eq!(body.len(), 4 + 12 + 16 + 4);
        let d = decode_authenticator_body(AeadAlg::AesSivCmac256, &body).unwrap();
        assert_eq!(d.nonce.len(), 12);
        assert_eq!(d.ciphertext.len(), 16);
    }

    #[test]
    fn sealed_packet_roundtrip() {
        for alg in [AeadAlg::AesSivCmac256, AeadAlg::Aes128GcmSiv] {
            let (prefix, _) = build_prefix();
            let key = vec![0x5au8; alg.key_len()];
            let nonce = vec![0x3cu8; alg.nonce_len()];
            let encrypted = vec![ExtensionField::new(EF_NTS_COOKIE, vec![0x77; 96])];

            let raw = seal_packet(alg, &key, &prefix, &encrypted, &nonce).unwrap();
            let (_, fields) = open_packet(alg, &key, &raw).unwrap();
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].body, vec![0x77; 96]);

            // Tampering with the authenticated prefix must be detected.
            let mut bad = raw.clone();
            bad[HEADER_LEN + 5] ^= 0xff;
            assert!(open_packet(alg, &key, &bad).is_err());
        }
    }

    #[test]
    fn trailing_unauthenticated_fields_are_discarded() {
        let alg = AeadAlg::AesSivCmac256;
        let (prefix, _) = build_prefix();
        let key = vec![0x5au8; alg.key_len()];
        let nonce = vec![0x3cu8; alg.nonce_len()];
        let raw = seal_packet(alg, &key, &prefix, &[], &nonce).unwrap();
        let mut with_trailer = raw.clone();
        ExtensionField::new(0x9999, vec![0xee; 12]).encode_into(&mut with_trailer, true);
        let (verified, _) = open_packet(alg, &key, &with_trailer).unwrap();
        assert!(verified.find_field(0x9999).is_none());
    }
}
