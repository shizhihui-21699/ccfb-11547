//! Key extraction shared by the KE client and server (RFC 8915 §5.1).
//!
//! The two AEAD working keys are extracted *directly* from the TLS 1.3
//! handshake with two separate exporter calls. Both use the label
//! `EXPORTER-network-time-security` and a five-octet context
//! `[protocol_id(2), aead_id(2), direction(1)]`, where direction is 0x00
//! for the client-to-server key and 0x01 for server-to-client:
//!
//! ```text
//! C2S = TLS-Exporter(label, [0x00,0x00, aead_hi,aead_lo, 0x00], key_len)
//! S2C = TLS-Exporter(label, [0x00,0x00, aead_hi,aead_lo, 0x01], key_len)
//! ```
//!
//! No additional HKDF layer is applied: RFC 8446's exporter already performs
//! the HKDF expansion internally. Adding another layer (an earlier design
//! mistake) produces different keys and breaks interop.

use crate::aead::AeadAlg;
use crate::constants::{
    EXPORTER_DIRECTION_C2S, EXPORTER_DIRECTION_S2C, EXPORTER_LABEL, NEXT_PROTOCOL_NTPV4,
};
use crate::{Error, Result};

/// Hash family selected by the negotiated TLS 1.3 cipher suite. Kept in the
/// API for callers that need to know the exporter's underlying hash, though
/// rustls resolves it internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsHash {
    Sha256,
    Sha384,
}

/// Build the five-octet exporter context for one direction.
/// `is_s2c` false → C2S (final byte 0x00), true → S2C (0x01).
pub fn exporter_context(alg: AeadAlg, is_s2c: bool) -> [u8; 5] {
    let id = alg.id();
    [
        ((NEXT_PROTOCOL_NTPV4 >> 8) & 0xff) as u8,
        (NEXT_PROTOCOL_NTPV4 & 0xff) as u8,
        ((id >> 8) & 0xff) as u8,
        (id & 0xff) as u8,
        if is_s2c {
            EXPORTER_DIRECTION_S2C
        } else {
            EXPORTER_DIRECTION_C2S
        },
    ]
}

pub fn exporter_label() -> &'static str {
    EXPORTER_LABEL
}

/// The C2S and S2C working keys, each `alg.key_len()` octets long.
#[derive(Clone)]
pub struct WorkingKeys {
    pub c2s: Vec<u8>,
    pub s2c: Vec<u8>,
}

/// Extract both working keys from an already-open TLS connection.
///
/// `export` must perform the RFC 8446 TLS-Exporter operation for the given
/// context and output length; rustls's `Connection::export_keying_material`
/// supplies exactly this.
pub fn derive_working_keys<F>(
    mut export: F,
    alg: AeadAlg,
) -> Result<WorkingKeys>
where
    F: FnMut(&'static str, &[u8], usize) -> Result<Vec<u8>>,
{
    let key_len = alg.key_len();
    let c2s_ctx = exporter_context(alg, false);
    let s2c_ctx = exporter_context(alg, true);
    let c2s = export(EXPORTER_LABEL, &c2s_ctx, key_len)?;
    let s2c = export(EXPORTER_LABEL, &s2c_ctx, key_len)?;
    if c2s.len() != key_len || s2c.len() != key_len {
        return Err(Error::ke("exporter returned unexpected key length"));
    }
    Ok(WorkingKeys { c2s, s2c })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_encoding_matches_rfc() {
        // GCM id 16, C2S: [00 00 00 10 00]
        assert_eq!(
            exporter_context(AeadAlg::Aes128Gcm, false),
            [0x00, 0x00, 0x00, 0x10, 0x00]
        );
        // GCM id 16, S2C: [00 00 00 10 01]
        assert_eq!(
            exporter_context(AeadAlg::Aes128Gcm, true),
            [0x00, 0x00, 0x00, 0x10, 0x01]
        );
        // SIV id 15
        assert_eq!(
            exporter_context(AeadAlg::AesSivCmac256, false),
            [0x00, 0x00, 0x00, 0x0f, 0x00]
        );
        assert_eq!(
            exporter_context(AeadAlg::AesSivCmac256, true),
            [0x00, 0x00, 0x00, 0x0f, 0x01]
        );
    }

    #[test]
    fn keys_use_exported_length_for_each_alg() {
        for alg in [AeadAlg::Aes128Gcm, AeadAlg::AesSivCmac256] {
            let mut calls: Vec<(&'static str, Vec<u8>, usize)> = Vec::new();
            let export = |label: &'static str, ctx: &[u8], len: usize| {
                calls.push((label, ctx.to_vec(), len));
                // Value encodes the direction byte for later assertion.
                Ok(vec![ctx[4]; len])
            };
            let wk = derive_working_keys(export, alg).unwrap();
            assert_eq!(wk.c2s.len(), alg.key_len());
            assert_eq!(wk.s2c.len(), alg.key_len());
            // Direction byte distinguishes the two exporter contexts.
            assert!(wk.c2s.iter().all(|&b| b == 0x00));
            assert!(wk.s2c.iter().all(|&b| b == 0x01));
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].2, alg.key_len());
            assert_eq!(calls[1].2, alg.key_len());
            assert_eq!(calls[0].1[4], 0x00);
            assert_eq!(calls[1].1[4], 0x01);
        }
    }
}
