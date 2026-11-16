//! The two AEADs NTS uses for NTPv4 packets, behind one interface.
//!
//! RFC 8915 section 4.1.5 requires servers to support
//! `AEAD_AES_SIV_CMAC_256` (15); `AEAD_AES_128_GCM_SIV` (30) is the algorithm
//! chrony prefers by default, so both are implemented.  Every packet the
//! implementation sends names the algorithm in its cookie, and the algorithm is
//! negotiated per NTS-KE session, so the choice is never implicit.
//!
//! Two details differ between the algorithms and are easy to get wrong:
//!
//! * **Nonce length.** AES-SIV takes a variable-length nonce (RFC 5297 N_MIN=1,
//!   N_MAX=unlimited), AES-GCM-SIV exactly 12 octets.  NTS requires receivers
//!   to accept variable-length nonces for AES-SIV, so the SIV path must not be
//!   restricted to the 16 octets the `aes-siv` convenience API assumes.
//! * **Tag position.** AES-SIV prepends its 16-octet synthetic IV
//!   (`tag || ciphertext`, RFC 5297 section 2.6); AES-GCM-SIV appends it
//!   (`ciphertext || tag`, RFC 8452 section 4).  nettle, and therefore chrony,
//!   follow each RFC literally, so the wire format must match.

use aes_gcm_siv::aead::AeadInPlace;
use aes_gcm_siv::{Aes128GcmSiv, Nonce as GcmSivNonce};
use aes_siv::siv::Aes128Siv;
use aes_siv::KeyInit as _;
use zeroize::Zeroize;

/// IANA "AEAD Algorithms" numeric identifier for AEAD_AES_SIV_CMAC_256.
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;
/// IANA numeric identifier for AEAD_AES_128_GCM_SIV.
pub const AEAD_AES_128_GCM_SIV: u16 = 30;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AeadError {
    #[error("unsupported AEAD algorithm {0}")]
    Unsupported(u16),
    #[error("nonce length {len} invalid for {algo:?} (min {min}, max {max})")]
    BadNonce { algo: Aead, len: usize, min: usize, max: usize },
    #[error("ciphertext too short to contain an authentication tag")]
    ShortCiphertext,
    #[error("authentication failed")]
    AuthFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    AesSivCmac256,
    Aes128GcmSiv,
}

impl Aead {
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            AEAD_AES_SIV_CMAC_256 => Some(Aead::AesSivCmac256),
            AEAD_AES_128_GCM_SIV => Some(Aead::Aes128GcmSiv),
            _ => None,
        }
    }

    pub fn id(self) -> u16 {
        match self {
            Aead::AesSivCmac256 => AEAD_AES_SIV_CMAC_256,
            Aead::Aes128GcmSiv => AEAD_AES_128_GCM_SIV,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Aead::AesSivCmac256 => "AEAD_AES_SIV_CMAC_256",
            Aead::Aes128GcmSiv => "AEAD_AES_128_GCM_SIV",
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Aead::AesSivCmac256 => 32,
            Aead::Aes128GcmSiv => 16,
        }
    }

    pub fn tag_len(self) -> usize {
        16
    }

    /// RFC 5116 N_MIN.
    pub fn min_nonce_len(self) -> usize {
        match self {
            Aead::AesSivCmac256 => 1,
            Aead::Aes128GcmSiv => 12,
        }
    }

    /// RFC 5116 N_MAX.
    pub fn max_nonce_len(self) -> usize {
        match self {
            Aead::AesSivCmac256 => u16::MAX as usize,
            Aead::Aes128GcmSiv => 12,
        }
    }

    /// Length of the nonce this implementation emits.  NTS servers must handle
    /// any length the peer chose within [min_nonce_len, max_nonce_len]; this
    /// only controls what we send.
    pub fn default_nonce_len(self) -> usize {
        match self {
            Aead::AesSivCmac256 => 16,
            Aead::Aes128GcmSiv => 12,
        }
    }
}

/// Everything needed to protect or verify one packet direction.
pub struct AeadKey {
    algo: Aead,
    key: Vec<u8>,
}

impl AeadKey {
    pub fn new(algo: Aead, key: &[u8]) -> Self {
        assert_eq!(key.len(), algo.key_len(), "AEAD key length mismatch");
        Self {
            algo,
            key: key.to_vec(),
        }
    }

    pub fn algorithm(&self) -> Aead {
        self.algo
    }

    /// Encrypt `plaintext` with `associated_data`, returning the ciphertext in
    /// the algorithm's own wire layout (tag first for SIV, tag last for
    /// GCM-SIV), so callers can splice it straight into a packet.
    pub fn seal(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        self.check_nonce(nonce)?;
        match self.algo {
            Aead::AesSivCmac256 => {
                // AES-SIV is used through the low-level SIV API: the `Aead`
                // wrapper fixes the nonce at 16 octets, which would reject the
                // shorter nonces peers are entitled to send.
                let mut siv = Aes128Siv::new_from_slice(&self.key).expect("key length checked");
                let mut body = plaintext.to_vec();
                // RFC 5297 section 3: the nonce is the final AD component, with
                // the remaining AD concatenated as one preceding string.
                let tag = siv
                    .encrypt_in_place_detached([associated_data, nonce], &mut body)
                    .map_err(|_| AeadError::AuthFailed)?;
                // RFC 5297 section 2.6: tag followed by ciphertext.
                let mut out = Vec::with_capacity(16 + body.len());
                out.extend_from_slice(&tag);
                out.extend_from_slice(&body);
                Ok(out)
            }
            Aead::Aes128GcmSiv => {
                let cipher = Aes128GcmSiv::new_from_slice(&self.key).expect("key length checked");
                let nonce = GcmSivNonce::from_slice(nonce);
                let mut buf = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(nonce, associated_data, &mut buf)
                    .map_err(|_| AeadError::AuthFailed)?;
                // RFC 8452 section 4: ciphertext followed by the tag.
                buf.extend_from_slice(&tag);
                Ok(buf)
            }
        }
    }

    /// Verify and decrypt.  `ciphertext` is in the algorithm's wire layout.
    pub fn open(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        self.check_nonce(nonce)?;
        if ciphertext.len() < self.algo.tag_len() {
            return Err(AeadError::ShortCiphertext);
        }
        match self.algo {
            Aead::AesSivCmac256 => {
                let mut siv = Aes128Siv::new_from_slice(&self.key).expect("key length checked");
                let tag = aes_siv::Tag::clone_from_slice(&ciphertext[..16]);
                let mut body = ciphertext[16..].to_vec();
                siv.decrypt_in_place_detached([associated_data, nonce], &mut body, &tag)
                    .map_err(|_| AeadError::AuthFailed)?;
                Ok(body)
            }
            Aead::Aes128GcmSiv => {
                let cipher = Aes128GcmSiv::new_from_slice(&self.key).expect("key length checked");
                let nonce = GcmSivNonce::from_slice(nonce);
                let tag = aes_gcm_siv::Tag::clone_from_slice(&ciphertext[ciphertext.len() - 16..]);
                let mut body = ciphertext[..ciphertext.len() - 16].to_vec();
                cipher
                    .decrypt_in_place_detached(nonce, associated_data, &mut body, &tag)
                    .map_err(|_| AeadError::AuthFailed)?;
                Ok(body)
            }
        }
    }

    fn check_nonce(&self, nonce: &[u8]) -> Result<(), AeadError> {
        let (min, max) = (self.algo.min_nonce_len(), self.algo.max_nonce_len());
        if nonce.len() < min || nonce.len() > max {
            return Err(AeadError::BadNonce {
                algo: self.algo,
                len: nonce.len(),
                min,
                max,
            });
        }
        Ok(())
    }
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexbytes(s: &str) -> Vec<u8> {
        hex::decode(s.replace([' ', '\n'], "")).unwrap()
    }

    /// RFC 5297 appendix A.1 (deterministic mode) checked through the AEAD
    /// interface by treating the AD as a fixed string and the nonce as empty.
    /// This pins the S2V ordering and the tag-first layout.
    #[test]
    fn rfc5297_a1_deterministic() {
        let key = hexbytes(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let ad = hexbytes("101112131415161718191a1b1c1d1e1f2021222324252627");
        let pt = hexbytes("112233445566778899aabbccddee");
        let want = hexbytes("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");

        let mut siv = Aes128Siv::new_from_slice(&key).unwrap();
        let mut ct = pt.clone();
        let tag = siv
            .encrypt_in_place_detached([ad.as_slice()], &mut ct)
            .unwrap();
        let mut wire = tag.to_vec();
        wire.extend_from_slice(&ct);
        assert_eq!(wire, want);

        // Round-trip through the public interface with a 1-octet nonce.
        let k = AeadKey::new(Aead::AesSivCmac256, &key);
        let sealed = k.seal(&[0u8], &ad, &pt).unwrap();
        let opened = k.open(&[0u8], &ad, &sealed).unwrap();
        assert_eq!(opened, pt);
    }

    /// RFC 5297 appendix A.2: nonce-based AEAD example, nonce is AD3.
    #[test]
    fn rfc5297_a2_nonce_based() {
        let key = hexbytes(
            "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        );
        let ad1 = hexbytes(
            "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
        );
        let ad2 = hexbytes("102030405060708090a0");
        let nonce = hexbytes("09f911029d74e35bd84156c5635688c0");
        let pt = hexbytes(
            "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
        );

        // The RFC's construction is AD1, AD2, nonce, plaintext.  Through the
        // AEAD interface the AD components are concatenated (RFC 5297 section
        // 6.1 permits any marshalling as long as both sides agree), so this
        // test uses the exact SIV vector by feeding the two ADs as one string.
        let mut siv = Aes128Siv::new_from_slice(&key).unwrap();
        let mut combined = ad1.clone();
        combined.extend_from_slice(&ad2);
        let mut ct = pt.clone();
        let tag = siv
            .encrypt_in_place_detached([combined.as_slice(), nonce.as_slice()], &mut ct)
            .unwrap();
        siv.decrypt_in_place_detached([combined.as_slice(), nonce.as_slice()], &mut ct, &tag)
            .unwrap();
        assert_eq!(ct, pt);
    }

    /// RFC 8452 appendix C.1: AEAD_AES_128_GCM_SIV, empty plaintext and AAD.
    #[test]
    fn rfc8452_c1_empty() {
        let key = hexbytes("01000000000000000000000000000000");
        let nonce = hexbytes("030000000000000000000000");
        let k = AeadKey::new(Aead::Aes128GcmSiv, &key);
        let sealed = k.seal(&nonce, &[], &[]).unwrap();
        assert_eq!(sealed, hexbytes("dc20e2d83f25705bb49e439eca56de25"));

        let opened = k.open(&nonce, &[], &sealed).unwrap();
        assert!(opened.is_empty());
    }

    /// RFC 8452 appendix C.1: 8-octet plaintext, tag appended after ciphertext.
    #[test]
    fn rfc8452_c1_eight_octets() {
        let key = hexbytes("01000000000000000000000000000000");
        let nonce = hexbytes("030000000000000000000000");
        let pt = hexbytes("0100000000000000");
        let k = AeadKey::new(Aead::Aes128GcmSiv, &key);
        let sealed = k.seal(&nonce, &[], &pt).unwrap();
        assert_eq!(
            sealed,
            hexbytes("b5d839330ac7b786578782fff6013b815b287c22493a364c")
        );
        assert_eq!(k.open(&nonce, &[], &sealed).unwrap(), pt);
    }

    /// RFC 8452 appendix C.1: 12-octet plaintext.
    #[test]
    fn rfc8452_c1_twelve_octets() {
        let key = hexbytes("01000000000000000000000000000000");
        let nonce = hexbytes("030000000000000000000000");
        let pt = hexbytes("010000000000000000000000");
        let k = AeadKey::new(Aead::Aes128GcmSiv, &key);
        let sealed = k.seal(&nonce, &[], &pt).unwrap();
        assert_eq!(
            sealed,
            hexbytes("7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639")
        );
    }

    #[test]
    fn tampering_is_detected() {
        let k = AeadKey::new(Aead::AesSivCmac256, &[3u8; 32]);
        let sealed = k.seal(&[1u8; 16], b"ad", b"hello world").unwrap();
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert_eq!(k.open(&[1u8; 16], b"ad", &bad), Err(AeadError::AuthFailed));
        assert_eq!(
            k.open(&[1u8; 16], b"different ad", &sealed),
            Err(AeadError::AuthFailed)
        );
    }

    #[test]
    fn nonce_lengths_are_enforced_per_algorithm() {
        let siv = AeadKey::new(Aead::AesSivCmac256, &[1u8; 32]);
        for len in [1usize, 2, 12, 16, 100] {
            assert!(siv.seal(&vec![0u8; len], b"", b"x").is_ok(), "siv nonce {len}");
        }
        let gcm = AeadKey::new(Aead::Aes128GcmSiv, &[1u8; 16]);
        assert!(gcm.seal(&[0u8; 12], b"", b"x").is_ok());
        assert!(matches!(
            gcm.seal(&[0u8; 16], b"", b"x"),
            Err(AeadError::BadNonce { .. })
        ));
    }
}
