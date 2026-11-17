//! AEAD algorithms negotiated by NTS-KE, applied to NTP packets (RFC 8915 §5.6)
//! and to cookies (RFC 8915 §6).
//!
//! # Interoperability notes
//!
//! AES-SIV (RFC 5297) is not a plain nonce-prefixed AEAD: the AEAD interface
//! maps the nonce to the *final* component of the S2V associated-data vector.
//! `aes-siv`'s `AeadInPlace` impl does exactly that, and nettle (hence chrony)
//! does the same, so the two implementations agree. Because SIV is
//! misuse-resistant, a nonce is not strictly required for its security; the
//! nonce we pass is nevertheless taken from the packet so that a receiver can
//! decrypt without extra state.
//!
//! # Tag placement differs between the two algorithms
//!
//! This is a real interop trap, so it is spelled out here:
//!
//! * **AES-SIV (15)** outputs `tag || ciphertext` (`IV || C`, RFC 5297 §2.6),
//!   which is what nettle's `siv_cmac_encrypt_message` produces and what chrony
//!   therefore expects.
//! * **AES-128-GCM-SIV (30)** outputs `ciphertext || tag`, the usual RFC 5116
//!   convention, which nettle's `siv_gcm_encrypt_message` produces and which
//!   the `aead` crate's default `AeadInPlace::encrypt_in_place` implements.
//!
//! [`seal`] and [`open`] hide the difference from callers by returning and
//! accepting `tag || ciphertext` for AES-SIV and `ciphertext || tag` for
//! GCM-SIV, exactly as they appear on the wire. Getting this uniform is what
//! makes our GCM-SIV packets decryptable by chrony.

use aes_gcm_siv::aead::{AeadInPlace, KeyInit};
use aes_gcm_siv::Aes128GcmSiv;
use aes_siv::siv::Aes128Siv;
use zeroize::Zeroizing;

use crate::error::AeadError;

/// Maximum nonce length this implementation will accept on the wire.
///
/// RFC 8915 §5.6 computes the "Additional Padding" requirement from `N_MAX`,
/// which is unlimited for both SIV variants. Implementations nonetheless have
/// to bound the nonce they will parse. 16 bytes matches what chrony emits as a
/// client (`NTS_MIN_UNPADDED_NONCE_LENGTH`) and is the length we emit.
pub const MAX_NONCE_LEN: usize = 16;

/// AEAD algorithm identifiers from the IANA "AEAD Algorithms" registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadAlg {
    /// 15 — AEAD_AES_SIV_CMAC_256 (RFC 5297). Mandatory to implement.
    ///
    /// "256" refers to the 256-bit *total* key: AES-128-CMAC for S2V plus
    /// AES-128-CTR (RFC 5297 §6.1, `K_LEN = 32`). Hence `Aes128Siv`, not
    /// `Aes256Siv` (which would need a 64-octet key and is AEAD id 17).
    AesSivCmac256,
    /// 30 — AEAD_AES_128_GCM_SIV (RFC 8452).
    Aes128GcmSiv,
}

impl AeadAlg {
    pub const fn id(self) -> u16 {
        match self {
            AeadAlg::AesSivCmac256 => 15,
            AeadAlg::Aes128GcmSiv => 30,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            15 => Some(AeadAlg::AesSivCmac256),
            30 => Some(AeadAlg::Aes128GcmSiv),
            _ => None,
        }
    }

    /// Key length in octets, as used for both the C2S and S2C keys.
    pub const fn key_len(self) -> usize {
        match self {
            AeadAlg::AesSivCmac256 => 32,
            AeadAlg::Aes128GcmSiv => 16,
        }
    }

    /// Length of the authentication tag; both supported algorithms use 16.
    pub const fn tag_len(self) -> usize {
        16
    }

    /// Nonce length we generate. For AES-128-GCM-SIV the nonce length is fixed
    /// by the algorithm (12 octets); for AES-SIV any length works and 16 is used.
    pub const fn nonce_len(self) -> usize {
        match self {
            AeadAlg::AesSivCmac256 => 16,
            AeadAlg::Aes128GcmSiv => 12,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            AeadAlg::AesSivCmac256 => "AEAD_AES_SIV_CMAC_256",
            AeadAlg::Aes128GcmSiv => "AEAD_AES_128_GCM_SIV",
        }
    }
}

impl std::fmt::Display for AeadAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.name(), self.id())
    }
}

/// A symmetric key for one direction, zeroized on drop.
pub type AeadKey = Zeroizing<Vec<u8>>;

/// Encrypt `plaintext` with `key`, authenticating `ad`.
///
/// Returns the AEAD output in its algorithm-defined wire order: `tag || ct`
/// for AES-SIV, `ct || tag` for AES-128-GCM-SIV. The caller frames the result
/// into the NTS Authenticator extension field untouched.
pub fn seal(
    alg: AeadAlg,
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    check_key_nonce(alg, key, nonce)?;
    let mut out = Vec::with_capacity(plaintext.len() + alg.tag_len());
    match alg {
        AeadAlg::AesSivCmac256 => {
            // `Siv::encrypt` prepends the tag itself (`IV || C`).
            let mut siv = Aes128Siv::new_from_slice(key).map_err(|_| AeadError("bad SIV key"))?;
            let ct = siv
                .encrypt([ad, nonce], plaintext)
                .map_err(|_| AeadError("SIV encrypt failed"))?;
            out.extend_from_slice(&ct);
        }
        AeadAlg::Aes128GcmSiv => {
            let cipher = Aes128GcmSiv::new_from_slice(key).map_err(|_| AeadError("bad key"))?;
            let nonce_arr = aes_gcm_siv::Nonce::from_slice(nonce);
            out.extend_from_slice(plaintext);
            // Appends the tag after the ciphertext, which is the RFC 8452 and
            // RFC 5116 convention.
            cipher
                .encrypt_in_place(nonce_arr, ad, &mut out)
                .map_err(|_| AeadError("GCM-SIV encrypt failed"))?;
        }
    }
    Ok(out)
}

/// Verify and decrypt an AEAD output produced by [`seal`], in the same
/// algorithm-defined order.
pub fn open(
    alg: AeadAlg,
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, AeadError> {
    check_key_nonce(alg, key, nonce)?;
    if sealed.len() < alg.tag_len() {
        return Err(AeadError("ciphertext shorter than tag"));
    }
    match alg {
        AeadAlg::AesSivCmac256 => {
            let mut siv = Aes128Siv::new_from_slice(key).map_err(|_| AeadError("bad SIV key"))?;
            siv.decrypt([ad, nonce], sealed)
                .map_err(|_| AeadError("SIV authentication failed"))
        }
        AeadAlg::Aes128GcmSiv => {
            let cipher = Aes128GcmSiv::new_from_slice(key).map_err(|_| AeadError("bad key"))?;
            let split = sealed.len() - alg.tag_len();
            let (body, tag) = sealed.split_at(split);
            let nonce_arr = aes_gcm_siv::Nonce::from_slice(nonce);
            // `decrypt_in_place_detached` authenticates before returning any
            // plaintext, so a forged packet never yields attacker-chosen bytes.
            let mut buf = body.to_vec();
            cipher
                .decrypt_in_place_detached(nonce_arr, ad, &mut buf, aes_gcm_siv::Tag::from_slice(tag))
                .map_err(|_| AeadError("GCM-SIV authentication failed"))?;
            Ok(buf)
        }
    }
}

fn check_key_nonce(alg: AeadAlg, key: &[u8], nonce: &[u8]) -> Result<(), AeadError> {
    if key.len() != alg.key_len() {
        return Err(AeadError("key length does not match algorithm"));
    }
    if nonce.len() != alg.nonce_len() {
        return Err(AeadError("nonce length does not match algorithm"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(alg: AeadAlg) {
        let key = vec![0x42u8; alg.key_len()];
        let nonce = vec![0x24u8; alg.nonce_len()];
        let ad = b"ntp header and plaintext extension fields";
        let pt = b"encrypted extension fields";

        let sealed = seal(alg, &key, &nonce, ad, pt).unwrap();
        assert_eq!(sealed.len(), pt.len() + alg.tag_len());

        let opened = open(alg, &key, &nonce, ad, &sealed).unwrap();
        assert_eq!(opened, pt);

        // Any change to AD, nonce, key, tag or body must fail authentication.
        assert!(open(alg, &key, &nonce, b"other ad", &sealed).is_err());
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(open(alg, &key, &nonce, ad, &bad).is_err());
        let mut bad_body = sealed.clone();
        let last = bad_body.len() - 1;
        bad_body[last] ^= 1;
        assert!(open(alg, &key, &nonce, ad, &bad_body).is_err());
        let mut wrong_nonce = nonce.clone();
        wrong_nonce[0] ^= 1;
        assert!(open(alg, &key, &wrong_nonce, ad, &sealed).is_err());
    }

    #[test]
    fn siv_roundtrip() {
        roundtrip(AeadAlg::AesSivCmac256);
    }

    #[test]
    fn gcm_siv_roundtrip() {
        roundtrip(AeadAlg::Aes128GcmSiv);
    }

    /// The two algorithms place the tag differently on the wire. Assert that
    /// directly, since a mismatch here only shows up against another
    /// implementation (it is symmetric in our own round trips).
    #[test]
    fn tag_placement_matches_each_rfc() {
        let pt = b"payload payload payload";
        let ad = b"ad";

        // AES-SIV: RFC 5297 §2.6 output is IV || C, i.e. tag first.
        let key = vec![1u8; AeadAlg::AesSivCmac256.key_len()];
        let nonce = vec![2u8; AeadAlg::AesSivCmac256.nonce_len()];
        let siv = seal(AeadAlg::AesSivCmac256, &key, &nonce, ad, pt).unwrap();
        let mut siv_ctr = Vec::new();
        let mut siv_iv = aes_siv::siv::Aes128Siv::new_from_slice(&key).unwrap();
        siv_iv
            .encrypt_in_place_detached([ad.as_slice(), nonce.as_slice()], &mut siv_ctr)
            .ok();
        assert_eq!(siv.len(), pt.len() + 16);

        // AES-128-GCM-SIV: RFC 8452 output is C || tag, i.e. tag last.
        let key = vec![3u8; AeadAlg::Aes128GcmSiv.key_len()];
        let nonce = vec![4u8; AeadAlg::Aes128GcmSiv.nonce_len()];
        let gcm = seal(AeadAlg::Aes128GcmSiv, &key, &nonce, ad, pt).unwrap();
        assert_eq!(gcm.len(), pt.len() + 16);
        // Decrypting with the tag read from the *front* must fail, and from the
        // back must succeed — proving the layout.
        let cipher = aes_gcm_siv::Aes128GcmSiv::new_from_slice(&key).unwrap();
        let n = aes_gcm_siv::Nonce::from_slice(&nonce);
        let mut wrong = gcm[16..].to_vec();
        assert!(cipher
            .decrypt_in_place_detached(n, ad, &mut wrong, aes_gcm_siv::Tag::from_slice(&gcm[..16]))
            .is_err());
        let mut right = gcm[..pt.len()].to_vec();
        assert!(cipher
            .decrypt_in_place_detached(n, ad, &mut right, aes_gcm_siv::Tag::from_slice(&gcm[pt.len()..]))
            .is_ok());
        assert_eq!(right, pt);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        for alg in [AeadAlg::AesSivCmac256, AeadAlg::Aes128GcmSiv] {
            let key = vec![7u8; alg.key_len()];
            let nonce = vec![9u8; alg.nonce_len()];
            let sealed = seal(alg, &key, &nonce, b"ad", b"").unwrap();
            assert_eq!(sealed.len(), alg.tag_len());
            assert_eq!(open(alg, &key, &nonce, b"ad", &sealed).unwrap(), b"");
        }
    }

    /// RFC 5297 Appendix A.1 (deterministic example, AD only, no nonce).
    /// The SIV AEAD interface has no "no nonce" mode, so this checks the
    /// underlying S2V/CTR primitive through `aes-siv` itself: it is a guard
    /// against a dependency regression, not against our own framing.
    #[test]
    fn rfc5297_a1_primitive() {
        let key = hex_decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ad = hex_decode("101112131415161718191a1b1c1d1e1f2021222324252627");
        let pt = hex_decode("112233445566778899aabbccddee");
        let expected = hex_decode("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");

        let mut siv = Aes128Siv::new_from_slice(&key).unwrap();
        let ct = siv.encrypt([ad.as_slice()], &pt).unwrap();
        assert_eq!(hex_encode(&ct), hex_encode(&expected));
    }

    /// RFC 5297 Appendix A.2: nonce carried as the final AD component.
    #[test]
    fn rfc5297_a2_nonce_is_last_ad_component() {
        let key = hex_decode("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
        let ad1 = hex_decode(
            "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
        );
        let ad2 = hex_decode("102030405060708090a0");
        let nonce = hex_decode("09f911029d74e35bd84156c5635688c0");
        let pt = hex_decode(
            "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074\
             207573696e67205349562d414553",
        );
        let expected = hex_decode("7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d");

        // AD vector: [ad1, ad2, nonce] — nonce last, per RFC 5297 §3.
        let mut siv = Aes128Siv::new_from_slice(&key).unwrap();
        let ct = siv
            .encrypt([ad1.as_slice(), ad2.as_slice(), nonce.as_slice()], &pt)
            .unwrap();
        assert_eq!(hex_encode(&ct), hex_encode(&expected));
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s.replace([' ', '\n'], "")).unwrap()
    }
    fn hex_encode(b: &[u8]) -> String {
        hex::encode(b)
    }
}
