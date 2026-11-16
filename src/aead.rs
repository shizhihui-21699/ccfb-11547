//! AEAD algorithms for NTS (RFC 8915 §5.1).
//!
//! Two algorithms, both mandatory-to-implement in NTS:
//!   * [`AeadAlg::Aes128Gcm`] — id 16, RFC 5116, nonce 12, tag 16, key 16
//!   * [`AeadAlg::AesSivCmac256`] — id 15, RFC 5297 AES-SIV (AES-128-SIV
//!     per the NTS registry/chrony), variable nonce, 16-octet tag, 32-octet key
//!
//! The 32-byte NTS Unique Identifier is used as nonce material:
//!   * SIV uses all 32 bytes as an authenticated component (AD vector)
//!   * GCM uses its first 12 bytes as the RFC 5116 nonce
//!
//! `seal` output includes the tag appended to the ciphertext in both cases
//! (GCM: RFC 5116 layout; SIV: RFC 5297 layout IV‖CT).

use aes::{Aes128, Aes256};
use cipher::crypto_common::generic_array::typenum::{IsLess, NonZero, U16, U256};
use cipher::crypto_common::generic_array::GenericArray;
use cipher::{
    BlockCipher, BlockEncryptMut, BlockSizeUser, KeyInit, KeyIvInit,
};
use cmac::{Cmac, Mac};
use ctr::cipher::StreamCipher;
use ctr::Ctr128BE;
use dbl::Dbl;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

/// Bounds for the AES primitive behind SIV: 16-byte blocks, usable as a
/// CMAC core (which requires the CoreWrapper KeyInit predicate `IsLess<256>`).
trait SivAes: BlockCipher<BlockSize = U16> + BlockEncryptMut + Clone + KeyInit
where
    GenericArray<u8, U16>: Dbl,
    <Self as BlockSizeUser>::BlockSize: IsLess<U256>,
    <<Self as BlockSizeUser>::BlockSize as IsLess<U256>>::Output: NonZero,
{
}

impl<T> SivAes for T where T: BlockCipher<BlockSize = U16> + BlockEncryptMut + Clone + KeyInit {}

use crate::constants::{AEAD_AES_128_GCM, AEAD_AES_SIV_CMAC_256, SUPPORTED_AEAD_IDS};
use crate::{Error, Result};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlg {
    /// AEAD_AES_128_GCM (RFC 5116), NTS id 16
    Aes128Gcm,
    /// AEAD_AES_SIV_CMAC_256 (RFC 5297), NTS id 15
    AesSivCmac256,
}

impl AeadAlg {
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            AEAD_AES_128_GCM => Ok(Self::Aes128Gcm),
            AEAD_AES_SIV_CMAC_256 => Ok(Self::AesSivCmac256),
            other => Err(Error::UnsupportedAead(other)),
        }
    }

    pub fn id(self) -> u16 {
        match self {
            Self::Aes128Gcm => AEAD_AES_128_GCM,
            Self::AesSivCmac256 => AEAD_AES_SIV_CMAC_256,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            // RFC 8915 id 15, AEAD_AES_SIV_CMAC_256, is instantiated with
            // AES-128-SIV: a 32-octet key split into two 16-octet subkeys
            // (K1 for CMAC, K2 for CTR). This matches chrony/GnuTLS, which
            // map id 15 to GNUTLS_CIPHER_AES_128_SIV (32-byte key).
            Self::AesSivCmac256 => 32,
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 12,
            // SIV nonces are variable length; this is the preferred NTS size.
            Self::AesSivCmac256 => 16,
        }
    }

    pub fn tag_len(self) -> usize {
        16
    }

    /// Pick the first id in our preference list that the peer also offered.
    pub fn negotiate(peer_offers: &[u16]) -> Result<Self> {
        for ours in SUPPORTED_AEAD_IDS {
            if peer_offers.contains(&ours) {
                return Self::from_id(ours);
            }
        }
        Err(Error::aead("no AEAD algorithm in common with peer"))
    }

    pub fn seal(self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(Error::aead(format!(
                "seal: key length {} != {}",
                key.len(),
                self.key_len()
            )));
        }
        match self {
            Self::Aes128Gcm => {
                let nonce = Nonce::try_assume_unique_for_key(&nonce[..12])
                    .map_err(|e| Error::aead(format!("nonce: {e}")))?;
                let unbound = UnboundKey::new(&AES_128_GCM, key)
                    .map_err(|e| Error::aead(format!("GCM key: {e}")))?;
                let gcm = LessSafeKey::new(unbound);
                let mut buf = plaintext.to_vec();
                gcm.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
                    .map_err(|e| Error::aead(format!("GCM seal: {e}")))?;
                Ok(buf)
            }
            Self::AesSivCmac256 => {
                // RFC 5297 SIV accepts a variable-length nonce (the synthetic
                // IV is derived over AD ‖ nonce ‖ plaintext). NTS peers such
                // as chrony use a 16-octet nonce; require at least one byte.
                if nonce.is_empty() {
                    return Err(Error::aead("SIV nonce must not be empty"));
                }
                // AES-128-SIV: two 16-octet subkeys inside the 32-octet key.
                let (k1, k2) = key.split_at(16);
                Ok(siv_seal::<Aes128, Ctr128BE<Aes128>>(
                    k1,
                    k2,
                    &[aad, nonce, plaintext],
                ))
            }
        }
    }

    pub fn open(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(Error::aead(format!(
                "open: key length {} != {}",
                key.len(),
                self.key_len()
            )));
        }
        if ciphertext_and_tag.len() < self.tag_len() {
            return Err(Error::aead("ciphertext shorter than tag"));
        }
        match self {
            Self::Aes128Gcm => {
                let nonce = Nonce::try_assume_unique_for_key(&nonce[..12])
                    .map_err(|e| Error::aead(format!("nonce: {e}")))?;
                let unbound = UnboundKey::new(&AES_128_GCM, key)
                    .map_err(|e| Error::aead(format!("GCM key: {e}")))?;
                let gcm = LessSafeKey::new(unbound);
                let mut buf = ciphertext_and_tag.to_vec();
                let pt = gcm
                    .open_in_place(nonce, Aad::from(aad), &mut buf)
                    .map_err(|e| Error::AuthFailed(format!("GCM open: {e}")))?;
                Ok(pt.to_vec())
            }
            Self::AesSivCmac256 => {
                // RFC 5297 SIV accepts a variable-length nonce (the synthetic
                // IV is derived over AD ‖ nonce ‖ plaintext). NTS peers such
                // as chrony use a 16-octet nonce; require at least one byte.
                if nonce.is_empty() {
                    return Err(Error::aead("SIV nonce must not be empty"));
                }
                let (iv_recv, ct) = ciphertext_and_tag.split_at(16);
                let iv_recv: [u8; 16] = iv_recv.try_into().unwrap();
                let (k1, k2) = key.split_at(16);
                let pt = siv_open::<Aes128, Ctr128BE<Aes128>>(
                    k1,
                    k2,
                    &iv_recv,
                    ct,
                    &[aad, nonce],
                )?;
                Ok(pt)
            }
        }
    }
}

// =======================================================================
// AES-SIV (RFC 5297), generic over the AES primitive so the RFC 5297
// Appendix A vectors (AES-128 SIV) and production NTS (AES-256 SIV) share
// one code path.
// =======================================================================

/// RFC 5297 §2.3 doubling in GF(2^128) with Rb = …87 in the final octet.
/// The block is a big-endian 128-bit string: a left shift by one, with the
/// bit leaving the leftmost position selecting the Rb XOR.
fn dbl(b: [u8; 16]) -> [u8; 16] {
    let x = u128::from_be_bytes(b);
    let top_bit = x >> 127;
    let shifted = x << 1;
    let out = if top_bit == 1 {
        shifted ^ 0x87
    } else {
        shifted
    };
    out.to_be_bytes()
}

/// pad(X) from §2.4: append a 1 bit then zero bits to a 128-bit boundary.
fn pad(x: &[u8]) -> Vec<u8> {
    debug_assert!(x.len() < 16);
    let mut v = x.to_vec();
    v.push(0x80);
    v.resize(16, 0);
    v
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = a[i] ^ b[i];
    }
    r
}

/// S2V (RFC 5297 §2.4 pseudocode). `components` is the full vector
/// [S1..Sn]; the last element receives xorend/pad treatment.
fn s2v<Aes>(cmac_key: &[u8], components: &[&[u8]]) -> [u8; 16]
where
    Aes: SivAes,
{
    let cmac_of = |data: &[u8]| -> [u8; 16] {
        let mut mac = <Cmac<Aes> as Mac>::new_from_slice(cmac_key).expect("CMAC key length");
        mac.update(data);
        let out: GenericArray<u8, U16> = mac.finalize().into_bytes();
        let mut r = [0u8; 16];
        r.copy_from_slice(&out);
        r
    };

    if components.is_empty() {
        // n = 0: V = AES-CMAC(K, <one>)
        let mut one = [0u8; 16];
        one[15] = 1;
        return cmac_of(&one);
    }

    // D = AES-CMAC(K, <zero>)
    let mut d = cmac_of(&[0u8; 16]);

    for sv in &components[..components.len() - 1] {
        d = xor16(&dbl(d), &cmac_of(sv));
    }

    let last = components[components.len() - 1];
    let t = if last.len() >= 16 {
        // T = Sn xorend D
        let mut t = last.to_vec();
        let off = t.len() - 16;
        for j in 0..16 {
            t[off + j] ^= d[j];
        }
        t
    } else {
        // T = dbl(D) xor pad(Sn)
        xor16(&dbl(d), &pad(last).as_slice().try_into().unwrap()).to_vec()
    };
    cmac_of(&t)
}

/// Clear the 63rd and 31st bits of the 128-bit counter (RFC 5297 §2.5;
/// bits numbered from the rightmost, zero-based). Octet 8 holds bits
/// 63..56 (bit 63 is its MSB), octet 12 holds bits 31..24 (bit 31 is
/// its MSB).
fn siv_counter_iv(mut v: [u8; 16]) -> [u8; 16] {
    v[8] &= 0x7f; // bit 63
    v[12] &= 0x7f; // bit 31
    v
}
/// SIV-encrypt (§2.6): V = S2V(K1, AD…, P); output V ‖ AES-CTR(K2, V*, P).
fn siv_seal<Aes, Ctr>(cmac_key: &[u8], enc_key: &[u8], s2v_components: &[&[u8]]) -> Vec<u8>
where
    Aes: SivAes,
    Ctr: StreamCipher + KeyIvInit,
{
    let v = s2v::<Aes>(cmac_key, s2v_components);
    let ctr_iv = siv_counter_iv(v);
    let mut ctr = Ctr::new_from_slices(enc_key, &ctr_iv).expect("CTR key/iv length");
    let plaintext = s2v_components[s2v_components.len() - 1];
    let mut out = Vec::with_capacity(16 + plaintext.len());
    out.extend_from_slice(&v);
    let mut ct = plaintext.to_vec();
    ctr.apply_keystream(&mut ct);
    out.extend_from_slice(&ct);
    out
}

/// SIV-decrypt (§2.7): CTR to recover P, then verify V = S2V(K1, AD…, P)
/// in constant time.
fn siv_open<Aes, Ctr>(
    cmac_key: &[u8],
    enc_key: &[u8],
    iv_recv: &[u8; 16],
    ct: &[u8],
    ad_components: &[&[u8]],
) -> Result<Vec<u8>>
where
    Aes: SivAes,
    Ctr: StreamCipher + KeyIvInit,
{
    let ctr_iv = siv_counter_iv(*iv_recv);
    let mut ctr = Ctr::new_from_slices(enc_key, &ctr_iv).expect("CTR key/iv length");
    let mut pt = ct.to_vec();
    ctr.apply_keystream(&mut pt);

    let mut comps: Vec<&[u8]> = ad_components.to_vec();
    comps.push(&pt);
    let v_calc = s2v::<Aes>(cmac_key, &comps);

    if v_calc.ct_eq(iv_recv).into() {
        Ok(pt)
    } else {
        Err(Error::AuthFailed("SIV IV/tag mismatch".into()))
    }
}

/// AES-256-SIV seal used for the cookie envelope: a 64-octet master key
/// (32-octet CMAC subkey K1 + 32-octet CTR subkey K2) and a 32-octet nonce.
/// This is distinct from the NTS AEAD id-15 working-key construction, which
/// uses AES-128-SIV with a 32-octet key.
pub fn aes256_siv_seal(master64: &[u8], nonce32: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if master64.len() != 64 {
        return Err(Error::aead("cookie master key must be 64 octets"));
    }
    if nonce32.len() != 32 {
        return Err(Error::aead("cookie SIV nonce must be 32 octets"));
    }
    let (k1, k2) = master64.split_at(32);
    Ok(siv_seal::<Aes256, Ctr128BE<Aes256>>(
        k1,
        k2,
        &[aad, nonce32, plaintext],
    ))
}

/// Inverse of [`aes256_siv_seal`].
pub fn aes256_siv_open(
    master64: &[u8],
    nonce32: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>> {
    if master64.len() != 64 {
        return Err(Error::aead("cookie master key must be 64 octets"));
    }
    if nonce32.len() != 32 {
        return Err(Error::aead("cookie SIV nonce must be 32 octets"));
    }
    if sealed.len() < 16 {
        return Err(Error::aead("sealed cookie region truncated"));
    }
    let (iv, ct) = sealed.split_at(16);
    let (k1, k2) = master64.split_at(32);
    siv_open::<Aes256, Ctr128BE<Aes256>>(
        k1,
        k2,
        iv.try_into().unwrap(),
        ct,
        &[aad, nonce32],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes128;
    use ctr::Ctr128BE;

    type Aes128Ctr = Ctr128BE<Aes128>;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex16(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }

    // ---------------- RFC 5297 Appendix A.1 (deterministic) ----------------
    #[test]
    fn rfc5297_a1_deterministic() {
        // AES-128-SIV: 32-byte key (16 CMAC + 16 CTR), one AD, no nonce.
        let k1 = hex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0");
        let k2 = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ad = hex("101112131415161718191a1b1c1d1e1f2021222324252627");
        let pt = hex("112233445566778899aabbccddee");
        let expect_iv = hex16("85632d07c6e8f37f950acd320a2ecc93");
        let expect_ct = hex("40c02b9690c4dc04daef7f6afe5c");

        // dbl() intermediate from the RFC's A.1 trace
        assert_eq!(
            dbl(hex16("0e04dfafc1efbf040140582859bf073a")),
            hex16("1c09bf5f83df7e080280b050b37e0e74")
        );

        let iv = s2v::<Aes128>(&k1, &[&ad, &pt]);
        assert_eq!(iv, expect_iv);

        let sealed = siv_seal::<Aes128, Aes128Ctr>(&k1, &k2, &[&ad, &pt]);
        let mut expect = Vec::new();
        expect.extend_from_slice(&expect_iv);
        expect.extend_from_slice(&expect_ct);
        assert_eq!(sealed, expect);

        let opened = siv_open::<Aes128, Aes128Ctr>(&k1, &k2, &expect_iv, &expect_ct, &[&ad])
            .unwrap();
        assert_eq!(opened, pt);
    }

    // ---------------- RFC 5297 Appendix A.2 (nonce-based) ----------------
    #[test]
    fn rfc5297_a2_nonce_based() {
        let k1 = hex("7f7e7d7c7b7a79787776757473727170");
        let k2 = hex("404142434445464748494a4b4c4d4e4f");
        let ad1 = hex(
            "00112233445566778899aabbccddeeff\
             deaddadadeaddadaffeeddccbbaa9988\
             7766554433221100",
        );
        let ad2 = hex("102030405060708090a0");
        let nonce = hex("09f911029d74e35bd84156c5635688c0");
        let pt = hex(
            "7468697320697320736f6d6520706c61\
             696e7465787420746f20656e63727970\
             74207573696e67205349562d414553",
        );
        let expect_iv = hex16("7bdb6e3b432667eb06f4d14bff2fbd0f");
        let expect_ct = hex(
            "cb900f2fddbe404326601965c889bf17\
             dba77ceb094fa663b7a3f748ba8af829\
             ea64ad544a272e9c485b62a3fd5c0d",
        );

        // RFC 5297 §2.5: the CTR counter clears IV bits 63 and 31. This
        // vector's IV has bit 31 set (octet 12 = 0xff); the full seal/open
        // checks below validate the resulting CTR keystream against the
        // RFC's published ciphertext.
        let ctr_iv = siv_counter_iv(expect_iv);
        assert_eq!(ctr_iv[12], 0x7f);
        assert_eq!(ctr_iv[8], expect_iv[8]); // bit 63 already zero here

        let sealed = siv_seal::<Aes128, Aes128Ctr>(&k1, &k2, &[&ad1, &ad2, &nonce, &pt]);
        let mut expect = Vec::new();
        expect.extend_from_slice(&expect_iv);
        expect.extend_from_slice(&expect_ct);
        assert_eq!(sealed, expect);

        let opened = siv_open::<Aes128, Aes128Ctr>(
            &k1,
            &k2,
            &expect_iv,
            &expect_ct,
            &[&ad1, &ad2, &nonce],
        )
        .unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn dbl_vectors() {
        // In GF(2^128), doubling the zero element stays zero.
        assert_eq!(dbl([0u8; 16]), [0u8; 16]);
        // dbl of the all-ones block: left shift gives ff..fe, then Rb
        // (top bit was 1) flips bit 7 of the last octet: fe -> 79.
        let d = dbl([0xffu8; 16]);
        assert_eq!(d[0], 0xff);
        assert_eq!(d[15], 0xfe ^ 0x87);
        // RFC 5297 A.1 trace
        assert_eq!(
            dbl(hex16("0e04dfafc1efbf040140582859bf073a")),
            hex16("1c09bf5f83df7e080280b050b37e0e74")
        );
        // a 1 in the lowest bit shifts one place to the left
        assert_eq!(dbl(hex16("00000000000000000000000000000001"))[15], 0x02);
    }

    #[test]
    fn siv128_roundtrip_and_tamper() {
        // AES-128-SIV as used by NTS AEAD id 15: 32-octet key, 16-octet nonce.
        let key = vec![7u8; 32];
        let nonce = [9u8; 16];
        let aad = b"NTP header 48 bytes exactly!!";
        for len in [0usize, 1, 15, 16, 17, 100, 1400] {
            let pt = (0..len).map(|i| i as u8).collect::<Vec<_>>();
            let sealed = AeadAlg::AesSivCmac256
                .seal(&key, &nonce, aad, &pt)
                .unwrap();
            assert_eq!(sealed.len(), pt.len() + 16);
            let opened = AeadAlg::AesSivCmac256
                .open(&key, &nonce, aad, &sealed)
                .unwrap();
            assert_eq!(opened, pt);
        }
        let sealed = AeadAlg::AesSivCmac256
            .seal(&key, &nonce, aad, b"hello world")
            .unwrap();
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x01;
            assert!(
                AeadAlg::AesSivCmac256
                    .open(&key, &nonce, aad, &bad)
                    .is_err(),
                "bit flip at {i} must be detected"
            );
        }
        assert!(AeadAlg::AesSivCmac256
            .open(&key, &nonce, b"wrong header!!", &sealed)
            .is_err());
        let mut n2 = nonce;
        n2[0] ^= 1;
        assert!(AeadAlg::AesSivCmac256
            .open(&key, &n2, aad, &sealed)
            .is_err());
    }

    #[test]
    fn gcm_roundtrip_and_tamper() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let nonce = [3u8; 32]; // only first 12 used
        let aad = b"NTP header 48 bytes exactly!!";
        let pt = b"extension field plaintext";
        let sealed = AeadAlg::Aes128Gcm.seal(&key, &nonce, aad, pt).unwrap();
        assert_eq!(sealed.len(), pt.len() + 16);
        let opened = AeadAlg::Aes128Gcm
            .open(&key, &nonce, aad, &sealed)
            .unwrap();
        assert_eq!(opened, pt);
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(AeadAlg::Aes128Gcm
            .open(&key, &nonce, aad, &bad)
            .is_err());
        assert!(AeadAlg::Aes128Gcm
            .open(&key, &nonce, b"other aad", &sealed)
            .is_err());
    }

    #[test]
    fn negotiate_prefers_gcm() {
        assert_eq!(
            AeadAlg::negotiate(&[AEAD_AES_SIV_CMAC_256, AEAD_AES_128_GCM]).unwrap(),
            AeadAlg::Aes128Gcm
        );
        assert_eq!(
            AeadAlg::negotiate(&[AEAD_AES_SIV_CMAC_256]).unwrap(),
            AeadAlg::AesSivCmac256
        );
        assert!(AeadAlg::negotiate(&[9999]).is_err());
    }
}
