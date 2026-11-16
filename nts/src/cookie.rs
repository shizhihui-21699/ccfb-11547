//! NTS cookies: encrypted, self-contained session state (RFC 8915 section 6).
//!
//! A cookie carries the negotiated AEAD algorithm and both NTP keys, sealed
//! under a long-lived server master key.  That is what lets the NTP server be
//! stateless: everything it needs to authenticate a packet arrives with the
//! packet.
//!
//! Cookie layout (`I || N || C`, as suggested in RFC 8915 section 6):
//!
//! ```text
//!  0        2        4                           ...
//! +--------+--------+---------------------------+------------------+
//! | key id | nonce  |  AEAD(key, N, plaintext)  |                  |
//! +--------+--------+---------------------------+------------------+
//!                    plaintext: aead_id(2) || c2s_key || s2c_key
//! ```
//!
//! The key id is 16 bits, so a key ring can hold many generations without
//! ambiguity.  Rotation keeps old keys decrypt-only: new cookies always use the
//! current key, while cookies minted before a rotation keep working until their
//! key is retired.  Because both the id and the key derive from the key's
//! predecessor by HKDF (a ratchet), no central key distribution is needed for
//! multiple server instances to stay in step as long as they share a seed.
//!
//! AES-SIV is used for cookie encryption regardless of the algorithm negotiated
//! for NTP, because SIV tolerates an accidental nonce reuse (RFC 8915 section 6
//! recommends exactly this).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::aead::Aead;

/// Cookie encryption AEAD: AEAD_AES_SIV_CMAC_256, keyed with its own key.
const COOKIE_KEY_LEN: usize = 32;
const COOKIE_NONCE_LEN: usize = 16;
const COOKIE_TAG_LEN: usize = 16;

/// Longest cookie we will mint or accept.  RFC 8915's suggested construction
/// lands well under this; the limit keeps a client from making us buffer
/// arbitrarily much.
pub const MAX_COOKIE_LEN: usize = 256;

/// 2 (key id) + 16 (nonce) + plaintext + 16 (tag), where the plaintext is
/// 2 + 2 * key length, so 32 octets for AES-SIV and 48 for AES-GCM-SIV.
pub fn cookie_len(aead: Aead) -> usize {
    2 + COOKIE_NONCE_LEN + 2 + 2 * aead.key_len() + COOKIE_TAG_LEN
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CookieError {
    #[error("cookie too short")]
    TooShort,
    #[error("cookie too long")]
    TooLong,
    #[error("unknown or retired cookie key id {0}")]
    UnknownKeyId(u16),
    #[error("cookie did not authenticate under key id {0}")]
    BadCookie(u16),
    #[error("cookie names unsupported AEAD algorithm {0}")]
    BadAlgorithm(u16),
    #[error("cookie plaintext has the wrong length")]
    BadPlaintext,
}

/// The session state carried inside a cookie.
#[derive(Clone)]
pub struct CookieContents {
    pub aead: Aead,
    pub c2s_key: Vec<u8>,
    pub s2c_key: Vec<u8>,
}

impl Drop for CookieContents {
    fn drop(&mut self) {
        self.c2s_key.zeroize();
        self.s2c_key.zeroize();
    }
}

// Hand-written so keys never reach a log line, even via `{:?}`.
impl std::fmt::Debug for CookieContents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieContents")
            .field("aead", &self.aead)
            .field("c2s_key", &"<redacted>")
            .field("s2c_key", &"<redacted>")
            .finish()
    }
}

fn cookie_aead(key: &[u8]) -> crate::aead::AeadKey {
    crate::aead::AeadKey::new(Aead::AesSivCmac256, key)
}

/// One generation of the master key.
struct Generation {
    id: u16,
    key: [u8; COOKIE_KEY_LEN],
}

impl Drop for Generation {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// A rotating set of cookie keys.
///
/// `primary` mints new cookies; every retained key can still decrypt.  A
/// cookie's key id selects the key, so rotation never invalidates cookies that
/// are still within their retention window.
pub struct KeyRing {
    primary: Generation,
    /// Decryption-only generations, oldest first.
    retired: Vec<Generation>,
    /// How many retired generations to keep.  Each generation is a full
    /// retention window, so at 24h per rotation, keeping 2 covers a 3-day span.
    max_retired: usize,
}

impl KeyRing {
    /// Create a key ring from a 32-octet seed.  All instances started from the
    /// same seed and rotation count generate identical keys.
    pub fn from_seed(seed: &[u8], max_retired: usize) -> Self {
        let mut key = [0u8; COOKIE_KEY_LEN];
        let hk = Hkdf::<Sha256>::new(None, seed);
        hk.expand(b"nts cookie master key v1", &mut key)
            .expect("fixed-length expand");
        Self {
            primary: Generation { id: 0, key },
            retired: Vec::new(),
            max_retired,
        }
    }

    /// Create a key ring with a fresh random seed.
    pub fn generate(max_retired: usize) -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let ring = Self::from_seed(&seed, max_retired);
        seed.zeroize();
        ring
    }

    pub fn primary_id(&self) -> u16 {
        self.primary.id
    }

    /// Rotate: the current key becomes decrypt-only and a fresh key is derived
    /// from it by HKDF, so the sequence is a one-way ratchet (RFC 8915
    /// section 6).  Deriving the successor rather than drawing independent
    /// randomness means an operator who has to restore a backup cannot silently
    /// reuse a key id with different key material.
    pub fn rotate(&mut self) {
        let hk = Hkdf::<Sha256>::new(Some(&self.primary.id.to_be_bytes()), &self.primary.key);
        let mut next = [0u8; COOKIE_KEY_LEN];
        hk.expand(b"nts cookie key ratchet v1", &mut next)
            .expect("fixed-length expand");
        let id = self.primary.id.wrapping_add(1);
        let old = std::mem::replace(
            &mut self.primary,
            Generation { id, key: next },
        );
        self.retired.push(old);
        while self.retired.len() > self.max_retired {
            self.retired.remove(0);
        }
    }

    fn find(&self, id: u16) -> Option<&Generation> {
        if self.primary.id == id {
            return Some(&self.primary);
        }
        self.retired.iter().find(|g| g.id == id)
    }

    pub fn mint(&self, contents: &CookieContents) -> Vec<u8> {
        let mut nonce = [0u8; COOKIE_NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.mint_with_nonce(contents, &nonce)
    }

    fn mint_with_nonce(&self, contents: &CookieContents, nonce: &[u8; 16]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(2 + contents.c2s_key.len() + contents.s2c_key.len());
        plaintext.extend_from_slice(&contents.aead.id().to_be_bytes());
        plaintext.extend_from_slice(&contents.c2s_key);
        plaintext.extend_from_slice(&contents.s2c_key);

        let sealed = cookie_aead(&self.primary.key)
            .seal(nonce, &[], &plaintext)
            .expect("cookie plaintext is short enough for SIV");
        plaintext.zeroize();

        let mut out = Vec::with_capacity(2 + COOKIE_NONCE_LEN + sealed.len());
        out.extend_from_slice(&self.primary.id.to_be_bytes());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&sealed);
        out
    }

    /// Decrypt a cookie.  Retired keys are tried, so rotation is transparent to
    /// clients until retention expires.
    pub fn open(&self, cookie: &[u8]) -> Result<CookieContents, CookieError> {
        if cookie.len() < 2 + COOKIE_NONCE_LEN + COOKIE_TAG_LEN {
            return Err(CookieError::TooShort);
        }
        if cookie.len() > MAX_COOKIE_LEN {
            return Err(CookieError::TooLong);
        }
        let id = u16::from_be_bytes([cookie[0], cookie[1]]);
        let gen = self.find(id).ok_or(CookieError::UnknownKeyId(id))?;
        let nonce = &cookie[2..2 + COOKIE_NONCE_LEN];
        let sealed = &cookie[2 + COOKIE_NONCE_LEN..];

        let mut plaintext = cookie_aead(&gen.key)
            .open(nonce, &[], sealed)
            .map_err(|_| CookieError::BadCookie(id))?;

        if plaintext.len() < 4 || plaintext.len() % 2 != 0 {
            plaintext.zeroize();
            return Err(CookieError::BadPlaintext);
        }
        let aead_id = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        let aead = Aead::from_id(aead_id).ok_or(CookieError::BadAlgorithm(aead_id))?;
        let rest = &plaintext[2..];
        if rest.len() != 2 * aead.key_len() {
            plaintext.zeroize();
            return Err(CookieError::BadPlaintext);
        }
        let contents = CookieContents {
            aead,
            c2s_key: rest[..aead.key_len()].to_vec(),
            s2c_key: rest[aead.key_len()..].to_vec(),
        };
        plaintext.zeroize();
        Ok(contents)
    }
}

/// Shared, rotating ring as used by a running server.
pub type SharedKeyRing = Arc<RwLock<KeyRing>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingStats {
    pub primary_id: u16,
    pub retired: usize,
}

impl KeyRing {
    pub fn stats(&self) -> RingStats {
        RingStats {
            primary_id: self.primary.id,
            retired: self.retired.len(),
        }
    }

    /// Key ids currently accepted for decryption, for diagnostics.
    pub fn accepted_ids(&self) -> BTreeMap<u16, bool> {
        let mut m = BTreeMap::new();
        m.insert(self.primary.id, true);
        for g in &self.retired {
            m.insert(g.id, false);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents(aead: Aead) -> CookieContents {
        let n = aead.key_len();
        CookieContents {
            aead,
            c2s_key: vec![0x11; n],
            s2c_key: vec![0x22; n],
        }
    }

    /// Cookies travel as extension field bodies, so they must be a multiple of
    /// four octets; `nts_ntp::build_response` refuses anything else rather than
    /// padding, because padding would corrupt the cookie.
    #[test]
    fn cookie_length_is_word_aligned() {
        for aead in [Aead::AesSivCmac256, Aead::Aes128GcmSiv] {
            assert_eq!(cookie_len(aead) % 4, 0, "{aead:?}");
            let ring = KeyRing::generate(1);
            assert_eq!(ring.mint(&contents(aead)).len() % 4, 0, "{aead:?}");
        }
    }

    #[test]
    fn roundtrip_both_algorithms() {
        let ring = KeyRing::generate(2);
        for aead in [Aead::AesSivCmac256, Aead::Aes128GcmSiv] {
            let c = contents(aead);
            let cookie = ring.mint(&c);
            assert_eq!(cookie.len(), cookie_len(aead));
            assert!(cookie.len() <= MAX_COOKIE_LEN);
            let back = ring.open(&cookie).unwrap();
            assert_eq!(back.aead, aead);
            assert_eq!(back.c2s_key, c.c2s_key);
            assert_eq!(back.s2c_key, c.s2c_key);
        }
    }

    #[test]
    fn cookies_open_after_rotation() {
        let mut ring = KeyRing::generate(3);
        let old = ring.mint(&contents(Aead::AesSivCmac256));
        ring.rotate();
        let new = ring.mint(&contents(Aead::AesSivCmac256));
        assert_ne!(old[..2], new[..2], "rotated cookie uses a new key id");
        // The pre-rotation cookie still works during the transition period.
        assert!(ring.open(&old).is_ok());
        assert!(ring.open(&new).is_ok());
    }

    #[test]
    fn expired_generation_is_rejected() {
        let mut ring = KeyRing::generate(1);
        let ancient = ring.mint(&contents(Aead::AesSivCmac256));
        ring.rotate();
        ring.rotate();
        // Only one generation is retained, so key id 0 is gone.
        assert_eq!(
            ring.open(&ancient).unwrap_err(),
            CookieError::UnknownKeyId(0)
        );
    }

    #[test]
    fn ratchet_is_deterministic_and_one_way() {
        let seed = [7u8; 32];
        let mut a = KeyRing::from_seed(&seed, 2);
        let mut b = KeyRing::from_seed(&seed, 2);
        let ca = a.mint(&contents(Aead::AesSivCmac256));
        let cb = b.mint(&contents(Aead::AesSivCmac256));
        // Different random nonces, but the same key id and key: b can open a's
        // cookie, which is what lets independent server processes share state.
        assert_eq!(ca[..2], cb[..2]);
        assert!(b.open(&ca).is_ok());
        a.rotate();
        b.rotate();
        assert_eq!(a.primary_id(), b.primary_id());
        assert!(b.open(&a.mint(&contents(Aead::AesSivCmac256))).is_ok());
    }

    #[test]
    fn tampered_cookie_is_rejected() {
        let ring = KeyRing::generate(2);
        let mut cookie = ring.mint(&contents(Aead::AesSivCmac256));
        let last = cookie.len() - 1;
        cookie[last] ^= 1;
        assert!(matches!(
            ring.open(&cookie),
            Err(CookieError::BadCookie(0))
        ));
    }

    #[test]
    fn bits_flipped_in_key_id_select_wrong_or_no_key() {
        let ring = KeyRing::generate(2);
        let mut cookie = ring.mint(&contents(Aead::AesSivCmac256));
        cookie[1] ^= 1;
        // Key id 1 does not exist yet, so this is reported as unknown, not as
        // an authentication failure: the client has to re-run NTS-KE either way.
        assert_eq!(ring.open(&cookie).unwrap_err(), CookieError::UnknownKeyId(1));
    }

    #[test]
    fn oversized_cookie_is_rejected() {
        let ring = KeyRing::generate(2);
        let cookie = vec![0u8; MAX_COOKIE_LEN + 1];
        assert_eq!(ring.open(&cookie).unwrap_err(), CookieError::TooLong);
    }
}
