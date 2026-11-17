//! NTS cookie construction and server-side master-key rotation
//! (RFC 8915 §6).
//!
//! A cookie is the server's entire per-client state, encrypted under a
//! long-lived master key and handed back to the client. Its plaintext is the
//! negotiated AEAD algorithm plus the C2S and S2C keys, so the server must keep
//! the master key across the whole cookie lifetime.
//!
//! # Layout
//!
//! ```text
//! cookie = key_id (4, BE) || nonce (12) || AES-SIV(plaintext)
//! plaintext = aead_id (2, BE) || c2s_key || s2c_key
//! ```
//!
//! The cookie master key is always AES-SIV-CMAC-256 regardless of the AEAD
//! negotiated for NTP packets: SIV is misuse-resistant, so a repeated nonce
//! degrades confidentiality but never authenticity, which is the property we
//! need for a value this long-lived. (RFC 8915 §6 recommends exactly this.)
//!
//! # Rotation
//!
//! Rotating means generating a new `(key_id, key)` and immediately using it for
//! new cookies while still accepting cookies made under the previous
//! generation. `KeyRing` keeps a bounded history and erases keys once they fall
//! out, which bounds how long a stolen master key stays useful.

use aes_siv::aead::KeyInit;
use aes_siv::siv::Aes128Siv;
use rand::RngCore;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

use crate::aead::AeadAlg;
use crate::error::{Error, Result};

/// Master key length for AES-SIV-CMAC-256.
pub const MASTER_KEY_LEN: usize = 32;

const KEY_ID_LEN: usize = 4;
const COOKIE_NONCE_LEN: usize = 12;

/// Largest cookie we will mint. chrony's client accepts bodies up to 256 octets
/// and its `MAX_TOTAL_COOKIE_LENGTH` budgeting assumes roughly 108-octet
/// cookies, so staying small keeps us compatible and keeps one request plus
/// seven placeholders inside a 1280-octet datagram (RFC 8915 §5.7).
pub const MAX_COOKIE_LEN: usize = 112;

/// A server cookie: opaque to clients.
pub type Cookie = Vec<u8>;

/// Key material recovered from a cookie: algorithm, C2S key, S2C key.
pub type RecoveredKeys = (AeadAlg, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// One generation of master key.
struct MasterKey {
    id: u32,
    key: Zeroizing<[u8; MASTER_KEY_LEN]>,
    /// Unix seconds at which this key was created; used to enforce a maximum
    /// cookie age independent of how many generations we retain.
    created_at: u64,
}

/// A bounded, rotating set of cookie master keys.
///
/// Thread-safe: the NTS-KE server mints cookies with `current()` while NTP
/// packet handling may concurrently `open()` cookies from older generations.
#[derive(Clone)]
pub struct KeyRing {
    inner: Arc<RwLock<RingInner>>,
}

struct RingInner {
    keys: VecDeque<MasterKey>,
    /// How many old generations remain valid (in addition to the current one).
    retain: usize,
    /// Hard ceiling on cookie age in seconds, regardless of generation count.
    max_age_secs: u64,
}

impl KeyRing {
    /// Create a ring with one freshly generated key.
    ///
    /// `retain` is the number of *previous* generations still accepted after a
    /// rotation. With `retain = 2` and daily rotation, a cookie minted just
    /// before a rotation stays valid for a bit over two more days.
    pub fn new(retain: usize, max_age_secs: u64) -> Self {
        let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        rand::thread_rng().fill_bytes(key.as_mut());
        let inner = RingInner {
            keys: VecDeque::from(vec![MasterKey {
                id: random_key_id(),
                key,
                created_at: now_secs(),
            }]),
            retain,
            max_age_secs,
        };
        Self {
            inner: Arc::new(RwLock::new(inner)),
        }
    }

    /// Build a ring from a known key — for tests and for clusters that share a
    /// key out of band.
    pub fn from_key(key: [u8; MASTER_KEY_LEN], key_id: u32, retain: usize, max_age_secs: u64) -> Self {
        let inner = RingInner {
            keys: VecDeque::from(vec![MasterKey {
                id: key_id,
                key: Zeroizing::new(key),
                created_at: now_secs(),
            }]),
            retain,
            max_age_secs,
        };
        Self {
            inner: Arc::new(RwLock::new(inner)),
        }
    }

    /// Rotate: generate a new master key and make it current, keeping at most
    /// `retain` previous generations. Old keys are zeroized as they drop.
    ///
    /// Returns the new key id.
    pub fn rotate(&self) -> u32 {
        let mut inner = self.inner.write().unwrap();
        let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        rand::thread_rng().fill_bytes(key.as_mut());
        // Avoid colliding with a live id, since ids are matched modulo the ring
        // size by some implementations and collisions would be ambiguous.
        let mut id = random_key_id();
        while inner.keys.iter().any(|k| k.id == id) {
            id = random_key_id();
        }
        inner.keys.push_front(MasterKey {
            id,
            key,
            created_at: now_secs(),
        });
        let keep = inner.retain + 1;
        inner.keys.truncate(keep);
        id
    }

    /// Number of generations currently retained (including current).
    pub fn generations(&self) -> usize {
        self.inner.read().unwrap().keys.len()
    }

    pub fn current_id(&self) -> u32 {
        self.inner.read().unwrap().keys[0].id
    }

    /// Encrypt a cookie under the current master key.
    ///
    /// The plaintext is `alg_id (2) || c2s || s2c` followed by zero padding to
    /// bring the *whole cookie* to a multiple of four octets. That alignment is
    /// not cosmetic: a cookie travels in an NTP extension field, whose length
    /// must be word-aligned (RFC 7822), and chrony rejects non-aligned ones.
    pub fn seal(&self, alg: AeadAlg, c2s: &[u8], s2c: &[u8]) -> Result<Cookie> {
        let inner = self.inner.read().unwrap();
        let master = &inner.keys[0];

        let mut plaintext = Vec::with_capacity(4 + c2s.len() + s2c.len());
        plaintext.extend_from_slice(&alg.id().to_be_bytes());
        plaintext.extend_from_slice(c2s);
        plaintext.extend_from_slice(s2c);

        let mut nonce = [0u8; COOKIE_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Pad so that key_id + nonce + tag + plaintext is 4-octet aligned.
        let unpadded = KEY_ID_LEN + COOKIE_NONCE_LEN + alg.tag_len() + plaintext.len();
        let pad = (4 - unpadded % 4) % 4;
        plaintext.resize(plaintext.len() + pad, 0);

        let mut siv =
            Aes128Siv::new_from_slice(master.key.as_ref()).map_err(|_| Error::Cookie("bad master key".into()))?;
        // The nonce travels in the clear in front of the ciphertext and is fed
        // to S2V as the trailing associated-data component. `open` must use the
        // same vector — see the note there.
        let ct = siv
            .encrypt([nonce.as_slice()], plaintext.as_slice())
            .map_err(|_| Error::Cookie("cookie encryption failed".into()))?;

        let mut cookie = Vec::with_capacity(KEY_ID_LEN + COOKIE_NONCE_LEN + ct.len());
        cookie.extend_from_slice(&master.id.to_be_bytes());
        cookie.extend_from_slice(&nonce);
        cookie.extend_from_slice(&ct);
        debug_assert_eq!(cookie.len() % 4, 0, "cookie must be word-aligned");
        if cookie.len() > MAX_COOKIE_LEN {
            return Err(Error::Cookie(format!(
                "cookie would be {} octets, over the {MAX_COOKIE_LEN} limit",
                cookie.len()
            )));
        }
        Ok(cookie)
    }

    /// Decrypt a cookie presented by a client.
    ///
    /// Returns the negotiated algorithm and the two directional keys. A cookie
    /// from a rotated-out or expired generation fails here, which the server
    /// turns into an NTS NAK.
    pub fn open(&self, cookie: &[u8]) -> Result<RecoveredKeys> {
        if cookie.len() < KEY_ID_LEN + COOKIE_NONCE_LEN + 16 {
            return Err(Error::Cookie("cookie too short".into()));
        }
        let key_id = u32::from_be_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]);
        // The nonce travels in the clear and must be bound into the SIV
        // associated-data vector exactly as `seal` did. (RFC 8915 §6 phrases it
        // as "encrypt under K with nonce N and no associated data"; for
        // AES-SIV the AEAD convention in RFC 5297 §3 is that N is the *final*
        // AD component, so the vector is `[N]`, not empty.)
        let nonce = &cookie[KEY_ID_LEN..KEY_ID_LEN + COOKIE_NONCE_LEN];
        let ct = &cookie[KEY_ID_LEN + COOKIE_NONCE_LEN..];

        let inner = self.inner.read().unwrap();
        let now = now_secs();
        let max_age = inner.max_age_secs;

        // Find a matching generation. We must not return early on the first id
        // mismatch: the cookie may belong to any retained generation.
        let master = inner
            .keys
            .iter()
            .find(|k| k.id == key_id)
            .ok_or_else(|| Error::Cookie("unknown master key id".into()))?;

        if now.saturating_sub(master.created_at) > max_age {
            return Err(Error::Cookie("cookie older than maximum age".into()));
        }

        let mut siv = Aes128Siv::new_from_slice(master.key.as_ref())
            .map_err(|_| Error::Cookie("bad master key".into()))?;
        let plaintext = siv
            .decrypt([nonce], ct)
            .map_err(|_| Error::Cookie("cookie authentication failed".into()))?;

        if plaintext.len() < 2 {
            return Err(Error::Cookie("cookie plaintext truncated".into()));
        }
        let alg_id = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        let alg = AeadAlg::from_id(alg_id).ok_or(Error::UnknownAead(alg_id))?;
        // `seal` pads the plaintext so the cookie is word-aligned. Keys always
        // have the algorithm's fixed length, so read exactly that much and
        // discard the trailing pad rather than deriving a length from it.
        let keys_len = 2 * alg.key_len();
        if plaintext.len() < 2 + keys_len {
            return Err(Error::Cookie("cookie plaintext too short for its algorithm".into()));
        }
        if (plaintext.len() - 2 - keys_len) > 3 {
            return Err(Error::Cookie("cookie padding longer than 3 octets".into()));
        }
        let c2s = Zeroizing::new(plaintext[2..2 + alg.key_len()].to_vec());
        let s2c = Zeroizing::new(plaintext[2 + alg.key_len()..2 + keys_len].to_vec());
        Ok((alg, c2s, s2c))
    }
}

fn random_key_id() -> u32 {
    let mut b = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut b);
    u32::from_be_bytes(b)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> KeyRing {
        KeyRing::new(2, 86_400 * 3)
    }

    #[test]
    fn cookie_roundtrip_both_algorithms() {
        for alg in [AeadAlg::AesSivCmac256, AeadAlg::Aes128GcmSiv] {
            let ring = ring();
            let c2s = vec![0x11u8; alg.key_len()];
            let s2c = vec![0x22u8; alg.key_len()];
            let cookie = ring.seal(alg, &c2s, &s2c).unwrap();
            assert!(cookie.len() <= MAX_COOKIE_LEN);
            assert_eq!(cookie.len() % 4, 0, "cookie must be word-aligned for an NTP EF");
            let (got_alg, got_c2s, got_s2c) = ring.open(&cookie).unwrap();
            assert_eq!(got_alg, alg);
            assert_eq!(got_c2s.to_vec(), c2s);
            assert_eq!(got_s2c.to_vec(), s2c);
        }
    }

    #[test]
    fn cookies_are_unique_even_for_identical_key_material() {
        // Distinct nonces must make cookies unlinkable.
        let ring = ring();
        let c2s = vec![0x11u8; 32];
        let s2c = vec![0x22u8; 32];
        let a = ring.seal(AeadAlg::AesSivCmac256, &c2s, &s2c).unwrap();
        let b = ring.seal(AeadAlg::AesSivCmac256, &c2s, &s2c).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn old_cookie_survives_one_rotation_then_dies() {
        let ring = KeyRing::new(2, 86_400 * 30);
        let c2s = vec![1u8; 32];
        let s2c = vec![2u8; 32];
        let cookie = ring.seal(AeadAlg::AesSivCmac256, &c2s, &s2c).unwrap();
        let first_id = ring.current_id();

        let second_id = ring.rotate();
        assert_ne!(first_id, second_id);
        // Still accepted during the transition window.
        assert!(ring.open(&cookie).is_ok());

        let third_id = ring.rotate();
        assert_ne!(second_id, third_id);
        // Retain=2 means current + 2 previous, so the first key is still live.
        assert!(ring.open(&cookie).is_ok());

        ring.rotate();
        // Now four generations have existed; the first has been erased.
        assert!(ring.open(&cookie).is_err());
        assert_eq!(ring.generations(), 3);
    }

    #[test]
    fn tampered_cookie_is_rejected() {
        let ring = ring();
        let cookie = ring.seal(AeadAlg::AesSivCmac256, &[1u8; 32], &[2u8; 32]).unwrap();
        for i in 0..cookie.len() {
            let mut bad = cookie.clone();
            bad[i] ^= 0x80;
            assert!(ring.open(&bad).is_err(), "flip at byte {i} was accepted");
        }
    }

    #[test]
    fn cookie_from_foreign_server_is_rejected() {
        let a = KeyRing::new(2, 1000);
        let b = KeyRing::new(2, 1000);
        let cookie = a.seal(AeadAlg::AesSivCmac256, &[1u8; 32], &[2u8; 32]).unwrap();
        assert!(b.open(&cookie).is_err());
    }

    #[test]
    fn cluster_shared_key_accepted() {
        let key = [7u8; MASTER_KEY_LEN];
        let a = KeyRing::from_key(key, 42, 1, 1000);
        let b = KeyRing::from_key(key, 42, 1, 1000);
        let cookie = a.seal(AeadAlg::Aes128GcmSiv, &[1u8; 16], &[2u8; 16]).unwrap();
        assert!(b.open(&cookie).is_ok());
    }

    #[test]
    fn expired_cookie_is_rejected() {
        // A ring that retains nothing and refuses anything older than now.
        let ring = KeyRing::new(0, 0);
        let cookie = ring.seal(AeadAlg::AesSivCmac256, &[1u8; 32], &[2u8; 32]).unwrap();
        // Age is measured in whole seconds, so wait until at least one second
        // has elapsed since minting rather than assuming sub-second precision.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(matches!(
            ring.open(&cookie),
            Err(Error::Cookie(_))
        ));
    }
}
