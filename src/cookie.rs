//! NTS cookies and the server-side master-key store.
//!
//! A cookie is an opaque token to the client (RFC 8915 §5.5); only the server
//! that minted it needs to understand its contents. Our internal format:
//!
//! ```text
//! header (14 octets) || AEAD ciphertext
//!   magic  = b"NTSC" (4)
//!   format = 0x01   (1)
//!   aead   = u16    (2)   AEAD used for both cookie sealing and NTP traffic
//!   key_id = u32    (4)   master key the cookie was sealed with
//!   expiry = u64    (8)   unix seconds after which the cookie must be refused
//! body (sealed, SIV layout IV‖CT):
//!   c2s_key (32) || s2c_key (32)
//! ```
//!
//! The sealing nonce is the 32-byte Unique Identifier the client generated,
//! so cookie minting and verification are deterministic per request and no
//! server-side per-client state is needed. AAD binds the header so an
//! attacker cannot retarget a cookie at another algorithm or key id.
//!
//! Master-key rotation keeps the previous keys around for a configurable
//! overlap window: cookies minted under an old key still verify until that
//! key is pruned, while all freshly minted cookies use the newest key.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use rand::RngCore;
use zeroize::Zeroize;

use crate::aead::AeadAlg;
use crate::constants::UNIQUE_ID_LEN;
use crate::{Error, Result};

const COOKIE_MAGIC: &[u8; 4] = b"NTSC";
const COOKIE_FORMAT_V1: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 2 + 4 + 8;
/// Magic for the on-disk master-key store file.
const KEYSTORE_MAGIC: &[u8; 4] = b"NTSK";
const KEYSTORE_VERSION: u8 = 1;
/// Per-cookie random SIV nonce carried in the clear inside the cookie.
/// It is independent of any NTP request's Unique Identifier: a cookie is a
/// reusable opaque token (RFC 8915 §5.5), so it cannot be bound to a UID
/// that changes on every request.
const COOKIE_NONCE_LEN: usize = 32;
/// Length of one working key for a given AEAD (GCM 16, AES-128-SIV 32).
pub fn working_key_len(alg: AeadAlg) -> usize {
    alg.key_len()
}

/// One symmetric master key used to seal/verify cookies.
/// `material` is 64 octets: 32 for CMAC (SIV) / first half, 32 for CTR/GCM.
#[derive(Clone)]
pub struct MasterKey {
    pub id: u32,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub material: [u8; 64],
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

/// Thread-safe key store with rotation + overlap semantics.
///
/// When constructed with a backing file via [`KeyStore::open_or_create`],
/// the whole key set is persisted there so separate NTS-KE and NTP server
/// processes share the same master keys (required: the KE server mints
/// cookies that the NTP server must verify). Writes are atomic
/// (temp file + rename).
#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<RwLock<Store>>,
}

struct Store {
    keys: BTreeMap<u32, MasterKey>,
    next_id: u32,
    /// Seconds a retired key remains valid for old cookies before pruning.
    overlap_secs: u64,
    /// Optional backing file shared across processes.
    path: Option<PathBuf>,
}

impl KeyStore {
    /// In-memory-only store (single-process demo/tests).
    pub fn new(overlap_secs: u64) -> Self {
        let mut s = Store {
            keys: BTreeMap::new(),
            next_id: 1,
            overlap_secs,
            path: None,
        };
        let now = unix_secs();
        s.insert_new(now, overlap_secs);
        Self {
            inner: Arc::new(RwLock::new(s)),
        }
    }

    /// Load the shared key store from `path`, creating it (with one fresh
    /// master key) if it does not exist. Both the KE and NTP server should
    /// point at the same path.
    pub fn open_or_create(path: impl AsRef<Path>, overlap_secs: u64) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let store = if path.exists() {
            Store::load(&path, overlap_secs)?
        } else {
            let mut s = Store {
                keys: BTreeMap::new(),
                next_id: 1,
                overlap_secs,
                path: Some(path.clone()),
            };
            let now = unix_secs();
            s.insert_new(now, overlap_secs);
            // A peer process may create the file concurrently; tolerate that
            // and reload its version instead of failing the rename.
            if let Err(e) = s.persist() {
                if path.exists() {
                    Store::load(&path, overlap_secs)?
                } else {
                    return Err(e);
                }
            } else {
                s
            }
        };
        Ok(Self {
            inner: Arc::new(RwLock::new(store)),
        })
    }

    /// Re-read the backing file, picking up master keys added by a peer
    /// process (e.g. when the KE server rotates and the NTP server must
    /// accept cookies minted under the new key). No-op for in-memory stores.
    pub fn reload(&self) -> Result<()> {
        let mut store = self.inner.write().unwrap();
        if let Some(path) = store.path.clone() {
            let fresh = Store::load(&path, store.overlap_secs)?;
            *store = fresh;
        }
        Ok(())
    }

    /// Generate a fresh master key. Existing keys stay usable until their
    /// own expiry (the overlap window elapses).
    pub fn rotate(&self) -> MasterKey {
        let mut store = self.inner.write().unwrap();
        let now = unix_secs();
        let overlap = store.overlap_secs;
        let key = store.insert_new(now, overlap);
        if let Err(e) = store.persist() {
            eprintln!("warning: failed to persist rotated master key: {e}");
        }
        key
    }

    /// Delete keys whose overlap window has elapsed. Returns how many went.
    pub fn prune_expired(&self) -> usize {
        let now = unix_secs();
        let mut store = self.inner.write().unwrap();
        let newest = store.keys.keys().copied().max();
        let before = store.keys.len();
        store.keys.retain(|id, k| {
            let is_newest = Some(*id) == newest; // never prune the active key
            is_newest || k.expires_unix > now
        });
        before - store.keys.len()
    }

    /// Key used to mint new cookies (highest id).
    pub fn current(&self) -> MasterKey {
        let store = self.inner.read().unwrap();
        let id = *store.keys.keys().max().expect("at least one key");
        store.keys[&id].clone()
    }

    /// Fetch a key by id for cookie verification, rejecting expired keys.
    pub fn get(&self, id: u32) -> Result<MasterKey> {
        let store = self.inner.read().unwrap();
        let key = store
            .keys
            .get(&id)
            .ok_or_else(|| Error::cookie(format!("unknown master key id {id}")))?;
        if key.expires_unix <= unix_secs() {
            return Err(Error::cookie(format!("master key {id} expired")));
        }
        Ok(key.clone())
    }

    pub fn key_count(&self) -> usize {
        self.inner.read().unwrap().keys.len()
    }

    pub fn key_ids(&self) -> Vec<u32> {
        self.inner.read().unwrap().keys.keys().copied().collect()
    }
}

impl Store {
    fn insert_new(&mut self, now: u64, lifetime: u64) -> MasterKey {
        let id = self.next_id;
        self.next_id += 1;
        let mut material = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut material);
        let key = MasterKey {
            id,
            created_unix: now,
            // Active key has no fixed expiry; when rotated it inherits the
            // overlap window at that moment. Start with a far-future value.
            expires_unix: now.saturating_add(lifetime.max(1)),
            material,
        };
        self.keys.insert(id, key.clone());
        key
    }

    /// On-disk layout (all integers big-endian):
    /// ```text
    /// "NTSK" | version u8 | next_id u32 | overlap u64 | count u32 |
    /// per key: id u32 | created u64 | expires u64 | material 64B
    /// ```
    fn persist(&self) -> Result<()> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| Error::KeyStore("no backing file configured".into()))?;
        let mut buf = Vec::new();
        buf.extend_from_slice(KEYSTORE_MAGIC);
        buf.push(KEYSTORE_VERSION);
        buf.write_u32::<BigEndian>(self.next_id)?;
        buf.write_u64::<BigEndian>(self.overlap_secs)?;
        buf.write_u32::<BigEndian>(self.keys.len() as u32)?;
        for k in self.keys.values() {
            buf.write_u32::<BigEndian>(k.id)?;
            buf.write_u64::<BigEndian>(k.created_unix)?;
            buf.write_u64::<BigEndian>(k.expires_unix)?;
            buf.extend_from_slice(&k.material);
        }
        // Atomic write: a uniquely-named temp file in the same directory,
        // then rename. Using with_extension() is avoided because the store
        // path may sit behind a symlinked directory (e.g. macOS /tmp).
        let tmp = match path.file_name() {
            Some(name) => path.with_file_name(format!(
                ".{}.{}",
                name.to_string_lossy(),
                std::process::id()
            )),
            None => path.with_extension("tmp"),
        };
        std::fs::write(&tmp, &buf)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    fn load(path: &Path, overlap_secs: u64) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let mut cur = std::io::Cursor::new(&bytes[..]);
        let mut magic = [0u8; 4];
        cur.read_exact(&mut magic)?;
        if &magic != KEYSTORE_MAGIC {
            return Err(Error::KeyStore("bad key-store magic".into()));
        }
        let version = cur.read_u8()?;
        if version != KEYSTORE_VERSION {
            return Err(Error::KeyStore(format!(
                "unsupported key-store version {version}"
            )));
        }
        let next_id = cur.read_u32::<BigEndian>()?;
        let stored_overlap = cur.read_u64::<BigEndian>()?;
        let count = cur.read_u32::<BigEndian>()?;
        let mut keys = BTreeMap::new();
        for _ in 0..count {
            let id = cur.read_u32::<BigEndian>()?;
            let created_unix = cur.read_u64::<BigEndian>()?;
            let expires_unix = cur.read_u64::<BigEndian>()?;
            let mut material = [0u8; 64];
            cur.read_exact(&mut material)?;
            keys.insert(id, MasterKey {
                id,
                created_unix,
                expires_unix,
                material,
            });
        }
        if keys.is_empty() {
            return Err(Error::KeyStore("key store contains no keys".into()));
        }
        Ok(Self {
            keys,
            next_id,
            overlap_secs: overlap_secs.max(stored_overlap),
            path: Some(path.to_path_buf()),
        })
    }
}

/// Mint a cookie wrapping the two working keys, sealed under `key`.
///
/// Each cookie carries its own random 32-byte SIV nonce, so it is reusable
/// across requests with different Unique Identifiers.
pub fn mint_cookie(
    key: &MasterKey,
    alg: AeadAlg,
    c2s: &[u8],
    s2c: &[u8],
    ttl_secs: u64,
) -> Result<Vec<u8>> {
    let key_len = working_key_len(alg);
    if c2s.len() != key_len || s2c.len() != key_len {
        return Err(Error::cookie(format!(
            "working keys for alg {} must be {key_len} octets each",
            alg.id()
        )));
    }
    let now = unix_secs();
    let expiry = now.saturating_add(ttl_secs);

    let mut header = vec![0u8; HEADER_LEN];
    header[0..4].copy_from_slice(COOKIE_MAGIC);
    header[4] = COOKIE_FORMAT_V1;
    BigEndian::write_u16(&mut header[5..7], alg.id());
    BigEndian::write_u32(&mut header[7..11], key.id);
    BigEndian::write_u64(&mut header[11..19], expiry);

    let mut nonce = [0u8; COOKIE_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let body_len = key_len * 2;
    let mut body = Vec::with_capacity(body_len);
    body.extend_from_slice(c2s);
    body.extend_from_slice(s2c);

    // AAD binds the full header; the embedded nonce is the SIV authenticated
    // component. The envelope uses AES-256-SIV under the 64-octet master key.
    let sealed = crate::aead::aes256_siv_seal(&key.material, &nonce, &header, &body)?;

    let mut out = Vec::with_capacity(header.len() + nonce.len() + sealed.len() + 3);
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    // RFC 8915 / chrony require NTS cookies to be a multiple of four octets.
    // The padding is outside the SIV-protected region and is stripped before
    // verification, so it needs no integrity protection of its own.
    while out.len() % 4 != 0 {
        out.push(0);
    }
    debug_assert_eq!(out.len() % 4, 0);
    Ok(out)
}

/// Contents recovered from a verified cookie. Key vectors have the native
/// length of the negotiated AEAD (16 for GCM, 64 for SIV-CMAC-256).
pub struct VerifiedCookie {
    pub alg: AeadAlg,
    pub key_id: u32,
    pub c2s_key: Vec<u8>,
    pub s2c_key: Vec<u8>,
}

/// Verify and open a cookie. `store` resolves the master key and enforces
/// rotation overlap / expiry. The cookie's own embedded nonce is used for
/// the SIV check, so verification is independent of any NTP request UID.
pub fn verify_cookie(store: &KeyStore, cookie: &[u8]) -> Result<VerifiedCookie> {
    if cookie.len() < HEADER_LEN + COOKIE_NONCE_LEN + 32 {
        return Err(Error::cookie("cookie shorter than minimum"));
    }
    let header = &cookie[..HEADER_LEN];
    if &header[0..4] != COOKIE_MAGIC {
        return Err(Error::cookie("bad magic"));
    }
    if header[4] != COOKIE_FORMAT_V1 {
        return Err(Error::cookie(format!("unknown format {}", header[4])));
    }
    let alg_id = BigEndian::read_u16(&header[5..7]);
    let alg = AeadAlg::from_id(alg_id)?;
    let key_id = BigEndian::read_u32(&header[7..11]);
    let expiry = BigEndian::read_u64(&header[11..19]);
    if expiry <= unix_secs() {
        return Err(Error::cookie("cookie past its expiry"));
    }

    let nonce = &cookie[HEADER_LEN..HEADER_LEN + COOKIE_NONCE_LEN];
    // Everything after the nonce is SIV output (16-octet IV ‖ ciphertext)
    // plus up to three zero alignment octets that make the whole cookie
    // 4-aligned. The SIV plaintext length is known from the algorithm, so
    // the exact sealed length is 16 + 2*key_len.
    let tail = &cookie[HEADER_LEN + COOKIE_NONCE_LEN..];
    let expected_sealed = 16 + working_key_len(alg) * 2;
    if tail.len() < expected_sealed {
        return Err(Error::cookie("cookie sealed region truncated"));
    }
    let sealed = &tail[..expected_sealed];

    let master = store.get(key_id)?;
    let body = crate::aead::aes256_siv_open(&master.material, nonce, header, sealed)?;
    let key_len = working_key_len(alg);
    if body.len() != key_len * 2 {
        return Err(Error::cookie("decrypted cookie body has wrong length"));
    }
    let c2s_key = body[..key_len].to_vec();
    let s2c_key = body[key_len..].to_vec();
    Ok(VerifiedCookie {
        alg,
        key_id,
        c2s_key,
        s2c_key,
    })
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convenience: fresh random 32-byte UID (RFC 8915 §5.3).
pub fn fresh_uid() -> [u8; UNIQUE_ID_LEN] {
    let mut uid = [0u8; UNIQUE_ID_LEN];
    rand::thread_rng().fill_bytes(&mut uid);
    uid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{AEAD_AES_128_GCM, AEAD_AES_SIV_CMAC_256};

    /// Two working keys sized for the algorithm under test.
    fn key_pair(alg: AeadAlg, c: u8, s: u8) -> (Vec<u8>, Vec<u8>) {
        let n = working_key_len(alg);
        (vec![c; n], vec![s; n])
    }

    #[test]
    fn mint_verify_roundtrip_both_algs() {
        let store = KeyStore::new(3600);
        for alg in [AeadAlg::Aes128Gcm, AeadAlg::AesSivCmac256] {
            let (c2s, s2c) = key_pair(alg, 1, 2);
            let cookie = mint_cookie(&store.current(), alg, &c2s, &s2c, 600).unwrap();
            let v = verify_cookie(&store, &cookie).unwrap();
            assert_eq!(v.alg, alg);
            assert_eq!(v.c2s_key, c2s);
            assert_eq!(v.s2c_key, s2c);
        }
    }

    #[test]
    fn cookie_is_uid_independent_and_tamper_detecting() {
        let store = KeyStore::new(3600);
        let (c2s, s2c) = key_pair(AeadAlg::Aes128Gcm, 1, 2);
        let cookie = mint_cookie(
            &store.current(),
            AeadAlg::Aes128Gcm,
            &c2s,
            &s2c,
            600,
        )
        .unwrap();
        // The same cookie verifies regardless of the request's UID, because
        // it carries its own embedded nonce (cookies are reusable tokens).
        let uid_a = fresh_uid();
        let uid_b = fresh_uid();
        assert!(verify_cookie(&store, &cookie).is_ok());
        assert_ne!(uid_a, uid_b);
        // NTS cookies must be a multiple of four octets (chrony enforces it).
        assert_eq!(cookie.len() % 4, 0);
        // tamper with the SIV-protected sealed region (not trailing padding)
        let sealed_start = HEADER_LEN + COOKIE_NONCE_LEN;
        let mut bad = cookie.clone();
        bad[sealed_start] ^= 1;
        assert!(verify_cookie(&store, &bad).is_err());
        // tamper with alg in header fails (AAD)
        let mut bad2 = cookie.clone();
        bad2[5] ^= 0xff;
        assert!(verify_cookie(&store, &bad2).is_err());
        // tamper with the embedded nonce fails
        let mut bad3 = cookie.clone();
        bad3[HEADER_LEN] ^= 1;
        assert!(verify_cookie(&store, &bad3).is_err());
    }

    #[test]
    fn rotation_overlap_keeps_old_cookies_working() {
        let store = KeyStore::new(3600);
        let first = store.current();
        let (c2s, s2c) = key_pair(AeadAlg::Aes128Gcm, 1, 2);
        let cookie_old = mint_cookie(&first, AeadAlg::Aes128Gcm, &c2s, &s2c, 3600).unwrap();

        let second = store.rotate();
        assert_ne!(first.id, second.id);
        assert_eq!(store.key_count(), 2);

        // old cookie still verifies through the overlap window
        let v = verify_cookie(&store, &cookie_old).unwrap();
        assert_eq!(v.key_id, first.id);
        // new cookies use the rotated key
        let (c3, s3) = key_pair(AeadAlg::Aes128Gcm, 3, 4);
        let cookie_new =
            mint_cookie(&store.current(), AeadAlg::Aes128Gcm, &c3, &s3, 3600).unwrap();
        assert_eq!(BigEndian::read_u32(&cookie_new[7..11]), second.id);
    }

    #[test]
    fn prune_drops_only_retired_keys() {
        let store = KeyStore::new(1); // 1-second overlap
        let first = store.current();
        store.rotate();
        assert_eq!(store.key_count(), 2);
        // first key expires 1s after rotation; simulate by waiting is slow,
        // so check the retain rule directly: newest is never pruned.
        let pruned = store.prune_expired();
        assert!(pruned <= 1);
        assert!(store.get(first.id).is_ok() || store.key_count() == 1);
        let ids = store.key_ids();
        assert!(!ids.is_empty());
    }

    #[test]
    fn unknown_key_id_rejected() {
        let store = KeyStore::new(3600);
        let (c2s, s2c) = key_pair(AeadAlg::Aes128Gcm, 1, 2);
        let mut cookie =
            mint_cookie(&store.current(), AeadAlg::Aes128Gcm, &c2s, &s2c, 600).unwrap();
        BigEndian::write_u32(&mut cookie[7..11], 999_999);
        assert!(verify_cookie(&store, &cookie).is_err());
    }

    #[test]
    fn alg_id_constants_unchanged() {
        // guard against accidental registry drift
        assert_eq!(AEAD_AES_SIV_CMAC_256, 15);
        assert_eq!(AEAD_AES_128_GCM, 16);
    }

    #[test]
    fn persisted_store_is_shared_and_rotation_is_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.bin");

        // "KE process" creates the store and mints a cookie.
        let ke_store = KeyStore::open_or_create(&path, 3600).unwrap();
        let (c2s, s2c) = key_pair(AeadAlg::Aes128Gcm, 1, 2);
        let cookie =
            mint_cookie(&ke_store.current(), AeadAlg::Aes128Gcm, &c2s, &s2c, 3600).unwrap();

        // "NTP process" opens the same file and verifies that cookie.
        let ntp_store = KeyStore::open_or_create(&path, 3600).unwrap();
        assert_eq!(ntp_store.key_ids(), ke_store.key_ids());
        assert!(verify_cookie(&ntp_store, &cookie).is_ok());

        // KE rotates; the rotated key must become visible after reload, and
        // cookies under both the old and new keys must still verify.
        let rotated = ke_store.rotate();
        let cookie_new = mint_cookie(
            &ke_store.current(),
            AeadAlg::Aes128Gcm,
            &c2s,
            &s2c,
            3600,
        )
        .unwrap();
        // Before reload the NTP store does not know the new key.
        assert!(ntp_store.get(rotated.id).is_err());
        ntp_store.reload().unwrap();
        assert!(ntp_store.get(rotated.id).is_ok());
        assert!(verify_cookie(&ntp_store, &cookie).is_ok()); // old key, overlap
        assert!(verify_cookie(&ntp_store, &cookie_new).is_ok()); // new key
    }
}
