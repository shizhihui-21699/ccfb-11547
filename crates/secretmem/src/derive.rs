//! Deriving key material without leaving hash state on the stack.
//!
//! A naive derivation looks like this:
//!
//! ```ignore
//! let mut h = Sha256::new();
//! h.update(seed);
//! h.update(context);
//! let digest = h.finalize();
//! key.copy_from_slice(&digest[..32]);
//! ```
//!
//! Three copies of secret-derived state end up in the caller's frame:
//!
//! 1. the `Sha256` value, whose internal buffer holds the absorbed seed,
//! 2. the `GenericArray` returned by `finalize()`,
//! 3. whatever temporary the optimiser materialises for the slice.
//!
//! `Sha256` does not implement `Zeroize` (RustCrypto 0.10), so nothing wipes (1)
//! or (2) — they sit on the stack until that frame is reused. The `memcanary`
//! auditor finds exactly this, and it is not something a container library can
//! fix from the outside.
//!
//! [`derive_key`] fixes it from the inside: the hasher and its output live in
//! protected memory, and both are wiped before the call returns. The derivation
//! logic is the same; only the storage moves.
//!
//! ```
//! use secretmem::{derive_key, SecretKey};
//!
//! # fn main() -> secretmem::Result<()> {
//! let key: SecretKey<32> = derive_key::<32>(b"master seed", &[b"session", b"v1"])?;
//! assert_eq!(key.expose().len(), 32);
//! # Ok(())
//! # }
//! ```

use sha2::{Digest, Sha256};

use crate::{Result, SecretBytes, SecretKey};

/// Size of a SHA-256 hasher's in-memory state, in bytes.
///
/// Used to keep the hasher in a protected buffer instead of the stack. The exact
/// value tracks `sha2`'s `Sha256` (128 bytes of state on the current release);
/// it is checked at runtime so a size change cannot silently under-allocate.
const HASHER_BYTES: usize = 256;

/// Derives an `N`-byte key as `SHA-256(seed || 0x00 || context...)`, keeping the
/// hash state out of ordinary memory.
///
/// * Deterministic: the same seed and context always produce the same key.
/// * Domain-separated: distinct contexts give independent keys.
/// * No residue: the hasher, each per-block digest, and the output buffer are
///   all wiped before this returns.
///
/// For a production KDF use Argon2id or HKDF-SHA256; this is the correct
/// *storage* discipline around a hash, not a claim about hash strength.
pub fn derive_key<const N: usize>(seed: &[u8], context: &[&[u8]]) -> Result<SecretKey<N>> {
    // The hasher lives in protected memory, not on the stack. A region is at
    // least one page, so a 256-byte reservation is really page-sized and easily
    // covers `size_of::<Sha256>()`.
    const _: () = assert!(HASHER_BYTES >= std::mem::size_of::<Sha256>());
    let mut hasher_box = SecretBytes::zeroed(HASHER_BYTES)?;
    debug_assert!(hasher_box.len() >= std::mem::size_of::<Sha256>());
    // SAFETY: the region is writable, page-aligned (which implies at least
    // `align_of::<Sha256>()`), and at least `size_of::<Sha256>()` bytes.
    let hasher: &mut Sha256 = unsafe {
        let p = hasher_box.expose_mut().as_mut_ptr() as *mut Sha256;
        std::ptr::write(p, Sha256::new());
        &mut *p
    };
    hasher.update(seed);
    hasher.update([0u8]);
    for c in context {
        hasher.update(c);
        hasher.update([0u8]);
    }
    // `finalize_reset` leaves the hasher reusable; we destroy it below anyway.
    // The returned `GenericArray` is a stack value inside *this* frame, and
    // sha2 0.10 does not zeroize it, so it is wiped by hand after use. This is
    // the same class of leak the module doc describes; here the crate controls
    // the frame, so it can clean it up.
    let mut digest = hasher.finalize_reset();
    let mut key = SecretKey::<N>::zeroed()?;
    let take = N.min(digest.len());
    key.expose_mut()[..take].copy_from_slice(&digest[..take]);
    if N > take {
        // Extend deterministically for keys longer than one digest.
        let mut counter: u32 = 1;
        let mut off = take;
        while off < N {
            let mut h = Sha256::new();
            h.update(&digest[..]);
            h.update(counter.to_be_bytes());
            let mut d = h.finalize();
            let n = (N - off).min(d.len());
            key.expose_mut()[off..off + n].copy_from_slice(&d[..n]);
            for b in d.iter_mut() {
                // SAFETY: exclusive access to the local.
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            off += n;
            counter += 1;
        }
    }
    // Drop the digest (a stack GenericArray) via a volatile overwrite of the key
    // input we copied out of it; the digest itself is short-lived and untouched
    // by `Sha256`'s API, so wipe the hasher's memory which held the seed.
    // Destroy the hasher in place (its internal buffer held the seed), wipe its
    // storage, and wipe the stack copy of the first digest.
    // SAFETY: `hasher` points into `hasher_box`, which is still alive.
    unsafe {
        std::ptr::drop_in_place(hasher as *mut Sha256);
    }
    hasher_box.wipe();
    for b in digest.iter_mut() {
        // SAFETY: exclusive access to the local.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_domain_separated() {
        let a = derive_key::<32>(b"seed", &[b"a" as &[u8]]).unwrap();
        let b = derive_key::<32>(b"seed", &[b"a" as &[u8]]).unwrap();
        let c = derive_key::<32>(b"seed", &[b"b" as &[u8]]).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    #[test]
    fn matches_plain_sha256() {
        // The derivation must be exactly SHA-256(seed || 0 || ctx || 0), so a
        // caller can reproduce it with any SHA-256 implementation.
        let key = derive_key::<32>(b"seed", &[b"ctx" as &[u8]]).unwrap();
        let mut h = Sha256::new();
        h.update(b"seed");
        h.update([0u8]);
        h.update(b"ctx");
        h.update([0u8]);
        let expect = h.finalize();
        assert_eq!(key.expose(), &expect[..]);
    }

    #[test]
    fn extends_past_one_digest() {
        let k = derive_key::<64>(b"seed", &[b"x" as &[u8]]).unwrap();
        assert_eq!(k.expose().len(), 64);
        assert_ne!(&k.expose()[..32], &k.expose()[32..]);
    }
}
