//! Fixed-size keys: the shape password hashing, HMAC and AEAD actually want.

use std::fmt;

use crate::sys::Region;
use crate::{Error, Result};

/// A key of compile-time-known length, held in a guarded, wired mapping.
///
/// The length is fixed by the type so there is no way to grow a key and leave
/// the old material behind: keys are created once and used. There is no
/// `Clone`; copy explicitly with [`SecretKey::duplicate`].
///
/// ```
/// # use secretmem::SecretKey;
/// // A raw 32-byte key. In practice derive it, do not hard-code it.
/// let key = SecretKey::<32>::from_slice(b"0123456789abcdef0123456789abcdef").unwrap();
/// assert_eq!(key.expose().len(), 32);
/// ```
pub struct SecretKey<const N: usize> {
    region: Region,
}

impl<const N: usize> SecretKey<N> {
    /// Copies exactly `N` bytes into protected memory. Fails when the input
    /// length differs from `N`.
    ///
    /// The input slice is the caller's buffer and is **not** wiped. Where the
    /// key is computed rather than read from an existing buffer, prefer
    /// [`SecretKey::from_fn`], which never materialises it outside protected
    /// memory.
    pub fn from_slice(src: &[u8]) -> Result<Self> {
        if src.len() != N {
            return Err(Error::TooLarge);
        }
        let region = Region::new(N)?;
        // SAFETY: region length >= N = src.len().
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), region.as_ptr(), N);
        }
        Ok(SecretKey { region })
    }

    /// Builds a key by writing directly into protected memory.
    ///
    /// The closure receives the protected buffer and fills it. Nothing the
    /// secret is derived from has to be materialised in an ordinary buffer
    /// first — which is the only way to keep a key derivation's intermediates
    /// off the stack. Preferred over [`SecretKey::from_slice`] when the key is
    /// computed rather than read.
    ///
    /// ```
    /// # use secretmem::SecretKey;
    /// # fn main() -> secretmem::Result<()> {
    /// let key = SecretKey::<32>::from_fn(|dst| {
    ///     // In real code: a KDF. Here, a pattern, to show the shape.
    ///     for (i, b) in dst.iter_mut().enumerate() {
    ///         *b = i as u8;
    ///     }
    /// })?;
    /// assert_eq!(key.expose()[1], 1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_fn(f: impl FnOnce(&mut [u8])) -> Result<Self> {
        let mut key = Self::zeroed()?;
        f(key.expose_mut());
        Ok(key)
    }

    /// Creates an all-zero key. Callers are expected to fill it from a real
    /// source (KDF, key file, HSM) before use.
    pub fn zeroed() -> Result<Self> {
        Ok(SecretKey { region: Region::new(N)? })
    }

    /// Key length in bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Always `false` for keys with `N > 0`.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Borrows the key material.
    #[inline]
    pub fn expose(&self) -> &[u8] {
        // SAFETY: region is exactly N bytes and exclusively ours.
        unsafe { std::slice::from_raw_parts(self.region.as_ptr(), N) }
    }

    /// Mutably borrows the key material, for initialising a zeroed key or
    /// rotating in place.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `expose`, and `&mut self` is exclusive.
        unsafe { std::slice::from_raw_parts_mut(self.region.as_ptr(), N) }
    }

    /// Wipes the key. Idempotent.
    pub fn wipe(&mut self) {
        self.region.wipe();
    }

    /// Whether every byte is zero.
    pub fn is_wiped(&self) -> bool {
        self.expose().iter().all(|&b| b == 0)
    }

    /// Independent copy; the copy is tracked like the original.
    pub fn duplicate(&self) -> Result<Self> {
        Self::from_slice(self.expose())
    }

    /// Whether the backing pages are wired.
    pub fn is_locked(&self) -> bool {
        self.region.is_locked()
    }
}

impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("len", &N)
            .field("redacted", &true)
            .finish()
    }
}

impl<const N: usize> Drop for SecretKey<N> {
    fn drop(&mut self) {
        self.region.wipe();
    }
}

/// Lets a `SecretKey` participate in code that is generic over `Zeroize`.
impl<const N: usize> zeroize::Zeroize for SecretKey<N> {
    fn zeroize(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_exactly_n_bytes() {
        let k = SecretKey::<16>::from_slice(&[7u8; 16]).unwrap();
        assert_eq!(k.len(), 16);
        assert_eq!(k.expose(), &[7u8; 16]);
        assert!(k.is_locked() || !crate::capabilities().can_lock);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(SecretKey::<16>::from_slice(&[0u8; 15]).is_err());
        assert!(SecretKey::<16>::from_slice(&[0u8; 17]).is_err());
    }

    #[test]
    fn wipe_zeroes() {
        let mut k = SecretKey::<8>::from_slice(&[0xAA; 8]).unwrap();
        assert!(!k.is_wiped());
        k.wipe();
        assert!(k.is_wiped());
    }

    #[test]
    fn debug_redacts() {
        let k = SecretKey::<4>::from_slice(&[1, 2, 3, 4]).unwrap();
        let s = format!("{k:?}");
        assert!(!s.contains("[1, 2, 3, 4]"));
        assert!(s.contains("redacted"));
    }
}
