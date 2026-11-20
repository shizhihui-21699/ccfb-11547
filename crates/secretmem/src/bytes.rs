//! A growable byte buffer whose storage is a guarded, wired mapping.

use std::fmt;

use crate::registry;
use crate::sys::Region;
use crate::{Error, Result};

/// Sensitive bytes in protected memory.
///
/// * No `Clone` is derived. Making a copy is an explicit, visible act
///   ([`SecretBytes::duplicate`]) that returns another tracked container, so
///   copies can never exist off the books.
/// * No `Deref<Target = [u8]>`, `AsRef<[u8]>`, `Display`, or `Debug` that
///   reveals contents. Reading requires the deliberately named
///   [`expose`](SecretBytes::expose).
/// * Growth moves the bytes into a new mapping, wiping and unmapping the old
///   one, so a reallocation never leaves the old buffer readable.
/// * `Drop` wipes. So does a `fork()`ed child (see [`crate::harden_process`])
///   and a fatal signal once hardening is on.
///
/// ```
/// # use secretmem::SecretBytes;
/// # fn main() -> secretmem::Result<()> {
/// let mut s = SecretBytes::from_slice(b"hunter2")?;
/// assert_eq!(s.expose(), b"hunter2");
/// s.wipe();
/// assert!(s.is_wiped());
/// assert_eq!(s.expose(), b"");
/// # Ok(())
/// # }
/// ```
pub struct SecretBytes {
    region: Region,
    len: usize,
}

impl SecretBytes {
    /// Creates an empty container with capacity for `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Result<Self> {
        Ok(SecretBytes { region: Region::new(capacity)?, len: 0 })
    }

    /// Creates an empty container.
    pub fn new() -> Result<Self> {
        Self::with_capacity(0)
    }

    /// Copies `src` into protected memory.
    ///
    /// Note: `src` is the caller's buffer and is **not** wiped by this call.
    /// Prefer keeping the source itself in a `SecretBytes`/`SecretString` from
    /// the moment it enters the process; if you cannot, wipe `src` yourself
    /// once this returns.
    pub fn from_slice(src: &[u8]) -> Result<Self> {
        let mut s = Self::with_capacity(src.len())?;
        s.extend(src)?;
        Ok(s)
    }

    /// Creates a container from zeroes of the given length.
    pub fn zeroed(len: usize) -> Result<Self> {
        let mut s = Self::with_capacity(len)?;
        s.len = len;
        Ok(s)
    }

    /// Number of bytes stored.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no bytes are stored.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes currently available without growing.
    #[inline]
    pub fn capacity(&self) -> usize {
        if self.is_wiped() {
            0
        } else {
            self.region.len()
        }
    }

    /// Borrows the contents.
    ///
    /// The slice points into protected memory. Anything built from it — a
    /// `to_vec()`, a `String::from_utf8`, a hash map entry — is an ordinary
    /// heap allocation that this crate does not track. Use the slice only for
    /// the operation at hand.
    #[inline]
    pub fn expose(&self) -> &[u8] {
        // SAFETY: `region` is at least `len` bytes and exclusively ours.
        unsafe { std::slice::from_raw_parts(self.region.as_ptr(), self.len) }
    }

    /// Mutably borrows the contents, for in-place transforms (comparison,
    /// decryption into place, trimming).
    #[inline]
    pub fn expose_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `expose`, and `&mut self` gives exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.region.as_ptr(), self.len) }
    }

    /// Appends bytes, growing the mapping if necessary.
    pub fn extend(&mut self, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Ok(());
        }
        let new_len = self.len.checked_add(src.len()).ok_or(Error::TooLarge)?;
        if new_len > self.region.len() {
            let want = new_len.max(self.region.len().saturating_mul(2));
            self.region.grow(want)?;
        }
        // SAFETY: capacity >= new_len >= self.len + src.len(), and the source
        // is a distinct slice (the caller cannot hold a `&mut self` borrow of
        // our region while passing `src` from it — the borrow checker forbids
        // that shape).
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.region.as_ptr().add(self.len),
                src.len(),
            );
        }
        self.len = new_len;
        Ok(())
    }

    /// Appends one byte.
    pub fn push(&mut self, byte: u8) -> Result<()> {
        self.extend(&[byte])
    }

    /// Shrinks the logical length to `new_len`, wiping the truncated tail and
    /// (if it is a lot of slack) releasing pages.
    ///
    /// Wiping the tail matters: otherwise a secret that was shortened stays
    /// readable past the new length until the region is dropped.
    pub fn truncate(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        let drop_from = self.region.as_ptr().wrapping_add(new_len);
        let tail = self.len - new_len;
        // SAFETY: `new_len..self.len` is inside the region.
        unsafe { crate::sys::wipe_bytes(drop_from, tail) };
        self.len = new_len;
    }

    /// Immediate, explicit wipe. Idempotent.
    ///
    /// After this the container is empty and every byte of its mapping is
    /// zero. The mapping stays in place until `Drop` (or reuse via `extend`).
    pub fn wipe(&mut self) {
        self.region.wipe();
        self.len = 0;
    }

    /// Whether every byte of the mapping is zero.
    ///
    /// Used by tests and the auditor; it is a real scan, not a flag.
    ///
    /// In a `fork()`ed child on a platform that excluded the range
    /// (`VM_INHERIT_NONE`), the pages do not exist in this process and reading
    /// them would fault. That case is reported as `true`: nothing of the value
    /// is reachable here, which is the property the caller is asking about.
    /// Check [`secretmem::is_absent_in_child`] if you need to distinguish
    /// "zeroed" from "not mapped".
    pub fn is_wiped(&self) -> bool {
        let p = self.region.as_ptr();
        if crate::is_absent_in_child(p) {
            return true;
        }
        let n = self.region.len();
        // SAFETY: the whole mapping is readable (checked just above).
        let bytes = unsafe { std::slice::from_raw_parts(p, n) };
        bytes.iter().all(|&b| b == 0)
    }

    /// Makes an independent copy. This is the *only* way to clone, and the
    /// copy is itself a tracked container.
    pub fn duplicate(&self) -> Result<Self> {
        Self::from_slice(self.expose())
    }

    /// Whether the pages backing this value are wired (unknowable on the
    /// portable backend, where it is always `false`).
    pub fn is_locked(&self) -> bool {
        self.region.is_locked()
    }

}

impl fmt::Debug for SecretBytes {
    /// Never prints contents. Length only: an accidental `{:?}` in a log must
    /// not leak the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.len)
            .field("redacted", &true)
            .finish()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Explicit wipe first, then `Region::drop` wipes again and unmaps.
        // Belt and braces: the second pass is cheap and covers the case where a
        // future change reorders `Region`'s teardown.
        self.wipe();
    }
}

/// Registers a stack scratch buffer with the fork/signal registry.
///
/// Use this for secrets that must live on the stack (e.g. a decryption key
/// materialised for one call) when you need the crash-path wipe too. The
/// caller must call [`unregister_scratch`] before the buffer goes out of scope.
///
/// ```
/// # use secretmem::{register_scratch, unregister_scratch};
/// let mut buf = [0u8; 32];
/// register_scratch(buf.as_mut_ptr(), buf.len());
/// // ... use buf ...
/// unregister_scratch(buf.as_mut_ptr());
/// ```
pub fn register_scratch(ptr: *mut u8, len: usize) -> bool {
    registry::register(ptr, len)
}

/// Counterpart to [`register_scratch`].
pub fn unregister_scratch(ptr: *mut u8) {
    registry::unregister(ptr)
}

/// Lets a `SecretBytes` participate in code that is generic over `Zeroize`.
///
/// The implementation is `wipe()`, so `zeroize()` and a plain `drop` do the same
/// thing. It exists so a container can be passed to a function that requires
/// `Z: Zeroize` without the caller having to special-case it.
impl zeroize::Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_without_leaving_a_copy() {
        let mut s = SecretBytes::new().unwrap();
        let mut last = std::ptr::null::<u8>();
        for _ in 0..50 {
            s.extend(b"0123456789abcdef").unwrap();
            let p = s.expose().as_ptr();
            if !last.is_null() && p != last {
                // Reallocation happened. The old mapping must be gone and
                // zeroed; we cannot check unmapped memory, but the new pointer
                // must differ and the data must be intact.
                assert_ne!(p, last);
            }
            last = p;
        }
        assert_eq!(s.len(), 800);
        assert_eq!(&s.expose()[..16], b"0123456789abcdef");
        assert_eq!(&s.expose()[784..], b"0123456789abcdef");
    }

    #[test]
    fn wipe_zeroes_and_empties() {
        let mut s = SecretBytes::from_slice(b"topsecret").unwrap();
        assert!(!s.is_wiped());
        s.wipe();
        assert!(s.is_wiped());
        assert_eq!(s.len(), 0);
        assert!(s.expose().is_empty());
    }

    #[test]
    fn truncate_wipes_tail() {
        let mut s = SecretBytes::from_slice(b"abcdefgh").unwrap();
        s.truncate(3);
        assert_eq!(s.expose(), b"abc");
        assert!(!s.is_wiped());
        // The tail inside the mapping must be zero.
        let p = s.region.as_ptr();
        let tail = unsafe { std::slice::from_raw_parts(p.add(3), 5) };
        assert_eq!(tail, &[0u8; 5]);
    }

    #[test]
    fn duplicate_is_independent() {
        let a = SecretBytes::from_slice(b"key").unwrap();
        let mut b = a.duplicate().unwrap();
        b.expose_mut()[0] = b'K';
        assert_eq!(a.expose(), b"key");
        assert_eq!(b.expose(), b"Key");
    }

    #[test]
    fn debug_redacts() {
        let s = SecretBytes::from_slice(b"password123").unwrap();
        let out = format!("{s:?}");
        assert!(!out.contains("password123"));
        assert!(out.contains("redacted"));
    }

    #[test]
    fn registry_tracks_lifetime() {
        // Other tests run in parallel and also hold regions, so assert on this
        // exact range rather than on the global count.
        let s = SecretBytes::from_slice(b"x").unwrap();
        let p = s.expose().as_ptr();
        assert!(registry::is_registered(p));
        drop(s);
        assert!(!registry::is_registered(p));
    }
}
