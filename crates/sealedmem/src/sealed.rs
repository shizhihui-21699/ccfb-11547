//! `String` and byte-container types that hold their value in a [`Region`].
//!
//! Both are deliberately:
//!
//! * **not `Copy`** — a copy would be silent duplication of a secret;
//! * **not `Clone`** — [`SealedBytes::duplicate`] exists, is explicit, and
//!   allocates a second independent sealed region rather than sharing a buffer;
//! * **not `Display`/`Debug`-transparent** — the impls print `[REDACTED]`;
//! * **not `Serialize`** — there is no derive that could leak through a
//!   telemetry path;
//! * **not `Sync`** — a scoped view unseals the page, so concurrent readers
//!   would race the seal.  They are `Send`.
//!
//! Reading requires the scoped [`with`](SealedBytes::with) API, which makes the
//! copy site visible in code review.  `Into<String>`, `AsRef<str>` and friends
//! are intentionally absent for the same reason.

use core::fmt;

use crate::error::Result;
use crate::region::Region;

/// A byte buffer that lives in a sealed page range.
pub struct SealedBytes {
    region: Region,
}

impl SealedBytes {
    /// Create from a borrowed slice.  The borrowed input remains the caller's
    /// problem: if it was a `String` or `Vec` on the heap, that allocation is
    /// still holding a copy until it is dropped or wiped.  At trust boundaries
    /// prefer reading directly into a sealed region (see
    /// [`from_callback`](SealedBytes::from_callback)).
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut region = Region::new(bytes.len())?;
        region.assign(bytes)?;
        Ok(Self { region })
    }

    /// Create by letting the caller write **directly** into the sealed page.
    /// The closure receives a mutable slice sized `capacity`; it returns the
    /// number of bytes actually used.  This is the no-intermediate-copy path:
    /// the only place the secret exists is inside our region.
    pub fn from_callback(capacity: usize, fill: impl FnOnce(&mut [u8]) -> usize) -> Result<Self> {
        let mut region = Region::new(capacity)?;
        let cap = region.capacity();
        // `fill` gives the callback the full page-backed slice, not the (empty)
        // logical view, so the secret is written straight into the sealed page.
        let used = region.fill(cap, |dst: &mut [u8]| {
            let n = fill(dst);
            assert!(n <= cap, "callback wrote past capacity");
            n
        });
        region.set_used(used);
        Ok(Self { region })
    }

    /// Number of stored bytes.
    pub fn len(&self) -> usize {
        self.region.len()
    }

    /// Whether no bytes are stored.
    pub fn is_empty(&self) -> bool {
        self.region.is_empty()
    }

    /// Page-rounded capacity.
    pub fn capacity(&self) -> usize {
        self.region.capacity()
    }

    /// Borrow the bytes for the duration of the closure.  The pages are readable
    /// only inside the closure; the guard re-seals on return **and on panic**.
    pub fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        self.region.with(f)
    }

    /// Replace the value.  May move to a new region; the old pages are wiped
    /// rather than merely freed.
    pub fn assign(&mut self, bytes: &[u8]) -> Result<()> {
        self.region.assign(bytes)
    }

    /// Append one byte, growing into a fresh sealed region when full.
    pub fn push_byte(&mut self, b: u8) -> Result<()> {
        self.region.push_byte(b)
    }

    /// Wipe now instead of at drop.  After this the container is empty.
    pub fn wipe(&mut self) -> Result<()> {
        self.region.wipe()
    }

    /// Explicit, visible duplication.  The result is a **second independent
    /// sealed region** with the same bytes; there is no shared backing store, so
    /// wiping one cannot resurrect the other's contents.
    pub fn duplicate(&self) -> Result<Self> {
        Self::from_callback(self.capacity(), |dst| {
            self.with(|src| {
                dst[..src.len()].copy_from_slice(src);
                src.len()
            })
        })
    }

    /// Constant-time equality against a borrowed slice of the same length.
    ///
    /// Length is compared first and **is not** constant-time; lengths of secrets
    /// are not usually sensitive, but this is documented rather than hidden.
    pub fn eq_ct(&self, other: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        self.with(|mine| mine.ct_eq(other).unwrap_u8() == 1)
    }

    /// Kernel-reported facts about the backing region (`None` after wipe, or on
    /// platforms without Mach).
    pub fn stats(&self) -> Option<crate::RegionStats> {
        self.region.stats()
    }

    /// Address of the sealed page's first data byte.  For the verification
    /// tooling; dereferencing it while sealed faults by design.
    pub fn data_addr(&self) -> usize {
        self.region.data_addr()
    }

    /// Read a secret from the environment **without materialising a heap copy**.
    ///
    /// The bytes go straight from `getenv`'s pointer into the sealed page, so the
    /// only copies are inside pages this crate owns.  `getenv` itself still reads
    /// libc's copy of `environ`; [`scrub::scrub_env_var`](crate::scrub::scrub_env_var)
    /// zeros that and the kernel's per-pid snapshot.  Prefer a file descriptor in
    /// production; this is the least-bad environment path.
    ///
    /// The value is copied byte by byte in a single pass, so no intermediate
    /// `String`/`Vec` exists even briefly.
    pub fn from_env(name: &str) -> Result<Option<Self>> {
        let mut cname = [0u8; 256];
        let bytes = name.as_bytes();
        if bytes.len() + 1 > cname.len() || bytes.contains(&0) {
            return Err(crate::Error::TooLarge);
        }
        cname[..bytes.len()].copy_from_slice(bytes);
        // SAFETY: `getenv` returns a pointer into the live environment or null.
        let value = unsafe { libc::getenv(cname.as_ptr().cast()) };
        if value.is_null() {
            return Ok(None);
        }
        // Size once, then copy straight into the sealed page.
        let mut len = 0usize;
        // SAFETY: the environment string is NUL-terminated.
        unsafe {
            while *value.add(len) != 0 {
                len += 1;
            }
        }
        let s = Self::from_callback(len.max(1), |dst| {
            for (i, slot) in dst.iter_mut().take(len).enumerate() {
                // SAFETY: same bounds as the sizing loop.
                *slot = unsafe { *value.add(i) as u8 };
            }
            len
        })?;
        Ok(Some(s))
    }
}

impl fmt::Debug for SealedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately no length: even the length of a key narrows a search.
        f.write_str("SealedBytes([REDACTED])")
    }
}

impl Drop for SealedBytes {
    fn drop(&mut self) {
        // Region::drop wipes; this impl exists only to document the intent and
        // to keep the drop order obvious (bytes -> region).
        let _ = self.region.wipe();
    }
}

/// A UTF-8 string stored in a sealed page range.
pub struct SealedString {
    inner: SealedBytes,
}

impl SealedString {
    /// Create from UTF-8 bytes.  The input slice's own storage is the caller's
    /// responsibility (see [`SealedBytes::from_slice`]).
    pub fn from_utf8(bytes: &[u8]) -> Result<Self> {
        // Validate before copying so we fail without materialising the value.
        if core::str::from_utf8(bytes).is_err() {
            return Err(crate::Error::TooLarge);
        }
        Ok(Self {
            inner: SealedBytes::from_slice(bytes)?,
        })
    }

    /// Create by writing directly into the sealed page.
    pub fn from_callback(capacity: usize, fill: impl FnOnce(&mut [u8]) -> usize) -> Result<Self> {
        let s = SealedBytes::from_callback(capacity, fill)?;
        // Validate the result in place, without materialising the value outside
        // the sealed page.
        let valid = s.with(|b| core::str::from_utf8(b).is_ok());
        if !valid {
            return Err(crate::Error::TooLarge);
        }
        Ok(Self { inner: s })
    }

    /// Number of bytes (UTF-8 bytes, not chars — intentionally: a `char` count
    /// would be a second observable).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Borrow as `&[u8]` for the duration of the closure.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        self.inner.with(f)
    }

    /// Borrow as `&str` for the duration of the closure.  Safe because the
    /// contents were validated on construction and only whole-value `assign`
    /// calls can change them.
    pub fn with_str<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        self.inner.with(|b| {
            let s = core::str::from_utf8(b).expect("SealedString invariant: valid UTF-8");
            f(s)
        })
    }

    /// Replace the value (must be valid UTF-8).
    pub fn assign(&mut self, value: &str) -> Result<()> {
        self.inner.assign(value.as_bytes())
    }

    /// Explicit duplication into a second sealed region.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            inner: self.inner.duplicate()?,
        })
    }

    /// Constant-time equality against a borrowed string.
    pub fn eq_ct(&self, other: &str) -> bool {
        self.inner.eq_ct(other.as_bytes())
    }

    /// Wipe now.
    pub fn wipe(&mut self) -> Result<()> {
        self.inner.wipe()
    }

    /// Kernel-reported facts about the backing region.
    pub fn stats(&self) -> Option<crate::RegionStats> {
        self.inner.stats()
    }

    /// Address of the sealed page's first data byte.
    pub fn data_addr(&self) -> usize {
        self.inner.data_addr()
    }

    /// Read a UTF-8 secret from the environment without a heap copy.  See
    /// [`SealedBytes::from_env`]; call
    /// [`scrub::scrub_env_var`](crate::scrub::scrub_env_var) immediately after.
    pub fn from_env(name: &str) -> Result<Option<Self>> {
        match SealedBytes::from_env(name)? {
            None => Ok(None),
            Some(inner) => {
                let valid = inner.with(|b| core::str::from_utf8(b).is_ok());
                if !valid {
                    return Err(crate::Error::TooLarge);
                }
                Ok(Some(Self { inner }))
            }
        }
    }
}

impl fmt::Debug for SealedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealedString([REDACTED])")
    }
}

impl Drop for SealedString {
    fn drop(&mut self) {
        let _ = self.inner.wipe();
    }
}
