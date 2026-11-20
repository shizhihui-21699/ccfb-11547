//! A UTF-8 text secret with the same guarantees as [`crate::SecretBytes`].

use std::fmt;

use crate::{Error, Result, SecretBytes};

/// Sensitive text: passwords, tokens, seed phrases.
///
/// Same contract as [`SecretBytes`] — no `Clone`, no `Display`, redacting
/// `Debug`, wiping `Drop`, guarded and wired storage — plus a UTF-8 invariant
/// so callers that need a `&str` can get one.
///
/// ```
/// # use secretmem::SecretString;
/// let pw = SecretString::from_str("hunter2").unwrap();
/// assert_eq!(pw.expose(), "hunter2");
/// assert!(!format!("{pw:?}").contains("hunter2"));
/// ```
pub struct SecretString {
    bytes: SecretBytes,
}

impl SecretString {
    /// Empty string.
    pub fn new() -> Result<Self> {
        Ok(SecretString { bytes: SecretBytes::new()? })
    }

    /// Copies `src` into protected memory. Fails if it is not valid UTF-8.
    ///
    /// Named `from_str` to mirror `SecretBytes::from_slice`; it is not the
    /// `FromStr` trait, which cannot fail on allocation. Use `s.parse()` only if
    /// you want the trait's error type.
    #[allow(clippy::should_implement_trait)]
    ///
    /// As with [`SecretBytes::from_slice`], `src` itself is not wiped.
    pub fn from_str(src: &str) -> Result<Self> {
        Ok(SecretString { bytes: SecretBytes::from_slice(src.as_bytes())? })
    }

    /// Copies a byte slice after validating it as UTF-8.
    pub fn from_utf8(src: Vec<u8>) -> Result<Self> {
        // Validate before copying so an invalid buffer never lands in a region.
        std::str::from_utf8(&src).map_err(|_| Error::InvalidUtf8)?;
        Ok(SecretString { bytes: SecretBytes::from_slice(&src)? })
    }

    /// Borrows the text.
    #[inline]
    pub fn expose(&self) -> &str {
        // SAFETY: the invariant is that the contents are always valid UTF-8.
        // Every mutation goes through methods that re-validate or only append
        // already-validated input.
        unsafe { std::str::from_utf8_unchecked(self.bytes.expose()) }
    }

    /// Bytes stored (not including any NUL terminator; there is none).
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the string is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Appends text.
    pub fn push_str(&mut self, s: &str) -> Result<()> {
        self.bytes.extend(s.as_bytes())
    }

    /// Wipes the contents. Idempotent.
    pub fn wipe(&mut self) {
        self.bytes.wipe();
    }

    /// Whether every byte of the backing mapping is zero.
    pub fn is_wiped(&self) -> bool {
        self.bytes.is_wiped()
    }

    /// The underlying byte container, for APIs that take raw bytes.
    pub fn as_secret_bytes(&self) -> &SecretBytes {
        &self.bytes
    }

    /// Consumes the string, returning the byte container.
    pub fn into_secret_bytes(self) -> SecretBytes {
        self.bytes
    }

    /// Independent copy; the copy is tracked like the original.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(SecretString { bytes: self.bytes.duplicate()? })
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretString")
            .field("len", &self.len())
            .field("redacted", &true)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_redaction() {
        let s = SecretString::from_str("pa\u{00df}w\u{00f6}rd").unwrap();
        assert_eq!(s.expose(), "pa\u{00df}w\u{00f6}rd");
        assert_eq!(s.len(), "pa\u{00df}w\u{00f6}rd".len());
        let d = format!("{s:?}");
        assert!(!d.contains("pa"));
        assert!(d.contains("redacted"));
    }

    #[test]
    fn wipe_clears() {
        let mut s = SecretString::from_str("secret").unwrap();
        s.wipe();
        assert!(s.is_wiped());
        assert_eq!(s.expose(), "");
    }

    #[test]
    fn invalid_utf8_rejected() {
        assert_eq!(
            SecretString::from_utf8(vec![0xff, 0xfe]).err(),
            Some(Error::InvalidUtf8)
        );
    }

    #[test]
    fn push_str_keeps_utf8() {
        let mut s = SecretString::new().unwrap();
        s.push_str("h\u{00e9}").unwrap();
        s.push_str("llo").unwrap();
        assert_eq!(s.expose(), "h\u{00e9}llo");
    }
}
