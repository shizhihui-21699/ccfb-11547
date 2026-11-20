//! Needles: the fingerprints the auditor searches for.
//!
//! The auditor must not itself hold the secret in plaintext — otherwise the
//! measuring instrument is another leak. Each [`Needle`] is therefore built by
//! deriving several encodings of the secret *inside protected memory*, reducing
//! each to a pair of fingerprints, and wiping the derivation immediately.
//!
//! What survives in the auditor:
//!
//! * the byte length of each derivation,
//! * a 64-bit rolling hash (prefilter),
//! * a SHA-256 digest (confirmation).
//!
//! Neither can be inverted to the secret, and both are only ever compared
//! against a window of memory that is already being scanned.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use secretmem::SecretBytes;

use crate::{Error, Result};

/// Per-auditor key for HMAC-SHA256.
///
/// Every digest the scanner looks for is keyed with this. Two consequences
/// matter:
///
/// - The auditor can never match its own bookkeeping. A fingerprint's value is
///   `HMAC(salt, derived_bytes)`; even when the derivation *is* a SHA-256 digest
///   (the `Sha256Raw`/`Sha256Hex` derivations), that digest is not the same value
///   as the keyed digest stored for the `Raw` derivation, so the auditor's own
///   tables do not look like a leak.
/// - The digests cannot be compared against a precomputed table of common
///   secrets: without the salt, a rainbow table is useless.
pub(crate) struct Salt {
    key: [u8; 32],
}

impl Salt {
    /// Draws a fresh salt from the OS CSPRNG.
    pub(crate) fn random() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)
            .map_err(|e| Error::Needle(format!("no CSPRNG for the auditor salt: {e}")))?;
        Ok(Salt { key })
    }

    /// Keyed digest of a window of memory.
    pub(crate) fn digest(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key)
            .expect("HMAC accepts keys of any length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

impl Drop for Salt {
    fn drop(&mut self) {
        // Best effort: the salt is not the secret, but wiping it keeps the
        // auditor's own state free of long-lived key material.
        for b in &mut self.key {
            // SAFETY: writing through a reference we exclusively own.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

/// One encoded form of a secret that the scan looks for.
///
/// Services leak secrets in whatever form they were stored or transmitted, so
/// the auditor checks the forms that actually show up in dumps: raw bytes, hex,
/// base64, URL-encoded, and the digest itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Derivation {
    /// The bytes as given.
    Raw,
    /// Lowercase hex.
    HexLower,
    /// Uppercase hex.
    HexUpper,
    /// Standard base64 (with `=` padding).
    Base64,
    /// URL-safe base64 (no padding).
    Base64Url,
    /// Percent-encoded, as it appears in URLs and form bodies.
    UrlEncoded,
    /// The raw 32-byte SHA-256 digest of the bytes.
    Sha256Raw,
    /// The lowercase hex SHA-256 digest of the bytes.
    Sha256Hex,
}

impl Derivation {
    /// All derivations, in the order the auditor checks them.
    pub const ALL: [Derivation; 8] = [
        Derivation::Raw,
        Derivation::HexLower,
        Derivation::HexUpper,
        Derivation::Base64,
        Derivation::Base64Url,
        Derivation::UrlEncoded,
        Derivation::Sha256Raw,
        Derivation::Sha256Hex,
    ];

    /// Human-readable name, used in reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Derivation::Raw => "raw",
            Derivation::HexLower => "hex-lower",
            Derivation::HexUpper => "hex-upper",
            Derivation::Base64 => "base64",
            Derivation::Base64Url => "base64url",
            Derivation::UrlEncoded => "url-encoded",
            Derivation::Sha256Raw => "sha256-raw",
            Derivation::Sha256Hex => "sha256-hex",
        }
    }
}

/// A fingerprint of one derivation of one secret.
///
/// Holds no secret: only a length, a 32-bit anchor (the first four bytes folded
/// into a lookup key), and a SHA-256 digest. The anchor makes the scan a single
/// O(bytes) pass; the digest confirms a candidate so an anchor collision is not
/// a false finding.
#[derive(Clone)]
pub(crate) struct Fingerprint {
    pub derivation: Derivation,
    pub len: usize,
    /// Folded rolling hash of the first four bytes, or `None` for short
    /// derivations (which are searched naively).
    pub anchor: Option<u32>,
    /// SHA-256 of the whole derivation, used to confirm a candidate.
    pub digest: [u8; 32],
}

/// Rolling-hash base used by both fingerprinting and scanning. Must match
/// `scan::ANCHOR_BASE`.
pub(crate) const ANCHOR_BASE: u64 = 0x9E37_79B9_7F4A_7C15;
/// Anchor width in bytes.
pub(crate) const ANCHOR_LEN: usize = 4;

/// Folds four bytes into the 32-bit anchor key the scan's hash table uses.
#[inline]
pub(crate) fn anchor_key(bytes: &[u8]) -> u32 {
    debug_assert!(bytes.len() >= ANCHOR_LEN);
    let mut h: u64 = 0;
    for &b in &bytes[..ANCHOR_LEN] {
        h = h.wrapping_mul(ANCHOR_BASE).wrapping_add(b as u64 + 1);
    }
    (h as u32) ^ ((h >> 32) as u32)
}

/// A labelled secret the auditor searches for.
///
/// Construct with [`Needle::label`] then one `from_*` method. The label is what
/// appears in reports; it must not itself be sensitive.
///
/// ```
/// # use memcanary::Needle;
/// let n = Needle::label("db-password").from_bytes(b"hunter2").unwrap();
/// assert_eq!(n.name(), "db-password");
/// assert!(n.len() >= 1);
/// ```
pub struct Needle {
    label: String,
    /// Longest derivation length; the scan window is this wide.
    max_len: usize,
    /// Set when any derivation is shorter than the "strong" threshold.
    weak: bool,
    pub(crate) prints: Vec<Fingerprint>,
    /// Keyed with the auditor's salt; never leaves this struct.
    pub(crate) salt: Salt,
}

/// Derivation lengths below this are flagged as weak: a random 4-byte sequence
/// occurs by chance often enough to make a hit ambiguous.
pub const STRONG_MIN_LEN: usize = 12;

impl Needle {
    /// Starts a needle with a report label.
    ///
    /// # Panics
    /// Panics if the OS CSPRNG is unavailable. Use [`Needle::try_label`] to
    /// handle that instead of panicking.
    pub fn label(label: impl Into<String>) -> Self {
        Self::try_label(label).expect("OS CSPRNG unavailable for the auditor salt")
    }

    /// Like [`Needle::label`] but reports a missing CSPRNG.
    pub fn try_label(label: impl Into<String>) -> Result<Self> {
        Ok(Needle {
            label: label.into(),
            max_len: 0,
            weak: false,
            prints: Vec::new(),
            salt: Salt::random()?,
        })
    }

    /// Builds fingerprints for every derivation the scan supports.
    ///
    /// `bytes` is the secret. It is copied into protected memory for each
    /// derivation and wiped before this returns; the caller's slice is not
    /// touched.
    pub fn from_bytes(self, bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::Needle("secret is empty".into()));
        }
        self.build(|d| derive(d, bytes))
    }

    /// Builds fingerprints for a text secret.
    pub fn from_str(self, s: &str) -> Result<Self> {
        self.from_bytes(s.as_bytes())
    }

    fn build<F>(mut self, mut derive: F) -> Result<Self>
    where
        F: FnMut(Derivation) -> Result<SecretBytes>,
    {
        for d in Derivation::ALL {
            // The derivation lives in protected memory only for as long as it
            // takes to fingerprint it.
            let derivation = derive(d)?;
            let len = derivation.len();
            if len == 0 {
                continue;
            }
            let anchor = if len >= ANCHOR_LEN { Some(anchor_key(derivation.expose())) } else { None };
            let digest = self.salt.digest(derivation.expose());
            drop(derivation); // wipes
            if len < STRONG_MIN_LEN {
                self.weak = true;
            }
            self.max_len = self.max_len.max(len);
            self.prints.push(Fingerprint { derivation: d, len, anchor, digest });
        }
        if self.prints.is_empty() {
            return Err(Error::Needle("no derivations produced".into()));
        }
        Ok(self)
    }

    /// The report label.
    pub fn name(&self) -> &str {
        &self.label
    }

    /// Longest derivation, which is the scan window width for this needle.
    pub fn len(&self) -> usize {
        self.max_len
    }

    /// Always `false`: a needle with no derivations is rejected at construction.
    pub fn is_empty(&self) -> bool {
        self.max_len == 0
    }

    /// Whether any derivation is short enough that a hit may be coincidence.
    pub fn is_weak(&self) -> bool {
        self.weak
    }

    /// Number of derivations being searched.
    pub fn derivations(&self) -> usize {
        self.prints.len()
    }

    /// The keyed digest function for this needle, used to confirm a candidate.
    #[inline]
    pub(crate) fn digest(&self, window: &[u8]) -> [u8; 32] {
        self.salt.digest(window)
    }
}

impl std::fmt::Debug for Needle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Needle")
            .field("label", &self.label)
            .field("derivations", &self.prints.len())
            .field("max_len", &self.max_len)
            .finish()
    }
}

/// Produce one derivation of `bytes`, held in protected memory.
fn derive(d: Derivation, bytes: &[u8]) -> Result<SecretBytes> {
    let map_err = |_e: secretmem::Error| Error::Needle("allocation failed".into());
    match d {
        Derivation::Raw => SecretBytes::from_slice(bytes).map_err(map_err),
        Derivation::HexLower => SecretBytes::from_slice(hex(bytes, false).as_bytes()).map_err(map_err),
        Derivation::HexUpper => SecretBytes::from_slice(hex(bytes, true).as_bytes()).map_err(map_err),
        Derivation::Base64 => {
            SecretBytes::from_slice(base64(bytes, false, true).as_bytes()).map_err(map_err)
        }
        Derivation::Base64Url => {
            SecretBytes::from_slice(base64(bytes, true, false).as_bytes()).map_err(map_err)
        }
        Derivation::UrlEncoded => {
            SecretBytes::from_slice(url_encode(bytes).as_bytes()).map_err(map_err)
        }
        Derivation::Sha256Raw => {
            let digest = Sha256::digest(bytes);
            SecretBytes::from_slice(digest.as_slice()).map_err(map_err)
        }
        Derivation::Sha256Hex => {
            let digest = Sha256::digest(bytes);
            SecretBytes::from_slice(hex(digest.as_slice(), false).as_bytes()).map_err(map_err)
        }
    }
}

fn hex(bytes: &[u8], upper: bool) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let (hi, lo) = (b >> 4, b & 0xF);
        for nib in [hi, lo] {
            let c = if nib < 10 {
                b'0' + nib
            } else if upper {
                b'A' + (nib - 10)
            } else {
                b'a' + (nib - 10)
            };
            out.push(c as char);
        }
    }
    out
}

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64(bytes: &[u8], url: bool, pad: bool) -> String {
    let table = if url { B64_URL } else { B64_STD };
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        match chunk.len() {
            1 => {
                if pad {
                    out.push('=');
                    out.push('=');
                }
            }
            2 => {
                out.push(table[((n >> 6) & 63) as usize] as char);
                if pad {
                    out.push('=');
                }
            }
            _ => {
                out.push(table[((n >> 6) & 63) as usize] as char);
                out.push(table[(n & 63) as usize] as char);
            }
        }
    }
    out
}

fn url_encode(bytes: &[u8]) -> String {
    const HEXU: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(HEXU[(b >> 4) as usize] as char);
            out.push(HEXU[(b & 0xF) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_base64_are_correct() {
        assert_eq!(hex(b"\x00\x0f\xff", false), "000fff");
        assert_eq!(hex(b"\x00\x0f\xff", true), "000FFF");
        assert_eq!(base64(b"Man", false, true), "TWFu");
        assert_eq!(base64(b"Ma", false, true), "TWE=");
        assert_eq!(base64(b"M", false, true), "TQ==");
        assert_eq!(base64(b"\xff\xfe\xfd", true, false), "__79");
    }

    #[test]
    fn url_encoding() {
        assert_eq!(url_encode(b"a b&c"), "a+b%26c");
        assert_eq!(url_encode(b"~.-_"), "~.-_");
    }

    #[test]
    fn anchor_key_is_stable() {
        assert_eq!(anchor_key(b"abcd"), anchor_key(b"abcd"));
        assert_ne!(anchor_key(b"abcd"), anchor_key(b"abce"));
        // Only the first four bytes matter.
        assert_eq!(anchor_key(b"abcdef"), anchor_key(b"abcd"));
    }

    #[test]
    fn needle_has_all_derivations() {
        let n = Needle::label("k").from_bytes(b"hunter2!").unwrap();
        assert_eq!(n.derivations(), Derivation::ALL.len());
        assert!(n.is_weak()); // 7 bytes < STRONG_MIN_LEN
        let n2 = Needle::label("k").from_bytes(b"a-long-enough-secret").unwrap();
        assert!(!n2.is_weak());
    }

    #[test]
    fn debug_never_shows_the_secret() {
        let n = Needle::label("db").from_bytes(b"hunter2!").unwrap();
        let s = format!("{n:?}");
        assert!(!s.contains("hunter2"));
    }
}
