//! `memcanary` — prove (or disprove) that a secret was wiped.
//!
//! A wiping library makes claims. This crate measures them: it walks the
//! process's own address space, reads every readable page, and looks for the
//! bytes of secrets you tell it about.
//!
//! # How it works
//!
//! On macOS the scan goes through Mach (`mach_vm_region_recurse` +
//! `mach_vm_read_overwrite`), which can read the process's *own* address space
//! without `ptrace` and without stopping threads — exactly the mechanism a
//! debugger or a crash reporter uses, which is why it is the right lens.
//!
//! On Linux it parses `/proc/self/maps` and copies via `process_vm_readv`.
//!
//! # Patterns, not plaintext
//!
//! You never hand the auditor the literal secret. You register a
//! [`Needle`] built from a *fingerprint*: the secret is expanded into several
//! derivations (plaintext, hex, base64, URL-encoded, SHA-256) inside protected
//! memory, and only their SHA-256 digests are kept for matching. The scan
//! hashes windows of memory and compares digests, so the auditor's own state
//! contains no copy of the value either.
//!
//! # Honest scoping
//!
//! * Matching is exact for the derivations you registered. A secret
//!   transformed some other way (compressed, encrypted under a key the auditor
//!   does not know, re-encoded with a custom alphabet) is not found.
//! * Very short needles (< 8 bytes) are reported as `Weak` rather than
//!   `Found` by default, because random bytes collide.
//! * The scan is advisory evidence, not a proof: absence of the bytes you
//!   searched for is not absence of every trace.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use memcanary::{Auditor, Needle};
//! use secretmem::SecretBytes;
//!
//! let mut auditor = Auditor::new()?;
//! {
//!     let secret = SecretBytes::from_slice(b"correct horse battery staple")?;
//!     auditor.watch(Needle::label("db-password").from_bytes(secret.expose())?);
//! } // dropped and wiped here
//!
//! let report = auditor.scan()?;
//! assert!(report.is_clean(), "residue found: {report}");
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod needle;
mod report;
mod scan;

pub use needle::{Derivation, Needle};
pub use report::{Finding, Provenance, RegionKind, Report, ScanRegion};
pub use scan::{Auditor, AuditorOptions, ScanStats};

use std::fmt;

/// Errors from building needles or running a scan.
#[derive(Debug)]
pub enum Error {
    /// A needle could not be built (empty input, encoding failure).
    Needle(String),
    /// The platform's region enumeration failed.
    Scan(String),
    /// The platform cannot scan its own memory (no backend).
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Needle(m) => write!(f, "needle: {m}"),
            Error::Scan(m) => write!(f, "scan: {m}"),
            Error::Unsupported => f.write_str("memory scanning is not supported on this platform"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
