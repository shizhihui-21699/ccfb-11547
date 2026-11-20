//! `secretmem` — containers for data that must not survive its use.
//!
//! # Threat model this crate addresses
//!
//! Sensitive values (passwords, session keys, private key material) that live in
//! ordinary `String` / `Vec<u8>` buffers leak in several ways that have nothing to
//! do with the code that *uses* them:
//!
//! 1. **Use-after-free residue.** `String`/`Vec` free without clearing, so the
//!    allocator keeps the plaintext and hands it to the next allocation.
//! 2. **Copies.** `clone()`, `to_vec()`, `to_string()`, growth/reallocation, and
//!    even `format!` leave independent copies that nobody tracks.
//! 3. **Swap.** Anonymous pages can be written to swap and stay there.
//! 4. **Core dumps / crash reporters.** They capture the whole address space.
//! 5. **`fork()`.** A child process inherits a full copy-on-write image of the
//!    parent heap, including every secret, and runs arbitrary code from there.
//! 6. **Unwind.** A panic mid-use skips nothing here (Rust runs `Drop`), but an
//!    `abort`/fatal signal bypasses destructors entirely.
//!
//! This crate gives each secret its own page-aligned mapping that is:
//!
//! * surrounded by `PROT_NONE` guard pages (overrun detection),
//! * `mlock(2)`-ed so it is never written to swap,
//! * marked `VM_INHERIT_NONE` (macOS) / `MADV_WIPEONFORK` (Linux) so a forked
//!   child either does not see it or sees only zeroes,
//! * `MADV_DONTDUMP` (Linux) / covered by `RLIMIT_CORE = 0` (see
//!   [`harden_process`]) so it stays out of core dumps,
//! * marked `VM_BEHAVIOR_ZERO_WIRED_PAGES` (macOS), so the kernel scrubs the
//!   wired pages if the process is killed without running destructors,
//! * wiped with volatile writes both on `Drop` and before any remap, and
//! * registered in a lock-free table so `pthread_atfork` children and fatal
//!   signal handlers can wipe everything without allocating.
//!
//! None of that is enough on its own: the only way to know you left no copy is
//! to look. Pair this crate with the `memcanary` auditor and measure.
//!
//! # Non-goals
//!
//! This is *not* a hardware enclave. A process that can read its own memory
//! (a debugger attached with rights, a kernel bug, DMA) can read the plaintext
//! while it is in use. The guarantee is about *residue*: after the value is
//! used and dropped, nothing readable remains, and it never leaves RAM.
//!
//! # Example
//!
//! ```
//! use secretmem::SecretBytes;
//!
//! # fn main() -> secretmem::Result<()> {
//! let mut pw = SecretBytes::from_slice(b"correct horse battery staple")?;
//! // Use it through a borrow; no copy is made.
//! assert_eq!(pw.expose().len(), 28);
//! pw.wipe();                       // explicit, immediate
//! assert!(pw.is_wiped());
//! // Dropping without `wipe()` also wipes.
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod bytes;
mod derive;
mod key;
mod process;
mod region;
mod registry;
mod string;
mod sys;

pub use bytes::{register_scratch, unregister_scratch, SecretBytes};
pub use derive::derive_key;
pub use key::SecretKey;
pub use process::{
    harden_process, hardening_report, is_hardened, HardeningOptions, HardeningReport,
};
pub use registry::{
    fork_wipe_installed, is_absent_in_child, is_protected_address, is_registered,
    protected_ranges, registered_ranges, wipe_all_registered_for_tests,
};
pub use string::SecretString;

/// Whether the pages backing `ptr..ptr+len` are resident in RAM (`mincore`).
///
/// `None` where the platform cannot answer (the portable backend) or the range
/// is not mapped. Intended for the auditor: a locked page must stay resident.
pub fn pages_resident(ptr: *const u8, len: usize) -> Option<bool> {
    sys::is_resident(ptr, len)
}

use std::fmt;

/// Errors raised while creating or growing a protected region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `mmap(2)` failed. Carries the OS error code.
    Map(i32),
    /// `mlock(2)` failed — the OS refused to wire the pages. Depending on
    /// configuration this is fatal; see [`HardeningOptions::require_locked`].
    Lock(i32),
    /// The requested capacity overflowed the page arithmetic.
    TooLarge,
    /// A page-alignment invariant was violated (a bug, not a caller error).
    Misaligned,
    /// The process-wide registry of protected regions is full.
    RegistryFull,
    /// The value cannot be represented (e.g. non-UTF-8 for `SecretString`).
    InvalidUtf8,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Map(e) => write!(f, "mmap failed (errno {e})"),
            Error::Lock(e) => write!(
                f,
                "mlock failed (errno {e}); the pages could be swapped to disk"
            ),
            Error::TooLarge => f.write_str("capacity overflows address arithmetic"),
            Error::Misaligned => f.write_str("internal page-alignment invariant violated"),
            Error::RegistryFull => f.write_str("protected-region registry is full"),
            Error::InvalidUtf8 => f.write_str("value is not valid UTF-8"),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Number of usable bytes in one page of this process's address space.
///
/// Apple silicon uses 16 KiB pages, x86-64 macOS uses 4 KiB, and Linux varies,
/// so never hard-code 4096.
#[inline]
pub fn page_size() -> usize {
    sys::page_size()
}

/// Whether the OS-level hardening (mlock, fork isolation, dump exclusion) is
/// actually in effect for this build and process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capabilities {
    /// Pages can be wired into RAM with `mlock(2)`.
    pub can_lock: bool,
    /// Forked children are kept from reading protected regions.
    pub fork_isolation: bool,
    /// Protected regions are excluded from core dumps.
    pub dump_exclusion: bool,
    /// The kernel scrubs wired pages when the process dies without unwinding.
    pub kernel_zero_on_abnormal_exit: bool,
}

/// Query the hardening actually available on this platform/process.
pub fn capabilities() -> Capabilities {
    sys::capabilities()
}
