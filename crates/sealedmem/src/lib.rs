//! `sealedmem` — a small library for holding passwords, keys and session tokens
//! in memory that is engineered to leave no residue.
//!
//! The threat model is **same-user, post-hoc memory inspection**: a crash dump,
//! a core file produced by a debugger or the OS, a child process after `fork`,
//! a swap file, or a later allocation that recycles the same physical pages.
//! Within that model the library makes the following promises, each backed by a
//! concrete mechanism (see `docs/THREAT-MODEL.md`):
//!
//! 1. **Every copy lives in its own dedicated page range.**  Segments are
//!    `mmap(MAP_ANON|MAP_PRIVATE)` allocations with two guard pages, page-aligned,
//!    so no other Rust allocation can share a page with secret bytes.
//! 2. **Never swapped out.**  Segments are `mlock(2)`-ed. A further
//!    `madvise(MADV_DONTNEED)`-free seal step is unnecessary because locked pages
//!    are not eligible for the pager.
//! 3. **Not inherited across `fork`.**  Segments are `mach_vm_inherit(VM_INHERIT_NONE)`.
//!    A forked child gets an unmapped hole at that address and faults if it touches it.
//! 4. **Excluded from core dumps while at rest.**  At rest a segment is
//!    `PROT_NONE`; on this platform a `PROT_NONE` page range is not written to a
//!    core file (`lldb process save-core`, default or `--full`, and the kernel core
//!    path), so even an explicit crash dump contains only zeros for the secret's
//!    address range.  Readable (`PROT_READ|PROT_WRITE`) mappings *are* dumped, even
//!    when `mlock`ed — that is the key empirical result behind the design.
//! 5. **Wiped on every exit path.**  `Drop`, panic-unwind, a fatal-signal handler
//!    (`SIGSEGV`/`SIGBUS`/`SIGABRT`/`SIGILL`/`SIGFPE`), `atexit`, and explicit
//!    calls all funnel through the same `wipe` routine, which overwrites with
//!    volatile stores, `madvise(MADV_ZERO)`s the pages, `munlock`s and `munmap`s.
//! 6. **No copies in `Copy`/`Clone`/grow/format paths.**  The type is not `Copy`,
//!    `Clone` is explicit and creates a second independent sealed segment (never a
//!    shared heap buffer), growth reallocates into a new segment and wipes the old
//!    one, and `Debug`/`Display` print a redacted form.
//!
//! What this library *cannot* do, and says so plainly:
//! - It cannot stop a same-user attacker who can `ptrace` your process.  On macOS
//!   the relevant permission is `com.apple.security.get-task-allow`; a binary with
//!   that entitlement (including every ad-hoc-signed debug build) can be read by a
//!   sibling process, which may `mach_vm_protect` a `PROT_NONE` region and read it.
//!   The library detects "somebody else holds our task port" only through the
//!   observable side effects of a *write* attempt; see `sealedmem::exposure`.
//! - It cannot scrub the OS's own copy of `argv`/`environ` until you call
//!   [`scrub::scrub_env_var`] (or [`scrub::scrub_argv`]); until then the kernel's
//!   per-pid copy is visible through `KERN_PROCARGS2`.
//! - It cannot stop a compiler from keeping the *input* copy alive in a register or
//!   stack slot if you hand it a `&str` from outside.  Feed secrets directly into
//!   [`SealedString`] / [`SealedBytes`] and never into a normal `String`.
//!
//! # Quick start
//!
//! ```
//! use sealedmem::{SealedBytes, SealedString};
//!
//! // Build from an external value; the input's own storage is the caller's
//! // problem, so pass owned/scrubbed values at the boundary.
//! let mut password = SealedString::from_utf8(b"hunter2")?;
//! assert_eq!(password.len(), 7);
//! // At rest the bytes are sealed (PROT_NONE).  These borrows unseal for the
//! // closure only and re-seal on return, including on panic.
//! password.with_str(|p| assert_eq!(p, "hunter2"));
//! password.with_bytes(|p| assert_eq!(p, b"hunter2"));
//! assert!(password.eq_ct("hunter2"));
//! // Explicit wipe, or let Drop do it.
//! password.wipe();
//!
//! // The no-intermediate-copy path: the caller writes straight into the sealed
//! // page, so no `String`/`Vec` ever holds the value.
//! let key = SealedBytes::from_callback(64, |dst| {
//!     dst[..16].copy_from_slice(&[7u8; 16]);
//!     16
//! })?;
//! key.with(|k| assert_eq!(k.len(), 16));
//! # Ok::<(), sealedmem::Error>(())
//! ```
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs, unreachable_pub)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[allow(unreachable_pub)]
mod alloc;
mod error;
mod region;
mod sealed;
pub mod exposure;
pub mod guard;
pub mod scrub;

pub use error::{Error, Result};
pub use region::{Region, RegionStats};
pub use sealed::{SealedBytes, SealedString};

/// Diagnostics that are useful to a verification harness but have no place in
/// the application-facing API.  Kept in one module so the main surface stays
/// small and reviewable.
pub mod diag {
    /// Number of regions the process could not register with the sweepers
    /// because the fixed table filled up.
    pub fn registry_overflowed() -> usize {
        crate::region::registry_overflowed()
    }

    /// Number of live (unwiped) registered regions.
    pub fn live_regions() -> usize {
        crate::region::live_regions()
    }

    /// Human-readable text for a `kern_return_t`.
    pub fn mach_error_string(kr: i32) -> &'static str {
        crate::alloc::mach::err_string(kr)
    }

    /// Share mode reported for a region (1 COW, 2 private, 5 shared, 6 aliased).
    /// `None` off Mach platforms.
    pub fn share_mode_of(addr: usize) -> Option<u8> {
        crate::alloc::mach::region_info(addr).map(|i| i.share_mode)
    }

    /// Whether this build has Mach-backed guarantees.
    pub fn mach_available() -> bool {
        crate::alloc::mach_available()
    }

    /// Wipe every registered region now.  For tests and harnesses only; calling
    /// it while regions are still in use makes them empty, not unsafe.
    pub fn sweep_all() {
        crate::region::sweep_all()
    }

    /// Fill an existing region's whole page range and set its logical length.
    /// A harness hook for residue tests; not part of the application API because
    /// it lets a caller write more bytes than a `SealedBytes` would expose.
    pub fn fill_region(r: &mut crate::Region, len: usize, f: impl FnOnce(&mut [u8])) {
        r.fill(len, f);
        r.set_used(len);
    }
}

/// Re-exported so downstream crates can name the wiping trait when they need to
/// chain their own types into our drop paths.
pub use zeroize::Zeroize;
