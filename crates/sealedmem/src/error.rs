//! Error type for `sealedmem`.
//!
//! Errors are deliberately coarse: an allocation problem, a length problem, or a
//! platform call failing. They never carry any part of the secret value.

use core::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// The ways a sealed allocation can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// `mmap` of the page range with guard pages failed.
    OutOfMemory,
    /// The requested length could not be rounded to a valid page range.
    LengthOverflow,
    /// A secret-adjacent length bound was exceeded (e.g. > isize::MAX).
    TooLarge,
    /// `mlock` failed.  *Not* ignored: an unlocked page may be paged out, which
    /// breaks promise 2 and would need to be surfaced to the caller.
    LockFailed {
        /// The `errno` from `mlock`.
        errno: i32,
    },
    /// A `mprotect` of the guard/data pages failed.
    ProtectFailed {
        /// The `errno` from `mprotect`.
        errno: i32,
    },
    /// A Mach-only hardening call failed (e.g. `mach_vm_inherit`).
    MachFailed {
        /// The `kern_return_t` value.
        code: i32,
    },
    /// A wipe path was attempted twice on the same region, which is a bug and
    /// not a memory-safety problem, but must never be silently ignored.
    AlreadyWiped,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OutOfMemory => f.write_str("mmap of a guard-page region failed"),
            Error::LengthOverflow => f.write_str("length overflows the page rounding math"),
            Error::TooLarge => f.write_str("secret exceeds the supported length"),
            Error::LockFailed { errno } => {
                write!(f, "mlock failed (errno {errno}); secret could be paged out")
            }
            Error::ProtectFailed { errno } => write!(f, "mprotect failed (errno {errno})"),
            Error::MachFailed { code } => write!(f, "Mach hardening call failed (kr {code})"),
            Error::AlreadyWiped => f.write_str("region was already wiped"),
        }
    }
}

impl core::error::Error for Error {}
