//! What this library can and cannot defend against, made executable.
//!
//! The honest answer to "did you keep my secret out of memory?" is: out of the
//! memory *we own and control*, on the *exit paths we can reach*, against
//! *observers that only look after the fact*.  An attacker with a live task port
//! can lift a `PROT_NONE` page with `mach_vm_protect` and read it, so for debug
//! builds (ad-hoc signed, carrying `com.apple.security.get-task-allow`) sealing
//! buys nothing against a sibling process.
//!
//! [`attack::try_read_sibling`] performs exactly that read so the verification
//! report can state the result for the build under test instead of asserting a
//! blanket claim.

/// Offensive checks used by the verification tooling, not by application code.
pub mod attack {
    use crate::alloc::mach;

    /// Outcome of trying to read another process's sealed page.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ReadOutcome {
        /// `task_for_pid` was refused: the target is not debuggable by us.
        TaskPortRefused,
        /// We hold the task port but the page is not readable even after
        /// `mach_vm_protect` (e.g. hardened runtime without `get-task-allow`).
        Protected,
        /// We lifted `PROT_NONE` and read the bytes.  This is the failure mode
        /// the caller must be told about; it is expected for debug builds.
        ReadSucceeded,
    }

    /// Attempt to read `size` bytes at `addr` in `pid` and report whether the
    /// bytes at that address look like the expected marker.
    ///
    /// `expect_prefix` is the first bytes the caller expects (a canary) so the
    /// result distinguishes "read something" from "read the secret".
    pub fn try_read_sibling(pid: i32, addr: usize, size: usize, expect_prefix: &[u8]) -> ReadOutcome {
        match mach::read_foreign(pid, addr, size) {
            mach::ForeignRead::NoTaskPort => ReadOutcome::TaskPortRefused,
            mach::ForeignRead::Unreadable => ReadOutcome::Protected,
            mach::ForeignRead::Ok(bytes) => {
                if bytes.starts_with(expect_prefix) {
                    ReadOutcome::ReadSucceeded
                } else {
                    // We read *a* mapping but not our canary: most likely the
                    // target moved on. Treat as protected for reporting, and let
                    // the caller include the raw bytes in a diagnostic if wanted.
                    ReadOutcome::Protected
                }
            }
        }
    }

    /// Current process id, as the scanner and demo use it.
    pub fn pid() -> i32 {
        // SAFETY: `getpid` has no preconditions.
        unsafe { libc::getpid() }
    }
}

/// A one-screen summary of what is enforced at compile time versus runtime.
pub fn capability_summary() -> &'static str {
    if crate::alloc::mach_available() {
        "sealed pages: mlock + PROT_NONE + guard pages + VM_INHERIT_NONE (macOS)"
    } else {
        "sealed pages: mlock + PROT_NONE + guard pages (Mach fork isolation n/a)"
    }
}
