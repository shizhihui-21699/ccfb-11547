//! macOS backend, built on the Mach VM API.
//!
//! One region is laid out:
//!
//! ```text
//!   +--------+----------------+--------+
//!   | guard  |    usable      | guard  |     guard = PROT_NONE
//!   +--------+----------------+--------+
//!   ^        ^                         ^
//!   |        ptr                       ptr+usable+page
//!   munmap base
//! ```
//!
//! Platform facts verified on macOS 26 / arm64 (see `docs/MEMORY-MODEL.md`):
//!
//! * Page size is **16384** on Apple silicon — never hard-code 4096.
//! * `MAP_NOCORE`, `MADV_DONTDUMP`, `MADV_WIPEONFORK` **do not exist**.
//!   Equivalents: `mach_vm_inherit(VM_INHERIT_NONE)` for fork, process-wide
//!   `RLIMIT_CORE = 0` for dumps.
//! * `VM_BEHAVIOR_ZERO_WIRED_PAGES` makes the kernel scrub pages when the
//!   entry is deleted while still wired — the last-resort guarantee when the
//!   process dies without running `Drop`.
//! * `mlock` succeeds unprivileged (`RLIMIT_MEMLOCK` is unlimited).
//! * `memset_s` is available; `explicit_bzero` is not.

use std::ffi::c_void;

use crate::sys::Mapping;
use crate::{Capabilities, Error, Result};

/// Whether a forked child sees the ranges this backend creates.
///
/// `map_guarded` sets `VM_INHERIT_NONE`; if that call fails on some future OS we
/// fall back to "child sees it" so the atfork wipe still runs.
pub(crate) static CHILD_INHERITS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

type KernReturn = libc::c_int;
type MachPort = libc::c_uint;


const VM_INHERIT_NONE: u32 = 2;
const VM_BEHAVIOR_ZERO_WIRED_PAGES: i32 = 7;

extern "C" {
    fn mach_task_self() -> MachPort;
    fn mach_vm_inherit(
        target_task: MachPort,
        address: u64,
        size: u64,
        new_inheritance: u32,
    ) -> KernReturn;
    fn mach_vm_behavior_set(
        target_task: MachPort,
        address: u64,
        size: u64,
        new_behavior: i32,
    ) -> KernReturn;
}

#[inline]
fn task_self() -> MachPort {
    // SAFETY: reads a Mach-initialised constant; no preconditions.
    unsafe { mach_task_self() }
}

#[inline]
pub(crate) fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions; _SC_PAGESIZE cannot fail on Darwin.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    debug_assert!(n > 0 && (n as usize).is_power_of_two());
    n.max(4096) as usize
}

pub(crate) fn map_guarded(usable: usize) -> Result<Mapping> {
    let page = page_size();
    let mapped = usable.checked_add(page * 2).ok_or(Error::TooLarge)?;
    // SAFETY: anonymous private mapping; ownership is exclusively ours.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mapped,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(Error::Map(io_errno()));
    }
    let base = base as *mut u8;

    // Guard pages on both sides. `mprotect` also splits the VM entry so the
    // usable range becomes *its own* entry, which the inherit/behaviour calls
    // below require (they operate on a single entry).
    // SAFETY: both ranges lie inside the mapping just created.
    unsafe {
        if libc::mprotect(base as *mut c_void, page, libc::PROT_NONE) != 0 {
            let e = io_errno();
            libc::munmap(base as *mut c_void, mapped);
            return Err(Error::Map(e));
        }
        if libc::mprotect(base.add(page + usable) as *mut c_void, page, libc::PROT_NONE) != 0 {
            let e = io_errno();
            libc::munmap(base as *mut c_void, mapped);
            return Err(Error::Map(e));
        }
    }
    let ptr = unsafe { base.add(page) };

    // Fork isolation: a child gets no mapping at all. Verified: after fork the
    // child's vm_region scan does not contain the range and reading it faults.
    // Non-fatal on failure: registry-based wipe-on-fork still covers the child.
    // SAFETY: `ptr..ptr+usable` is one VM entry we own.
    let inherit_kr =
        unsafe { mach_vm_inherit(task_self(), ptr as u64, usable as u64, VM_INHERIT_NONE) };
    if inherit_kr != 0 {
        // Could not exclude the range from children: record that the child
        // inherits, so the atfork wipe runs (and is not skipped).
        CHILD_INHERITS.store(true, std::sync::atomic::Ordering::Release);
    }

    // Kernel scrub if the entry is deleted while still wired.
    // SAFETY: same range; behaviour value valid per <mach/vm_behavior.h>.
    unsafe {
        mach_vm_behavior_set(
            task_self(),
            ptr as u64,
            usable as u64,
            VM_BEHAVIOR_ZERO_WIRED_PAGES,
        );
    }

    Ok(Mapping { ptr, usable, mapped })
}

pub(crate) fn lock(ptr: *mut u8, len: usize) -> Result<()> {
    // SAFETY: range belongs to the caller's live mapping.
    let r = unsafe { libc::mlock(ptr as *const c_void, len) };
    if r == 0 {
        Ok(())
    } else {
        Err(Error::Lock(io_errno()))
    }
}

pub(crate) fn unmap(base: *mut u8, mapped: usize, usable: usize, locked: bool) {
    let page = page_size();
    if locked {
        // SAFETY: still mapped and wired.
        unsafe { libc::munlock(base as *const c_void, usable) };
    }
    let start = unsafe { base.sub(page) };
    // SAFETY: `start`/`mapped` describe the original mmap exactly.
    unsafe { libc::munmap(start as *mut c_void, mapped) };
}

pub(crate) fn capabilities() -> Capabilities {
    Capabilities {
        can_lock: probe_mlock(),
        fork_isolation: true,
        // The mechanism exists; whether it is active depends on whether
        // `harden_process` ran in this process.
        dump_exclusion: true,
        kernel_zero_on_abnormal_exit: true,
    }
}

fn probe_mlock() -> bool {
    let page = page_size();
    // SAFETY: one page, released immediately.
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            return false;
        }
        let ok = libc::mlock(p, page) == 0;
        libc::munmap(p, page);
        ok
    }
}

#[inline]
fn io_errno() -> i32 {
    // SAFETY: errno is thread-local and always readable.
    unsafe { *libc::__error() }
}

/// Whether the pages backing `ptr..ptr+len` are currently resident in RAM,
/// per `mincore(2)`. `None` if the call fails (e.g. not a mapped range).
///
/// Used by the auditor to prove a wired page was not quietly evicted.
pub fn is_resident(ptr: *const u8, len: usize) -> Option<bool> {
    let page = page_size();
    let pages = len.div_ceil(page);
    let mut vec = vec![0i8; pages];
    // SAFETY: caller passes a live mapping of at least `len` bytes.
    let r = unsafe { libc::mincore(ptr as *const c_void, len, vec.as_mut_ptr()) };
    if r != 0 {
        return None;
    }
    Some(vec.iter().all(|&b| b & 1 != 0))
}

/// Sets `RLIMIT_CORE` to zero so no core is ever written, whatever the crash.
///
/// Darwin has no per-region "exclude from dump" flag (`MAP_NOCORE` and friends
/// are absent), so the whole process opts out. Returns whether the limit is now
/// zero.
pub(crate) fn disable_core_dumps() -> bool {
    let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: setrlimit with a well-formed struct.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    if rc != 0 {
        return false;
    }
    let mut now = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
    // SAFETY: reading back a valid limit.
    unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut now) };
    now.rlim_cur == 0
}

/// Overwrite `len` bytes at `p` with zeroes, non-elidably.
///
/// # Safety
/// `p` must be valid for writes of `len` bytes.
pub(crate) unsafe fn wipe_bytes(p: *mut u8, len: usize) {
    // `memset_s` is C11 Annex K, shipped specifically so "this wipe must
    // happen" survives the optimiser. smax == n, so the bounds check passes.
    // SAFETY: caller guarantees validity.
    unsafe { libc::memset_s(p as *mut c_void, len, 0, len) };
}
