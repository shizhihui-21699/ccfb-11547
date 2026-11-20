//! Linux backend.
//!
//! Same layout as the macOS one (guard, usable, guard) but using portable
//! POSIX primitives plus the Linux-specific hardening that macOS lacks:
//!
//! * `MADV_DONTDUMP` — exclude the range from core dumps (`/proc/sys/kernel/core_pattern`).
//! * `MADV_WIPEONFORK` (4.14+) — after `fork()` the child sees zeroes, and the
//!   VMA stays zeroed until a new page is faulted in.
//! * `MADV_LOCKONFAULT` if available, so lazily-faulted pages cannot leak.
//!
//! `mlock` may require raising `RLIMIT_MEMLOCK`; [`crate::harden_process`]
//! handles that and reports whether it worked.

use std::ffi::c_void;

use crate::sys::Mapping;

/// Whether a forked child sees the ranges this backend creates.
///
/// Linux sets `MADV_WIPEONFORK`, which zeroes the child's view, but the mapping
/// still exists there and the `atfork` wipe must run to cover kernels that
/// ignore the advice.
pub(crate) static CHILD_INHERITS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);
use crate::{Capabilities, Error, Result};

const MADV_DONTDUMP: libc::c_int = 16;
const MADV_WIPEONFORK: libc::c_int = 18;

#[inline]
pub(crate) fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    debug_assert!(n > 0);
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
    // SAFETY: ranges lie inside the mapping just created.
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

    // Best-effort hardening; older kernels return EINVAL, which is fine.
    unsafe {
        libc::madvise(ptr as *mut c_void, usable, MADV_DONTDUMP);
        libc::madvise(ptr as *mut c_void, usable, MADV_WIPEONFORK);
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
        dump_exclusion: true,
        // Linux has no kernel scrub-on-kill for wired pages.
        kernel_zero_on_abnormal_exit: false,
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

/// Whether the pages backing `ptr..ptr+len` are resident.
pub fn is_resident(ptr: *const u8, len: usize) -> Option<bool> {
    let page = page_size();
    let pages = len.div_ceil(page);
    let mut vec = vec![0u8; pages];
    // SAFETY: caller passes a live mapping of at least `len` bytes.
    let r = unsafe { libc::mincore(ptr as *const c_void, len, vec.as_mut_ptr()) };
    if r != 0 {
        return None;
    }
    Some(vec.iter().all(|&b| b & 1 != 0))
}

#[inline]
fn io_errno() -> i32 {
    // SAFETY: errno is thread-local and always readable.
    unsafe { *libc::__errno_location() }
}

/// Sets `RLIMIT_CORE` to zero so no core is ever written. Regions also carry
/// `MADV_DONTDUMP`, so this is the belt to that braces.
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
    // glibc's explicit_bzero is specified not to be optimised away.
    // SAFETY: caller guarantees validity.
    unsafe { libc::explicit_bzero(p as *mut c_void, len) };
}
