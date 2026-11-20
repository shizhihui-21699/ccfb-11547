//! Portable fallback backend: a page-aligned heap allocation.
//!
//! No guard pages, no `mlock`, no fork isolation, no dump exclusion. Only the
//! zeroizing contract holds. Use this on platforms without a real backend and
//! read [`crate::capabilities`] before trusting anything stronger.

use crate::sys::Mapping;

/// Whether a forked child sees the ranges this backend creates.
///
/// Linux sets `MADV_WIPEONFORK`, which zeroes the child's view, but the mapping
/// still exists there and the `atfork` wipe must run to cover kernels that
/// ignore the advice.
pub(crate) static CHILD_INHERITS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);
use crate::{Capabilities, Error, Result};

#[inline]
pub(crate) fn page_size() -> usize {
    // A conservative power of two. This backend does not actually need page
    // alignment; it is reported so callers doing their own arithmetic stay
    // consistent.
    4096
}

pub(crate) fn map_guarded(usable: usize) -> Result<Mapping> {
    let page = page_size();
    let usable = usable.max(1);
    let layout =
        std::alloc::Layout::from_size_align(usable, page).map_err(|_| Error::TooLarge)?;
    // SAFETY: layout has non-zero size, guaranteed above.
    let base = unsafe { std::alloc::alloc_zeroed(layout) };
    if base.is_null() {
        return Err(Error::Map(0));
    }
    let mapped = usable;
    Ok(Mapping { ptr: base, usable, mapped })
}

pub(crate) fn lock(_ptr: *mut u8, _len: usize) -> Result<()> {
    Err(Error::Lock(0))
}

pub(crate) fn unmap(base: *mut u8, mapped: usize, _usable: usize, _locked: bool) {
    if base.is_null() || mapped == 0 {
        return;
    }
    let layout = std::alloc::Layout::from_size_align(mapped, page_size()).expect("layout");
    // SAFETY: base came from `std::alloc::alloc_zeroed` with this layout.
    unsafe { std::alloc::dealloc(base, layout) };
}

pub(crate) fn capabilities() -> Capabilities {
    Capabilities {
        can_lock: false,
        fork_isolation: false,
        dump_exclusion: false,
        kernel_zero_on_abnormal_exit: false,
    }
}

/// There is no portable way to suppress core dumps; report failure so callers
/// know the guarantee is missing.
pub(crate) fn disable_core_dumps() -> bool {
    false
}

/// Whether the range is resident; unknowable without OS support.
pub fn is_resident(_ptr: *const u8, _len: usize) -> Option<bool> {
    None
}

/// Overwrite `len` bytes at `p` with zeroes, non-elidably.
///
/// # Safety
/// `p` must be valid for writes of `len` bytes.
pub(crate) unsafe fn wipe_bytes(p: *mut u8, len: usize) {
    // SAFETY: caller guarantees validity. Volatile writes cannot be elided.
    unsafe {
        let mut i = 0;
        while i < len {
            std::ptr::write_volatile(p.add(i), 0u8);
            i += 1;
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
