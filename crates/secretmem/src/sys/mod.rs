//! Platform abstraction. Everything OS-specific lives here.
//!
//! Three backends exist:
//!
//! * `macos` — Mach VM: guard pages, `mlock`, `VM_INHERIT_NONE`,
//!   `VM_BEHAVIOR_ZERO_WIRED_PAGES`.
//! * `linux` — `mmap`+`mprotect`+`mlock`+`MADV_DONTDUMP`+`MADV_WIPEONFORK`.
//! * `portable` — a plain page-aligned heap allocation. No guard pages, no
//!   locking. Only the zeroizing guarantees hold; [`super::capabilities`] says
//!   so.
//!
//! Every backend exposes the same four entry points: `page_size`,
//! `capabilities`, `map_guarded`, `lock`, `unmap`, and `wipe_bytes`.

use crate::{Capabilities, Result};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
use macos as imp;
#[cfg(target_os = "linux")]
use linux as imp;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use portable as imp;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod portable;

#[inline]
pub(crate) fn page_size() -> usize {
    imp::page_size()
}

pub(crate) fn disable_core_dumps() -> bool {
    imp::disable_core_dumps()
}

pub(crate) fn install_fork_wipe() -> bool {
    crate::registry::install_fork_wipe()
}

pub(crate) fn install_fatal_signal_wipe() -> bool {
    signal::install()
}

#[cfg(unix)]
mod signal;

/// A non-unix fallback: nothing to install.
#[cfg(not(unix))]
mod signal {
    pub(crate) fn install() -> bool {
        false
    }
}

pub(crate) fn capabilities() -> Capabilities {
    imp::capabilities()
}

/// Non-elidable overwrite of `len` bytes at `p`. Single funnel so backends
/// cannot drift.
///
/// # Safety
/// `p` must be valid for writes of `len` bytes.
#[inline]
pub(crate) unsafe fn wipe_bytes(p: *mut u8, len: usize) {
    // SAFETY: forwarded from the caller's contract.
    unsafe { imp::wipe_bytes(p, len) }
}

/// Whether the pages covering `ptr..ptr+len` are resident in RAM.
pub(crate) fn is_resident(ptr: *const u8, len: usize) -> Option<bool> {
    imp::is_resident(ptr, len)
}

/// A platform mapping: guard pages around `usable` bytes of caller data.
///
/// Constructed only by the backend. `Region` owns it and is responsible for
/// calling `imp::unmap` exactly once on the values captured at construction.
pub(crate) struct Mapping {
    /// First usable byte (page-aligned).
    pub ptr: *mut u8,
    /// Usable bytes (a whole number of pages).
    pub usable: usize,
    /// Total bytes covering guard + usable, as passed to the OS.
    pub mapped: usize,
}

/// A region that owns its mapping and pours zeros over it on drop.
pub(crate) struct Region {
    ptr: *mut u8,
    usable: usize,
    mapped: usize,
    locked: bool,
}

// SAFETY: the region owns its mapping exclusively. `&mut` is required to read
// or write (see `wipe`/`grow` callers), so `Send`/`Sync` mirror `Box<[u8]>`.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    pub(crate) fn new(usable: usize) -> Result<Self> {
        let page = page_size();
        let usable = crate::region::round_up_pages(usable, page)?;
        let Mapping { ptr, usable, mapped } = imp::map_guarded(usable)?;
        // Best effort: if wiring fails we keep the memory but remember it may
        // be swapped. `harden_process` decides whether that is fatal.
        let locked = imp::lock(ptr, usable).is_ok();
        // If the backend made the range absent in forked children, the atfork
        // wipe must not touch it.
        if imp::CHILD_INHERITS.load(std::sync::atomic::Ordering::Acquire) {
            crate::registry::register(ptr, usable);
        } else {
            crate::registry::register_absent_in_child(ptr, usable);
        }
        Ok(Region { ptr, usable, mapped, locked })
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.usable
    }

    #[inline]
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }

    /// Volatile overwrite of the whole region. Does not free.
    pub(crate) fn wipe(&mut self) {
        // SAFETY: `ptr`/`usable` are valid for the life of `self`.
        unsafe { imp::wipe_bytes(self.ptr, self.usable) };
    }

    /// Move the contents into a fresh, larger region, wiping and freeing the
    /// old one. Never leaves a stale copy behind.
    pub(crate) fn grow(&mut self, new_usable: usize) -> Result<()> {
        let page = page_size();
        let new_usable = crate::region::round_up_pages(new_usable, page)?;
        if new_usable <= self.usable {
            return Ok(());
        }
        let fresh = Region::new(new_usable)?;
        // SAFETY: both regions are valid for their own lengths and disjoint.
        unsafe { std::ptr::copy_nonoverlapping(self.ptr, fresh.ptr, self.usable) };
        // Wipe the old mapping *before* releasing it so nothing readable is
        // ever returned to the OS, then drop (which unregisters and unmaps).
        self.wipe();
        let old = std::mem::replace(self, fresh);
        drop(old);
        Ok(())
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // Order matters: unregister first so a fork racing with this cannot try
        // to wipe memory we are about to unmap, then wipe, then release.
        crate::registry::unregister(self.ptr);
        self.wipe();
        imp::unmap(self.ptr, self.mapped, self.usable, self.locked);
        self.ptr = std::ptr::null_mut();
        self.usable = 0;
        self.mapped = 0;
    }
}
