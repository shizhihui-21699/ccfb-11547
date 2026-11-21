//! The page-level primitive: [`Region`].
//!
//! A `Region` owns a private anonymous mapping laid out as
//!
//! ```text
//!  [ guard page | data page 0 | data page 1 | ... | guard page ]
//!    PROT_NONE      data (sealed at rest)                PROT_NONE
//! ```
//!
//! The guard pages exist so that an off-by-one in a caller's slice maths faults
//! instead of silently reading a neighbouring allocation; they also keep the
//! data pages from sharing a page with anything else.  The data pages are
//! `mlock`ed, marked `VM_INHERIT_NONE`, and left `PROT_NONE` until a scoped
//! view is requested.  See the crate docs for the empirical basis.

use core::fmt;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::error::{Error, Result};

/// Maximum number of simultaneously live regions that can be tracked by the
/// fatal-signal and `atexit` sweepers.  Slots are never reused after a wipe, so
/// a stale address can never be dereferenced.  When the table is full, newly
/// created regions are still wiped by their own `Drop`; they are only invisible
/// to the sweepers.  [`registry_overflowed`] reports that and the demo surfaces it.
pub(crate) const REGISTRY_SLOTS: usize = 512;

// Slot states.  Exactly one wiper can claim a `LIVE` slot.
const SLOT_FREE: u8 = 0;
const SLOT_LIVE: u8 = 1;
const SLOT_WIPING: u8 = 2;
const SLOT_WIPED: u8 = 3;

struct Slot {
    addr: AtomicUsize,
    /// Length of the data pages, guards excluded.
    len: AtomicUsize,
    state: AtomicU8,
}

impl Slot {
    const fn new() -> Self {
        Self {
            addr: AtomicUsize::new(0),
            len: AtomicUsize::new(0),
            state: AtomicU8::new(SLOT_FREE),
        }
    }
}

/// Global list of live regions.  Lock-free on purpose: a fatal-signal handler
/// cannot take a mutex, so sweepers use CAS on per-slot state.
static REGISTRY: [Slot; REGISTRY_SLOTS] = [const { Slot::new() }; REGISTRY_SLOTS];

static REGISTRY_OVERFLOW: AtomicUsize = AtomicUsize::new(0);

/// Number of regions that could not be registered because [`REGISTRY_SLOTS`]
/// was exhausted.  Non-zero means the sweepers have blind spots.
pub(crate) fn registry_overflowed() -> usize {
    REGISTRY_OVERFLOW.load(Ordering::Relaxed)
}

/// Number of registry slots currently `LIVE`.
pub(crate) fn live_regions() -> usize {
    REGISTRY
        .iter()
        .filter(|s| s.state.load(Ordering::Acquire) == SLOT_LIVE)
        .count()
}

/// Public, kernel-derived statistics about one region.  The verification tool
/// prints these to prove the promises mechanically rather than by assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegionStats {
    /// Number of data pages (guard pages excluded).
    pub data_pages: usize,
    /// Bytes the caller considers live in those pages.
    pub bytes_used: usize,
    /// `user_wired_count` reported by `vm_region_recurse` for the data range.
    pub wired: bool,
    /// Current protection of the data range (`true` == sealed / `PROT_NONE`).
    pub sealed: bool,
    /// Inheritance attribute as reported by the kernel (`2` == `VM_INHERIT_NONE`).
    pub inheritance: u32,
}

/// A sealed, locked, fork-isolated page range that holds secret bytes.
///
/// Not `Clone`, not `Copy`.  Dropping it wipes it.  The only way to read the
/// bytes is a scoped [`with`](Region::with) / [`with_mut`](Region::with_mut)
/// view; the pages are readable for the duration of the view and re-sealed on
/// exit, including on panic.
pub struct Region {
    /// Start of the first guard page (the `mmap` base).
    base: *mut u8,
    /// Number of data pages.
    data_pages: usize,
    /// Bytes the caller has stored; always `<= data_pages * PAGE`.
    used: usize,
    /// Registry slot index, or `None` when the registry was full.
    slot: Option<usize>,
    /// Set once wiped; further access becomes a no-op error, never UB.
    wiped: bool,
}

// SAFETY: `Region` owns a private mapping that is only accessible through
// `&mut self` or the `&self` scoped views.  Moving it between threads keeps a
// single owner, so `Send` is sound.  It is deliberately **not** `Sync`: two
// threads holding `&Region` would race the unseal/re-seal pair.
unsafe impl Send for Region {}

impl fmt::Debug for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Region")
            .field("data_pages", &self.data_pages)
            .field("bytes", &self.used)
            .field("wiped", &self.wiped)
            .finish_non_exhaustive()
    }
}

/// Page size on the running system, cached.
fn page_size() -> usize {
    static PAGE: AtomicUsize = AtomicUsize::new(0);
    let p = PAGE.load(Ordering::Relaxed);
    if p != 0 {
        return p;
    }
    // SAFETY: `sysconf(_SC_PAGESIZE)` has no preconditions.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let p = if p > 0 { p as usize } else { 16 * 1024 };
    PAGE.store(p, Ordering::Relaxed);
    p
}

impl Region {
    /// Create a region able to hold at least `len` bytes.  It starts zeroed and
    /// sealed.
    pub fn new(len: usize) -> Result<Self> {
        let page = page_size();
        let data_bytes = len.max(1);
        let pages = data_bytes
            .checked_add(page - 1)
            .ok_or(Error::LengthOverflow)?
            / page;
        let total_pages = pages.checked_add(2).ok_or(Error::LengthOverflow)?;
        let total = total_pages.checked_mul(page).ok_or(Error::LengthOverflow)?;

        // SAFETY: plain anonymous private mapping; flags are constants.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if base.is_null() || base == libc::MAP_FAILED.cast() {
            return Err(Error::OutOfMemory);
        }
        let base = base.cast::<u8>();
        // SAFETY: `base` heads a `total`-byte mapping.
        let data = unsafe { base.add(page) };
        let data_len = pages * page;

        // Guard pages.
        // SAFETY: both guard ranges are inside the mapping we just made.
        let guard_a = unsafe { libc::mprotect(base.cast(), page, libc::PROT_NONE) };
        let guard_b = unsafe { libc::mprotect(data.add(data_len).cast(), page, libc::PROT_NONE) };
        if guard_a != 0 || guard_b != 0 {
            let errno = unsafe { *libc::__error() };
            // SAFETY: we own the mapping.
            unsafe { libc::munmap(base.cast(), total) };
            return Err(Error::ProtectFailed { errno });
        }

        // Wire the data pages so they can never be paged out.
        // SAFETY: `data` points at `data_len` writable mapped bytes.
        let lock = unsafe { libc::mlock(data.cast(), data_len) };
        if lock != 0 {
            let errno = unsafe { *libc::__error() };
            unsafe { libc::munmap(base.cast(), total) };
            return Err(Error::LockFailed { errno });
        }

        // Fork isolation: a child gets no mapping at these addresses.
        #[cfg(target_os = "macos")]
        {
            let kr = crate::alloc::mach::vm_inherit_none(data as usize, data_len);
            if kr != 0 {
                unsafe {
                    libc::munlock(data.cast(), data_len);
                    libc::munmap(base.cast(), total);
                }
                return Err(Error::MachFailed { code: kr });
            }
        }

        // Seal at rest.
        // SAFETY: same range as above.
        if unsafe { libc::mprotect(data.cast(), data_len, libc::PROT_NONE) } != 0 {
            let errno = unsafe { *libc::__error() };
            unsafe {
                libc::munlock(data.cast(), data_len);
                libc::munmap(base.cast(), total);
            }
            return Err(Error::ProtectFailed { errno });
        }

        let slot = register(data as usize, data_len);
        Ok(Self {
            base,
            data_pages: pages,
            used: 0,
            slot,
            wiped: false,
        })
    }

    /// Bytes the caller has stored.
    pub fn len(&self) -> usize {
        self.used
    }

    /// Whether the caller has stored zero bytes.
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Capacity in bytes (page-rounded).
    pub fn capacity(&self) -> usize {
        self.data_pages * page_size()
    }

    /// Read the region through a scoped view.  The pages are unsealed only for
    /// the duration of the closure and re-sealed by a guard, including on panic.
    /// **Any copy made inside the closure lives outside our protection.**
    pub fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        debug_assert!(!self.wiped, "with() on a wiped Region");
        let _guard = self.unseal();
        // SAFETY: the guard unsealed `data..data+capacity`; `used <= capacity`.
        let slice = unsafe { core::slice::from_raw_parts(self.data(), self.used) };
        f(slice)
    }

    /// Mutate the region through a scoped view.  Same exposure rules as
    /// [`with`](Region::with).
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        debug_assert!(!self.wiped, "with_mut() on a wiped Region");
        let _guard = self.unseal();
        // SAFETY: the guard unsealed the pages, and `&self` views are
        // serialised by construction (`Region` is not `Sync`).
        let slice = unsafe { core::slice::from_raw_parts_mut(self.data(), self.used) };
        f(slice)
    }

    /// Internal: mutate `n` bytes (which may exceed `used`) through a scoped view.
    /// Only used to fill a fresh region or to copy into a successor; the caller
    /// must keep `n <= capacity`.
    pub(crate) fn fill<R>(&mut self, n: usize, f: impl FnOnce(&mut [u8]) -> R) -> R {
        debug_assert!(!self.wiped, "fill() on a wiped Region");
        debug_assert!(n <= self.capacity());
        let _guard = self.unseal();
        // SAFETY: the guard unsealed `data..data+capacity`, and `n <= capacity`.
        let slice = unsafe { core::slice::from_raw_parts_mut(self.data(), n) };
        f(slice)
    }

    /// Internal: record how many bytes the caller considers live.  Must not
    /// exceed capacity; callers arrange that.
    pub(crate) fn set_used(&mut self, used: usize) {
        debug_assert!(used <= self.capacity());
        self.used = used.min(self.capacity());
    }

    /// Replace the contents with `bytes`, growing into a **new sealed region**
    /// if needed.  On growth the old region is wiped before it is dropped, so
    /// the previous, possibly shorter, secret never lingers.
    pub fn assign(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.capacity() {
            // Build the successor first, so a failure leaves the current value
            // untouched rather than half-wiped.
            let mut next = Region::new(bytes.len())?;
            let n = bytes.len();
            next.fill(n, |dst: &mut [u8]| dst.copy_from_slice(bytes));
            next.set_used(n);
            let old = core::mem::replace(self, next);
            drop(old); // Drop wipes and unmaps.
            return Ok(());
        }
        let n = bytes.len();
        // `fill` exposes `n` bytes even though the logical length is smaller;
        // `with_mut` deliberately exposes only the current value.
        self.fill(n, |dst: &mut [u8]| dst.copy_from_slice(bytes));
        self.used = n;
        Ok(())
    }

    /// Append one byte, growing geometrically if needed.  Growth allocates a
    /// fresh sealed region, copies the old value **through the scoped views**
    /// (no intermediate heap buffer), then wipes the old region.
    pub fn push_byte(&mut self, b: u8) -> Result<()> {
        if self.used == self.capacity() {
            let bigger = self.capacity().saturating_mul(2).max(page_size());
            let mut next = Region::new(bigger)?;
            // Copy old bytes straight into the new sealed page through two
            // scoped views: no stack or heap buffer ever holds the secret.
            let used = self.used;
            next.fill(used, |dst: &mut [u8]| {
                self.with(|src: &[u8]| dst.copy_from_slice(src));
            });
            next.set_used(used);
            let old = core::mem::replace(self, next);
            drop(old); // Wipes the old pages, so no duplicate secret survives.
        }
        let idx = self.used;
        self.fill(idx + 1, |dst: &mut [u8]| dst[idx] = b);
        self.used = idx + 1;
        Ok(())
    }

    /// Zero, unlock and unmap the region.  Safe to call more than once.
    pub fn wipe(&mut self) -> Result<()> {
        if self.wiped {
            return Ok(());
        }
        let total = (self.data_pages + 2) * page_size();
        // SAFETY: we own the whole mapping.
        unsafe {
            wipe_raw(self.data(), self.data_pages * page_size());
            libc::munmap(self.base.cast(), total);
        }
        self.wiped = true;
        unregister(self.slot);
        self.slot = None;
        Ok(())
    }

    /// Kernel-derived stats, to verify the promises on the running machine.
    pub fn stats(&self) -> Option<RegionStats> {
        if self.wiped {
            return None;
        }
        let info = crate::alloc::mach::region_info(self.data() as usize)?;
        Some(RegionStats {
            data_pages: self.data_pages,
            bytes_used: self.used,
            wired: info.wired,
            sealed: info.protection & 0b011 == 0,
            inheritance: info.inheritance,
        })
    }

    /// Address of the first data byte.  Exposed for the verification tooling;
    /// touching it while sealed faults, which is the point.
    pub fn data_addr(&self) -> usize {
        self.data() as usize
    }

    fn data(&self) -> *mut u8 {
        // SAFETY: `base` heads a mapping `(data_pages + 2)` pages long.
        unsafe { self.base.add(page_size()) }
    }

    fn unseal(&self) -> SealGuard<'_> {
        // SAFETY: data pages are owned and page-aligned; unsealing is idempotent.
        let rc = unsafe {
            libc::mprotect(
                self.data().cast(),
                self.capacity(),
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        debug_assert_eq!(rc, 0, "unsealing an owned region must succeed");
        SealGuard { region: self }
    }
}

struct SealGuard<'a> {
    region: &'a Region,
}

impl Drop for SealGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: same range this guard unsealed.
        unsafe {
            libc::mprotect(
                self.region.data().cast(),
                self.region.capacity(),
                libc::PROT_NONE,
            );
        }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // A panic inside a `with` closure re-seals first (the SealGuard drops
        // before the Region), so we arrive here with a sealed, owned range.
        let _ = self.wipe();
    }
}

/// Core wipe sequence shared by `Drop`, explicit `wipe`, the `atexit` sweeper
/// and the fatal-signal handler.
///
/// Ordering was validated empirically on macOS 26 (see
/// `docs/PLATFORM-NOTES.md`):
/// `mprotect(RW)` → volatile byte overwrite → `madvise(MADV_ZERO)` (zeroes in
/// place, refused on `PROT_NONE`) → `madvise(MADV_ZERO_WIRED_PAGES)` (marks
/// wired pages so the kernel zeroes them when the mapping is deleted) →
/// `munlock`.
///
/// # Safety
/// `data` must point at `len` bytes this crate owns and has not freed.
pub(crate) unsafe fn wipe_raw(data: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: caller guarantees the range.
    unsafe {
        libc::mprotect(data.cast(), len, libc::PROT_READ | libc::PROT_WRITE);
        let mut i = 0;
        while i < len {
            core::ptr::write_volatile(data.add(i), 0u8);
            i += 1;
        }
        libc::madvise(data.cast(), len, libc::MADV_ZERO);
        libc::madvise(data.cast(), len, libc::MADV_ZERO_WIRED_PAGES);
        libc::munlock(data.cast(), len);
    }
}

/// Wipe every registered region from a context that cannot take locks
/// (signal handler / `atexit`).  CAS ensures a region is wiped once, and never
/// concurrently with its owning `Drop`.
pub(crate) fn sweep_all() {
    for slot in REGISTRY.iter() {
        if slot
            .state
            .compare_exchange(SLOT_LIVE, SLOT_WIPING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // SAFETY: the slot only records an address whose `Region` keeps the
            // mapping alive until its own wipe or drop.  We are the sole claimant
            // because of the CAS, and in the signal case the process is dying, so
            // the owner will not free it underneath us.
            unsafe {
                let addr = slot.addr.load(Ordering::Relaxed) as *mut u8;
                let len = slot.len.load(Ordering::Relaxed);
                wipe_raw(addr, len);
            }
            slot.state.store(SLOT_WIPED, Ordering::Release);
        }
    }
}

fn register(addr: usize, len: usize) -> Option<usize> {
    for (i, slot) in REGISTRY.iter().enumerate() {
        if slot
            .state
            .compare_exchange(SLOT_FREE, SLOT_LIVE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.addr.store(addr, Ordering::Relaxed);
            slot.len.store(len, Ordering::Relaxed);
            return Some(i);
        }
    }
    REGISTRY_OVERFLOW.fetch_add(1, Ordering::Relaxed);
    None
}

fn unregister(slot: Option<usize>) {
    if let Some(i) = slot {
        let s = &REGISTRY[i];
        // A signal handler may already have claimed it; the end state is Wiped
        // either way, and slots are never reused.
        let _ = s.state.compare_exchange(
            SLOT_LIVE,
            SLOT_WIPING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        s.state.store(SLOT_WIPED, Ordering::Release);
        s.addr.store(0, Ordering::Relaxed);
        s.len.store(0, Ordering::Relaxed);
    }
}

/// Called from the `pthread_atfork` child hook: the child inherited the registry
/// array but **not** the mappings (`VM_INHERIT_NONE`), so every recorded address
/// is invalid in the child.  Mark all slots dead so the child's signal handler
/// never dereferences them.
pub(crate) fn mark_registry_dead_in_child() {
    for slot in REGISTRY.iter() {
        slot.addr.store(0, Ordering::Release);
        slot.len.store(0, Ordering::Release);
        slot.state.store(SLOT_WIPED, Ordering::Release);
    }
}
