//! A lock-free registry of live protected ranges.
//!
//! Why this exists: `Drop` handles the ordinary path, but two paths never run
//! it — a `fork()`ed child that inherited copy-on-write pages, and a fatal
//! signal (`SIGSEGV`, `SIGBUS`, `SIGABRT`, …) with no unwinding. Both are
//! exactly the situations where a secret would otherwise survive in a process
//! (the child) or a crash artefact (the core).
//!
//! The registry is a fixed-size array of atomics so the handlers that consume
//! it — `pthread_atfork` and `sigaction` — can run without allocating, taking
//! locks, or touching anything mid-update.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Maximum concurrently-live protected regions. Enough for a service holding a
/// handful of long-lived keys plus in-flight per-request values; when full,
/// `SecretBytes::new` returns [`crate::Error::RegistryFull`].
pub(crate) const SLOTS: usize = 4096;

/// Values stored in the pointer word.
const FREE: usize = 0;
/// A registration is in progress: the pointer is not yet valid, so wipers skip
/// the slot. Real addresses are never 1 (they are at least one page aligned).
const RESERVED: usize = 1;

struct Slot {
    ptr: AtomicUsize,
    len: AtomicUsize,
    /// Whether a `fork()`ed child sees this range and must wipe it.
    ///
    /// On macOS the region is `VM_INHERIT_NONE`, so the child has no mapping at
    /// all and touching these addresses would fault inside the `atfork`
    /// handler. Recording the fact at registration lets the handler skip them.
    /// On Linux and the portable backend the child does see the range (which is
    /// why Linux backends also set `MADV_WIPEONFORK`, as a second layer).
    child_wipes: AtomicBool,
}

impl Slot {
    const fn new() -> Self {
        Slot {
            ptr: AtomicUsize::new(FREE),
            len: AtomicUsize::new(0),
            child_wipes: AtomicBool::new(true),
        }
    }
}

// All fields are atomics, so this needs no `mut` and no lazy initialisation: it
// is valid from the first instruction of `main` and inside a signal handler.
static SLOTS_TABLE: [Slot; SLOTS] = [const { Slot::new() }; SLOTS];

fn table() -> &'static [Slot; SLOTS] {
    &SLOTS_TABLE
}

/// Registers a range so the fork/signal paths can find it.
///
/// Failure is deliberately silent: the region still works and still wipes on
/// `Drop`; it only loses the crash-path guarantee. Run the auditor to see
/// whether any range is missing.
pub(crate) fn register(ptr: *mut u8, len: usize) -> bool {
    register_inner(ptr, len, /* child_wipes */ true)
}

/// Registers a range the child will **not** see (e.g. `VM_INHERIT_NONE`), so
/// the `atfork` handler must leave it alone.
pub(crate) fn register_absent_in_child(ptr: *mut u8, len: usize) -> bool {
    register_inner(ptr, len, false)
}

fn register_inner(ptr: *mut u8, len: usize, child_wipes: bool) -> bool {
    let table = table();
    for slot in table.iter() {
        // Reserve: FREE -> RESERVED. Exactly one registrar wins the slot.
        if slot
            .ptr
            .compare_exchange(FREE, RESERVED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        // Safe order for a concurrent wiper: until `ptr` becomes a real
        // address, the slot is skipped; once it does, `len` and
        // `child_wipes` are already correct.
        slot.len.store(len, Ordering::Release);
        slot.child_wipes.store(child_wipes, Ordering::Release);
        slot.ptr.store(ptr as usize, Ordering::Release);
        return true;
    }
    false
}

/// Removes a range. Safe to call with an address that was never registered.
pub(crate) fn unregister(ptr: *mut u8) {
    let table = table();
    for slot in table.iter() {
        if slot.ptr.load(Ordering::Acquire) == ptr as usize {
            // Clear the length first, then release the slot, so a wiper that
            // still sees the old pointer cannot use a stale length.
            slot.len.store(0, Ordering::Release);
            slot.ptr.store(FREE, Ordering::Release);
            return;
        }
    }
}

/// Which callers a wipe is running for.
///
/// The two differ in a way that is easy to get wrong:
///
/// * A **forked child** may not have the mapping at all (macOS
///   `VM_INHERIT_NONE`). Writing to an absent range faults, and a fault inside
///   an `atfork` handler is unrecoverable — the first version of this code hung
///   the child that way. So the child path skips ranges marked
///   "absent in child".
/// * A **fatal signal** is delivered to the process that owns the ranges. Every
///   range exists here and every one must be wiped, including those excluded
///   from children.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WipeScope {
    /// Running in a `fork()`ed child: skip ranges the child does not have.
    ForkChild,
    /// Running in the owning process (a fatal signal): wipe everything.
    Owner,
}

/// Wipes registered ranges according to `scope`.
///
/// Must not allocate, lock, or panic: it runs inside `pthread_atfork` and
/// inside fatal-signal handlers.
///
/// # Safety
/// Only sound when the registry is consistent with the caller's address space,
/// which holds in a forked child (before it makes its own allocations) and in a
/// signal handler interrupting the process's own threads.
pub(crate) unsafe fn wipe_all(scope: WipeScope) {
    let table = table();
    for slot in table.iter() {
        let p = slot.ptr.load(Ordering::Acquire);
        if p <= RESERVED {
            continue;
        }
        let len = slot.len.load(Ordering::Acquire);
        if len == 0 {
            continue;
        }
        // See `WipeScope`: an absent range faults if written.
        if scope == WipeScope::ForkChild && !slot.child_wipes.load(Ordering::Acquire) {
            continue;
        }
        // SAFETY: for `Owner` the range is a live mapping in this process; for
        // `ForkChild` it is present (checked above) and inherited.
        unsafe { crate::sys::wipe_bytes(p as *mut u8, len) };
    }
}

/// Every live protected range, as `(start, len)`.
///
/// Exposed so a service can publish its container ranges to a *cooperating*
/// auditor — e.g. a debug endpoint or a startup log line — letting an external
/// scan classify its hits precisely instead of conservatively. Publishing an
/// address does not reveal the value in it; it only says which ranges the
/// service manages.
///
/// Order is unspecified. Takes no locks: a range may be freed immediately after
/// it is returned, so a consumer must treat the list as advisory.
pub fn protected_ranges() -> Vec<(usize, usize)> {
    table()
        .iter()
        .filter_map(|s| {
            let p = s.ptr.load(Ordering::Acquire);
            if p <= RESERVED {
                return None;
            }
            let len = s.len.load(Ordering::Acquire);
            (len > 0).then_some((p, len))
        })
        .collect()
}

/// Wipes every registered range through the same code path the fork and
/// fatal-signal handlers use.
///
/// Exposed so tests can prove the crash path works without having to crash the
/// test runner. Not intended for application code.
pub fn wipe_all_registered_for_tests() {
    // SAFETY: the caller is in a normal execution context with a consistent
    // address space, which is exactly what `wipe_all` requires.
    unsafe { wipe_all(WipeScope::Owner) }
}

/// Number of currently-registered ranges (for diagnostics and tests).
pub fn registered_ranges() -> usize {
    table()
        .iter()
        .filter(|s| s.ptr.load(Ordering::Acquire) > RESERVED)
        .count()
}

/// Whether the range starting at `ptr` is absent in **this** process.
///
/// Only true inside a `fork()`ed child, and only for ranges the backend
/// excluded from children (`VM_INHERIT_NONE` on macOS). In the parent these
/// ranges are present and readable, so this returns `false` there.
///
/// Why existence is not enough: a child inherits the registry's contents (it is
/// read-only after fork, so both processes see the same slots) but not
/// necessarily the mappings. A container method called in the child therefore
/// has to ask "does this range exist here at all?" before touching it, or it
/// faults. The registry tracks that through a process-wide flag set at fork.
pub fn is_absent_in_child(ptr: *const u8) -> bool {
    // If this process still owns live ranges that the backend excludes from
    // children, and we are *not* the creating process, then those ranges are
    // absent here.
    if !registry_in_forked_child() {
        return false;
    }
    table().iter().any(|s| {
        s.ptr.load(Ordering::Acquire) == ptr as usize
            && !s.child_wipes.load(Ordering::Acquire)
    })
}

/// Set by the atfork child handler, so the process knows it is a fork child
/// before it has any other way to tell.
static IN_FORKED_CHILD: AtomicBool = AtomicBool::new(false);

#[inline]
pub(crate) fn registry_in_forked_child() -> bool {
    IN_FORKED_CHILD.load(Ordering::Acquire)
}

/// Whether `addr` falls inside a range owned by a `secretmem` container.
///
/// This is the question an auditor needs in order to tell two very different
/// situations apart:
///
/// * a live secret inside its guarded, locked container — the service is
///   supposed to hold it, and the container will wipe it;
/// * a copy anywhere else (heap, stack, a `String` the HTTP layer built, a
///   compiler-embedded literal) — that is a leak the container cannot reach.
///
/// Answers from the same lock-free table the fork and signal paths use, so it
/// is cheap and safe to call from a scanner.
pub fn is_protected_address(addr: usize) -> bool {
    table().iter().any(|s| {
        let p = s.ptr.load(Ordering::Acquire);
        if p <= RESERVED {
            return false;
        }
        let len = s.len.load(Ordering::Acquire);
        addr >= p && addr < p.saturating_add(len)
    })
}

/// Whether the exact range starting at `ptr` is currently registered.
pub fn is_registered(ptr: *const u8) -> bool {
    table()
        .iter()
        .any(|s| s.ptr.load(Ordering::Acquire) == ptr as usize)
}

/// Whether the process-wide fork wipe has been installed.
pub fn fork_wipe_installed() -> bool {
    FORK_HANDLER.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Process-wide wiring: atfork.
// ---------------------------------------------------------------------------

static FORK_HANDLER: AtomicBool = AtomicBool::new(false);

extern "C" fn atfork_child() {
    // Record that we are the child *before* touching any range, so a later
    // container method knows the excluded mappings are gone here.
    IN_FORKED_CHILD.store(true, Ordering::Release);
    // SAFETY: pthread_atfork guarantees the child runs with a consistent
    // address space and no other thread alive.
    unsafe { wipe_all(WipeScope::ForkChild) };
}

/// Installs the child-side fork wipe. Idempotent. Returns whether it is in
/// effect afterwards.
pub(crate) fn install_fork_wipe() -> bool {
    if FORK_HANDLER.load(Ordering::Acquire) {
        return true;
    }
    // SAFETY: standard POSIX registration; the handler does not allocate.
    let rc = unsafe { libc::pthread_atfork(None, None, Some(atfork_child)) };
    if rc == 0 {
        FORK_HANDLER.store(true, Ordering::Release);
        true
    } else {
        false
    }
}
