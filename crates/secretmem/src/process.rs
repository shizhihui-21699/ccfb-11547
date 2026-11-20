//! Process-wide hardening: the parts of the guarantee that are not per-object.
//!
//! A container can wipe its own pages, but three leaks are properties of the
//! *process*, not of any one value:
//!
//! * **Core dumps.** Whether the kernel writes the address space to disk on a
//!   crash is set by a process resource limit.
//! * **fatal signals.** `SIGSEGV`/`SIGBUS`/`SIGABRT` bypass every destructor.
//! * **fork.** A child starts with a copy-on-write image of every live secret.
//!
//! [`harden_process`] installs the process-global machinery for those. Call it
//! once, as early as possible — ideally before any secret is created, and never
//! from a signal handler or an `atfork` handler.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::sys;

/// Which process-wide protections to attempt. The defaults enable everything;
/// disable items only for tests or for platforms that misbehave.
#[derive(Debug, Clone, Copy)]
pub struct HardeningOptions {
    /// Set `RLIMIT_CORE` to 0 so no core is ever written.
    pub disable_core_dumps: bool,
    /// Install the `pthread_atfork` child wipe.
    pub wipe_on_fork: bool,
    /// Install handlers for fatal signals that wipe before re-raising.
    pub wipe_on_fatal_signal: bool,
    /// Treat "cannot `mlock`" as fatal at [`harden_process`] time.
    ///
    /// When false (the default) a locked-region failure is reported in the
    /// [`HardeningReport`] and the process continues unwired. When true, a
    /// process that cannot wire memory should refuse to start rather than risk
    /// swapping secrets.
    pub require_locked: bool,
}

impl Default for HardeningOptions {
    fn default() -> Self {
        HardeningOptions {
            disable_core_dumps: true,
            wipe_on_fork: true,
            wipe_on_fatal_signal: true,
            require_locked: false,
        }
    }
}

impl HardeningOptions {
    /// Strictest configuration: every protection, and refuse to run if memory
    /// cannot be wired.
    pub fn strict() -> Self {
        HardeningOptions { require_locked: true, ..Self::default() }
    }
}

/// What [`harden_process`] actually achieved. Read this: a `false` field is a
/// leak path you still have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HardeningReport {
    /// Core dumps are disabled for this process.
    pub core_dumps_disabled: bool,
    /// A forked child wipes inherited secrets (atfork handler installed).
    pub fork_wipe_installed: bool,
    /// Fatal signals wipe registered ranges before the process dies.
    pub fatal_signal_wipe_installed: bool,
    /// `mlock` works for the sizes this process will use.
    pub memory_lockable: bool,
    /// Kernel-backed scrub of wired pages on abnormal exit (macOS).
    pub kernel_scrub_on_abnormal_exit: bool,
}

impl HardeningReport {
    /// Whether every protection this platform can offer is in effect.
    pub fn is_complete(&self) -> bool {
        self.core_dumps_disabled
            && self.fork_wipe_installed
            && self.fatal_signal_wipe_installed
            && self.memory_lockable
    }
}

static HARDENED: AtomicBool = AtomicBool::new(false);
static REPORT: AtomicUsize = AtomicUsize::new(0);

/// Installs the process-wide protections. Idempotent; the first call's report
/// is what later calls return.
///
/// Returns `Err` only when `opts.require_locked` is set and memory cannot be
/// wired. Everything else is reported, not raised, so callers can log exactly
/// which guarantee they are missing.
///
/// # Safety of calling early
///
/// Call from `main`, after runtime initialisation, before spawning threads that
/// will create secrets. Signal handlers are installed with `SA_ONSTACK`
/// deliberately *off* and no `SA_RESTART` games; they only touch the registry
/// (atomics) and call `write(2)`-free code paths, so they cannot deadlock on a
/// lock that the interrupted thread held.
pub fn harden_process(opts: HardeningOptions) -> crate::Result<HardeningReport> {
    if HARDENED.load(Ordering::Acquire) {
        return decode(REPORT.load(Ordering::Acquire)).ok_or(crate::Error::Misaligned);
    }

    let mut report = HardeningReport {
        core_dumps_disabled: false,
        fork_wipe_installed: false,
        fatal_signal_wipe_installed: false,
        memory_lockable: sys::capabilities().can_lock,
        kernel_scrub_on_abnormal_exit: sys::capabilities().kernel_zero_on_abnormal_exit,
    };

    if opts.disable_core_dumps {
        report.core_dumps_disabled = sys::disable_core_dumps();
    }
    if opts.wipe_on_fork {
        report.fork_wipe_installed = sys::install_fork_wipe();
    }
    if opts.wipe_on_fatal_signal {
        report.fatal_signal_wipe_installed = sys::install_fatal_signal_wipe();
    }

    if opts.require_locked && !report.memory_lockable {
        return Err(crate::Error::Lock(0));
    }

    REPORT.store(encode(report), Ordering::Release);
    HARDENED.store(true, Ordering::Release);
    Ok(report)
}

// Compact encoding of the five booleans, so the report can live in one atomic
// and a second `harden_process` call returns the same answer.
const FIELDS: [fn(&HardeningReport) -> bool; 5] = [
    |r| r.core_dumps_disabled,
    |r| r.fork_wipe_installed,
    |r| r.fatal_signal_wipe_installed,
    |r| r.memory_lockable,
    |r| r.kernel_scrub_on_abnormal_exit,
];

fn encode(r: HardeningReport) -> usize {
    let mut v = 0usize;
    for (i, f) in FIELDS.iter().enumerate() {
        if f(&r) {
            v |= 1 << i;
        }
    }
    // Bit 8 marks "a report has been stored".
    v | (1 << 8)
}

fn decode(v: usize) -> Option<HardeningReport> {
    if v & (1 << 8) == 0 {
        return None;
    }
    Some(HardeningReport {
        core_dumps_disabled: v & 1 != 0,
        fork_wipe_installed: v & 2 != 0,
        fatal_signal_wipe_installed: v & 4 != 0,
        memory_lockable: v & 8 != 0,
        kernel_scrub_on_abnormal_exit: v & 16 != 0,
    })
}

/// The report from the most recent successful [`harden_process`], if any.
pub fn hardening_report() -> Option<HardeningReport> {
    if !HARDENED.load(Ordering::Acquire) {
        return None;
    }
    decode(REPORT.load(Ordering::Acquire))
}

/// Whether [`harden_process`] has run.
pub fn is_hardened() -> bool {
    HARDENED.load(Ordering::Acquire)
}
