//! Fatal-signal and `atexit` coverage.
//!
//! `Drop` covers normal returns, `?` early returns, panics and unwinds.  It does
//! **not** run for a fatal signal or for `std::process::exit`.  This module adds
//! both:
//!
//! * an `atexit(3)` hook that sweeps every live [`Region`](crate::Region), and
//! * handlers for the fault signals (`SIGSEGV`, `SIGBUS`, `SIGABRT`, `SIGILL`,
//!   `SIGFPE`, `SIGTRAP`) which wipe, restore the default disposition and
//!   re-raise, so the crash still looks like a crash to the shell and to a core
//!   file writer.
//!
//! Everything in the handler is async-signal-safe: `mprotect`, `madvise`,
//! `munlock`, volatile stores and atomic CAS.  No allocation, no locks, no
//! formatting.
//!
//! Optional: [`install_termination`] adds `SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT`
//! to the same sweep-then-re-raise treatment, which keeps default behaviour while
//! still wiping.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::region;

static FAULTS_INSTALLED: AtomicBool = AtomicBool::new(false);
static TERM_INSTALLED: AtomicBool = AtomicBool::new(false);
static ATEXIT_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Signals whose default action terminates (or dumps core for).
const FAULT_SIGNALS: [libc::c_int; 6] = [
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGABRT,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGTRAP,
];

const TERM_SIGNALS: [libc::c_int; 4] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
];

/// Alternate stack size; generous because the handler is tiny but the default
/// signal stack is on the thread's own (possibly overflowed) stack.
const ALT_STACK_SIZE: usize = 64 * 1024;

static mut ALT_STACK: [u8; ALT_STACK_SIZE] = [0; ALT_STACK_SIZE];

extern "C" fn atexit_sweep() {
    region::sweep_all();
}

/// The one handler.  Sweep, then reproduce the default action.
extern "C" fn on_fatal(sig: libc::c_int) {
    region::sweep_all();
    // SAFETY: `signal` and `raise` are async-signal-safe.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

fn install_handler(sig: libc::c_int) {
    // SAFETY: `sigaction` with a static handler pointer; the struct is fully
    // initialised and lives on this stack frame for the call only.
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_fatal as *const () as usize;
        sa.sa_flags = libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, core::ptr::null_mut());
    }
}

fn install_alt_stack() {
    // SAFETY: the alternate stack is a static buffer owned by this process; we
    // hand its address to the kernel exactly once.
    unsafe {
        let mut ss: libc::stack_t = core::mem::zeroed();
        ss.ss_sp = core::ptr::addr_of_mut!(ALT_STACK).cast();
        ss.ss_size = ALT_STACK_SIZE;
        ss.ss_flags = 0;
        libc::sigaltstack(&ss, core::ptr::null_mut());
    }
}

/// Install fault-signal handlers and the `atexit` hook.  Idempotent.
///
/// Call this once, early, **before** any other component installs its own
/// `SIGSEGV` handler; later installs replace ours (we do not chain to previous
/// handlers, because chaining into arbitrary foreign handlers from a wiping
/// context is not async-signal-safe).  The demo calls it first thing in `main`.
pub fn install() {
    if FAULTS_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    install_alt_stack();
    for sig in FAULT_SIGNALS {
        install_handler(sig);
    }
    install_atexit();
}

/// Also cover the polite termination signals (Ctrl-C, `kill`, terminal hangup).
/// They are wiped and then re-raised with default disposition, so a shell still
/// sees a `SIGINT` death rather than a clean exit.
pub fn install_termination() {
    if TERM_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    install();
    for sig in TERM_SIGNALS {
        install_handler(sig);
    }
}

fn install_atexit() {
    if ATEXIT_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    // SAFETY: `atexit` takes a plain `extern "C" fn()`.
    unsafe {
        libc::atexit(atexit_sweep);
    }
    install_atfork();
}

// `fork(2)` handling.
//
// Regions are `VM_INHERIT_NONE`, so a child has **no mapping** at the addresses
// the registry memcpy carried over.  Without this hook, a child that later
// crashed would run the signal handler, try to wipe addresses it never mapped,
// and fault recursively.  The child hook therefore marks every slot dead.
extern "C" {
    fn pthread_atfork(
        prepare: Option<extern "C" fn()>,
        parent: Option<extern "C" fn()>,
        child: Option<extern "C" fn()>,
    ) -> libc::c_int;
}

extern "C" fn atfork_child() {
    region::mark_registry_dead_in_child();
}

fn install_atfork() {
    // SAFETY: standard pthread API; handlers are plain `extern "C" fn()`.
    unsafe {
        pthread_atfork(None, None, Some(atfork_child));
    }
}

/// Whether fatal-signal coverage is active.  The verification tool prints this
/// so a "clean core" result is only trusted when a handler was actually armed.
pub fn faults_installed() -> bool {
    FAULTS_INSTALLED.load(Ordering::Acquire)
}
