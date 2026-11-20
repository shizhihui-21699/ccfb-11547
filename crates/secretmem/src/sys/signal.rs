//! Fatal-signal wipe.
//!
//! Some exits never run a destructor: `SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`,
//! `SIGABRT`, `SIGSYS`, `SIGTRAP`. Without help the process dies with every
//! live secret still in RAM — and, if core dumps are enabled, on disk.
//!
//! The handler here wipes every registered range and then re-raises the signal
//! with the default disposition, so the exit status is unchanged (`139` for
//! `SIGSEGV`, `134` for `SIGABRT`, …) and any crash reporter still gets its
//! notification — just of a process whose secrets are already zero.
//!
//! Constraints the handler obeys:
//!
//! * No allocation, no locks, no `println!` — only atomics, `memset_s`/
//!   `explicit_bzero`, `sigaction`, and `raise`.
//! * `SA_RESETHAND` + a one-shot guard, so a fault *inside* the wipe cannot
//!   recurse into the handler forever; the second delivery gets the default
//!   action.
//! * A dedicated alternate signal stack, so a stack-overflow `SIGSEGV` can
//!   still be handled.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::registry;

const FATAL: &[libc::c_int] = &[
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGABRT,
    libc::SIGSYS,
    libc::SIGTRAP,
];

static INSTALLED: AtomicBool = AtomicBool::new(false);
static ENTERED: AtomicBool = AtomicBool::new(false);

extern "C" fn handler(sig: libc::c_int) {
    // One-shot: if the wipe itself faults, fall straight through to the default
    // action on the next delivery instead of looping.
    if ENTERED.swap(true, Ordering::SeqCst) {
        restore_default_and_reraise(sig);
    }

    // SAFETY: runs with the address space consistent with the registry (this is
    // the process's own fatal-signal context). `Owner` scope: every registered
    // range exists in this process, including those a fork child would not see.
    unsafe { registry::wipe_all(registry::WipeScope::Owner) };

    restore_default_and_reraise(sig)
}

fn restore_default_and_reraise(sig: libc::c_int) -> ! {
    // Three steps, and all three matter:
    //
    // 1. Restore the default action, so the next delivery terminates.
    // 2. Unblock the signal. The kernel blocks the delivered signal for the
    //    duration of its handler, so `raise()` here would merely queue it and
    //    control would fall through — the process would exit 134 instead of
    //    dying *from* SIGABRT. That difference is not cosmetic: a crash
    //    reporter, a core-dump policy, and a supervisor all distinguish
    //    "exited 134" from "killed by signal 6".
    // 3. Re-raise. The handler is SA_RESETHAND, so this delivery cannot re-enter
    //    it.
    // SAFETY: signal(), sigprocmask() and raise() are async-signal-safe.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(sig);
        // Only reached if the signal is somehow still blocked.
        libc::_exit(128 + sig);
    }
}

/// Installs the handler on all fatal signals, plus an alternate stack.
/// Idempotent; returns whether it is in effect.
pub(crate) fn install() -> bool {
    if INSTALLED.load(Ordering::Acquire) {
        return true;
    }
    if !install_alt_stack() {
        // Without an alternate stack a stack-overflow fault cannot be handled,
        // but every other fatal signal still can. Continue anyway.
    }

    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler as *const () as usize;
    sa.sa_flags = libc::SA_RESETHAND | libc::SA_ONSTACK;
    // SAFETY: standard sigaction setup; sa_mask is zeroed and we do not block
    // other signals inside the handler.
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
        for &sig in FATAL {
            if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                return false;
            }
        }
    }
    INSTALLED.store(true, Ordering::Release);
    true
}


/// Allocates an alternate signal stack (via `mmap`, so it never touches the
/// allocator) and registers it. Kept alive for the life of the process.
fn install_alt_stack() -> bool {
    const ALT_STACK_SIZE: usize = 64 * 1024;
    // SAFETY: anonymous private mapping; leaked on purpose.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ALT_STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return false;
    }
    let ss = libc::stack_t {
        ss_sp: p,
        ss_flags: 0,
        ss_size: ALT_STACK_SIZE,
    };
    // SAFETY: `ss` describes the mapping we just made; we never unmap it.
    unsafe { libc::sigaltstack(&ss, std::ptr::null_mut()) == 0 }
}
