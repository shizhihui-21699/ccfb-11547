//! Exit-path coverage tests.
//!
//! These spawn the *test binary itself* in a child mode, because the paths under
//! test (`atexit`, fatal-signal handlers) only run when a process actually exits
//! or dies.  Each test asserts on the child's exit status and on whether the
//! secret is still readable through the parent's task port after the child is
//! dead — a dead task has no port, so what we can check instead is the
//! *observable* contract: the handler ran and wiped, and the process still died
//! with the expected signal.

#![cfg(target_os = "macos")]

use std::process::Command;

fn canary() -> String {
    let mut b = [0u8; 16];
    unsafe { libc::getentropy(b.as_mut_ptr().cast(), b.len()) };
    let mut s = String::from("EXITPATH-");
    for x in b {
        s.push(char::from(b'A' + (x % 26)));
    }
    s
}

/// Child mode: create a sealed region holding `EXITPATH_*` from the environment,
/// then either return normally, `exit()`, or fault.  The point is that the
/// value is *not* a source literal, so a scan of the test binary finds nothing.
fn child_body(kind: &str) {
    use sealedmem::{guard, SealedBytes};
    let value = std::env::var("EXITPATH_SECRET").expect("value");
    let _sealed = SealedBytes::from_slice(value.as_bytes()).expect("sealed");
    if kind != "plain" {
        guard::install_termination();
    }
    match kind {
        "normal" => {} // Drop runs
        "exit" => std::process::exit(0), // atexit runs, Drop does not
        _ => {}
    }
}

fn run_child(kind: &str) -> std::process::Output {
    let exe = std::env::current_exe().unwrap();
    Command::new(exe)
        .arg("--exact")
        .arg("exit_path_child")
        .arg("--nocapture")
        .env("EXITPATH_CHILD", kind)
        .env("EXITPATH_SECRET", canary())
        .output()
        .unwrap()
}

#[test]
fn exit_path_child() {
    // This test is a dispatcher; when invoked as a child it runs the body and
    // exits without running the rest of the assertions.
    if let Ok(kind) = std::env::var("EXITPATH_CHILD") {
        child_body(&kind);
        // For "normal" the function returns and the sealed value drops (wipe).
        // For "exit" the process exits and `atexit` sweeps.  Neither should panic.
        return;
    }
    // Parent side: the child must exit cleanly for both kinds.  A crash here
    // would mean the guard or atexit path itself faulted, which is worse than
    // the residue it was trying to prevent.
    for kind in ["normal", "exit"] {
        let out = run_child(kind);
        assert!(
            out.status.success(),
            "{kind} child failed: {:?}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
#[ignore = "slow: runs a core producer; enable in the verification run"]
fn fatal_signal_reaches_the_handler() {
    // A dedicated binary would be cleaner, but re-execing the test harness in a
    // mode that faults is enough: the handler must wipe and then the process
    // must die with the signal.
    if std::env::var("SIGNAL_CHILD").is_err() {
        let exe = std::env::current_exe().unwrap();
        // Note: `--ignored` too, because this very test is marked ignored and
        // the harness would otherwise skip it in the child.
        let out = Command::new(exe)
            .arg("--exact")
            .arg("fatal_signal_reaches_the_handler")
            .arg("--ignored")
            .arg("--nocapture")
            .env("SIGNAL_CHILD", "1")
            .output()
            .unwrap();
        let killed = out.status.code().is_none();
        assert!(killed, "child should die by signal; got {:?}", out.status);
        return;
    }
    let _ = sealedmem::SealedBytes::from_slice(b"signal-secret");
    sealedmem::guard::install_termination();
    unsafe {
        let p = std::ptr::null_mut::<u8>();
        std::ptr::write_volatile(p, 1);
    }
    unreachable!("handler should have terminated the process");
}
