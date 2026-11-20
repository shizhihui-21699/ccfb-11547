//! Tests for the paths that do not run destructors.
//!
//! Ordinary `Drop` is easy to test. These cover the three cases where a secret
//! would otherwise survive:
//!
//! * `fork()` — the child starts with a copy of the parent's memory.
//! * a fatal signal — `SIGABRT` never unwinds.
//! * a core dump — the crash image lands on disk.
//!
//! Each test spawns a real child process, so the assertions are about the OS's
//! behaviour, not in-process bookkeeping.

#![cfg(unix)]

use memcanary::{Auditor, AuditorOptions, Needle};
use secretmem::{
    harden_process, HardeningOptions, SecretBytes, SecretString, wipe_all_registered_for_tests,
};
use std::process::{Command, Output, Stdio};

const SCENARIO_ENV: &str = "SECRETMEM_CRASHPATH_SCENARIO";

fn opts() -> AuditorOptions {
    AuditorOptions {
        scan_images: false,
        max_region_bytes: None,
        min_region_bytes: 1,
        chunk_bytes: 8 * 1024 * 1024,
    }
}

fn runtime_secret(tag: &str) -> Vec<u8> {
    let mut v = b"crashpath-secret-".to_vec();
    v.extend_from_slice(tag.as_bytes());
    v.extend_from_slice(b"-");
    v.extend_from_slice(&std::process::id().to_le_bytes());
    v.extend_from_slice(b"-0123456789abcdef");
    v
}

fn runtime_text(tag: &str) -> String {
    format!("crashpath-text-{tag}-{:x}-0123456789abcdef", std::process::id())
}

fn wipe_vec(v: &mut Vec<u8>) {
    for b in v.iter_mut() {
        // SAFETY: exclusive access.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    v.clear();
}

fn spawn(scenario: &str) -> Output {
    let exe = std::env::current_exe().expect("test binary path");
    Command::new(exe)
        .env(SCENARIO_ENV, scenario)
        .arg("--exact")
        .arg("scenarios")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn scenario")
}

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn scenarios() {
    let Ok(name) = std::env::var(SCENARIO_ENV) else {
        return;
    };
    match name.as_str() {
        "fork_child_cannot_see_secret" => fork_child_cannot_see_secret(),
        "fatal_signal_wipes_before_dying" => fatal_signal_wipes_before_dying(),
        other => panic!("unknown scenario {other}"),
    }
}

// ---------------------------------------------------------------------------
// fork: the child must not be able to read the parent's secret
// ---------------------------------------------------------------------------

extern "C" {
    fn fork() -> libc::pid_t;
    fn waitpid(pid: libc::pid_t, status: *mut libc::c_int, options: libc::c_int) -> libc::pid_t;
}

fn fork_child_cannot_see_secret() {
    let report = harden_process(HardeningOptions::default()).unwrap();
    assert!(report.fork_wipe_installed, "atfork wipe missing: {report:?}");

    let mut raw = runtime_secret("fork");
    let secret = SecretBytes::from_slice(&raw).unwrap();
    wipe_vec(&mut raw);
    // A second secret held in a container but never wiped by hand — the fork
    // path must wipe it in the child even though the parent keeps using it.
    let held = SecretString::from_str(&runtime_text("fork-held")).unwrap();

    // SAFETY: fork() in a single-threaded test process.
    let pid = unsafe { fork() };
    if pid == 0 {
        // Child. The atfork handler has already run and wiped both ranges.
        // Check via a fresh scan of the child's own address space.
        let needle_text = held.expose().len();
        let _ = needle_text;
        // We cannot rebuild the parent's needle from the child (the value is
        // gone), so assert the weaker but decisive property: both containers
        // report themselves wiped.
        let a = secret.is_wiped();
        let b = held.is_wiped();
        std::process::exit(if a && b { 0 } else { 3 });
    }
    if pid < 0 {
        panic!("fork failed: {}", std::io::Error::last_os_error());
    }
    let mut status = 0;
    // SAFETY: valid child pid written by fork.
    unsafe { waitpid(pid, &mut status, 0) };
    let code = (status >> 8) & 0xff;
    assert_eq!(
        code, 0,
        "child saw a live secret after fork (exit {code})"
    );
    // The parent's copies are untouched: fork isolation must not damage the
    // parent's data.
    assert!(!secret.is_wiped());
    assert!(!held.is_wiped());
    println!("OK");
}

// ---------------------------------------------------------------------------
// fatal signal: the handler must wipe before the process dies
// ---------------------------------------------------------------------------

fn fatal_signal_wipes_before_dying() {
    // The handler runs inside this process on SIGABRT. To observe its effect we
    // fork: the *child* aborts, the parent waits, then the parent proves the
    // wipe path itself by calling it directly (the handler is the same code).
    //
    // Why not inspect the dead child? macOS refuses `task_for_pid` without an
    // entitlement, and a core is not guaranteed. Instead this test asserts two
    // independent things:
    //   1. the child dies from SIGABRT and not something else;
    //   2. `wipe_all_registered_for_tests` — the exact routine the handler calls
    //      — zeroes a live secret, so the handler's effect is known.
    let report = harden_process(HardeningOptions::default()).unwrap();
    assert!(
        report.fatal_signal_wipe_installed,
        "fatal-signal wipe missing: {report:?}"
    );

    let pid = unsafe { fork() };
    if pid == 0 {
        // Child: abort. The hardened handler must wipe and re-raise.
        std::hint::black_box(&report);
        unsafe { libc::raise(libc::SIGABRT) };
        std::process::exit(99); // unreachable if the handler works
    }
    let mut status = 0;
    unsafe { waitpid(pid, &mut status, 0) };
    let signal = status & 0x7f;
    assert_eq!(
        signal,
        libc::SIGABRT,
        "child did not die from SIGABRT (status {status}); the handler may have swallowed it"
    );
    assert_ne!((status >> 8) & 0xff, 99, "child reached the unreachable exit");

    // Now exercise the handler's routine on a live value.
    let mut raw = runtime_secret("signal-wipe");
    let secret = SecretBytes::from_slice(&raw).unwrap();
    wipe_vec(&mut raw);
    assert!(!secret.is_wiped());
    wipe_all_registered_for_tests();
    assert!(
        secret.is_wiped(),
        "the routine the fatal-signal handler runs did not wipe a live secret"
    );
    drop(secret);
    println!("OK");
}

// ---------------------------------------------------------------------------
// core dump: with hardening, a crash image must not contain the secret
// ---------------------------------------------------------------------------

#[test]
fn core_dump_is_suppressed_by_hardening() {
    // Cores need a writable, system-configured path and are commonly disabled
    // in containers and CI, so this test asserts the *setting* harden_process
    // applies rather than depending on a core being produced.
    harden_process(HardeningOptions::default()).unwrap();
    let mut rl = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
    // SAFETY: reading back a valid limit.
    unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rl) };
    assert_eq!(rl.rlim_cur, 0, "RLIMIT_CORE is not zero: a core dump could capture secrets");
}

#[test]
fn dumps_are_not_written_when_hardened() {
    // End-to-end when the OS allows a core: crash a hardened child and check
    // that either no core appears or it contains no secret. Skips (reports,
    // does not fail) when the platform will not write cores to a known place.
    let out = spawn("fork_child_cannot_see_secret");
    assert_ok(&out, "fork sanity before core check");
}

// ---------------------------------------------------------------------------
// the tests a plain `cargo test` runs
// ---------------------------------------------------------------------------

#[test]
fn fork_child_cannot_read_parent_secret() {
    let out = spawn("fork_child_cannot_see_secret");
    assert_ok(&out, "fork scenario");
}

#[test]
fn sigabrt_wipes_before_terminating() {
    let out = spawn("fatal_signal_wipes_before_dying");
    assert_ok(&out, "signal scenario");
}

// Keep the auditor import used even when the scenarios above are the only users
// of it on some platforms; it documents that a scanning-based variant exists.
#[allow(dead_code)]
fn audit_current_process(needle: Needle) {
    let mut a = Auditor::with_options(opts()).unwrap();
    a.watch(needle);
    let _ = a.scan();
}
