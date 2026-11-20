//! Provenance and external-attach tests.
//!
//! These lock in the properties that make the audit meaningful:
//!
//! * a value inside a `secretmem` container is classified `protected` (not a
//!   leak), and the same value in an ordinary buffer is classified as a leak;
//! * the classifier is not secretly returning `protected` for everything, which
//!   would make every hardened report falsely clean;
//! * external attach either finds a live leak in another process or fails with a
//!   clear permission error — never silently reports clean.

use memcanary::{Auditor, AuditorOptions, Needle, Provenance};
use secretmem::{harden_process, HardeningOptions, SecretBytes};
use std::process::{Command, Stdio};

const SCENARIO_ENV: &str = "MEMCANARY_PROVENANCE_SCENARIO";

fn runtime_secret(tag: &str) -> Vec<u8> {
    let mut v = b"provtest-secret-".to_vec();
    v.extend_from_slice(tag.as_bytes());
    v.extend_from_slice(b"-");
    v.extend_from_slice(&std::process::id().to_le_bytes());
    v.extend_from_slice(b"-0123456789abcdef");
    v
}

fn wipe_vec(v: &mut Vec<u8>) {
    for b in v.iter_mut() {
        // SAFETY: exclusive access.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    v.clear();
}

fn opts() -> AuditorOptions {
    AuditorOptions {
        scan_images: false,
        max_region_bytes: None,
        min_region_bytes: 1,
        chunk_bytes: 8 * 1024 * 1024,
    }
}

fn spawn(scenario: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .env(SCENARIO_ENV, scenario)
        .arg("--exact")
        .arg("scenarios")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn scenario")
}

#[test]
fn scenarios() {
    let Ok(name) = std::env::var(SCENARIO_ENV) else {
        return;
    };
    match name.as_str() {
        "classifier" => scenario_classifier(),
        "external_target" => scenario_external_target(),
        other => panic!("unknown scenario {other}"),
    }
}

/// In one process: hold a value in a container *and* in a plain Vec, then check
/// the classifier labels each one the way it must.
fn scenario_classifier() {
    let mut raw = runtime_secret("classifier");
    let held = SecretBytes::from_slice(&raw).unwrap();
    let leaked: Vec<u8> = raw.clone();
    std::hint::black_box(&leaked);

    let mut auditor = Auditor::with_options(opts()).unwrap();
    auditor.watch(Needle::label("prov").from_bytes(&raw).unwrap());
    let report = auditor.scan().unwrap();

    let mut saw_protected = false;
    let mut saw_leak = false;
    for f in report.findings.iter().filter(|f| !f.weak) {
        if secretmem::is_protected_address(f.address as usize) {
            assert_eq!(
                f.provenance,
                Provenance::Protected,
                "address inside a container must be classified protected"
            );
            saw_protected = true;
        } else {
            assert_ne!(
                f.provenance,
                Provenance::Protected,
                "address outside any container must not be classified protected"
            );
            saw_leak = true;
        }
    }
    assert!(saw_protected, "the container's own copy was not found");
    assert!(
        saw_leak,
        "the plain heap copy was not found — the classifier or the scan is broken"
    );
    assert!(!report.is_clean(), "a live heap leak must make the report dirty");

    drop(held);
    wipe_vec(&mut raw);
    println!("OK");
}

/// Keeps a leaked secret alive in another process, prints its pid, and waits.
/// The parent scans it by pid.
fn scenario_external_target() {
    let mut raw = runtime_secret("external");
    let leaked: Vec<u8> = raw.clone();
    std::hint::black_box(&leaked);
    println!("PID {}", std::process::id());
    // Hold for long enough for the parent to attach.
    std::thread::sleep(std::time::Duration::from_secs(20));
    drop(leaked);
    wipe_vec(&mut raw);
}

#[test]
fn classifier_distinguishes_container_from_leak() {
    let out = spawn("classifier");
    assert!(
        out.status.success(),
        "classifier scenario failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn external_attach_finds_a_live_leak_or_refuses_clearly() {
    // The child is a copy of this test binary. On macOS the *test binary* is not
    // signed with get-task-allow, so attach is expected to be refused; the test
    // then asserts the refusal is explicit. If the environment does allow
    // attach, it asserts a leak is found. It never accepts a silent "clean".
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env(SCENARIO_ENV, "external_target")
        .arg("--exact")
        .arg("scenarios")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn target");

    // Wait for the child to announce its pid.
    let stdout = child.stdout.take().expect("stdout");
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(stdout);
    let mut pid_line = String::new();
    // Skip the harness's "running 1 test" lines until the PID line appears.
    let mut pid: Option<u32> = None;
    while reader.read_line(&mut pid_line).is_ok() {
        if let Some(rest) = pid_line.strip_prefix("PID ") {
            pid = rest.trim().parse().ok();
            break;
        }
        pid_line.clear();
    }
    let Some(pid) = pid else {
        let _ = child.kill();
        panic!("child never announced its pid");
    };

    let result = Auditor::for_pid(pid, opts());
    let outcome = match result {
        Ok(mut auditor) => {
            auditor.watch(
                Needle::label("external")
                    .from_bytes(&{
                        let mut v = b"provtest-secret-external-".to_vec();
                        v.extend_from_slice(&pid.to_le_bytes());
                        v.extend_from_slice(b"-0123456789abcdef");
                        v
                    })
                    .unwrap(),
            );
            let r = auditor.scan().unwrap();
            let found = !r.is_clean();
            Some(found)
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("cannot attach") || msg.contains("permission"),
                "attach failed with an unexpected error (it must explain the permission boundary): {msg}"
            );
            None
        }
    };

    let _ = child.kill();
    let _ = child.wait();

    match outcome {
        Some(true) => {} // attach worked and found the leak: ideal
        Some(false) => panic!("attach succeeded but reported clean for a process holding a live secret"),
        None => {} // attach refused with a clear message: acceptable here
    }
}

#[test]
fn hardening_makes_core_dumps_and_fork_isolation_real() {
    let report = harden_process(HardeningOptions::default()).expect("hardening");
    assert!(report.is_complete(), "{report:?}");
}
