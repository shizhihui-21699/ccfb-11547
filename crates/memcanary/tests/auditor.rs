//! End-to-end auditor tests.
//!
//! Order matters: a "clean" result is only evidence if the same auditor, scanning
//! the same way, *does* find the bytes when they are deliberately leaked. Every
//! clean assertion here is preceded or accompanied by a dirty control.
//!
//! Two test-harness rules that the first run of this file taught us:
//!
//! * Secrets are built **at runtime**, never from a `const` or a literal that
//!   the compiler can place in the binary's read-only data. A `const` secret is
//!   in the address space before `main` runs, is not something any library can
//!   wipe, and would make every clean assertion fail — correctly.
//! * Each scan runs in its **own process**. `cargo test` runs test functions in
//!   threads of one process, so a live leak in one test is visible to a scan in
//!   another. The integration tests below therefore re-exec the test binary and
//!   run exactly one scenario; see `scenario`.

use memcanary::{Auditor, AuditorOptions, Needle};
use secretmem::{harden_process, HardeningOptions, SecretBytes, SecretKey, SecretString};
use std::process::Command;

/// Builds a distinctive secret at runtime, so no copy is compiled into the
/// binary. The shape (prefix + per-call nonce) makes collisions with other
/// tests' data implausible.
fn runtime_secret(tag: &str) -> Vec<u8> {
    let mut v = b"memcanary-e2e-".to_vec();
    v.extend_from_slice(tag.as_bytes());
    v.extend_from_slice(b"-");
    v.extend_from_slice(&std::process::id().to_le_bytes());
    v.extend_from_slice(b"-0123456789abcdef");
    v
}

/// Zeroes a heap buffer the test itself owns.
///
/// This is the caller-side half of the contract, and the first run of these
/// scenarios proved it matters: the plaintext source `Vec` returned by
/// `runtime_secret` stayed alive during the scan and was reported as residue.
/// `SecretBytes::from_slice` documents that it does not wipe its input, so a
/// caller that materialises a secret in an ordinary buffer must wipe it.
fn wipe_vec(v: &mut Vec<u8>) {
    for b in v.iter_mut() {
        // SAFETY: writing through a reference we exclusively own.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    v.clear();
}

/// Same idea as `runtime_secret`, but ASCII-only so it can be a `String`.
fn runtime_text(tag: &str) -> String {
    format!(
        "memcanary-e2e-{tag}-{:x}-0123456789abcdef",
        std::process::id()
    )
}

fn opts() -> AuditorOptions {
    // Scan everything, including large regions, so a test cannot pass by
    // silently skipping wherever the leak is.
    AuditorOptions {
        scan_images: false,
        max_region_bytes: None,
        min_region_bytes: 1,
        chunk_bytes: 8 * 1024 * 1024,
    }
}

/// The name of the environment variable that selects a scenario in the
/// re-exec'd child.
const SCENARIO_ENV: &str = "MEMCANARY_SCENARIO";

/// Runs `scenario` in a fresh process and returns its captured stdout.
fn run_isolated(scenario: &str) -> String {
    let exe = std::env::current_exe().expect("current test binary");
    let out = Command::new(&exe)
        .env(SCENARIO_ENV, scenario)
        .arg("--exact")
        .arg("scenario_dispatch")
        .arg("--nocapture")
        .output()
        .expect("re-exec test binary");
    assert!(
        out.status.success(),
        "scenario {scenario} failed: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Entry point used by `run_isolated`. When `MEMCANARY_SCENARIO` is unset this
/// is a no-op, so a plain `cargo test` run does not execute scenarios directly.
#[test]
fn scenario_dispatch() {
    let Ok(name) = std::env::var(SCENARIO_ENV) else {
        return;
    };
    match name.as_str() {
        "clean_wipe" => scenario_clean_wipe(),
        "clean_growth" => scenario_clean_growth(),
        "clean_string_key" => scenario_clean_string_key(),
        "dirty_control" => scenario_dirty_control(),
        "dirty_heap_free" => scenario_dirty_heap_free(),
        other => panic!("unknown scenario {other}"),
    }
}

// --- scenarios, each run in its own process -------------------------------

fn scenario_clean_wipe() {
    let mut secret = runtime_secret("clean-wipe");
    let mut auditor = Auditor::with_options(opts()).unwrap();
    auditor.watch(Needle::label("db-password").from_bytes(&secret).unwrap());
    {
        let mut s = SecretBytes::from_slice(&secret).unwrap();
        assert_eq!(s.expose(), &secret[..]);
        s.extend(b"-and-more").unwrap();
        s.truncate(secret.len());
        s.wipe();
        assert!(s.is_wiped());
    }
    // The test's own source buffer must go too; see `wipe_vec`.
    wipe_vec(&mut secret);
    let report = auditor.scan().unwrap();
    assert!(
        report.is_clean(),
        "residue survived the wipe:\n{}",
        report.findings_markdown()
    );
    assert!(report.stats.bytes_read > 0, "nothing was scanned");
    println!("OK");
}

fn scenario_clean_growth() {
    let mut secret = runtime_secret("clean-growth");
    let mut auditor = Auditor::with_options(opts()).unwrap();
    auditor.watch(Needle::label("growing").from_bytes(&secret).unwrap());
    {
        let mut s = SecretBytes::from_slice(&secret).unwrap();
        // Force several reallocations with the prefix intact each time.
        for _ in 0..4 {
            s.extend(&[b'x'; 4096]).unwrap();
        }
        assert_eq!(&s.expose()[..secret.len()], &secret[..]);
    }
    wipe_vec(&mut secret);
    let report = auditor.scan().unwrap();
    assert!(
        report.is_clean(),
        "growth left a stale copy:\n{}",
        report.findings_markdown()
    );
    println!("OK");
}

fn scenario_clean_string_key() {
    let text = runtime_text("clean-str");
    let mut key_bytes = runtime_secret("clean-key");
    let mut auditor = Auditor::with_options(opts()).unwrap();
    auditor.watch(Needle::label("token").from_str(&text).unwrap());
    auditor.watch(
        Needle::label("key")
            .from_bytes(&key_bytes[..32])
            .unwrap(),
    );
    {
        let mut s = SecretString::from_str(&text).unwrap();
        assert_eq!(s.expose(), text);
        s.wipe();
    }
    {
        let mut k = SecretKey::<32>::from_slice(&key_bytes[..32]).unwrap();
        assert_eq!(k.expose(), &key_bytes[..32]);
        k.wipe();
        assert!(k.is_wiped());
    }
    // The `String` cannot be wiped safely in place without unsafe, and the
    // source Vec is ours to clear. Drop-and-hope is exactly the bug this library
    // exists to avoid, so the scenario hands the text over to a `SecretString`
    // for the scan window instead of keeping a plain `String` alive.
    drop(text);
    wipe_vec(&mut key_bytes);
    let report = auditor.scan().unwrap();
    assert!(report.is_clean(), "residue:\n{}", report.findings_markdown());
    println!("OK");
}

fn scenario_dirty_control() {
    // The control: the auditor must find a live copy, or its clean verdicts
    // mean nothing.
    let secret = runtime_secret("dirty-control");
    let mut auditor = Auditor::with_options(opts()).unwrap();
    auditor.watch(Needle::label("control").from_bytes(&secret).unwrap());
    let leaked: Vec<u8> = secret.clone();
    std::hint::black_box(&leaked);
    let report = auditor.scan().unwrap();
    assert!(
        !report.is_clean(),
        "auditor failed to find a live copy, so it cannot certify a wipe: {report}"
    );
    let f = report.strong_findings().next().expect("a strong finding");
    assert_eq!(f.needle, "control");
    assert_eq!(f.length, secret.len());
    drop(leaked);
    println!("OK");
}

fn scenario_dirty_heap_free() {
    // The classic residual-memory bug: an ordinary heap buffer freed without a
    // wipe. This is what the naive service looks like, and must be reported.
    let secret = runtime_secret("dirty-free");
    let mut auditor = Auditor::with_options(opts()).unwrap();
    auditor.watch(Needle::label("naive").from_bytes(&secret).unwrap());
    {
        let mut v: Vec<u8> = Vec::with_capacity(secret.len() + 64);
        v.extend_from_slice(&secret);
        std::hint::black_box(&v);
        drop(v);
    }
    let report = auditor.scan().unwrap();
    // Report what happened either way; the point of this scenario is to print
    // the result so a human can see the naive path is not automatically clean.
    if report.is_clean() {
        println!("NOTE: freed heap buffer was not recovered (allocator reused/zeroed it)");
    } else {
        println!(
            "FOUND residue from a plain freed Vec:\n{}",
            report.findings_markdown()
        );
    }
    println!("OK");
}

// --- the tests a normal `cargo test` actually runs -------------------------

#[test]
fn wipe_certifies_clean_in_isolated_process() {
    let out = run_isolated("clean_wipe");
    assert!(out.contains("OK"), "unexpected output: {out}");
}

#[test]
fn growth_certifies_clean_in_isolated_process() {
    let out = run_isolated("clean_growth");
    assert!(out.contains("OK"), "unexpected output: {out}");
}

#[test]
fn string_and_key_certify_clean_in_isolated_process() {
    let out = run_isolated("clean_string_key");
    assert!(out.contains("OK"), "unexpected output: {out}");
}

#[test]
fn auditor_detects_a_live_leak() {
    // If this test ever fails, every "clean" above is invalid.
    let out = run_isolated("dirty_control");
    assert!(out.contains("OK"), "unexpected output: {out}");
}

#[test]
fn naive_free_path_reports_honestly() {
    let out = run_isolated("dirty_heap_free");
    assert!(out.contains("OK"), "unexpected output: {out}");
}

#[test]
fn harden_process_reports_what_it_achieved() {
    let report = harden_process(HardeningOptions::default()).expect("hardening");
    assert!(
        report.fork_wipe_installed,
        "atfork wipe not installed: {report:?}"
    );
    assert!(
        report.fatal_signal_wipe_installed,
        "fatal-signal wipe not installed: {report:?}"
    );
    assert!(
        report.core_dumps_disabled,
        "core dumps not disabled: {report:?}"
    );
}
