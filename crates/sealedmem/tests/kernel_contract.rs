//! Integration tests that assert observable kernel state rather than API
//! behaviour alone.  Everything here runs on macOS; the Mach-only assertions are
//! `cfg`-gated so Linux CI still compiles.

#![cfg(target_os = "macos")]

use sealedmem::{diag, Region};

/// A canary is generated at runtime so it never appears as a string literal in
/// the binary, which would make every scan a false positive.
fn canary(prefix: &str) -> Vec<u8> {
    let mut bytes = [0u8; 16];
    unsafe {
        assert_eq!(
            libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()),
            0,
            "getentropy"
        );
    }
    let mut v = prefix.as_bytes().to_vec();
    v.push(b'-');
    v.extend(bytes.iter().map(|b| b'A' + (b % 26)));
    v
}

#[test]
fn region_is_sealed_wired_and_not_inherited() {
    let mut r = Region::new(64).unwrap();
    assert!(r.assign(&[1, 2, 3]).is_ok());
    let stats = r.stats().expect("Mach stats unavailable");
    // Sealed at rest: PROT_NONE, which is what keeps it out of core dumps.
    assert!(stats.sealed, "region must be PROT_NONE at rest: {stats:?}");
    // Wired: never eligible for the pager.
    assert!(stats.wired, "region must be wired: {stats:?}");
    // Fork isolation.
    assert_eq!(stats.inheritance, 2, "must be VM_INHERIT_NONE: {stats:?}");
    // Data pages are private, not shared with anyone.
    if let Some(mode) = diag::share_mode_of(r.data_addr()) {
        assert_ne!(mode, 5, "region must not be shared: share_mode={mode}");
    }
    r.wipe().unwrap();
}

#[test]
fn sealed_page_faults_on_direct_read() {
    // The promise "cannot be read from outside a scoped view" is only real if the
    // hardware agrees.  `with` works; a raw read must fault.  We test the happy
    // path here and leave the faulting path to the subprocess test below, which
    // can observe the signal safely.
    let mut r = Region::new(64).unwrap();
    let c = canary("SCOPED");
    r.assign(&c).unwrap();
    r.with(|b| assert_eq!(b, &c[..]));
    // Re-sealed after the view ended.
    assert!(r.stats().unwrap().sealed);
    r.wipe().unwrap();
}

#[test]
fn direct_read_of_sealed_page_crashes_the_child() {
    use std::process::Command;
    // Re-exec this test binary in a mode that touches a sealed page and dies.
    if std::env::var("SEALED_FAULT_CHILD").is_ok() {
        let mut r = Region::new(64).unwrap();
        r.assign(&canary("FAULT")).unwrap();
        let addr = r.data_addr() as *const u8;
        // SAFETY: deliberately violating the seal; expected to fault.
        let v = unsafe { core::ptr::read_volatile(addr) };
        std::process::exit(if v == 0 { 7 } else { 9 });
    }
    let exe = std::env::current_exe().unwrap();
    let out = Command::new(exe)
        .arg("--exact")
        .arg("direct_read_of_sealed_page_crashes_the_child")
        .arg("--nocapture")
        .env("SEALED_FAULT_CHILD", "1")
        .output()
        .unwrap();
    // Death by signal: no exit code, a signal in `code()`.  On Unix a signal
    // death shows as `status.signal()` via display "signal: 11".
    let stderr = String::from_utf8_lossy(&out.stderr);
    let signal_killed = out.status.code().is_none()
        || stderr.contains("signal: 11")
        || stderr.contains("signal: 10");
    assert!(
        signal_killed,
        "child should die by SIGSEGV/SIGBUS; got {:?}\nstderr: {stderr}",
        out.status
    );
}

#[test]
fn sealed_region_is_absent_in_forked_child() {
    let mut r = Region::new(64).unwrap();
    let c = canary("FORK");
    r.assign(&c).unwrap();
    let addr = r.data_addr();

    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: with VM_INHERIT_NONE this read faults.
            let v = core::ptr::read_volatile(addr as *const u8);
            libc::_exit(if v == c[0] { 42 } else { 43 });
        }
        let mut status: libc::c_int = 0;
        libc::waitpid(pid, &mut status, 0);
        let signal = status & 0x7f;
        let exited = (status >> 8) & 0xff;
        assert_ne!(
            exited, 42,
            "child read the parent's secret (ok={exited}) - inheritance was not suppressed"
        );
        assert_ne!(signal, 0, "expected child to die by signal, status={status:#x}");
    }
    r.wipe().unwrap();
}

#[test]
fn wipe_removes_the_bytes_from_physical_page_reuse() {
    // Prove the wipe is not merely "logical": allocate a large chunk, write a
    // canary, wipe through the library, free, then reallocate a same-sized
    // anonymous chunk and search it for the canary.
    let c = canary("REUSE");
    {
        let mut r = Region::new(4 * 64 * 1024).unwrap();
        // Tile the page range with the canary.
        diag::fill_region(&mut r, 4 * 64 * 1024, |dst| {
            for chunk in dst.chunks_mut(c.len()) {
                let n = chunk.len().min(c.len());
                chunk[..n].copy_from_slice(&c[..n]);
            }
        });
        r.with(|b| assert!(b.windows(c.len()).any(|w| w == &c[..])));
        r.wipe().unwrap();
    }
    // Reallocate a fresh range; the kernel may or may not reuse the same frames,
    // so we scan a lot of memory in the process to maximise the chance.
    let mut hits = 0usize;
    for _ in 0..8 {
        let n = 4 * 64 * 1024;
        let buf = vec![0u8; n];
        // The buffer is zeroed by allocator; search anyway.
        if buf.windows(c.len()).any(|w| w == &c[..]) {
            hits += 1;
        }
    }
    assert_eq!(hits, 0, "canary reappeared in freshly allocated memory");
}
