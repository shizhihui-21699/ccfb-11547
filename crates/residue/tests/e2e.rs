//! The end-to-end proof, as a test.
//!
//! `scripts/verify.sh` is the human-readable version of this; a CI run just
//! wants the exit status.  This wraps the script so `cargo test` fails loudly if
//! the sealed/naive contrast ever regresses.  It is `#[ignore]`d by default
//! because it takes ~20 s and needs `lldb` + code signing; run it with
//! `cargo test --test e2e -- --ignored`.

#![cfg(target_os = "macos")]

use std::process::Command;

#[test]
#[ignore = "spawns lldb and signs binaries; run in the verification job"]
fn end_to_end_contrast() {
    // `CARGO_MANIFEST_DIR` is `<workspace>/crates/residue`.
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_dir.parent().unwrap().parent().unwrap();
    let script = workspace.join("scripts/verify.sh");
    let out = Command::new("/bin/bash")
        .arg(&script)
        .current_dir(workspace)
        .output()
        .expect("run verify.sh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Always show the stage lines in the test log; they are the artifact.
    println!("{stdout}");
    if !out.stderr.is_empty() {
        println!("{}", String::from_utf8_lossy(&out.stderr));
    }
    assert!(
        out.status.success(),
        "verify.sh failed; see output above"
    );
    // A pass must include both halves of the contrast, not just "no failures".
    assert!(
        stdout.contains("plain load: secret found"),
        "naive mode did not leak at load; the scanner is not seeing the secret"
    );
    assert!(
        stdout.contains("sealed crash: crash secret absent from core"),
        "sealed mode's core was not verified"
    );
    assert!(stdout.contains("checks failed: 0"), "non-zero failures");
}
