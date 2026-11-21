//! A toy authentication/session service with a build-time switch between plain
//! handling and `sealedmem`.
//!
//! The service models the incident that motivated the library: it loads a
//! database password and mints short-lived session keys. Both values are
//! *ephemeral secrets* — they must exist long enough to do work, and then must
//! not be findable afterwards.
//!
//! It is deliberately small and self-reporting. Every stage prints a machine
//! readable `STAGE <name>` line and, where it matters, the runtime canary it
//! just loaded, so the verification harness can scan for it from the outside.
//!
//! Modes (`--mode`):
//! * `plain`     — the naive implementation: `String`/`Vec`, derive `Clone`, format
//!   into logs, keep the password in the process environment.  This is the "before".
//! * `sealed`    — every secret is a `SealedString`/`SealedBytes`, env is scrubbed
//!   after load, keys are held in sealed pages, and the fatal-signal/`atexit`
//!   guards are installed.  This is the "after".
//!
//! Stages (`--stage`), in order:
//! * `load`   — read the database password and generate a session key
//! * `use`    — use both (HMAC a message, compare a password) and demonstrate
//!   they are usable
//! * `erase`  — release/erase them
//! * `crash`  — (optional) after the erase stage, deliberately crash; for plain
//!   mode the crash happens with the secrets still live, showing what a dump
//!   would contain.
//!
//! `--stay` keeps the process alive between stages (`readline` on stdin) so the
//! harness can scan it at each stage. That is the whole point: the scanner sees
//! the same process at "secret live" and "secret erased".

use std::io::{BufRead, Write};

use hmac::{Hmac, KeyInit, Mac};
use sealedmem::{guard, scrub, SealedBytes, SealedString};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const DATABASE_PASSWORD_ENV: &str = "DEMO_DB_PASSWORD";
const SESSION_KEY_ENV: &str = "DEMO_SESSION_KEY";
const CRASH_KEY_ENV: &str = "DEMO_CRASH_KEY";

/// A runtime canary: unique per run, never a source-code literal. Printed to
/// stdout so the harness can grep it, and embedded in the "database password" so
/// a scan for it tells us where the password went.
struct Config {
    sealed: bool,
    stay: bool,
    crash: bool,
}

/// State for the two modes.  Keeping them in one enum makes the demo's promise
/// obvious: the plain variant has *fields you can read*, the sealed one does not.
enum Secrets {
    Plain {
        db_password: String,
        session_key: Vec<u8>,
    },
    Sealed {
        db_password: SealedString,
        session_key: SealedBytes,
    },
}

fn stage(name: &str) {
    println!("STAGE {name}");
    let _ = std::io::stdout().flush();
}

fn pause(cfg: &Config, what: &str) {
    if !cfg.stay {
        return;
    }
    println!("PAUSED {what}");
    let _ = std::io::stdout().flush();
    let stdin = std::io::stdin();
    let mut line = String::new();
    let _ = stdin.lock().read_line(&mut line);
}

fn main() {
    // Anything printed to stdout that the harness reads is *not* secret; the
    // secret canaries are printed so a scanner can search for them.
    run();
}

fn run() {
    // Parse very small flags by hand: no dependency on clap for a demo.
    let mut sealed = false;
    let mut stay = false;
    let mut crash = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--sealed" => sealed = true,
            "--stay" => stay = true,
            "--crash" => crash = true,
            other => {
                eprintln!("unknown flag {other}; use --sealed --stay --crash");
                std::process::exit(2);
            }
        }
    }
    let cfg = Config {
        sealed,
        stay,
        crash,
    };

    // Install the guards *first* in sealed mode, before any secret exists.  In
    // plain mode we deliberately do not: that is part of the comparison.
    if cfg.sealed {
        guard::install_termination();
    }

    // The canaries are supplied by the harness on the environment, so this demo
    // never constructs or prints a secret itself.  That matters: a canary the
    // program formatted into a `String` would be a *second* copy outside the
    // sealed page, and the comparison would no longer be about the library.
    //
    //   DEMO_DB_PASSWORD   : canary prefix + "::s3cr3t-shared-db-pw"
    //   DEMO_SESSION_KEY   : session-key canary, exactly 24 bytes
    //
    // Missing values are a configuration error (a real service would refuse to
    // start), not a fallback to a generated secret.
    let mut secrets = if cfg.sealed {
        // Sealed mode reads the environment **by pointer** and copies the bytes
        // straight into the sealed page.  It never calls `env::var` (no `String`)
        // and never needs the canary prefix separately: the password is compared
        // against a freshly formatted copy (which is "just" a stack/heap value
        // that lives as briefly as any comparison operand).
        let password = SealedString::from_env(DATABASE_PASSWORD_ENV)
            .expect("sealed read")
            .expect("password present");
        let key = SealedBytes::from_env(SESSION_KEY_ENV)
            .expect("sealed read")
            .expect("key present");
        // Immediately scrub libc's copy and the kernel's per-pid snapshot.
        scrub::scrub_env_var(DATABASE_PASSWORD_ENV);
        scrub::scrub_env_var(SESSION_KEY_ENV);
        Secrets::Sealed {
            db_password: password,
            session_key: key,
        }
    } else {
        // Naive: the environment keeps a live copy (never scrubbed), `var()`
        // copies it into a `String`, and the use stage formats a second copy for
        // logging and comparison.  Nothing here is wiped until the values drop.
        let password = std::env::var(DATABASE_PASSWORD_ENV)
            .expect("DEMO_DB_PASSWORD must be set by the harness");
        let key = std::env::var(SESSION_KEY_ENV)
            .expect("DEMO_SESSION_KEY must be set by the harness")
            .into_bytes();
        Secrets::Plain {
            db_password: password,
            session_key: key,
        }
    };
    stage("load");
    pause(&cfg, "load");

    // ---- stage: use ----
    // Authenticate a request: HMAC with the session key and constant-time
    // compare the password.
    match &secrets {
        Secrets::Sealed { session_key, db_password } => {
            let tag = session_key.with(|k| hmac_tag(k, b"GET /admin"));
            // Constant-time compare against the static suffix of the password,
            // which is not secret and is the only part the demo needs to check.
            // (A real service would hash the presented password and compare the
            // hash; the point here is to show the value is usable without being
            // readable at rest.)
            let ok = db_password.with_bytes(|b| b.ends_with(b"s3cr3t-shared-db-pw"));
            println!(
                "USE mode=sealed password_ok={ok} tag={}",
                residue_safe_hex(&tag)
            );
            // Show the kernel's own view: sealed, wired, not inherited.
            for (name, s) in [("db_password", db_password.stats()), ("session_key", session_key.stats())] {
                if let Some(st) = s {
                    println!("REGION {name} sealed={} wired={} inherit={}", st.sealed, st.wired, st.inheritance);
                }
            }
        }
        Secrets::Plain { session_key, db_password } => {
            let tag = hmac_tag(session_key, b"GET /admin");
            // Correct comparison, done the naive way: the expected value is
            // re-derived with `format!`, creating yet another heap copy of the
            // password - the kind of copy that survives the later "wipe".
            let ok = db_password.ends_with("s3cr3t-shared-db-pw");
            // The classic mistake: log the request "for debugging".  This is a
            // second heap copy of the key, made by `format!`.
            let logged = format!("key={:?}", session_key);
            println!(
                "USE mode=plain password_ok={ok} tag={} debug_log={}",
                residue_safe_hex(&tag),
                logged
            );
            println!("REGION db_password sealed=false wired=false inherit=inherit (ordinary heap)");
        }
    }
    stage("use");
    pause(&cfg, "use");

    // ---- stage: erase ----
    match &mut secrets {
        Secrets::Sealed { db_password, session_key } => {
            db_password.wipe().ok();
            session_key.wipe().ok();
            println!("ERASE mode=sealed wiped=both");
        }
        Secrets::Plain { db_password, session_key } => {
            // Best-effort wipe, which is exactly the point: `String::clear`/`Vec`
            // capacity, the allocator's free list and any clone still hold bytes.
            db_password.zeroize();
            session_key.zeroize();
            println!("ERASE mode=plain wiped=best_effort");
        }
    }
    println!(
        "RESIDUE_EXPECT mode={} leak_after_erase={}",
        if cfg.sealed { "sealed" } else { "plain" },
        if cfg.sealed { "no" } else { "unknown" }
    );
    stage("erased");
    pause(&cfg, "erased");

    // ---- stage: use-again + crash (optional) ----
    // The harness supplies a fresh canary on the environment (`DEMO_CRASH_KEY`),
    // so the value has no other in-process copy: in sealed mode it is read
    // straight into a `PROT_NONE` page and never exists as a `String`/`Vec`
    // anywhere else, which makes a core scan a fair test of where *our* copy went.
    //
    // In plain mode the same bytes land in a `Vec` and stay there as the process
    // faults; a debugger's core dump contains them.  In sealed mode the page is
    // `PROT_NONE` (so the core writer cannot include it) and the fatal-signal
    // handler wipes it before the process dies.
    if cfg.crash {
        let rehydrated = if cfg.sealed {
            let key = SealedBytes::from_env(CRASH_KEY_ENV)
                .expect("sealed read")
                .expect("DEMO_CRASH_KEY must be set by the harness");
            scrub::scrub_env_var(CRASH_KEY_ENV);
            Secrets::Sealed {
                // The password was wiped in the erase stage; this is only about
                // the key, so a fresh sealed page for it is enough.
                db_password: SealedString::from_utf8(b"post-erase").expect("sealed pw"),
                session_key: key,
            }
        } else {
            let raw = std::env::var(CRASH_KEY_ENV)
                .expect("DEMO_CRASH_KEY must be set by the harness");
            // Keep a heap copy alive across the fault, as ordinary code does.
            Secrets::Plain {
                db_password: String::from("post-erase"),
                session_key: raw.into_bytes(),
            }
        };
        // Use the value once right before the fault, the way a live request
        // would, so the compiler cannot prove it dead and elide it: `rehydrated`
        // is still in scope when the fault happens.  Nothing is `mem::forget`-ed;
        // the plain-mode value simply has not been dropped yet, which is the
        // realistic crash case, and the sealed value is still in its page.
        let _tag = match &rehydrated {
            Secrets::Sealed { session_key, .. } => session_key.with(|k| hmac_tag(k, b"GET /last")),
            Secrets::Plain { session_key, .. } => hmac_tag(session_key, b"GET /last"),
        };

        stage("use-again");
        pause(&cfg, "use-again");
        stage("crash");
        let armed = guard::faults_installed();
        println!("SIGNAL_HANDLER armed={armed}");
        let _ = std::io::stdout().flush();
        unsafe {
            let p = std::ptr::null_mut::<u8>();
            std::ptr::write_volatile(p, 1);
        }
    }
}

fn hmac_tag(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn residue_safe_hex(bytes: &[u8]) -> String {
    // The tag is not secret (it is a MAC output the client is meant to see), so
    // printing it is fine and makes the demo observable.
    bytes.iter().take(8).fold(String::new(), |mut acc, b| {
        let _ = std::fmt::Write::write_fmt(&mut acc, format_args!("{b:02x}"));
        acc
    })
}
