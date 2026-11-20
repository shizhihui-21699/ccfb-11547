//! `memcanary` command-line tool.
//!
//! Three subcommands:
//!
//! * `audit` — run one service implementation in this process, capture memory at
//!   each lifecycle stage, and report which stages contain residue.
//! * `compare` — run both implementations in separate child processes and print
//!   a side-by-side table.
//! * `scan` — scan an already-running process (requires `get-task-allow` on
//!   macOS; see the README).
//!
//! The command exits non-zero when a *hardened* run leaves residue, so it can be
//! a CI gate.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use memcanary::{Auditor, Needle};
use secretmem::{harden_process, hardening_report, HardeningOptions};

use demo_service::{Config, Flow, Mode, Request, Response, Stage};

mod report_io;

#[derive(Parser)]
#[command(
    name = "memcanary",
    about = "Prove that sensitive values were wiped, stage by stage",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one implementation and capture memory at each stage.
    Audit {
        /// `naive` or `hardened`.
        #[arg(long, default_value = "hardened")]
        mode: String,
        /// Write a JSON report here.
        #[arg(long)]
        json: Option<std::path::PathBuf>,
        /// Write a Markdown report here.
        #[arg(long)]
        markdown: Option<std::path::PathBuf>,
        /// Skip regions larger than this many MiB.
        #[arg(long, default_value_t = 512)]
        max_region_mib: usize,
        /// Exit non-zero if a hardened run leaves residue.
        #[arg(long, default_value_t = true)]
        fail_on_residue: bool,
    },
    /// Run both implementations in separate processes and diff the results.
    Compare {
        /// Write the side-by-side Markdown report here.
        #[arg(long)]
        markdown: Option<std::path::PathBuf>,
        /// Write the raw JSON for both runs here.
        #[arg(long)]
        json: Option<std::path::PathBuf>,
    },
    /// Scan a running process by pid (external attach).
    ///
    /// On macOS the target must be signed with `com.apple.security.get-task-allow`.
    /// On Linux the reader needs ptrace permission. This is how a service is
    /// inspected in production, or how evidence is taken around a crash.
    Scan {
        /// Process id to inspect.
        #[arg(long)]
        pid: u32,
        /// How many times to scan before giving up on a transient state.
        #[arg(long, default_value_t = 1)]
        repeats: u32,
        /// Milliseconds between repeats.
        #[arg(long, default_value_t = 250)]
        interval_ms: u64,
        /// Exit non-zero when leaks are found.
        #[arg(long, default_value_t = true)]
        fail_on_residue: bool,
        /// File containing the target's `PROTECTED <start> <len>` lines
        /// (cooperative mode). Without it, hits in the target are reported as
        /// `foreign` and counted as leaks, which over-reports.
        #[arg(long)]
        protected_file: Option<std::path::PathBuf>,
    },
    /// Run the service and park it, so an external scanner can attach.
    ///
    /// Prints its pid and waits. Used by `scripts/attach-demo.sh` and by anyone
    /// who wants to point `memcanary-cli scan --pid` at a live instance.
    ///
    /// With `--self-report`, the service also publishes the addresses of its
    /// containers to stdout. An external auditor that reads those addresses can
    /// classify its hits precisely; without them it can only say "foreign", which
    /// is conservative and over-reports (see the scan output).
    Serve {
        /// `naive` or `hardened`.
        #[arg(long, default_value = "hardened")]
        mode: String,
        /// Seconds to stay alive.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        /// Log in once before parking, so per-request material is in play as
        /// well as the long-lived keys. On by default; `--skip-login` turns it
        /// off.
        #[arg(long)]
        skip_login: bool,
        /// Print the addresses of every live container, so an external auditor
        /// can match them (cooperative mode). Off by default: a real service
        /// would gate this behind an authenticated debug endpoint.
        #[arg(long)]
        self_report: bool,
    },
    /// Internal: run one mode and print a machine-readable summary.
    #[command(hide = true)]
    RunOne {
        #[arg(long)]
        mode: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Audit { mode, json, markdown, max_region_mib, fail_on_residue } => {
            audit(&mode, json, markdown, max_region_mib, fail_on_residue)
        }
        Command::Compare { markdown, json } => compare(markdown, json),
        Command::Scan { pid, repeats, interval_ms, fail_on_residue, protected_file } => {
            scan_pid(pid, repeats, interval_ms, fail_on_residue, protected_file)
        }
        Command::Serve { mode, seconds, skip_login, self_report } => {
            serve(&mode, seconds, !skip_login, self_report)
        }
        Command::RunOne { mode } => run_one(&mode),
    }
}

/// Derives the demo's secret values from a fixed seed.
///
/// Two requirements pull in opposite directions:
///
/// * the value must be **identical** in every process (so an external scan for
///   it matches, and the naive and hardened runs are compared on the same
///   bytes), which argues for a constant;
/// * the value must **not appear in the binary**, or it sits in read-only data
///   before `main` runs and no library can wipe it.
///
/// Expanding a seed with SHA-256 satisfies both: the seed is in rodata, the
/// value is not. This is also how a real service should treat a master secret —
/// store the seed, derive the working key at startup.
fn derive(domain: &str, len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    // A 32-byte seed. Its *contents* are not secret in this demo; in a real
    // service the seed comes from the environment or a secret manager, never
    // from source.
    let seed = b"memcanary-demo-seed-v1-do-not-use-in-production";
    let mut out = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(b":");
        h.update(domain.as_bytes());
        h.update(b":");
        h.update(counter.to_be_bytes());
        let digest = h.finalize();
        out.extend_from_slice(&digest);
        counter += 1;
    }
    out.truncate(len);
    // Render as lowercase hex so every byte is printable and any encoding of it
    // (raw, url-encoded) is easy to spot.
    let hex: Vec<u8> = out
        .iter()
        .flat_map(|b| {
            const H: &[u8; 16] = b"0123456789abcdef";
            [H[(b >> 4) as usize], H[(b & 0xf) as usize]]
        })
        .collect();
    let mut hex = hex;
    hex.truncate(len);
    hex
}

/// Fills `dst` from the seed by hex-expanding a chain of SHA-256 digests.
///
/// This is the *naive* derivation. It does not wipe its hash state: that is
/// exactly what a service that has not thought about memory lifetime does, and it
/// is what gives the naive run its residue. The hardened service uses
/// [`secretmem::derive_key`] instead, which keeps the hasher in protected memory.
/// Keeping both makes the difference attributable: same output bytes, different
/// handling of the intermediate state.
fn derive_naive_into(domain: &str, dst: &mut [u8]) {
    use sha2::{Digest, Sha256};
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut off = 0;
    let mut counter: u32 = 0;
    while off < dst.len() {
        let mut h = Sha256::new();
        h.update(DEMO_SEED);
        h.update(b":");
        h.update(domain.as_bytes());
        h.update(b":");
        h.update(counter.to_be_bytes());
        let digest = h.finalize();
        for &b in digest[..].iter() {
            if off >= dst.len() {
                break;
            }
            dst[off] = H[(b >> 4) as usize];
            off += 1;
            if off < dst.len() {
                dst[off] = H[(b & 0xf) as usize];
                off += 1;
            }
        }
        counter += 1;
    }
}

/// The naive service's DB password: a plain `Vec` built by a derivation that
/// leaves its hash state on the stack.
fn demo_password() -> Vec<u8> {
    let mut v = vec![0u8; 24];
    derive_naive_into("db-password", &mut v);
    v
}

fn demo_signing_key() -> Vec<u8> {
    derive("session-signing-key", 32)
}

fn demo_user_password() -> Vec<u8> {
    derive("user-password", 20)
}

/// The secrets the demo service is built with.
fn demo_config() -> Config {
    let password = demo_password();
    let signing_key = demo_signing_key();

    // One enrolled user. The verifier is computed here, at runtime, so the
    // value exists only in memory.
    let user_password = demo_user_password();
    let enrolled = demo_service::wire::enrol(&user_password);

    Config {
        database_url: "postgres://db.internal:5432/app".to_string(),
        database_password: password,
        session_signing_key: signing_key,
        users: vec![demo_service::UserRecord {
            username: "alice".to_string(),
            salt: enrolled.salt.to_vec(),
            password_verifier: enrolled.verifier.to_vec(),
        }],
    }
}

/// Needles for every sensitive value the demo holds.
fn needles() -> Vec<Needle> {
    let cfg = demo_config();
    vec![
        Needle::label("db-password").from_bytes(&cfg.database_password).expect("needle"),
        Needle::label("session-key").from_bytes(&cfg.session_signing_key).expect("needle"),
        Needle::label("password-verifier")
            .from_bytes(&cfg.users[0].password_verifier)
            .expect("needle"),
        Needle::label("user-password")
            .from_bytes(&demo_user_password())
            .expect("needle"),
    ]
}

/// Runs the lifecycle and takes a checkpoint at every stage.
fn audit(
    mode: &str,
    json: Option<std::path::PathBuf>,
    markdown: Option<std::path::PathBuf>,
    max_region_mib: usize,
    fail_on_residue: bool,
) -> ExitCode {
    let mode: Mode = match mode.parse() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    if mode == Mode::Hardened {
        let report = harden_process(HardeningOptions::default()).expect("hardening failed");
        eprintln!("process hardening: {report:?}");
        if !report.is_complete() {
            eprintln!(
                "WARNING: hardening incomplete; some leak paths remain. See the report above."
            );
        }
    }

    let mut auditor = Auditor::with_options(memcanary::AuditorOptions {
        scan_images: false,
        max_region_bytes: Some(max_region_mib * 1024 * 1024),
        min_region_bytes: 1,
        chunk_bytes: 8 * 1024 * 1024,
    })
    .expect("auditor");
    for n in needles() {
        auditor.watch(n);
    }

    let stages = run_lifecycle(mode, &mut auditor);
    let verdict = report_io::Verdict::from_stages(mode, &stages);

    if let Some(path) = &json {
        report_io::write_json(path, mode, &stages, &verdict, hardening_report()).expect("write json");
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = &markdown {
        report_io::write_markdown(path, mode, &stages, &verdict).expect("write markdown");
        eprintln!("wrote {}", path.display());
    }
    report_io::print_summary(mode, &stages, &verdict);

    if mode == Mode::Hardened && verdict.has_residue() && fail_on_residue {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Builds the hardened service with **no intermediate secret buffer**.
///
/// Every long-lived secret is derived directly into its container; only public
/// data (URL, usernames, salts) is built as ordinary values. This is what the
/// `Config`-based `Flow::startup` cannot do, and why the audit distinguishes the
/// two: `startup(config)` necessarily receives the secrets already materialised.
/// The demo's master seed. Public in this demo; a real service reads it from the
/// environment or a secret manager.
const DEMO_SEED: &[u8] = b"memcanary-demo-seed-v1-do-not-use-in-production";

fn hardened_from_seed() -> demo_service::hardened::Service {
    use demo_service::hardened::{PublicConfig, PublicUser, Service};
    // `secretmem::derive_key` keeps the SHA-256 state in protected memory and
    // wipes it, so neither the digest nor the hasher's block buffer is left on
    // the stack. Using it here (rather than a local derivation) is the whole
    // point: the derivation frames belong to the library, which does the wiping.
    let signed: secretmem::SecretKey<32> =
        secretmem::derive_key(DEMO_SEED, &[b"session-signing-key"]).expect("derive");
    let password: secretmem::SecretBytes = {
        let k: secretmem::SecretKey<24> =
            secretmem::derive_key(DEMO_SEED, &[b"db-password"]).expect("derive");
        secretmem::SecretBytes::from_slice(k.expose()).expect("region")
    };
    // Verifiers: the demo's user password is public to the *service builder*
    // here for simplicity; a real enrolment derives it in a container too.
    let user_pw = demo_user_password();
    let enrolled = demo_service::wire::enrol(&user_pw);
    let mut user_pw = user_pw;
    for b in user_pw.iter_mut() {
        // SAFETY: exclusive access.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    let public = PublicConfig {
        database_url: "postgres://db.internal:5432/app".to_string(),
        users: vec![PublicUser { username: "alice".to_string(), salt: enrolled.salt.to_vec() }],
    };
    Service::from_secrets(public, password, signed, vec![enrolled.verifier.to_vec()])
}

/// Drives the service through login, verification and shutdown, scanning after
/// each phase.
fn run_lifecycle(mode: Mode, auditor: &mut Auditor) -> Vec<report_io::StageReport> {
    let mut out = Vec::new();

    // --- startup ---------------------------------------------------------
    let cfg = demo_config();
    match mode {
        Mode::Naive => {
            let mut svc = demo_service::naive::Service::startup(cfg);
            out.push(checkpoint(auditor, Stage::Loaded));
            // The same in-flight sample as the hardened run, so the two tables
            // are comparable: the password is live in an ordinary Vec.
            {
                let mut pw = demo_user_password();
                std::hint::black_box(&pw);
                out.push(checkpoint(auditor, Stage::LoginInFlight));
                for b in pw.iter_mut() {
                    // SAFETY: exclusive access to our own buffer.
                    unsafe { std::ptr::write_volatile(b, 0) };
                }
            }
            // Touch the connection string, which logs the password into a
            // String the way a real driver error would.
            std::hint::black_box(svc.connection_string());
            let token = login(&mut svc);
            out.push(checkpoint(auditor, Stage::LoginSettled));
            let _ = verify(&mut svc, token);
            out.push(checkpoint(auditor, Stage::TokenVerified));
            // Scan while the service is still holding its secrets, which is the
            // state a crash dump captures. Scanning *after* `shutdown` would be
            // misleading: `free()` returns the pages to the allocator and the
            // bytes may or may not survive depending on whether something else
            // reused them, so a clean result there would be luck, not design.
            out.push(checkpoint(auditor, Stage::Shutdown));
            svc.shutdown();
        }
        Mode::Hardened => {
            // Ignore the Config path for the hardened service; build from the
            // seed so nothing secret ever sits in an ordinary buffer.
            drop(cfg);
            let mut svc = hardened_from_seed();
            out.push(checkpoint(auditor, Stage::Loaded));
            // In-flight: the auditor runs while the password is live. We cannot
            // pause the service mid-call, so this models the state a debugger
            // would sample: call the scan from a wrapper that holds the
            // plaintext in a protected container.
            {
                let mut pw = secretmem::SecretBytes::from_slice(&demo_user_password())
                    .expect("region");
                std::hint::black_box(pw.expose());
                out.push(checkpoint(auditor, Stage::LoginInFlight));
                pw.wipe();
            }
            let token = login(&mut svc);
            out.push(checkpoint(auditor, Stage::LoginSettled));
            let _ = verify(&mut svc, token);
            out.push(checkpoint(auditor, Stage::TokenVerified));
            // Same sampling point as the naive run: still holding long-lived
            // secrets, about to shut down.
            out.push(checkpoint(auditor, Stage::Shutdown));
            svc.shutdown();
        }
    }
    out
}

fn login(svc: &mut impl Flow) -> String {
    match svc.handle(Request::Login {
        username: "alice".to_string(),
        password: demo_user_password(),
    }) {
        Response::Token(t) => t,
        other => panic!("login failed: {other:?}"),
    }
}

fn verify(svc: &mut impl Flow, token: String) -> Response {
    svc.handle(Request::Verify { token })
}

fn checkpoint(auditor: &mut Auditor, stage: Stage) -> report_io::StageReport {
    let report = auditor.checkpoint(stage.as_str()).expect("scan").clone();
    report_io::StageReport::from_report(stage, &report)
}

fn run_one(mode: &str) -> ExitCode {
    // Used by `compare`: emit JSON to stdout for the parent to collect.
    let mode: Mode = match mode.parse() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if mode == Mode::Hardened {
        let _ = harden_process(HardeningOptions::default());
    }
    let mut auditor = Auditor::with_options(memcanary::AuditorOptions {
        max_region_bytes: Some(512 * 1024 * 1024),
        ..Default::default()
    })
    .expect("auditor");
    for n in needles() {
        auditor.watch(n);
    }
    let stages = run_lifecycle(mode, &mut auditor);
    let verdict = report_io::Verdict::from_stages(mode, &stages);
    let json = report_io::render_json(mode, &stages, &verdict, hardening_report());
    println!("{json}");
    ExitCode::SUCCESS
}

fn serve(mode: &str, seconds: u64, do_login: bool, self_report: bool) -> ExitCode {
    let mode: Mode = match mode.parse() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if mode == Mode::Hardened {
        if let Ok(r) = harden_process(HardeningOptions::default()) {
            eprintln!("hardening: {r:?}");
        }
    }
    let cfg = demo_config();
    // Announced before the service is built, so a scanner can attach as early as
    // it likes.
    println!("PID {}", std::process::id());
    println!("PORT none");
    use std::io::Write;
    let _ = std::io::stdout().flush();

    match mode {
        Mode::Naive => {
            let mut svc = demo_service::naive::Service::startup(cfg);
            if do_login {
                let token = login(&mut svc);
                let _ = verify(&mut svc, token);
            }
            announce(self_report);
            std::hint::black_box(&svc);
            park(seconds);
            svc.shutdown();
        }
        Mode::Hardened => {
            drop(cfg);
            let mut svc = hardened_from_seed();
            if do_login {
                let token = login(&mut svc);
                let _ = verify(&mut svc, token);
            }
            // Announced *after* startup, so the containers holding the
            // long-lived keys already exist and are listed.
            announce(self_report);
            std::hint::black_box(&svc);
            park(seconds);
            svc.shutdown();
        }
    }
    ExitCode::SUCCESS
}

fn announce(self_report: bool) {
    if !self_report {
        return;
    }
    report_self_containers();
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Prints `PROTECTED <start> <len>` for each live container range.
///
/// A cooperating auditor reads these lines and can then classify its own hits:
/// anything inside a published range is under management (and will be wiped),
/// anything outside is residue. Without this, an external scan can only say
/// "foreign" and must over-report.
fn report_self_containers() {
    for (start, len) in secretmem::protected_ranges() {
        println!("PROTECTED {start} {len}");
    }
}

fn park(seconds: u64) {
    std::thread::sleep(std::time::Duration::from_secs(seconds));
}

fn scan_pid(
    pid: u32,
    repeats: u32,
    interval_ms: u64,
    fail_on_residue: bool,
    protected_file: Option<std::path::PathBuf>,
) -> ExitCode {
    let mut auditor = match Auditor::for_pid(
        pid,
        memcanary::AuditorOptions {
            max_region_bytes: Some(512 * 1024 * 1024),
            ..Default::default()
        },
    ) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    for n in needles() {
        auditor.watch(n);
    }
    if let Some(path) = protected_file {
        match parse_protected(&path) {
            Ok(ranges) => {
                eprintln!("using {} declared protected range(s) from {}", ranges.len(), path.display());
                auditor.declare_protected(ranges);
            }
            Err(e) => {
                eprintln!("cannot read {}: {e}", path.display());
                return ExitCode::from(2);
            }
        }
    }
    let mut worst = 0usize;
    for i in 0..repeats.max(1) {
        match auditor.scan() {
            Ok(report) => {
                let leaks: Vec<String> = report.leaks().map(|f| f.needle.clone()).collect();
                worst = worst.max(leaks.len());
                println!(
                    "scan {}: {} region(s), {} bytes, {} leak(s){}",
                    i + 1,
                    report.stats.regions_read,
                    report.stats.bytes_read,
                    leaks.len(),
                    if leaks.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", leaks.join(", "))
                    }
                );
            }
            Err(e) => {
                eprintln!("scan {} failed: {e}", i + 1);
                return ExitCode::FAILURE;
            }
        }
        if i + 1 < repeats {
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
        }
    }
    if worst > 0 && fail_on_residue {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Parses `PROTECTED <start> <len>` lines.
fn parse_protected(path: &std::path::Path) -> std::io::Result<Vec<(u64, u64)>> {
    let text = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if it.next() != Some("PROTECTED") {
            continue;
        }
        let (Some(start), Some(len)) = (it.next(), it.next()) else {
            continue;
        };
        if let (Ok(start), Ok(len)) = (start.parse::<u64>(), len.parse::<u64>()) {
            out.push((start, start.saturating_add(len)));
        }
    }
    Ok(out)
}

fn compare(markdown: Option<std::path::PathBuf>, json: Option<std::path::PathBuf>) -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot find own executable: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut runs = Vec::new();
    for mode in ["naive", "hardened"] {
        let out = std::process::Command::new(&exe)
            .args(["run-one", "--mode", mode])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout).into_owned();
                match report_io::parse_run(&text) {
                    Ok(run) => runs.push(run),
                    Err(e) => {
                        eprintln!("could not parse {mode} output: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            Ok(o) => {
                eprintln!(
                    "run-one {mode} failed ({}):\n{}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                );
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("could not spawn run-one: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if let Some(path) = &json {
        report_io::write_compare_json(path, &runs).expect("write json");
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = &markdown {
        report_io::write_compare_markdown(path, &runs).expect("write markdown");
        eprintln!("wrote {}", path.display());
    }
    report_io::print_compare(&runs);
    ExitCode::SUCCESS
}
