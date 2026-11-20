//! Report shaping and serialisation for the CLI.
//!
//! Kept out of the library: the library reports findings, this decides how a
//! *service owner* wants to read them (per stage, side by side, JSON for a CI
//! gate).

use std::path::Path;

use demo_service::{Mode, Stage};
use memcanary::{Finding, Report};
use secretmem::HardeningReport;
use serde_json::json;

/// One stage's scan, flattened for reporting.
pub struct StageReport {
    pub stage: Stage,
    pub findings: Vec<FindingSummary>,
    pub bytes_read: u64,
    pub regions_read: usize,
    pub regions_skipped: usize,
    pub elapsed_ms: u128,
}

/// A finding without the library's internal types, so it can be printed.
pub struct FindingSummary {
    pub needle: String,
    pub encoding: &'static str,
    pub address: u64,
    pub length: usize,
    pub provenance: &'static str,
    pub region: &'static str,
    pub weak: bool,
}

impl FindingSummary {
    /// Whether this is residue the service should not have: strong, and not
    /// inside a container that will wipe it.
    pub fn is_leak(&self) -> bool {
        !self.weak && self.provenance != "protected"
    }
}

impl StageReport {
    pub fn from_report(stage: Stage, r: &Report) -> Self {
        StageReport {
            stage,
            findings: r
                .findings
                .iter()
                .map(|f: &Finding| FindingSummary {
                    needle: f.needle.clone(),
                    encoding: f.derivation.as_str(),
                    address: f.address,
                    length: f.length,
                    provenance: f.provenance.as_str(),
                    region: f.region.kind.as_str(),
                    weak: f.weak,
                })
                .collect(),
            bytes_read: r.stats.bytes_read,
            regions_read: r.stats.regions_read,
            regions_skipped: r.stats.regions_skipped,
            elapsed_ms: r.stats.elapsed.as_millis(),
        }
    }

    /// Hits that count as leaks (strong, not protected).
    pub fn strong(&self) -> impl Iterator<Item = &FindingSummary> {
        self.findings.iter().filter(|f| f.is_leak())
    }

    /// Strong hits inside live containers. Expected, and will be wiped; shown
    /// separately so a reader can see the value is present but contained.
    pub fn protected(&self) -> impl Iterator<Item = &FindingSummary> {
        self.findings
            .iter()
            .filter(|f| !f.weak && f.provenance == "protected")
    }
}

/// The whole run's verdict.
pub struct Verdict {
    pub mode: Mode,
    pub dirty_stages: Vec<Stage>,
    /// Stages that are *expected* to hold a live secret (the in-flight one).
    pub expected_live: Vec<Stage>,
}

impl Verdict {
    pub fn from_stages(mode: Mode, stages: &[StageReport]) -> Self {
        let dirty_stages: Vec<Stage> = stages
            .iter()
            .filter(|s| s.strong().count() > 0)
            .map(|s| s.stage)
            .collect();
        // "login-in-flight" is *supposed* to contain the password: it models the
        // moment a debugger samples the service mid-request. Counting it as a
        // failure would be dishonest the other way.
        let expected_live = stages
            .iter()
            .filter(|s| s.stage == Stage::LoginInFlight && s.strong().count() > 0)
            .map(|s| s.stage)
            .collect();
        Verdict { mode, dirty_stages, expected_live }
    }

    /// Stages with residue that are not expected to have it.
    pub fn unexpected_dirty(&self) -> impl Iterator<Item = Stage> + '_ {
        self.dirty_stages
            .iter()
            .copied()
            .filter(move |&s| !self.expected_live.contains(&s))
    }

    pub fn has_residue(&self) -> bool {
        self.unexpected_dirty().next().is_some()
    }
}

pub fn render_json(
    mode: Mode,
    stages: &[StageReport],
    verdict: &Verdict,
    hardening: Option<HardeningReport>,
) -> String {
    let stages_json: Vec<_> = stages
        .iter()
        .map(|s| {
            json!({
                "stage": s.stage.as_str(),
                "bytes_read": s.bytes_read,
                "regions_read": s.regions_read,
                "regions_skipped": s.regions_skipped,
                "elapsed_ms": s.elapsed_ms,
                "findings": s.findings.iter().map(|f| json!({
                    "needle": f.needle,
                    "encoding": f.encoding,
                    "address": format!("{:#x}", f.address),
                    "length": f.length,
                    "provenance": f.provenance,
                    "region": f.region,
                    "weak": f.weak,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let v = json!({
        "mode": mode.to_string(),
        "hardening": hardening.map(|h| json!({
            "core_dumps_disabled": h.core_dumps_disabled,
            "fork_wipe_installed": h.fork_wipe_installed,
            "fatal_signal_wipe_installed": h.fatal_signal_wipe_installed,
            "memory_lockable": h.memory_lockable,
            "kernel_scrub_on_abnormal_exit": h.kernel_scrub_on_abnormal_exit,
        })),
        "stages": stages_json,
        "verdict": {
            "dirty_stages": verdict.dirty_stages.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "expected_live": verdict.expected_live.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "unexpectedly_dirty": verdict.unexpected_dirty().map(|s| s.as_str()).collect::<Vec<_>>(),
            "has_residue": verdict.has_residue(),
        }
    });
    serde_json::to_string_pretty(&v).expect("serialise")
}

pub fn write_json(
    path: &Path,
    mode: Mode,
    stages: &[StageReport],
    verdict: &Verdict,
    hardening: Option<HardeningReport>,
) -> std::io::Result<()> {
    std::fs::write(path, render_json(mode, stages, verdict, hardening))
}

pub fn write_markdown(
    path: &Path,
    mode: Mode,
    stages: &[StageReport],
    verdict: &Verdict,
) -> std::io::Result<()> {
    let mut s = String::new();
    s.push_str(&format!("# Memory audit — {mode} service\n\n"));
    s.push_str(
        "Each row is a scan of the whole address space taken at that lifecycle \
         stage. `residue` means a registered secret's bytes were found in \
         readable memory.\n\n",
    );
    s.push_str("| stage | bytes scanned | strong findings | residue | needles |\n");
    s.push_str("|---|---|---|---|---|\n");
    for st in stages {
        let names: Vec<String> = st.strong().map(|f| f.needle.clone()).collect();
        let residue = if names.is_empty() {
            let contained = st.protected().count();
            if contained > 0 {
                format!("clean ({contained} inside containers)")
            } else {
                "clean".to_string()
            }
        } else {
            names.join(", ")
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            st.stage,
            human_bytes(st.bytes_read),
            st.strong().count(),
            residue
        ));
    }
    s.push('\n');
    if verdict.has_residue() {
        s.push_str("## Residue detail\n\n");
        for st in stages {
            let strong: Vec<_> = st.strong().collect();
            if strong.is_empty() {
                continue;
            }
            s.push_str(&format!("### {}\n\n", st.stage));
            s.push_str("| needle | encoding | address | bytes | provenance | region |\n");
            s.push_str("|---|---|---|---|---|---|\n");
            for f in strong {
                s.push_str(&format!(
                    "| {} | {} | `{:#x}` | {} | {} | {} |\n",
                    f.needle, f.encoding, f.address, f.length, f.provenance, f.region
                ));
            }
            s.push('\n');
        }
    }
    s.push_str(&format!(
        "\n**Verdict:** {}\n",
        if verdict.has_residue() {
            "RESIDUE FOUND in unexpected stages"
        } else {
            "no residue outside the in-flight window"
        }
    ));
    std::fs::write(path, s)
}

pub fn print_summary(mode: Mode, stages: &[StageReport], verdict: &Verdict) {
    println!("mode: {mode}");
    println!("{:<20} {:>14} {:>16}  residue (leaks outside containers)", "stage", "bytes scanned", "leaks");
    println!("{}", "-".repeat(72));
    for st in stages {
        let leaks: Vec<&str> = st.strong().map(|f| f.needle.as_str()).collect();
        let contained = st.protected().count();
        let note = if leaks.is_empty() {
            if contained > 0 {
                format!("clean ({contained} hit(s) inside containers)")
            } else {
                "clean".to_string()
            }
        } else {
            leaks.join(", ")
        };
        println!(
            "{:<20} {:>14} {:>16}  {}",
            st.stage.as_str(),
            human_bytes(st.bytes_read),
            st.strong().count(),
            note
        );
    }
    println!();
    if verdict.has_residue() {
        println!(
            "VERDICT ({}): residue in {} stage(s): {}",
            verdict.mode,
            verdict.unexpected_dirty().count(),
            verdict
                .unexpected_dirty()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        println!(
            "VERDICT ({}): clean outside the in-flight window ({} container hits)",
            verdict.mode,
            stages.iter().map(|s| s.protected().count()).sum::<usize>()
        );
    }
}

/// A stage's leak needles, deduplicated and with a count for repeated encodings.
///
/// A single leaked value is usually found in several encodings (raw,
/// url-encoded, ...); listing "db-password, db-password, db-password" is noise.
fn summarize_leaks(st: &StageReport) -> String {
    let mut names: Vec<&str> = st.strong().map(|f| f.needle.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        "—".to_string()
    } else {
        names.join(", ")
    }
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

// --- compare --------------------------------------------------------------

/// A parsed `run-one` output.
pub struct Run {
    pub mode: String,
    pub stages: Vec<StageReport>,
}

pub fn parse_run(text: &str) -> Result<Run, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mode: Mode = v["mode"].as_str().ok_or("missing mode")?.parse()?;
    let mut stages = Vec::new();
    for st in v["stages"].as_array().ok_or("missing stages")? {
        let stage = match st["stage"].as_str().ok_or("stage name")? {
            "loaded" => Stage::Loaded,
            "login-in-flight" => Stage::LoginInFlight,
            "login-settled" => Stage::LoginSettled,
            "token-verified" => Stage::TokenVerified,
            "shutdown" => Stage::Shutdown,
            "crashed" => Stage::Crashed,
            other => return Err(format!("unknown stage {other}")),
        };
        let findings = st["findings"]
            .as_array()
            .ok_or("findings")?
            .iter()
            .map(|f| FindingSummary {
                needle: f["needle"].as_str().unwrap_or("?").to_string(),
                encoding: leak_static(f["encoding"].as_str().unwrap_or("raw")),
                address: u64::from_str_radix(
                    f["address"].as_str().unwrap_or("0x0").trim_start_matches("0x"),
                    16,
                )
                .unwrap_or(0),
                length: f["length"].as_u64().unwrap_or(0) as usize,
                provenance: leak_static(f["provenance"].as_str().unwrap_or("unknown")),
                region: leak_static(f["region"].as_str().unwrap_or("other")),
                weak: f["weak"].as_bool().unwrap_or(false),
            })
            .collect();
        stages.push(StageReport {
            stage,
            findings,
            bytes_read: st["bytes_read"].as_u64().unwrap_or(0),
            regions_read: st["regions_read"].as_u64().unwrap_or(0) as usize,
            regions_skipped: st["regions_skipped"].as_u64().unwrap_or(0) as usize,
            elapsed_ms: st["elapsed_ms"].as_u64().unwrap_or(0) as u128,
        });
    }
    Ok(Run { mode: mode.to_string(), stages })
}

/// The set of encoding and region names is fixed, so map back to the `'static`
/// strings the report types use.
fn leak_static(s: &str) -> &'static str {
    const ENCODINGS: &[&str] = &[
        "raw",
        "hex-lower",
        "hex-upper",
        "base64",
        "base64url",
        "url-encoded",
        "sha256-raw",
        "sha256-hex",
    ];
    const REGIONS: &[&str] = &[
        "anonymous",
        "image",
        "file-backed",
        "auditor-scratch",
        "other",
    ];
    const PROVENANCE: &[&str] = &["protected", "stack", "heap", "file-backed", "unknown"];
    for c in ENCODINGS.iter().chain(REGIONS.iter()).chain(PROVENANCE.iter()) {
        if *c == s {
            return c;
        }
    }
    "other"
}

pub fn write_compare_json(path: &Path, runs: &[Run]) -> std::io::Result<()> {
    let doc = json!(runs
        .iter()
        .map(|r| json!({
            "mode": r.mode,
            "stages": r.stages.iter().map(|s| json!({
                "stage": s.stage.as_str(),
                "strong_findings": s.strong().count(),
                "needles": s.strong().map(|f| f.needle.clone()).collect::<Vec<_>>(),
                "bytes_read": s.bytes_read,
            })).collect::<Vec<_>>(),
        }))
        .collect::<Vec<_>>());
    std::fs::write(path, serde_json::to_string_pretty(&doc).expect("json"))
}

pub fn write_compare_markdown(path: &Path, runs: &[Run]) -> std::io::Result<()> {
    let mut s = String::new();
    s.push_str("# Naive vs hardened: memory residue by lifecycle stage\n\n");
    s.push_str(
        "Both services run the identical request flow with identical crypto, in \
         separate processes. The only difference is where the sensitive values \
         live. `login-in-flight` is sampled while the password is deliberately \
         live, so a finding there is expected in both.\n\n",
    );
    s.push_str("| stage | naive: residue | hardened: residue |\n");
    s.push_str("|---|---|---|\n");
    let stages: Vec<Stage> = runs
        .iter()
        .flat_map(|r| r.stages.iter().map(|s| s.stage))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for stage in stages {
        let mut cells = Vec::new();
        for run in runs {
            let cell = match run.stages.iter().find(|s| s.stage == stage) {
                Some(st) => summarize_leaks(st),
                None => "n/a".to_string(),
            };
            cells.push(cell);
        }
        s.push_str(&format!("| {} | {} | {} |\n", stage, cells[0], cells[1]));
    }
    s.push('\n');
    std::fs::write(path, s)
}

pub fn print_compare(runs: &[Run]) {
    let stages: Vec<Stage> = runs
        .iter()
        .flat_map(|r| r.stages.iter().map(|s| s.stage))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    println!("{:<20} {:>34} {:>34}", "stage", "naive", "hardened");
    println!("{}", "-".repeat(90));
    for stage in stages {
        let cells: Vec<String> = runs
            .iter()
            .map(|run| match run.stages.iter().find(|s| s.stage == stage) {
                Some(st) => {
                    let s = summarize_leaks(st);
                    if s == "—" {
                        "clean".to_string()
                    } else {
                        s
                    }
                }
                None => "n/a".to_string(),
            })
            .collect();
        println!("{:<20} {:>34} {:>34}", stage.as_str(), cells[0], cells[1]);
    }
}
