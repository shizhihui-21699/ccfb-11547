//! `residue` — capture memory at defined stages and search it for canaries.
//!
//! Two subcommands:
//!
//! * `residue live <pid> --needle <hex-or-ascii>` — read the task's memory the way
//!   a debugger would and report every occurrence.
//! * `residue core <file.core> --needle ...` — parse a Mach-O core and do the same.
//!
//! The point of supporting both is that the two methods model different
//! attackers: the first is "somebody with a task port", the second is "somebody
//! who got a crash dump".  A credible claim needs both to be clean.

use std::process::ExitCode;

use residue::{corefile, read_live_filtered};

fn usage() -> ExitCode {
    eprintln!(
        "residue - secret-residue scanner\n\
         \n\
         USAGE:\n\
         \x20 residue live <pid> [--needle S]... [--include-sealed] [--scan-readonly] [--max-bytes N] [--json]\n\
         \x20 residue core <file>  [--needle S]... [--json]\n\
         \x20 residue scan <file>  [--needle S]... [--json]\n\
         \n\
         --needle accepts a plain string or hex: prefixed bytes (hex:DEADBEEF).\n\
         --scan-readonly also scans read-only regions (slow; secrets are written, so\n\
         \x20 they cannot be there unless the program copied them into a rodata blob).\n\
         --include-sealed reproduces a debugger's mach_vm_protect trick on PROT_NONE\n\
         \x20 pages, so you can see what a task-port attacker would get.\n\
         Exit status: 0 = clean, 1 = residue found, 2 = usage/IO error."
    );
    ExitCode::from(2)
}

fn parse_needle(s: &str) -> Result<Vec<u8>, String> {
    if let Some(hex) = s.strip_prefix("hex:") {
        let mut out = Vec::new();
        let mut buf = String::new();
        for ch in hex.chars() {
            if ch.is_ascii_whitespace() {
                continue;
            }
            buf.push(ch);
            if buf.len() == 2 {
                out.push(u8::from_str_radix(&buf, 16).map_err(|e| format!("bad hex: {e}"))?);
                buf.clear();
            }
        }
        if !buf.is_empty() {
            return Err("hex needle has an odd number of digits".into());
        }
        Ok(out)
    } else {
        Ok(s.as_bytes().to_vec())
    }
}

struct Args {
    needles: Vec<Vec<u8>>,
    include_sealed: bool,
    writable_only: bool,
    max_bytes: usize,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<(Vec<String>, Args), String> {
    let mut positional = Vec::new();
    let mut needles = Vec::new();
    let mut include_sealed = false;
    let mut writable_only = true;
    let mut max_bytes = 8 * 1024 * 1024 * 1024usize;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--needle" => {
                i += 1;
                let v = args.get(i).ok_or("--needle needs a value")?;
                needles.push(parse_needle(v)?);
            }
            "--include-sealed" => include_sealed = true,
            "--scan-readonly" => writable_only = false,
            "--max-bytes" => {
                i += 1;
                let v = args.get(i).ok_or("--max-bytes needs a value")?;
                max_bytes = v.parse().map_err(|e| format!("bad --max-bytes: {e}"))?;
            }
            "--json" => json = true,
            "--help" | "-h" => return Err("help".into()),
            other if other.starts_with('-') => return Err(format!("unknown flag {other}")),
            other => positional.push(other.to_string()),
        }
        i += 1;
    }
    Ok((
        positional,
        Args {
            needles,
            include_sealed,
            writable_only,
            max_bytes,
            json,
        },
    ))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (positional, parsed) = match parse_args(&args) {
        Ok(v) => v,
        Err(e) if e == "help" => return usage(),
        Err(e) => {
            eprintln!("error: {e}");
            return usage();
        }
    };
    if positional.len() < 2 {
        return usage();
    }
    if parsed.needles.is_empty() {
        eprintln!("error: at least one --needle is required");
        return usage();
    }

    let mode = positional[0].as_str();
    let target = &positional[1];

    let mut total_hits = 0usize;
    match mode {
        "live" => {
            let pid: i32 = match target.parse() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: bad pid '{target}': {e}");
                    return ExitCode::from(2);
                }
            };
            let image = match read_live_filtered(
                pid,
                !parsed.include_sealed,
                parsed.max_bytes,
                parsed.writable_only,
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            if parsed.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "mode": "live", "pid": pid, "regions": image.regions.len(),
                        "bytes_read": image.bytes_read,
                        "regions_detail": image.regions,
                    })
                );
            } else {
                println!(
                    "live pid={pid}: {} regions, {} bytes read{}",
                    image.regions.len(),
                    image.bytes_read,
                    if parsed.include_sealed { " (sealed pages included, attacker mode)" } else { "" }
                );
            }
            for needle in &parsed.needles {
                let label = format!("needle#{}", parsed.needles.iter().position(|x| x == needle).unwrap());
                let mut hits = 0usize;
                for page in &image.pages {
                    if page.data.is_empty() {
                        continue;
                    }
                    for h in residue::find_all(
                        &page.data,
                        needle,
                        0,
                        &format!("page @{:#x} (region {:#x} prot={})", page.addr, page.region.addr, page.region.protection),
                    ) {
                        hits += 1;
                        total_hits += 1;
                        if !parsed.json {
                            println!(
                                "[{label}] HIT {} +{:#x} wired={} ctx={}",
                                h.where_, h.offset, page.region.wired, h.context
                            );
                        }
                    }
                }
                if !parsed.json {
                    println!("[{label}] {hits} hit(s) in memory image");
                }
            }
            // List sealed wired regions so a clean result is attributable.
            if !parsed.json {
                let sealed_wired: Vec<_> = image
                    .regions
                    .iter()
                    .filter(|r| r.sealed() && r.wired)
                    .collect();
                for r in sealed_wired {
                    println!(
                        "  sealed region @{:#x} size={:#x} prot={} wired={} inherit={} share={}",
                        r.addr, r.size, r.protection, r.wired, r.inheritance, r.share_mode
                    );
                }
            }
        }
        "core" => {
            let cf = match corefile::parse(std::path::Path::new(target)) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let mut any = 0usize;
            for needle in &parsed.needles {
                let hits = cf.scan(needle);
                any += hits.len();
                total_hits += hits.len();
                for h in &hits {
                    if !parsed.json {
                        println!(
                            "HIT {} vm={:#x} prot={} ctx={}",
                            h.where_,
                            h.offset,
                            h.protection.unwrap_or(0),
                            h.context
                        );
                    }
                }
            }
            if parsed.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "mode": "core", "file": target, "segments": cf.segments.len(),
                        "hits": total_hits,
                    })
                );
            } else {
                println!(
                    "core {target}: {} segments scanned, {any} hit(s)",
                    cf.segments.len()
                );
            }
        }
        "scan" => {
            let hits = match residue::scan_file(std::path::Path::new(target), &parsed.needles[0]) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            total_hits += hits.len();
            if parsed.json {
                println!("{}", serde_json::json!({"hits": hits.len(), "detail": hits}));
            } else {
                println!("file {target}: {} hit(s)", hits.len());
                for h in &hits {
                    println!("  {} +{:#x} ctx={}", h.where_, h.offset, h.context);
                }
            }
        }
        other => {
            eprintln!("error: unknown mode '{other}'");
            return usage();
        }
    }

    if total_hits == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
