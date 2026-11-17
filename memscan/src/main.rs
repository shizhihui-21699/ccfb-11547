//! memscan 命令行:
//!
//! ```text
//! memscan self --hex <HEX> [--hex <HEX>...] [--json]
//! memscan regions
//! memscan lock-info
//! memscan version
//! ```
//!
//! 模式只接受十六进制输入 —— 避免秘密本身出现在 `ps`/argv 里,
//! 这正是本项目要消灭的泄漏途径之一。

use std::process::ExitCode;

use memscan::{list_regions, scan_self};

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() % 2 != 0 {
        return Err(format!("hex pattern 长度不是偶数: {s}"));
    }
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn usage() -> &'static str {
    "用法:\n  \
     memscan self --hex <HEX> [--hex <HEX> ...] [--json]   扫描自身进程内存\n  \
     memscan regions                                      列出可读内存区域\n  \
     memscan lock-info                                    mlock/swap/core 限制证据\n  \
     memscan version\n"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", usage());
        return ExitCode::from(2);
    }

    match args[0].as_str() {
        "version" | "-V" | "--version" => {
            println!("memscan {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "regions" => cmd_regions(),
        "lock-info" => cmd_lock_info(),
        "self" => cmd_self_scan(&args[1..]),
        other => {
            eprintln!("未知子命令: {other}\n{}", usage());
            ExitCode::from(2)
        }
    }
}

fn cmd_regions() -> ExitCode {
    match list_regions() {
        Ok(regions) => {
            println!(
                "{:>18}  {:>14}  {:>4}  label",
                "start", "size", "perm"
            );
            for r in &regions {
                println!(
                    "{:#18x}  {:>14}  {:>4}  {}",
                    r.start,
                    r.size,
                    if r.writable { "rw" } else { "r-" },
                    if r.label.is_empty() { "[anon]" } else { &r.label }
                );
            }
            println!("共 {} 个可读区域", regions.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("regions 失败: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_self_scan(args: &[String]) -> ExitCode {
    let mut needles: Vec<Vec<u8>> = Vec::new();
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--hex" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--hex 缺少参数");
                    return ExitCode::from(2);
                }
                match decode_hex(&args[i]) {
                    Ok(p) => needles.push(p),
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--json" => json = true,
            other => {
                eprintln!("未知参数: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    if needles.is_empty() {
        eprintln!("至少需要一个 --hex <HEX> 模式");
        return ExitCode::from(2);
    }

    let needle_refs: Vec<&[u8]> = needles.iter().map(|n| n.as_slice()).collect();
    match scan_self(&needle_refs) {
        Ok(report) => {
            if json {
                println!("{{");
                println!("  \"bytes_scanned\": {},", report.bytes_scanned);
                println!("  \"region_count\": {},", report.regions.len());
                println!("  \"needles\": [");
                for (idx, n) in needles.iter().enumerate() {
                    let comma = if idx + 1 == needles.len() { "" } else { "," };
                    let labels = report.hit_labels(idx);
                    let labels_json: Vec<String> = labels
                        .iter()
                        .map(|(l, c)| format!("{{\"region\": \"{}\", \"hits\": {}}}", json_escape(l), c))
                        .collect();
                    println!(
                        "    {{\"index\": {}, \"len\": {}, \"total_hits\": {}, \"by_region\": [{}]}}{}",
                        idx,
                        n.len(),
                        report.hit_count(idx),
                        labels_json.join(", "),
                        comma
                    );
                }
                println!("  ]");
                println!("}}");
            } else {
                print!("{report}");
                for (idx, n) in needles.iter().enumerate() {
                    println!(
                        "needle#{idx} ({} 字节): {} 次命中, 分布: {:?}",
                        n.len(),
                        report.hit_count(idx),
                        report.hit_labels(idx)
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("扫描失败: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_lock_info() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        for line in status.lines() {
            if line.starts_with("VmLck") || line.starts_with("VmSwap") {
                println!("{line}");
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // 全局 swap 使用 (macOS swap 本身加密, 这里证明机制存在并给出用量)
        if let Ok(out) = std::process::Command::new("sysctl").arg("vm.swapusage").output() {
            print!("{}", String::from_utf8_lossy(&out.stdout));
        }
        // 当前进程的 core limit
        unsafe {
            let mut lim: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_CORE, &mut lim) == 0 {
                let soft = if lim.rlim_cur == libc::RLIM_INFINITY {
                    "unlimited".to_string()
                } else {
                    lim.rlim_cur.to_string()
                };
                println!("RLIMIT_CORE soft = {soft} (0 表示不会产生 core dump)");
            }
        }
    }
    println!("secret-vault 本进程累计 mlock 字节 = {}", secret_vault::locked_bytes());
    ExitCode::SUCCESS
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
