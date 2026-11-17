//! 示例认证服务: 同一业务逻辑的 naive / hardened 两套实现,
//! 在生命周期各阶段自扫进程内存, 输出结构化对比报告。
//!
//! 两个模式跑在**独立进程**里 (由 compare 子命令分别 spawn),
//! 保证 naive 模式制造的残留不会污染 hardened 模式的扫描结果。

mod hardened;
mod naive;
mod sentinel;

use std::process::ExitCode;

use zeroize::Zeroize;

use memscan::scan_self;

use sentinel::{to_hex, Fixture};

/// 分阶段扫描覆盖的生命周期节点 (文档性常量, 与下方各 run_* 函数的阶段对应)。
#[allow(dead_code)]
const STAGES: [&str; 6] = [
    "bootstrap",   // 秘密刚加载
    "replicate",   // 模拟复制 (连接串/clone)
    "grow",        // 模拟扩容
    "sign",        // HMAC 签名
    "error-path",  // 错误返回路径
    "after-drop",  // 服务关闭后
];

fn usage() -> &'static str {
    "用法:\n  \
     demo-service run <naive|hardened> [--seed N] [--json]   单模式分阶段扫描\n  \
     demo-service compare [--seed N]                         两模式对比报告\n  \
     demo-service doctor                                    系统加固自检\n  \
     demo-service abort-hardened [--seed N]                 panic=abort 退出验证\n  \
     demo-service hold <naive|hardened> [--seed N] [--seconds N]  持有秘密等待外部抓取\n"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", usage());
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "run" => cmd_run(&args[1..]),
        "compare" => cmd_compare(&args[1..]),
        "doctor" => cmd_doctor(),
        "abort-hardened" => cmd_abort(&args[1..]),
        "hold" => cmd_hold(&args[1..]),
        other => {
            eprintln!("未知子命令: {other}\n{}", usage());
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// 单模式运行
// ---------------------------------------------------------------------------

struct StageRow {
    stage: String,
    db_password_hits: usize,
    signing_key_hits: usize,
    session_token_hits: usize,
    labels: Vec<(String, usize)>,
}

fn cmd_run(args: &[String]) -> ExitCode {
    let mut mode = "";
    let mut seed: u64 = 0x5EED_1234;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                seed = args[i].parse().unwrap();
            }
            "--json" => json = true,
            value if mode.is_empty() => mode = value,
            other => {
                eprintln!("未知参数: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let fixture = Fixture::generate(seed);
    let rows = match mode {
        "naive" => run_naive(&fixture),
        "hardened" => run_hardened(fixture),
        other => {
            eprintln!("模式必须是 naive 或 hardened, 得到: {other}");
            return ExitCode::from(2);
        }
    };

    if json {
        print_json(mode, seed, &rows);
    } else {
        print_table(mode, seed, &rows);
    }
    ExitCode::SUCCESS
}

/// 扫描模式的受保护存放处。
///
/// 验证工具的 needle 本身也是敏感明文: 若放在普通 Vec 里, 每次扫描都会
/// 在堆上制造副本, 污染测量结果。三个模式各占一个 mmap+mlock 页,
/// 借用切片直接喂给 memscan, 全程零拷贝。
struct PatternVault {
    db_password: secret_vault::SecretBuf,
    signing_key: secret_vault::SecretBuf,
    session_token: secret_vault::SecretBuf,
}

impl PatternVault {
    fn from_fixture(f: &Fixture) -> Self {
        Self {
            db_password: secret_vault::SecretBuf::from_slice(&f.db_password).unwrap(),
            signing_key: secret_vault::SecretBuf::from_slice(&f.signing_key).unwrap(),
            session_token: secret_vault::SecretBuf::from_slice(&f.session_token).unwrap(),
        }
    }

    fn needles(&self) -> Vec<&[u8]> {
        vec![
            self.db_password.as_bytes(),
            self.signing_key.as_bytes(),
            self.session_token.as_bytes(),
        ]
    }

    /// 三个受保护页各自的地址区间。
    fn ranges(&self) -> Vec<(u64, u64)> {
        [&self.db_password, &self.signing_key, &self.session_token]
            .iter()
            .map(|b| {
                let p = b.as_bytes().as_ptr() as u64;
                (p, p + b.len() as u64)
            })
            .collect()
    }
}

fn scan_counts(patterns: &PatternVault) -> (usize, usize, usize, Vec<(String, usize)>) {
    let needles = patterns.needles();
    let report = scan_self(&needles).expect("self scan failed");
    (
        report.hit_count(0),
        report.hit_count(1),
        report.hit_count(2),
        report.hit_labels(0),
    )
}

fn run_naive(fixture: &Fixture) -> Vec<StageRow> {
    let mut rows = Vec::new();
    // 即使是 naive 模式, 测量仪器 (扫描模式) 也放进受保护页,
    // 否则工具自身的副本会算到 naive 的账上, 对比就不公平。
    let patterns = PatternVault::from_fixture(fixture);
    let mut svc = naive::NaiveService::bootstrap(
        &fixture.db_password,
        &fixture.signing_key,
        &fixture.session_token,
    );

    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("bootstrap", a, b, c, l));

    let _conn = svc.connect_database();
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("replicate", a, b, c, l));

    svc.accumulate_sessions(b"MORE-SESSION-BYTES-0123456789-ABCDEFGHIJKLMNOP");
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("grow", a, b, c, l));

    let _sig = svc.sign(b"GET /profile");
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("sign", a, b, c, l));

    let _ = svc.fallible_operation(true);
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("error-path", a, b, c, l));

    svc.shutdown();
    // 再制造一些堆扰动, 促使分配器复用/搬运内存, 模拟服务继续运行
    churn_heap();
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("after-drop", a, b, c, l));

    rows
}

fn run_hardened(mut fixture: Fixture) -> Vec<StageRow> {
    let mut rows = Vec::new();
    secret_vault::harden_process().expect("harden_process failed");

    // 先建扫描模式的受保护存放处
    let patterns = PatternVault::from_fixture(&fixture);

    let mut svc = hardened::HardenedService::bootstrap(
        &fixture.db_password,
        &fixture.signing_key,
        &fixture.session_token,
    )
    .expect("bootstrap failed");
    // 关键动作: 明文一旦进入受保护容器, 立刻清零调用方持有的源副本。
    // 真实服务里对应 "从 socket 读入 SecretBuf 后, 栈/堆上中转块 zeroize"。
    fixture.db_password.zeroize();
    fixture.signing_key.zeroize();
    fixture.session_token.zeroize();

    // 活容器地址区间: 命中落在这里属于 "预期内的明文"
    // (服务自己的三个容器 + 扫描模式的三个容器)
    let live_ranges = |svc: &hardened::HardenedService| -> Vec<(u64, u64)> {
        let mut v = vec![
            svc.db_password_range(),
            svc.signing_key_range(),
            svc.session_token_range(),
        ];
        v.extend(patterns.ranges());
        v
    };

    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("bootstrap", a, b, c, l));
    assert_all_hits_live(&patterns, &live_ranges(&svc), "bootstrap");

    svc.connect_database().unwrap();
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("replicate", a, b, c, l));
    assert_all_hits_live(&patterns, &live_ranges(&svc), "replicate");

    svc.accumulate_sessions(b"MORE-SESSION-BYTES-0123456789-ABCDEFGHIJKLMNOP")
        .unwrap();
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("grow", a, b, c, l));
    assert_all_hits_live(&patterns, &live_ranges(&svc), "grow");

    let _sig = svc.sign(b"GET /profile");
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("sign", a, b, c, l));
    assert_all_hits_live(&patterns, &live_ranges(&svc), "sign");

    let _ = svc.fallible_operation(true);
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("error-path", a, b, c, l));
    assert_all_hits_live(&patterns, &live_ranges(&svc), "error-path");

    svc.shutdown();
    churn_heap();
    let (a, b, c, l) = scan_counts(&patterns);
    rows.push(row("after-drop", a, b, c, l));
    // 关键断言: 服务关闭后, 只剩扫描模式自己的受保护页 (3 个 needle 各 1 处),
    // 业务秘密的残留为 0。
    let needles = patterns.needles();
    let report = scan_self(&needles).unwrap();
    let pattern_ranges = patterns.ranges();
    for h in &report.hits {
        assert!(
            pattern_ranges
                .iter()
                .any(|(s, e)| h.address >= *s && h.address < *e),
            "hardened after-drop 发现活容器之外的残留: {report}"
        );
    }

    rows
}

/// 断言每个 needle 的全部命中都落在 "允许存在明文" 的区间内。
///
/// `ranges` 按 needle 下标排列, 每个 needle 可有多个合法区间
/// (服务容器 + 扫描模式容器, 同一下标的区间在子切片里)。
fn assert_all_hits_live(
    patterns: &PatternVault,
    ranges: &[(u64, u64)],
    stage: &str,
) {
    let needles = patterns.needles();
    let report = scan_self(&needles).unwrap();
    for h in &report.hits {
        // ranges 布局: [svc_db, svc_key, svc_tok, pat_db, pat_key, pat_tok]
        // needle i 的合法区间是 i 和 i+3
        let allowed = [h.needle_index, h.needle_index + 3];
        let ok = allowed
            .iter()
            .filter_map(|&ri| ranges.get(ri))
            .any(|(s, e)| h.address >= *s && h.address < *e);
        assert!(
            ok,
            "stage {stage}: needle#{} 在活容器之外发现命中 @ {:#x}",
            h.needle_index, h.address
        );
    }
}

/// 分配/释放一批普通堆块, 模拟服务继续运行时的分配器活动。
fn churn_heap() {
    let mut garbage = Vec::new();
    for i in 0..256u32 {
        let mut v = vec![0u8; 64 + (i as usize % 7) * 128];
        for (j, b) in v.iter_mut().enumerate() {
            *b = (j as u8).wrapping_add(i as u8);
        }
        garbage.push(v);
    }
    drop(garbage);
}

fn row(stage: &str, a: usize, b: usize, c: usize, l: Vec<(String, usize)>) -> StageRow {
    StageRow {
        stage: stage.to_string(),
        db_password_hits: a,
        signing_key_hits: b,
        session_token_hits: c,
        labels: l,
    }
}

// ---------------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------------

fn print_table(mode: &str, seed: u64, rows: &[StageRow]) {
    println!("== 模式: {mode} (seed={seed:#x}) ==");
    println!(
        "{:<11} {:>10} {:>10} {:>10}  口令命中区域分布",
        "stage", "db_pwd", "sig_key", "sess_tok"
    );
    for r in rows {
        let labels: Vec<String> = r.labels.iter().map(|(l, n)| format!("{l}×{n}")).collect();
        println!(
            "{:<11} {:>10} {:>10} {:>10}  {}",
            r.stage,
            r.db_password_hits,
            r.signing_key_hits,
            r.session_token_hits,
            labels.join(", ")
        );
    }
}

fn print_json(mode: &str, seed: u64, rows: &[StageRow]) {
    println!("{{\"mode\": \"{mode}\", \"seed\": {seed}, \"stages\": [");
    for (i, r) in rows.iter().enumerate() {
        let comma = if i + 1 == rows.len() { "" } else { "," };
        let labels: Vec<String> = r
            .labels
            .iter()
            .map(|(l, n)| format!("{{\"region\": \"{}\", \"hits\": {}}}", l.replace('"', "'"), n))
            .collect();
        println!(
            "  {{\"stage\": \"{}\", \"db_password_hits\": {}, \"signing_key_hits\": {}, \"session_token_hits\": {}, \"regions\": [{}]}}{}",
            r.stage, r.db_password_hits, r.signing_key_hits, r.session_token_hits,
            labels.join(", "), comma
        );
    }
    println!("]}}");
}

// ---------------------------------------------------------------------------
// compare: 两个独立子进程
// ---------------------------------------------------------------------------

fn cmd_compare(args: &[String]) -> ExitCode {
    let mut seed: u64 = 0x5EED_1234;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                seed = args[i].parse().unwrap();
            }
            other => {
                eprintln!("未知参数: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let naive = std::process::Command::new(&exe)
        .args(["run", "naive", "--seed", &seed.to_string(), "--json"])
        .output()
        .expect("spawn naive");
    let hardened = std::process::Command::new(&exe)
        .args(["run", "hardened", "--seed", &seed.to_string(), "--json"])
        .output()
        .expect("spawn hardened");

    if !naive.status.success() {
        eprintln!("naive 子进程失败:\n{}", String::from_utf8_lossy(&naive.stderr));
        return ExitCode::FAILURE;
    }
    if !hardened.status.success() {
        eprintln!(
            "hardened 子进程失败:\n{}",
            String::from_utf8_lossy(&hardened.stderr)
        );
        return ExitCode::FAILURE;
    }

    let naive_json = String::from_utf8_lossy(&naive.stdout);
    let hardened_json = String::from_utf8_lossy(&hardened.stdout);
    let n_rows = parse_rows(&naive_json);
    let h_rows = parse_rows(&hardened_json);

    println!("############ 改造前后内存残留对比 (seed={seed:#x}) ############");
    println!(
        "{:<11} | {:^27} | {:^27} | 残留削减",
        "stage", "naive (pwd/key/token)", "hardened (pwd/key/token)"
    );
    println!("{}", "-".repeat(92));
    for (n, h) in n_rows.iter().zip(h_rows.iter()) {
        let n_total = n.db_password_hits + n.signing_key_hits + n.session_token_hits;
        let h_total = h.db_password_hits + h.signing_key_hits + h.session_token_hits;
        let reduction = if n_total == 0 {
            "-".to_string()
        } else {
            format!(
                "{:.0}%",
                (1.0 - h_total as f64 / n_total as f64) * 100.0
            )
        };
        println!(
            "{:<11} | {:>9} / {:>5} / {:>9} | {:>9} / {:>5} / {:>9} | {}",
            n.stage,
            n.db_password_hits,
            n.signing_key_hits,
            n.session_token_hits,
            h.db_password_hits,
            h.signing_key_hits,
            h.session_token_hits,
            reduction
        );
    }
    println!();
    let n_after = n_rows.last().unwrap();
    let h_after = h_rows.last().unwrap();
    println!(
        "after-drop 总残留: naive={} 处, hardened={} 处",
        n_after.db_password_hits + n_after.signing_key_hits + n_after.session_token_hits,
        h_after.db_password_hits + h_after.signing_key_hits + h_after.session_token_hits
    );
    ExitCode::SUCCESS
}

/// 极简 JSON 行解析 (只解析本程序自己打印的格式, 不引入 serde 依赖)。
fn parse_rows(json: &str) -> Vec<StageRow> {
    let mut out = Vec::new();
    for line in json.lines() {
        let line = line.trim().trim_end_matches(',');
        if !line.starts_with("{\"stage\"") {
            continue;
        }
        let get = |key: &str| -> usize {
            let pat = format!("\"{key}\": ");
            let start = line.find(&pat).unwrap() + pat.len();
            let rest = &line[start..];
            let end = rest
                .find([',', '}'])
                .unwrap_or(rest.len());
            rest[..end].parse().unwrap()
        };
        let stage = {
            let pat = "\"stage\": \"";
            let start = line.find(pat).unwrap() + pat.len();
            let end = line[start..].find('"').unwrap() + start;
            line[start..end].to_string()
        };
        out.push(StageRow {
            stage,
            db_password_hits: get("db_password_hits"),
            signing_key_hits: get("signing_key_hits"),
            session_token_hits: get("session_token_hits"),
            labels: Vec::new(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// doctor: 系统能力自检
// ---------------------------------------------------------------------------

fn cmd_doctor() -> ExitCode {
    println!("== secret-vault 运行环境自检 ==");
    match secret_vault::harden_process() {
        Ok(report) => println!(
            "[OK] core dump 已禁用 (旧 soft limit: {:?})",
            report.previous_core_limit
        ),
        Err(e) => {
            println!("[FAIL] 禁用 core dump 失败: {e}");
            return ExitCode::FAILURE;
        }
    }

    // 实际建一个受保护分配, 验证 mmap+mlock 全链路。
    // 探针值必须运行时生成: 字符串字面量会被编进二进制 __TEXT 段,
    // 那种残留任何容器都管不到 (这本身也是一条要演示的教训)。
    let mut probe_source = sentinel::sentinel(0xD0C7_0001, 32);
    // 扫描模式单独占一个受保护页, 测量仪器自身不产生普通内存副本
    let pattern_buf = match secret_vault::SecretBuf::from_slice(&probe_source) {
        Ok(b) => b,
        Err(e) => {
            println!("[FAIL] 扫描模式分配失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    // 被测容器
    let buf = match secret_vault::SecretBuf::from_slice(&probe_source) {
        Ok(b) => b,
        Err(e) => {
            println!("[FAIL] 受保护分配失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    // 源头副本立即清零 —— 容器只负责自己的页, 调用方带来的副本要调用方负责
    probe_source.zeroize();
    {
        println!(
            "[OK] mmap+mlock 分配成功, 本进程累计锁定 {} 字节",
            secret_vault::locked_bytes()
        );
        let needles = [pattern_buf.as_bytes()];
        let report = memscan::scan_self(&needles).unwrap();
        // 用 "页级受保护小映射" 判据识别活容器, 自动剔除扫描器在 MB 级
        // malloc 区的瞬态回显。期望恰好 2 个活容器: 被测 + 模式。
        let live = report.live_container_hits();
        let ok = live == 2;
        println!(
            "[{}] 探针明文的活受保护容器数 = {} (期望 2; 其余命中为扫描器瞬态回显)",
            if ok { "OK" } else { "WARN" },
            live
        );
    }
    drop(buf);
    let needles = [pattern_buf.as_bytes()];
    let after = memscan::scan_self(&needles).unwrap();
    // 被测容器 drop 后, 活受保护容器应只剩模式自己那 1 个, 业务残留为 0。
    let live_after = after.live_container_hits();
    let business_residual = live_after.saturating_sub(1);
    println!(
        "[{}] 被测容器 drop 后业务残留 = {} (期望 0; 模式容器自身 {} 处)",
        if business_residual == 0 { "OK" } else { "FAIL" },
        business_residual,
        live_after
    );
    drop(pattern_buf);

    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        for line in status.lines() {
            if line.starts_with("VmLck") || line.starts_with("VmSwap") {
                println!("[INFO] {line}");
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .arg("vm.swapusage")
            .output()
            .ok();
        if let Some(o) = out {
            print!("[INFO] {}", String::from_utf8_lossy(&o.stdout));
        }
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// abort-hardened: 验证 panic=abort 路径不产生 core、不留持久化副本
// ---------------------------------------------------------------------------

fn cmd_abort(args: &[String]) -> ExitCode {
    let mut seed: u64 = 0x000A_B0B7;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                seed = args[i].parse().unwrap();
            }
            other => {
                eprintln!("未知参数: {other}");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }
    secret_vault::harden_process().expect("harden");
    let mut fixture = Fixture::generate(seed);

    // 先打印哨兵的 hex 和自身 pid, 供外部脚本在 abort 后验证
    println!("PID={}", std::process::id());
    println!("NEEDLE_DB={}", to_hex(&fixture.db_password));
    println!("NEEDLE_KEY={}", to_hex(&fixture.signing_key));
    println!("NEEDLE_TOK={}", to_hex(&fixture.session_token));
    std::io::Write::flush(&mut std::io::stdout()).unwrap();

    let _svc = hardened::HardenedService::bootstrap(
        &fixture.db_password,
        &fixture.signing_key,
        &fixture.session_token,
    )
    .expect("bootstrap");
    // 入容器后源副本清零, 随后只在受保护页里持有秘密
    fixture.db_password.zeroize();
    fixture.signing_key.zeroize();
    fixture.session_token.zeroize();

    // 持有秘密的状态下主动 panic; workspace 配置 panic=abort, 进程立即死亡,
    // 不展开、不跑后续 drop —— 但 mlock 匿名页随进程销毁整体回收,
    // 且 RLIMIT_CORE=0 保证没有 core 文件落盘。
    panic!("intentional panic while holding secrets (abort path test)");
}

// ---------------------------------------------------------------------------
// hold: 持有秘密驻留, 给 lldb/gcore 等外部工具一个抓取窗口
// ---------------------------------------------------------------------------

fn cmd_hold(args: &[String]) -> ExitCode {
    let mut mode = "";
    let mut seed: u64 = 0x5EED_1234;
    let mut seconds: u64 = 60;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                seed = args[i].parse().unwrap();
            }
            "--seconds" => {
                i += 1;
                seconds = args[i].parse().unwrap();
            }
            value if mode.is_empty() => mode = value,
            other => {
                eprintln!("未知参数: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let mut fixture = Fixture::generate(seed);
    println!("PID={}", std::process::id());
    println!("MODE={mode}");
    println!("NEEDLE_DB={}", to_hex(&fixture.db_password));
    println!("NEEDLE_KEY={}", to_hex(&fixture.signing_key));
    println!("NEEDLE_TOK={}", to_hex(&fixture.session_token));
    println!("HOLDING={seconds}s");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();

    match mode {
        "naive" => {
            let svc = naive::NaiveService::bootstrap(
                &fixture.db_password,
                &fixture.signing_key,
                &fixture.session_token,
            );
            let _conn = svc.connect_database();
            wait_seconds(seconds);
            // 故意不做清理就退出, 模拟朴素服务的真实行为
            drop(svc);
        }
        "hardened" => {
            secret_vault::harden_process().expect("harden");
            let svc = hardened::HardenedService::bootstrap(
                &fixture.db_password,
                &fixture.signing_key,
                &fixture.session_token,
            )
            .expect("bootstrap");
            // 明文进入受保护容器后, 源副本立即清零 (与 run_hardened 一致)
            fixture.db_password.zeroize();
            fixture.signing_key.zeroize();
            fixture.session_token.zeroize();
            svc.connect_database().unwrap();
            wait_seconds(seconds);
            svc.shutdown();
            // 关闭后再驻留几秒, 供外部工具验证 "已清零" 状态
            println!("SHUTDOWN_DONE");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            wait_seconds(seconds.min(10));
        }
        other => {
            eprintln!("模式必须是 naive 或 hardened, 得到: {other}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn wait_seconds(mut s: u64) {
    while s > 0 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        s -= 1;
    }
}
