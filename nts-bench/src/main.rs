//! Measurement harness that compares NTS against plain NTP on the same server
//! and produces the numbers behind the comparison report.
//!
//! Two modes:
//!
//! * `--mode nts`   — one NTS-KE run, then repeated NTS-protected samples.
//! * `--mode plain` — repeated unprotected NTPv4 samples (the baseline a
//!   datacentre with bare NTP would see).
//!
//! Both modes report offset and delay per sample plus summary statistics, so
//! the delta attributable to NTS (extra 4–8 extension fields, AEAD work) is
//! visible as the difference in delay and in jitter.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "nts-bench",
    about = "Compare NTS-protected and plain NTP timing on the same server",
    version
)]
struct Cli {
    #[arg(long, value_enum)]
    mode: Mode,
    /// NTS-KE / NTP server hostname.
    #[arg(long)]
    server: String,
    #[arg(long, default_value_t = 4460)]
    ke_port: u16,
    /// NTP port. Required for plain mode; optional override for NTS mode.
    #[arg(long)]
    ntp_port: Option<u16>,
    /// Send NTP to this address instead of resolving the server name.
    #[arg(long)]
    ntp_server: Option<String>,
    /// Number of samples.
    #[arg(long, default_value_t = 30)]
    count: usize,
    #[arg(long, default_value_t = 0.2)]
    interval: f64,
    #[arg(long, default_value_t = 2.0)]
    timeout: f64,
    /// AEAD algorithms to offer (NTS mode only).
    #[arg(long, default_value = "15,30", value_delimiter = ',')]
    aead: Vec<u16>,
    /// Trust this CA certificate (PEM) for NTS-KE.
    #[arg(long)]
    ca: Option<std::path::PathBuf>,
    #[arg(long)]
    insecure: bool,
    /// Label for this run, copied into the JSON output.
    #[arg(long)]
    label: Option<String>,
    /// Write the JSON result here instead of stdout.
    #[arg(long)]
    json_out: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    Nts,
    Plain,
}

#[derive(Debug, Serialize)]
struct SampleOut {
    offset_ms: f64,
    delay_ms: f64,
    /// Round-trip time measured locally around the request, including all
    /// processing; compare this to `delay_ms` to see protocol overhead.
    wall_rtt_ms: f64,
}

#[derive(Debug, Serialize)]
struct Summary {
    mean: f64,
    median: f64,
    stdev: f64,
    min: f64,
    max: f64,
    p95: f64,
}

#[derive(Debug, Serialize)]
struct Report {
    label: Option<String>,
    mode: String,
    server: String,
    /// Negotiated AEAD id, NTS mode only.
    algorithm: Option<u16>,
    samples: usize,
    failures: usize,
    offset_ms: Summary,
    delay_ms: Summary,
    /// RFC 5905 §11.4 jitter: RMS of successive offset differences.
    jitter_ms: f64,
    /// Wall-clock RTT of the local request/response, protocol overhead included.
    wall_rtt_ms: Summary,
    /// Time to run NTS-KE, when applicable. This is the one-off cost of NTS.
    ke_ms: Option<f64>,
    per_sample: Vec<SampleOut>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = match cli.mode {
        Mode::Nts => run_nts(&cli).await?,
        Mode::Plain => run_plain(&cli).await?,
    };

    if let Some(path) = &cli.json_out {
        std::fs::write(path, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("writing {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    eprintln!(
        "{}: n={} offset mean {:.3} ms  delay mean {:.3} ms  jitter {:.3} ms{}",
        report.mode,
        report.samples,
        report.offset_ms.mean,
        report.delay_ms.mean,
        report.jitter_ms,
        report
            .ke_ms
            .map(|k| format!("  ke {k:.1} ms"))
            .unwrap_or_default()
    );
    Ok(())
}

async fn run_nts(cli: &Cli) -> Result<Report> {
    let offered = cli
        .aead
        .iter()
        .map(|id| {
            nts_core::aead::AeadAlg::from_id(*id)
                .with_context(|| format!("unsupported AEAD id {id}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let extra_roots = match &cli.ca {
        Some(p) => {
            let data = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
            let mut r = std::io::BufReader::new(&data[..]);
            rustls_pemfile::certs(&mut r).collect::<std::result::Result<Vec<_>, _>>()?
        }
        None => Vec::new(),
    };

    let cfg = nts_client::ClientConfig {
        ke_server: cli.server.clone(),
        ke_port: cli.ke_port,
        tls_server_name: String::new(),
        ntp_server_override: cli.ntp_server.clone(),
        ntp_port_override: cli.ntp_port,
        offered,
        extra_roots,
        insecure: cli.insecure,
    };

    let ke_start = Instant::now();
    let mut client = nts_client::NtsClient::connect(cfg).await?;
    let ke_ms = ke_start.elapsed().as_secs_f64() * 1000.0;
    let alg = client.negotiated_alg.id();

    let mut rows = Vec::new();
    let mut failures = 0;
    for i in 0..cli.count {
        let t0 = Instant::now();
        match client
            .measure(Duration::from_secs_f64(cli.timeout))
            .await
        {
            Ok(s) => rows.push(SampleOut {
                offset_ms: s.offset * 1000.0,
                delay_ms: s.delay * 1000.0,
                wall_rtt_ms: t0.elapsed().as_secs_f64() * 1000.0,
            }),
            Err(e) => {
                failures += 1;
                eprintln!("sample {} failed: {e:#}", i + 1);
            }
        }
        if i + 1 < cli.count {
            tokio::time::sleep(Duration::from_secs_f64(cli.interval)).await;
        }
    }
    Ok(build_report(cli, "nts", Some(alg), Some(ke_ms), rows, failures))
}

async fn run_plain(cli: &Cli) -> Result<Report> {
    let port = cli.ntp_port.unwrap_or(123);
    let host = cli.ntp_server.clone().unwrap_or_else(|| cli.server.clone());
    let addr: SocketAddr = resolve(&host, port).await?;
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(addr).await?;

    let mut rows = Vec::new();
    let mut failures = 0;
    for i in 0..cli.count {
        match plain_sample(&sock, Duration::from_secs_f64(cli.timeout)).await {
            Ok(r) => rows.push(r),
            Err(e) => {
                failures += 1;
                eprintln!("sample {} failed: {e:#}", i + 1);
            }
        }
        if i + 1 < cli.count {
            tokio::time::sleep(Duration::from_secs_f64(cli.interval)).await;
        }
    }
    Ok(build_report(cli, "plain", None, None, rows, failures))
}

/// One plain (unprotected) NTPv4 client/server exchange.
async fn plain_sample(sock: &tokio::net::UdpSocket, timeout: Duration) -> Result<SampleOut> {
    let mut pkt = [0u8; 48];
    pkt[0] = (4 << 3) | 3; // v4, client
    let t1 = nts_core::ntp::now_ntp_timestamp();
    pkt[40..48].copy_from_slice(&t1);

    let t0 = Instant::now();
    sock.send(&pkt).await?;
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .context("timeout")??;
    let wall = t0.elapsed().as_secs_f64() * 1000.0;
    if n < 48 {
        anyhow::bail!("short reply ({n} bytes)");
    }

    let server_rx = nts_core::ntp::ntp_timestamp_to_unix(&buf[32..40].try_into().unwrap());
    let server_tx = nts_core::ntp::ntp_timestamp_to_unix(&buf[40..48].try_into().unwrap());
    // Take T4 from our own clock at receive time, as a real client would.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs_f64();
    let t4 = nts_core::ntp::ntp_timestamp_from_unix(now.trunc() as u64, (now.fract() * 1e9) as u32);
    let t4 = nts_core::ntp::ntp_timestamp_to_unix(&t4);
    let t1s = nts_core::ntp::ntp_timestamp_to_unix(&t1);

    let offset = ((server_rx - t1s) + (server_tx - t4)) / 2.0;
    let delay = (t4 - t1s) - (server_tx - server_rx);
    Ok(SampleOut {
        offset_ms: offset * 1000.0,
        delay_ms: delay * 1000.0,
        wall_rtt_ms: wall,
    })
}

fn build_report(
    cli: &Cli,
    mode: &str,
    algorithm: Option<u16>,
    ke_ms: Option<f64>,
    rows: Vec<SampleOut>,
    failures: usize,
) -> Report {
    let offsets: Vec<f64> = rows.iter().map(|r| r.offset_ms).collect();
    let delays: Vec<f64> = rows.iter().map(|r| r.delay_ms).collect();
    let walls: Vec<f64> = rows.iter().map(|r| r.wall_rtt_ms).collect();
    Report {
        label: cli.label.clone(),
        mode: mode.to_string(),
        server: cli.server.clone(),
        algorithm,
        samples: rows.len(),
        failures,
        offset_ms: summarize(&offsets),
        delay_ms: summarize(&delays),
        jitter_ms: jitter(&offsets),
        wall_rtt_ms: summarize(&walls),
        ke_ms,
        per_sample: rows,
    }
}

fn summarize(v: &[f64]) -> Summary {
    if v.is_empty() {
        return Summary {
            mean: 0.0,
            median: 0.0,
            stdev: 0.0,
            min: 0.0,
            max: 0.0,
            p95: 0.0,
        };
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = s.iter().sum::<f64>() / s.len() as f64;
    let var = if s.len() > 1 {
        s.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (s.len() - 1) as f64
    } else {
        0.0
    };
    let mid = s.len() / 2;
    let median = if s.len() % 2 == 0 {
        (s[mid - 1] + s[mid]) / 2.0
    } else {
        s[mid]
    };
    let p95_idx = ((s.len() as f64) * 0.95).ceil() as usize - 1;
    Summary {
        mean,
        median,
        stdev: var.sqrt(),
        min: s[0],
        max: *s.last().unwrap(),
        p95: s[p95_idx.min(s.len() - 1)],
    }
}

fn jitter(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let sum: f64 = v.windows(2).map(|w| (w[1] - w[0]).powi(2)).sum();
    (sum / (v.len() - 1) as f64).sqrt()
}

async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for {host}"))
}
