use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use nts_client::{ClientConfig, NtsClient};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "nts-client",
    about = "NTS (RFC 8915) client: NTS-KE then NTS-protected NTPv4",
    version
)]
struct Cli {
    /// NTS-KE server hostname or address. Also the TLS server name, unless
    /// --tls-server-name is given.
    #[arg(long, env = "NTS_KE_SERVER")]
    server: String,
    /// NTS-KE port.
    #[arg(long, default_value_t = 4460)]
    ke_port: u16,
    /// Name to validate the server certificate against, when the KE server is
    /// reached by an address that the certificate does not name.
    #[arg(long)]
    tls_server_name: Option<String>,
    /// Send NTP to this address instead of the one the KE server advertises.
    #[arg(long)]
    ntp_server: Option<String>,
    /// Send NTP to this port instead of the advertised one.
    #[arg(long)]
    ntp_port: Option<u16>,
    /// Number of timing samples to take.
    #[arg(long, default_value_t = 8)]
    count: usize,
    /// Pause between samples, seconds.
    #[arg(long, default_value_t = 0.5)]
    interval: f64,
    /// Per-request timeout, seconds.
    #[arg(long, default_value_t = 3.0)]
    timeout: f64,
    /// AEAD algorithms to offer, comma separated, in preference order.
    #[arg(long, default_value = "15,30", value_delimiter = ',')]
    aead: Vec<u16>,
    /// Additional trusted CA certificate (PEM) for a private NTS-KE server.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Do not verify the NTS-KE server certificate. Lab use only.
    #[arg(long)]
    insecure: bool,
    /// Emit results as JSON instead of a table.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let offered = cli
        .aead
        .iter()
        .map(|id| {
            nts_core::aead::AeadAlg::from_id(*id)
                .with_context(|| format!("unsupported AEAD algorithm id {id}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let extra_roots = match &cli.ca {
        Some(path) => {
            let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            let mut reader = std::io::BufReader::new(&data[..]);
            rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("parsing CA certificate")?
        }
        None => Vec::new(),
    };

    let cfg = ClientConfig {
        ke_server: cli.server.clone(),
        ke_port: cli.ke_port,
        tls_server_name: cli.tls_server_name.clone().unwrap_or_default(),
        ntp_server_override: cli.ntp_server.clone(),
        ntp_port_override: cli.ntp_port,
        offered,
        extra_roots,
        insecure: cli.insecure,
    };

    let mut client = NtsClient::connect(cfg).await?;

    if !cli.json {
        println!(
            "NTS-KE ok: server={} ntp={} alg={} cookies={}",
            cli.server,
            client.ntp_addr(),
            client.negotiated_alg,
            client.cookie_count()
        );
        println!(
            "{:>4} {:>14} {:>14} {:>6} {:>6}",
            "#", "offset_ms", "delay_ms", "stratum", "cookies"
        );
    }

    let mut samples = Vec::new();
    for i in 0..cli.count {
        match client
            .measure(Duration::from_secs_f64(cli.timeout))
            .await
        {
            Ok(s) => {
                if !cli.json {
                    println!(
                        "{:>4} {:>14.3} {:>14.3} {:>6} {:>6}",
                        i + 1,
                        s.offset * 1000.0,
                        s.delay * 1000.0,
                        s.stratum,
                        s.cookies_received
                    );
                }
                samples.push(s);
            }
            Err(e) => {
                eprintln!("sample {} failed: {e:#}", i + 1);
            }
        }
        if i + 1 < cli.count {
            tokio::time::sleep(Duration::from_secs_f64(cli.interval)).await;
        }
    }

    if samples.is_empty() {
        anyhow::bail!("no successful samples");
    }

    if cli.json {
        let offsets: Vec<f64> = samples.iter().map(|s| s.offset * 1000.0).collect();
        let delays: Vec<f64> = samples.iter().map(|s| s.delay * 1000.0).collect();
        let out = serde_json::json!({
            "server": cli.server,
            "ntp": client.ntp_addr().to_string(),
            "algorithm": client.negotiated_alg.id(),
            "samples": samples.len(),
            "offset_ms": offsets,
            "delay_ms": delays,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        let stats = summarize(&samples);
        println!(
            "\noffset  mean={:.3} ms  median={:.3} ms  stdev={:.3} ms  min={:.3}  max={:.3}",
            stats.offset_mean, stats.offset_median, stats.offset_stdev, stats.offset_min, stats.offset_max
        );
        println!(
            "delay   mean={:.3} ms  median={:.3} ms  stdev={:.3} ms",
            stats.delay_mean, stats.delay_median, stats.delay_stdev
        );
        println!(
            "jitter  {:.3} ms  (RFC 5905 §11.4, mean abs. difference of successive offsets)",
            stats.jitter
        );
    }
    Ok(())
}

pub struct Stats {
    pub offset_mean: f64,
    pub offset_median: f64,
    pub offset_stdev: f64,
    pub offset_min: f64,
    pub offset_max: f64,
    pub delay_mean: f64,
    pub delay_median: f64,
    pub delay_stdev: f64,
    pub jitter: f64,
}

fn summarize(samples: &[nts_client::Sample]) -> Stats {
    let offsets: Vec<f64> = samples.iter().map(|s| s.offset * 1000.0).collect();
    let delays: Vec<f64> = samples.iter().map(|s| s.delay * 1000.0).collect();
    Stats {
        offset_mean: mean(&offsets),
        offset_median: median(&offsets),
        offset_stdev: stdev(&offsets),
        offset_min: offsets.iter().copied().fold(f64::INFINITY, f64::min),
        offset_max: offsets.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        delay_mean: mean(&delays),
        delay_median: median(&delays),
        delay_stdev: stdev(&delays),
        jitter: jitter(&offsets),
    }
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<f64>() / v.len() as f64
}

fn median(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = s.len() / 2;
    if s.len() % 2 == 0 {
        (s[mid - 1] + s[mid]) / 2.0
    } else {
        s[mid]
    }
}

fn stdev(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let m = mean(v);
    let var = v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
    var.sqrt()
}

/// RFC 5905 §11.4 jitter estimate: RMS of successive offset differences.
fn jitter(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let sum: f64 = v.windows(2).map(|w| (w[1] - w[0]).powi(2)).sum();
    (sum / (v.len() - 1) as f64).sqrt()
}
