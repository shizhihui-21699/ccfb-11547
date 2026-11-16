//! Measurement harness: sample a server repeatedly and report offset and jitter
//! statistics.  Supports plain NTP and NTS so the two can be compared on the
//! same path.
//!
//! Jitter is the RFC 5905 section 11.4 estimate: the root mean square of
//! successive offset differences.  It is reported alongside the standard
//! deviation because the two answer different questions — standard deviation
//! measures spread about the mean, jitter measures sample-to-sample noise, which
//! is what a clock filter actually has to reject.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use clap::Parser;
use nts::aead::Aead;
use nts::client::{jitter, Client};
use nts::ke::{ClientConfig, DEFAULT_KE_PORT};
use nts::ntp;

#[derive(Parser, Debug)]
#[command(name = "nts-bench", about = "Compare NTS and plain NTP offset/jitter")]
struct Args {
    /// NTS-KE host[:port], for --mode nts.
    #[arg(long)]
    server: Option<String>,

    /// Target for plain NTP, or override for NTS.
    #[arg(long, default_value = "127.0.0.1:12301")]
    ntp: String,

    /// `nts`, `plain`, or `both`.
    #[arg(long, default_value = "both")]
    mode: String,

    /// Samples to collect per mode.
    #[arg(short = 'n', long, default_value = "200")]
    count: u64,

    /// Request interval in seconds, with jitter.
    #[arg(short = 'i', long, default_value = "0.2")]
    interval: f64,

    /// Request interval jitter as a fraction (0.1 = ±10%).
    #[arg(long, default_value = "0.1")]
    spread: f64,

    /// AEAD to use for NTS.
    #[arg(long, default_value = "15")]
    aead: String,

    /// CA certificate for a private NTS-KE server.
    #[arg(long)]
    ca: Option<String>,

    /// Emit JSON instead of a text report.
    #[arg(long)]
    json: bool,

    /// Also run a digest of the two modes' offsets against each other.
    #[arg(long)]
    compare: bool,
}

#[derive(Default, Clone, serde::Serialize)]
struct Stats {
    n: usize,
    mean: f64,
    median: f64,
    stdev: f64,
    jitter: f64,
    min: f64,
    max: f64,
    p95: f64,
    /// Mean of |offset|, which is the number that matters for accuracy.
    mean_abs: f64,
}

fn summarise(xs: &[f64]) -> Stats {
    if xs.is_empty() {
        return Stats::default();
    }
    let n = xs.len();
    let mean = xs.iter().sum::<f64>() / n as f64;
    let var = if n > 1 {
        xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let mut sorted = xs.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    };
    // RFC 5905 jitter: RMS of successive differences.
    let jit = if n > 1 {
        let s: f64 = xs.windows(2).map(|w| (w[1] - w[0]).powi(2)).sum();
        (s / (n - 1) as f64).sqrt()
    } else {
        0.0
    };
    let p95 = sorted[((n as f64) * 0.95).ceil() as usize - 1];
    Stats {
        n,
        mean,
        median,
        stdev: var.sqrt(),
        jitter: jit,
        min: sorted[0],
        max: sorted[n - 1],
        p95,
        mean_abs: xs.iter().map(|x| x.abs()).sum::<f64>() / n as f64,
    }
}

#[derive(serde::Serialize)]
struct ModeResult {
    mode: String,
    aead: Option<String>,
    ntp_target: String,
    elapsed_s: f64,
    ke_ms: Option<f64>,
    offset: Stats,
    delay: Stats,
    rtt: Stats,
    failures: u64,
    /// Per-sample offsets, so others can re-analyse them.
    offsets: Vec<f64>,
    delays: Vec<f64>,
}

fn resolve(spec: &str) -> anyhow::Result<SocketAddr> {
    let s = if spec.rsplit_once(':').map(|(_, p)| p.parse::<u16>().is_ok()).unwrap_or(false) {
        spec.to_string()
    } else {
        format!("{spec}:123")
    };
    s.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for {spec}"))
}

fn parse_aead(s: &str) -> anyhow::Result<Aead> {
    if let Ok(id) = s.parse::<u16>() {
        return Aead::from_id(id).ok_or_else(|| anyhow::anyhow!("unknown AEAD {id}"));
    }
    match s.to_ascii_uppercase().as_str() {
        "SIV" | "AES-SIV" | "AEAD_AES_SIV_CMAC_256" => Ok(Aead::AesSivCmac256),
        "GCM-SIV" | "AES-GCM-SIV" | "AEAD_AES_128_GCM_SIV" => Ok(Aead::Aes128GcmSiv),
        o => Err(anyhow::anyhow!("unknown AEAD {o}")),
    }
}

/// Plain NTP: a single mode-3 request, no extension fields.
fn plain_sample(addr: SocketAddr) -> anyhow::Result<(f64, f64, f64)> {
    let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
    sock.connect(addr)?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))?;

    let mut p = ntp::Packet::new();
    let t1_ntp = ntp::ntp_now();
    p.set_transmit_ts(t1_ntp);
    let wire = p.encode();

    let t1 = ntp::system_unix_f64();
    let i1 = Instant::now();
    sock.send(&wire)?;
    let mut buf = [0u8; 1024];
    let n = sock.recv(&mut buf)?;
    let i4 = Instant::now();
    let t4 = ntp::system_unix_f64();

    let resp = ntp::Packet::parse(&buf[..n])?;
    if resp.mode() != ntp::MODE_SERVER {
        anyhow::bail!("not a server response");
    }
    if resp.origin_ts() != t1_ntp {
        anyhow::bail!("origin timestamp does not match our request");
    }
    if resp.stratum() == 0 {
        anyhow::bail!("kiss-o'-death from server");
    }
    let t2 = ntp::ntp_to_unix(resp.receive_ts(), t4);
    let t3 = ntp::ntp_to_unix(resp.transmit_ts(), t4);
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    let delay = (t4 - t1) - (t3 - t2);
    let rtt = i4.duration_since(i1).as_secs_f64();
    Ok((offset, delay, rtt))
}

fn run_plain(args: &Args, addr: SocketAddr) -> anyhow::Result<ModeResult> {
    let (mut offsets, mut delays, mut rtts) = (Vec::new(), Vec::new(), Vec::new());
    let mut failures = 0u64;
    let start = Instant::now();
    for i in 0..args.count {
        match plain_sample(addr) {
            Ok((o, d, r)) => {
                offsets.push(o);
                delays.push(d);
                rtts.push(r);
            }
            Err(_) => failures += 1,
        }
        if i + 1 < args.count {
            std::thread::sleep(jitter(
                Duration::from_secs_f64(args.interval),
                args.spread,
            ));
        }
    }
    Ok(ModeResult {
        mode: "plain".into(),
        aead: None,
        ntp_target: addr.to_string(),
        elapsed_s: start.elapsed().as_secs_f64(),
        ke_ms: None,
        offset: summarise(&offsets),
        delay: summarise(&delays),
        rtt: summarise(&rtts),
        failures,
        offsets,
        delays,
    })
}

fn run_nts(args: &Args, aead: Aead) -> anyhow::Result<ModeResult> {
    let server = args
        .server
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--mode nts needs --server"))?;
    let (host, port) = nts::ke::split_host_port(&server, DEFAULT_KE_PORT);
    let mut cfg = ClientConfig::new(&host, port)?;
    if let Some(ca) = &args.ca {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let pem = std::fs::read(ca)?;
        for c in rustls_pemfile::certs(&mut std::io::BufReader::new(&pem[..])) {
            roots.add(c?)?;
        }
        cfg = cfg.with_roots(roots);
    }
    let ntp_target = if args.ntp.is_empty() {
        resolve(&host)?
    } else {
        resolve(&args.ntp)?
    };
    let mut c = Client::new(cfg, ntp_target, vec![aead]);
    let t_ke = Instant::now();
    c.key_establish()?;
    let ke_ms = t_ke.elapsed().as_secs_f64() * 1000.0;

    let (mut offsets, mut delays, mut rtts) = (Vec::new(), Vec::new(), Vec::new());
    let mut failures = 0u64;
    let start = Instant::now();
    for i in 0..args.count {
        match c.poll() {
            Ok(s) => {
                offsets.push(s.offset);
                delays.push(s.delay);
                rtts.push(s.rtt);
            }
            Err(_) => failures += 1,
        }
        if i + 1 < args.count {
            std::thread::sleep(jitter(
                Duration::from_secs_f64(args.interval),
                args.spread,
            ));
        }
    }
    Ok(ModeResult {
        mode: "nts".into(),
        aead: Some(aead.name().into()),
        ntp_target: c.ntp_target().to_string(),
        elapsed_s: start.elapsed().as_secs_f64(),
        ke_ms: Some(ke_ms),
        offset: summarise(&offsets),
        delay: summarise(&delays),
        rtt: summarise(&rtts),
        failures,
        offsets,
        delays,
    })
}

fn print_report(results: &[ModeResult]) {
    for r in results {
        let alg = r.aead.as_deref().unwrap_or("-");
        println!();
        println!("{} ({})", r.mode.to_uppercase(), alg);
        println!("  target        {}", r.ntp_target);
        println!("  samples       {} ok, {} failed in {:.1}s", r.offset.n, r.failures, r.elapsed_s);
        if let Some(ke) = r.ke_ms {
            println!("  NTS-KE        {ke:.1} ms once, then zero server state per packet");
        }
        println!("  offset  mean {:+10.3} ms   median {:+10.3} ms   |mean| {:8.3} ms",
            r.offset.mean * 1e3, r.offset.median * 1e3, r.offset.mean_abs * 1e3);
        println!("          stdev{:10.3} ms   jitter {:.3} ms   p95 |{:8.3}| ms",
            r.offset.stdev * 1e3, r.offset.jitter * 1e3, r.offset.p95.abs() * 1e3);
        println!("          min  {:+10.3} ms   max    {:+10.3} ms",
            r.offset.min * 1e3, r.offset.max * 1e3);
        println!("  delay   mean {:10.3} ms   stdev {:8.3} ms   min {:8.3} ms",
            r.delay.mean * 1e3, r.delay.stdev * 1e3, r.delay.min * 1e3);
        println!("  rtt     mean {:10.3} ms   stdev {:8.3} ms", r.rtt.mean * 1e3, r.rtt.stdev * 1e3);
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let aead = parse_aead(&args.aead)?;

    let mut results = Vec::new();
    match args.mode.as_str() {
        "nts" => results.push(run_nts(&args, aead)?),
        "plain" => results.push(run_plain(&args, resolve(&args.ntp)?)?),
        "both" => {
            // Plain first: it needs no session setup, so any interference from
            // the NTS handshake cannot affect the baseline.
            results.push(run_plain(&args, resolve(&args.ntp)?)?);
            results.push(run_nts(&args, aead)?);
        }
        other => anyhow::bail!("--mode must be nts, plain or both (got {other})"),
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        print_report(&results);
        if args.compare && results.len() == 2 {
            let (p, n) = (&results[0], &results[1]);
            println!();
            println!("COMPARISON");
            println!("  offset |mean|   plain {:.3} ms vs nts {:.3} ms",
                p.offset.mean_abs * 1e3, n.offset.mean_abs * 1e3);
            println!("  offset stdev   plain {:.3} ms vs nts {:.3} ms",
                p.offset.stdev * 1e3, n.offset.stdev * 1e3);
            println!("  offset jitter  plain {:.3} ms vs nts {:.3} ms",
                p.offset.jitter * 1e3, n.offset.jitter * 1e3);
            println!("  delay mean     plain {:.3} ms vs nts {:.3} ms",
                p.delay.mean * 1e3, n.delay.mean * 1e3);
            println!("  failures       plain {} vs nts {}", p.failures, n.failures);
        }
    }
    Ok(())
}
