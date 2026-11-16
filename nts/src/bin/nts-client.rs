//! NTS client: run NTS-KE, then poll an NTS-protected NTP server.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use nts::aead::Aead;
use nts::client::{resolve, Client};
use nts::ke::{ClientConfig, DEFAULT_KE_PORT, DEFAULT_NTP_PORT};

#[derive(Parser, Debug)]
#[command(name = "nts-client", about = "RFC 8915 NTS client")]
struct Args {
    /// NTS-KE server, host[:port].  Default port 4460.
    #[arg(short = 's', long)]
    server: Option<String>,

    /// NTP server address, if it differs from the NTS-KE host.
    #[arg(long)]
    ntp: Option<String>,

    /// NTS-KE port.
    #[arg(long, default_value_t = DEFAULT_KE_PORT)]
    ke_port: u16,

    /// NTP port, when not given by the server in its NTS-KE response.
    #[arg(long, default_value_t = DEFAULT_NTP_PORT)]
    ntp_port: u16,

    /// Extra CA certificate (PEM) to trust, in addition to the system roots.
    /// Used for private deployments with an internal CA.
    #[arg(long)]
    ca: Option<PathBuf>,

    /// AEAD algorithms to offer, in order of preference.
    #[arg(long, value_delimiter = ',', default_value = "15,30")]
    aeads: Vec<String>,

    /// Number of polls.
    #[arg(short = 'c', long, default_value = "1")]
    count: u64,

    /// Seconds between polls.
    #[arg(short = 'i', long, default_value = "1.0")]
    interval: f64,

    /// Print one line of JSON per sample instead of a table.
    #[arg(long)]
    json: bool,

    /// Also print cookie stock and NTS-KE statistics at the end.
    #[arg(long)]
    verbose: bool,
}

fn parse_aead(s: &str) -> anyhow::Result<Aead> {
    let t = s.trim();
    if let Ok(id) = t.parse::<u16>() {
        return Aead::from_id(id)
            .ok_or_else(|| anyhow::anyhow!("unsupported AEAD algorithm id {id}"));
    }
    match t.to_ascii_uppercase().replace(['-', ' '], "_").as_str() {
        "AEAD_AES_SIV_CMAC_256" | "AES_SIV_CMAC_256" | "AES_SIV" | "SIV" => {
            Ok(Aead::AesSivCmac256)
        }
        "AEAD_AES_128_GCM_SIV" | "AES_128_GCM_SIV" | "GCM_SIV" => Ok(Aead::Aes128GcmSiv),
        other => Err(anyhow::anyhow!("unknown AEAD algorithm {other}")),
    }
}

#[derive(serde::Serialize)]
struct JsonSample {
    seq: u64,
    ke_ms: f64,
    unix_time: f64,
    offset_s: f64,
    delay_s: f64,
    rtt_s: f64,
    stratum: u8,
    cookie_stock: usize,
    aead: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let server = args
        .server
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--server is required (an NTS-KE host)"))?;

    let aeads = args
        .aeads
        .iter()
        .map(|s| parse_aead(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Split host:port if the caller put the port in --server.
    let (ke_host, ke_port) = nts::ke::split_host_port(&server, args.ke_port);

    let mut ke_cfg = ClientConfig::new(&ke_host, ke_port)?;
    if let Some(ca) = &args.ca {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let pem = std::fs::read(ca)?;
        let mut reader = std::io::BufReader::new(&pem[..]);
        let mut added = 0;
        for cert in rustls_pemfile::certs(&mut reader) {
            roots.add(cert?)?;
            added += 1;
        }
        anyhow::ensure!(added > 0, "{} contained no certificates", ca.display());
        ke_cfg = ke_cfg.with_roots(roots);
    }

    let ntp_addr: SocketAddr = match &args.ntp {
        Some(n) => resolve(n, args.ntp_port)?,
        None => resolve(&ke_host, args.ntp_port)?,
    };

    let mut client = Client::new(ke_cfg, ntp_addr, aeads);

    let t_ke = Instant::now();
    client.key_establish()?;
    let ke_time = t_ke.elapsed();
    let ke_ms = ke_time.as_secs_f64() * 1000.0;
    if std::env::var_os("NTS_DEBUG").is_some() {
        eprintln!("debug: negotiated ntp target {:?}", client.ntp_target());
    }
    if args.verbose {
        eprintln!(
            "NTS-KE with {ke_host}:{ke_port}: {:?}, AEAD {}, {} cookies",
            ke_time,
            client.aead().map(|a| a.name()).unwrap_or("?"),
            client.cookie_count()
        );
    }

    let mut last = None;
    for seq in 0..args.count {
        let s = client.poll()?;
        last = Some(s);
        if args.json {
            let rec = JsonSample {
                seq,
                ke_ms,
                unix_time: nts::ntp::system_unix_f64(),
                offset_s: s.offset,
                delay_s: s.delay,
                rtt_s: s.rtt,
                stratum: s.stratum,
                cookie_stock: client.cookie_count(),
                aead: client.aead().map(|a| a.name()).unwrap_or("?").to_string(),
            };
            println!("{}", serde_json::to_string(&rec)?);
        } else {
            println!(
                "seq={seq:<4} offset={:+.6}s delay={:.6}s rtt={:.6}s stratum={} cookies={}",
                s.offset,
                s.delay,
                s.rtt,
                s.stratum,
                client.cookie_count()
            );
        }
        if seq + 1 < args.count {
            std::thread::sleep(Duration::from_secs_f64(args.interval));
        }
    }

    if args.verbose {
        eprintln!(
            "stats: ke={} ke_fail={} req={} resp={} auth_fail={} nak={} cookies_in={} cookies_out={}",
            client.stats.ke_runs,
            client.stats.ke_failures,
            client.stats.requests,
            client.stats.responses,
            client.stats.auth_failures,
            client.stats.naks,
            client.stats.cookies_received,
            client.stats.cookies_consumed,
        );
        if let Some(s) = last {
            eprintln!(
                "final: offset {:+.6}s, delay {:.6}s, aead {}",
                s.offset,
                s.delay,
                client.aead().map(|a| a.name()).unwrap_or("?")
            );
        }
    }
    Ok(())
}
