//! Command-line front-end for the NTS client/server implementation.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use nts::aead::AeadAlg;
use nts::cert::{
    client_config_insecure, client_config_pinned, client_config_webpki, generate_self_signed,
    server_config,
};
use nts::constants::DEFAULT_NTS_KE_PORT;
use nts::cookie::KeyStore;
use nts::ke_client::KeClient;
use nts::ke_server::{KeServer, KeServerConfig};
use nts::ntp_client::NtsNtpClient;
use nts::ntp_server::{NtsNtpServer, NtsNtpServerConfig};
use nts::stats::{fmt_ns, fmt_u128_ns, summarize};

#[derive(Parser)]
#[command(name = "nts", version, about = "RFC 8915 Network Time Security client & server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a self-signed certificate for an NTS-KE server (lab use).
    GenCert {
        #[arg(long, default_value = "nts-ke.local")]
        common_name: String,
        #[arg(long, default_value = "ke-cert.pem")]
        cert_out: PathBuf,
        #[arg(long, default_value = "ke-key.pem")]
        key_out: PathBuf,
    },
    /// Run the NTS-KE (TLS 4460) server.
    KeServer {
        #[arg(long, default_value = "127.0.0.1:4460")]
        listen: String,
        #[arg(long, default_value = "ke-cert.pem")]
        cert: PathBuf,
        #[arg(long, default_value = "ke-key.pem")]
        key: PathBuf,
        #[arg(long)]
        ntp_host_hint: Option<String>,
        #[arg(long, default_value_t = 4123)]
        ntp_port_hint: u16,
        #[arg(long, default_value_t = 3600)]
        key_overlap_secs: u64,
        #[arg(long, default_value_t = 600)]
        cookie_ttl_secs: u64,
        #[arg(long, default_value_t = 8)]
        cookies: usize,
        /// Shared master-key file; the NTP server must use the same path.
        #[arg(long, default_value = "nts-keys.bin")]
        key_store: PathBuf,
    },
    /// Run the NTS-protected NTP (UDP) server.
    NtpServer {
        #[arg(long, default_value = "127.0.0.1:4123")]
        listen: String,
        #[arg(long, default_value_t = 3600)]
        key_overlap_secs: u64,
        #[arg(long, default_value_t = 600)]
        cookie_ttl_secs: u64,
        #[arg(long, default_value_t = 3)]
        stratum: u8,
        /// Shared master-key file written by the KE server.
        #[arg(long, default_value = "nts-keys.bin")]
        key_store: PathBuf,
        /// Re-read the key file every N milliseconds to pick up rotations.
        #[arg(long, default_value_t = 1000)]
        reload_ms: u64,
    },
    /// Run one KE exchange then a series of authenticated NTP queries.
    Client {
        #[arg(long, default_value = "127.0.0.1")]
        ke_host: String,
        #[arg(long, default_value_t = DEFAULT_NTS_KE_PORT)]
        ke_port: u16,
        #[arg(long)]
        ntp_addr: Option<SocketAddr>,
        /// PEM certificate to pin (lab). Conflicts with --insecure / WebPKI.
        #[arg(long)]
        pin_cert: Option<PathBuf>,
        /// Skip certificate verification (lab only).
        #[arg(long)]
        insecure: bool,
        #[arg(long, default_value_t = 10)]
        count: usize,
        #[arg(long, default_value_t = 200)]
        interval_ms: u64,
        #[arg(long)]
        json_out: Option<PathBuf>,
    },
    /// End-to-end in-process demo: KE + NTP server + client in one process.
    Demo {
        #[arg(long, default_value_t = 20)]
        count: usize,
        /// Rotate the master key halfway through to exercise the overlap path.
        #[arg(long)]
        rotate_midway: bool,
    },
    /// Rotate the master key in a shared key-store file. The KE server uses
    /// the new key for fresh cookies; the NTP server reloads and keeps
    /// accepting old cookies until the overlap window elapses.
    RotateKeys {
        #[arg(long, default_value = "nts-keys.bin")]
        key_store: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::GenCert {
            common_name,
            cert_out,
            key_out,
        } => {
            let id = generate_self_signed(&common_name)?;
            fs::write(&cert_out, &id.cert_pem)?;
            fs::write(&key_out, &id.key_pem)?;
            println!("wrote {} and {}", cert_out.display(), key_out.display());
        }
        Cmd::KeServer {
            listen,
            cert,
            key,
            ntp_host_hint,
            ntp_port_hint,
            key_overlap_secs,
            cookie_ttl_secs,
            cookies,
            key_store,
        } => {
            let cert_pem = fs::read_to_string(&cert).context("reading cert PEM")?;
            let key_pem = fs::read_to_string(&key).context("reading key PEM")?;
            let cert_der = nts::cert::cert_from_pem(&cert_pem)?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no certificate in PEM"))?;
            let key_der = nts::cert::private_key_from_pem(&key_pem)?;
            let identity = nts::cert::Identity {
                cert_der: cert_der.to_vec(),
                key_der: key_der.secret_der().to_vec(),
                cert_pem,
                key_pem,
            };
            let tls = Arc::new(server_config(&identity)?);
            let cfg = KeServerConfig {
                tls,
                key_store: KeyStore::open_or_create(&key_store, key_overlap_secs)?,
                ntp_server_hint: ntp_host_hint,
                ntp_port_hint,
                cookies_per_handshake: cookies,
                cookie_ttl_secs,
            };
            let server = KeServer::bind(&listen, cfg)?;
            println!(
                "NTS-KE server listening on {} (key store {})",
                server.local_addr()?,
                key_store.display()
            );
            loop {
                if let Err(e) = server.handle_one() {
                    eprintln!("KE connection error: {e:#}");
                }
            }
        }
        Cmd::NtpServer {
            listen,
            key_overlap_secs,
            cookie_ttl_secs,
            stratum,
            key_store,
            reload_ms,
        } => {
            let store = KeyStore::open_or_create(&key_store, key_overlap_secs)?;
            let cfg = NtsNtpServerConfig {
                key_store: store.clone(),
                cookie_ttl_secs,
                stratum,
                reference_id: *b"NTS1",
            };
            let server = NtsNtpServer::bind(&listen, cfg)?;
            // Bound recv so the loop can periodically reload rotated keys.
            server.set_recv_timeout(Duration::from_millis(reload_ms.max(50)))?;
            println!(
                "NTS NTP server listening on {} (key store {})",
                server.local_addr()?,
                key_store.display()
            );
            loop {
                match server.serve_one() {
                    Ok(_peer) => {}
                    Err(nts::Error::Io(e))
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        // Idle window: pick up keys rotated by the KE server.
                        if let Err(e) = store.reload() {
                            eprintln!("key store reload failed: {e:#}");
                        }
                    }
                    Err(e) => eprintln!("NTP packet error: {e:#}"),
                }
            }
        }
        Cmd::Client {
            ke_host,
            ke_port,
            ntp_addr,
            pin_cert,
            insecure,
            count,
            interval_ms,
            json_out,
        } => {
            let tls = if insecure {
                Arc::new(client_config_insecure())
            } else if let Some(path) = pin_cert {
                let pem = fs::read_to_string(path)?;
                let der = nts::cert::cert_from_pem(&pem)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("no cert in pin file"))?;
                Arc::new(client_config_pinned(&der)?)
            } else {
                Arc::new(client_config_webpki()?)
            };
            let ke = KeClient::new(tls);
            let session = ke.negotiate(&ke_host, ke_port)?;
            println!(
                "KE ok: AEAD id {} ({}), {} cookies, NTP hint {}:{}",
                session.alg.id(),
                alg_name(session.alg),
                session.cookies.len(),
                session.ntp_server.clone().unwrap_or_else(|| ke_host.clone()),
                session.ntp_port
            );
            let addr = ntp_addr
                .map(Ok)
                .unwrap_or_else(|| format!("{}:{}", ke_host, session.ntp_port).parse())?;
            let mut client = NtsNtpClient::connect(session, addr)?;

            let mut samples = Vec::with_capacity(count);
            for i in 0..count {
                match client.query() {
                    Ok(s) => {
                        println!(
                            "#{i:02} offset={:<12} rtt={:<12} stratum={} cookies_left={}",
                            fmt_ns(s.offset_nanos as f64),
                            fmt_u128_ns(s.rtt_nanos),
                            s.stratum,
                            s.cookies_remaining
                        );
                        samples.push(s);
                    }
                    Err(e) => eprintln!("#{i:02} failed: {e:#}"),
                }
                if i + 1 < count {
                    std::thread::sleep(Duration::from_millis(interval_ms));
                }
            }
            let stats = summarize(&samples);
            print_stats(&stats);
            if let Some(path) = json_out {
                let json = serde_json_lite(&samples, &stats);
                fs::write(path, json)?;
            }
        }
        Cmd::Demo { count, rotate_midway } => {
            run_demo(count, rotate_midway)?;
        }
        Cmd::RotateKeys { key_store } => {
            let store = KeyStore::open_or_create(&key_store, 3600)?;
            let before: Vec<u32> = store.key_ids();
            let fresh = store.rotate();
            let after: Vec<u32> = store.key_ids();
            println!(
                "rotated master key in {}: ids {:?} -> {:?} (new active id {})",
                key_store.display(),
                before,
                after,
                fresh.id
            );
        }
    }
    Ok(())
}

fn alg_name(alg: AeadAlg) -> &'static str {
    match alg {
        AeadAlg::Aes128Gcm => "AES-128-GCM",
        AeadAlg::AesSivCmac256 => "AES-SIV-CMAC-256",
    }
}

fn print_stats(st: &nts::stats::SampleStats) {
    println!("\n=== summary (n={}) ===", st.count);
    println!("offset mean   : {}", fmt_ns(st.mean_offset_ns));
    println!("offset range  : {} .. {}", fmt_ns(st.min_offset_ns as f64), fmt_ns(st.max_offset_ns as f64));
    println!("offset stddev : {}", fmt_ns(st.stddev_offset_ns));
    println!("jitter (RFC5905): {}", fmt_ns(st.jitter_ns));
    println!("RTT mean      : {}", fmt_ns(st.mean_rtt_ns));
    println!("RTT min/med/p95/max: {} / {} / {} / {}",
        fmt_u128_ns(st.min_rtt_ns),
        fmt_u128_ns(st.median_rtt_ns),
        fmt_u128_ns(st.p95_rtt_ns),
        fmt_u128_ns(st.max_rtt_ns));
}

/// Minimal JSON emitter for samples (avoids a serde dependency in the demo).
fn serde_json_lite(samples: &[nts::ntp_client::TimeSample], stats: &nts::stats::SampleStats) -> String {
    let mut s = String::new();
    s.push_str("{\n  \"samples\": [\n");
    for (i, x) in samples.iter().enumerate() {
        s.push_str(&format!(
            "    {{\"i\": {i}, \"offset_ns\": {}, \"rtt_ns\": {}, \"stratum\": {}}}{}\n",
            x.offset_nanos,
            x.rtt_nanos,
            x.stratum,
            if i + 1 == samples.len() { "" } else { "," }
        ));
    }
    s.push_str("  ],\n  \"stats\": {\n");
    s.push_str(&format!("    \"count\": {},\n", stats.count));
    s.push_str(&format!("    \"mean_offset_ns\": {:.3},\n", stats.mean_offset_ns));
    s.push_str(&format!("    \"stddev_offset_ns\": {:.3},\n", stats.stddev_offset_ns));
    s.push_str(&format!("    \"jitter_ns\": {:.3},\n", stats.jitter_ns));
    s.push_str(&format!("    \"mean_rtt_ns\": {:.3},\n", stats.mean_rtt_ns));
    s.push_str(&format!("    \"min_rtt_ns\": {},\n", stats.min_rtt_ns));
    s.push_str(&format!("    \"median_rtt_ns\": {},\n", stats.median_rtt_ns));
    s.push_str(&format!("    \"p95_rtt_ns\": {},\n", stats.p95_rtt_ns));
    s.push_str(&format!("    \"max_rtt_ns\": {}\n", stats.max_rtt_ns));
    s.push_str("  }\n}\n");
    s
}

/// In-process demo wiring every component together.
fn run_demo(count: usize, rotate_midway: bool) -> Result<()> {
    use nts::ke_server::KeServer;

    let identity = generate_self_signed("127.0.0.1")?;
    let tls = Arc::new(server_config(&identity)?);
    // Back the demo's key store with a temp file so rotation persistence is
    // exercised exactly as in the split-process deployment.
    let tmp_dir = tempfile::tempdir()?;
    let key_path = tmp_dir.path().join("demo-keys.bin");
    let key_store = KeyStore::open_or_create(&key_path, 86_400)?;

    // NTP server on an ephemeral UDP port
    let ntp_cfg = NtsNtpServerConfig {
        key_store: key_store.clone(),
        cookie_ttl_secs: 3600,
        stratum: 3,
        reference_id: *b"NTS1",
    };
    let ntp_server = NtsNtpServer::bind("127.0.0.1:0", ntp_cfg)?;
    let ntp_addr = ntp_server.local_addr()?;
    let ntp_port = ntp_addr.port();

    // KE server on an ephemeral TCP port
    let ke_cfg = KeServerConfig {
        tls,
        key_store: key_store.clone(),
        ntp_server_hint: Some("127.0.0.1".into()),
        ntp_port_hint: ntp_port,
        cookies_per_handshake: 8,
        cookie_ttl_secs: 3600,
    };
    let ke_server = KeServer::bind("127.0.0.1:0", ke_cfg)?;
    let ke_addr = ke_server.local_addr()?;

    // Drive both servers on background threads.
    let ke_handle = std::thread::spawn(move || loop {
        let _ = ke_server.handle_one();
    });
    let ntp_handle = std::thread::spawn(move || loop {
        let _ = ntp_server.serve_one();
    });

    let tls_client = Arc::new(client_config_pinned(&identity.cert_der)?);
    let ke = KeClient::new(tls_client);
    let session = ke.negotiate("127.0.0.1", ke_addr.port())?;
    println!(
        "demo KE ok: {} with {} cookies, hint port {ntp_port}",
        alg_name(session.alg),
        session.cookies.len()
    );
    let mut client = NtsNtpClient::connect(session, ntp_addr)?;

    let mut samples = Vec::new();
    for i in 0..count {
        if rotate_midway && i == count / 2 {
            let new_key = key_store.rotate();
            println!(">>> rotated master key, new id {}", new_key.id);
        }
        match client.query() {
            Ok(s) => {
                println!(
                    "demo #{i:02} offset={:<12} rtt={:<10} cookies={}",
                    fmt_ns(s.offset_nanos as f64),
                    fmt_u128_ns(s.rtt_nanos),
                    s.cookies_remaining
                );
                samples.push(s);
            }
            Err(e) => eprintln!("demo #{i:02} error: {e:#}"),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    print_stats(&summarize(&samples));

    // Background threads are detached; process exits here.
    drop(ke_handle);
    drop(ntp_handle);
    Ok(())
}
