use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use nts_server::{ServerConfig, NtsServer};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "nts-server",
    about = "NTS (RFC 8915) time server: NTS-KE over TLS 1.3 plus NTS-protected NTPv4",
    version
)]
struct Cli {
    /// Certificate chain in PEM format, leaf first.
    #[arg(long, env = "NTS_CERT")]
    cert: PathBuf,
    /// Private key in PEM format.
    #[arg(long, env = "NTS_KEY")]
    key: PathBuf,
    /// Address to listen on for NTS-KE (TCP).
    #[arg(long, default_value = "0.0.0.0:4460")]
    ke_bind: SocketAddr,
    /// Address to listen on for NTP (UDP). Use :10123 to run unprivileged.
    #[arg(long, default_value = "0.0.0.0:123")]
    ntp_bind: SocketAddr,
    /// Name to advertise in the NTPv4 Server Negotiation record.
    #[arg(long)]
    ntp_server_name: Option<String>,
    /// Port to advertise when it is not 123.
    #[arg(long, default_value_t = 123)]
    ntp_port: u16,
    /// AEAD algorithms to accept, comma separated, in preference order.
    #[arg(long, default_value = "15,30", value_delimiter = ',')]
    aead: Vec<u16>,
    /// Rotate the cookie master key this often, in seconds.
    #[arg(long, default_value_t = 86_400)]
    rotate_secs: u64,
    /// How many previous master keys to keep accepting.
    #[arg(long, default_value_t = 2)]
    key_retain: usize,
    /// Maximum cookie age in seconds.
    #[arg(long, default_value_t = 259_200)]
    cookie_max_age: u64,
    /// Script a key rotation every N seconds, to exercise the transition path.
    #[arg(long)]
    test_rotation_secs: Option<u64>,
    /// Advertised stratum.
    #[arg(long, default_value_t = 2)]
    stratum: u8,
    /// Also answer plain NTP requests. Off by default; see ServerConfig docs.
    #[arg(long)]
    allow_plain_ntp: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let algorithms = cli
        .aead
        .iter()
        .map(|id| {
            nts_core::aead::AeadAlg::from_id(*id)
                .with_context(|| format!("unsupported AEAD algorithm id {id}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let cert_chain = load_certs(&cli.cert)?;
    let key = load_key(&cli.key)?;

    let cfg = ServerConfig {
        ke_bind: cli.ke_bind,
        ntp_bind: cli.ntp_bind,
        cert_chain,
        key,
        ntp_server_name: cli.ntp_server_name.clone(),
        ntp_port: cli.ntp_port,
        algorithms,
        key_retain: cli.key_retain,
        cookie_max_age: Duration::from_secs(cli.cookie_max_age),
        stratum: cli.stratum,
        allow_plain_ntp: cli.allow_plain_ntp,
    };

    let server = std::sync::Arc::new(NtsServer::new(cfg));

    if cli.rotate_secs > 0 {
        let _rotation = server.spawn_rotation(Duration::from_secs(cli.rotate_secs));
        std::mem::forget(_rotation);
    }
    if let Some(secs) = cli.test_rotation_secs {
        let s = server.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(secs));
            t.tick().await;
            loop {
                t.tick().await;
                let id = s.rotate();
                tracing::info!(key_id = id, "test rotation");
            }
        });
    }

    tokio::select! {
        r = server.serve() => r,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}

fn load_certs(path: &PathBuf) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .context("parsing certificates")?;
    if certs.is_empty() {
        anyhow::bail!("{} contains no certificates", path.display());
    }
    Ok(certs)
}

fn load_key(path: &PathBuf) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)
        .context("parsing private key")?
        .ok_or_else(|| anyhow::anyhow!("{} contains no private key", path.display()))
}
