//! NTS server: NTS-KE on TCP plus NTS-protected NTP on UDP.

use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::Ordering;
use std::time::Duration;

use clap::Parser;
use nts::aead::Aead;
use nts::server::{self, ServerConfig, ServerState};
use nts::ntp;

#[derive(Parser, Debug)]
#[command(name = "nts-server", about = "RFC 8915 NTS server (NTS-KE + NTP)")]
struct Args {
    /// Address to serve NTS-protected NTP on (UDP).
    #[arg(long, default_value = "127.0.0.1:12300")]
    ntp: String,

    /// Address to serve NTS-KE on (TCP).  Enables NTS-KE when given.
    #[arg(long)]
    ke: Option<String>,

    /// TLS certificate chain (PEM), required with --ke.
    #[arg(long)]
    cert: Option<String>,

    /// TLS private key (PEM), required with --ke.
    #[arg(long)]
    key: Option<String>,

    /// Cookie master seed, hex.  All server instances that must accept each
    /// other's cookies need the same seed.  Random if omitted.
    #[arg(long, env = "NTS_COOKIE_SEED")]
    cookie_seed: Option<String>,

    /// Cookie key rotation interval (seconds).  0 disables rotation.
    #[arg(long, default_value = "86400")]
    rotate_every: u64,

    /// How many rotated cookie keys to keep decrypt-only.
    #[arg(long, default_value = "2")]
    keep_old_cookie_keys: usize,

    /// Cookies handed out per NTS-KE run.
    #[arg(long, default_value = "8")]
    cookies_per_ke: usize,

    /// AEAD algorithms to negotiate, in order of preference.  Accepts numeric
    /// IANA identifiers or names.
    #[arg(long, value_delimiter = ',', default_value = "15,30")]
    aeads: Vec<String>,

    /// Stratum to advertise.
    #[arg(long, default_value = "1")]
    stratum: u8,

    /// Address to advertise to clients, if different from --ntp.
    #[arg(long)]
    advertise: Option<String>,

    /// Print configuration and exit.
    #[arg(long)]
    check: bool,
}

/// Install a SIGUSR1 handler that rotates the cookie key.
///
/// The handler only sets a flag; a background thread does the rotation.  Signal
/// handlers may not allocate or take locks, and `rotate()` does both.
fn install_rotate_signal(state: std::sync::Arc<ServerState>) {
    use std::sync::atomic::AtomicBool;
    static PENDING: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_signal(_sig: libc::c_int) {
        PENDING.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    // SAFETY: the handler writes one atomic and nothing else.
    unsafe {
        libc::signal(
            libc::SIGUSR1,
            on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }

    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(100));
        if !state.running.load(Ordering::Relaxed) {
            return;
        }
        if PENDING.swap(false, std::sync::atomic::Ordering::SeqCst) {
            state.rotate();
            let st = state.ring_stats();
            eprintln!(
                "cookie key rotated on SIGUSR1: primary id {}, {} old keys retained",
                st.primary_id, st.retired
            );
        }
    });
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

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let aeads = args
        .aeads
        .iter()
        .map(|s| parse_aead(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if aeads.is_empty() {
        anyhow::bail!("at least one AEAD algorithm is required");
    }
    if !aeads.contains(&Aead::AesSivCmac256) {
        // RFC 8915 section 4.1.5 makes AES-SIV-CMAC-256 mandatory for servers.
        anyhow::bail!("AEAD_AES_SIV_CMAC_256 (15) is mandatory for NTS servers; include it");
    }

    let listen_ntp = server::resolve_addr(&args.ntp)?;
    let listen_ke = match &args.ke {
        Some(k) => Some(server::resolve_addr(k)?),
        None => None,
    };

    let cfg = ServerConfig {
        listen_ntp,
        listen_ke,
        supported_aeads: aeads.clone(),
        stratum: args.stratum,
        max_retired_cookie_keys: args.keep_old_cookie_keys,
        cookies_per_ke: args.cookies_per_ke,
        advertised_ntp: args.advertise.clone(),
        ..Default::default()
    };

    if args.check {
        println!("ntp:        {listen_ntp}");
        println!("nts-ke:     {listen_ke:?}");
        println!("aeads:      {:?}", aeads.iter().map(|a| a.name()).collect::<Vec<_>>());
        println!("stratum:    {}", cfg.stratum);
        println!("cookies/ke: {}", cfg.cookies_per_ke);
        println!("rotation:   {}s, keep {} old", args.rotate_every, args.keep_old_cookie_keys);
        return Ok(());
    }

    let seed = match &args.cookie_seed {
        Some(h) => {
            let bytes = hex::decode(h.trim())?;
            anyhow::ensure!(
                bytes.len() >= 16,
                "cookie seed must be at least 16 octets of hex"
            );
            bytes
        }
        None => {
            let mut s = vec![0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut s);
            eprintln!(
                "no --cookie-seed given; generated one for this run only:\n  {}",
                hex::encode(&s)
            );
            s
        }
    };

    let state = ServerState::new(cfg.clone(), &seed);

    // SIGUSR1 forces an immediate rotation, which is what an operator needs
    // when a key is suspected compromised: waiting for the timer is not good
    // enough, and restarting the process would also drop every listener.
    install_rotate_signal(state.clone());

    let udp = UdpSocket::bind(listen_ntp)?;
    println!("NTS NTP listening on UDP {}", udp.local_addr()?);
    println!("  time base: {}", server::time_base_description());

    let mut handles = Vec::new();

    if let Some(ke_addr) = listen_ke {
        let cert = args
            .cert
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--ke requires --cert"))?;
        let key = args
            .key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--ke requires --key"))?;
        let tls = server::load_tls_config(cert, key)?;
        let tcp = TcpListener::bind(ke_addr)?;
        println!("NTS-KE listening on TCP {} (ALPN ntske/1, TLS 1.3)", tcp.local_addr()?);
        let s = state.clone();
        handles.push(std::thread::spawn(move || {
            server::run_ke_listener(s, tls, tcp)
        }));
    } else {
        println!("NTS-KE disabled (no --ke); serving NTP only");
    }

    if args.rotate_every > 0 {
        let s = state.clone();
        let period = args.rotate_every;
        handles.push(std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(period));
                if !s.running.load(Ordering::Relaxed) {
                    return;
                }
                s.rotate();
                let st = s.ring_stats();
                eprintln!(
                    "cookie key rotated: primary id {}, {} old keys retained",
                    st.primary_id, st.retired
                );
            }
        }));
    }

    // Report counters once a minute so a long soak is observable.
    {
        let s = state.clone();
        handles.push(std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(60));
            if !s.running.load(Ordering::Relaxed) {
                return;
            }
            eprintln!(
                "stats: ntp {}/{} (nak {}), ke {} (errors {}), cookies minted {}, rotations {}",
                s.requests.load(Ordering::Relaxed),
                s.responses.load(Ordering::Relaxed),
                s.naks.load(Ordering::Relaxed),
                s.ke_sessions.load(Ordering::Relaxed),
                s.ke_errors.load(Ordering::Relaxed),
                s.cookies_minted.load(Ordering::Relaxed),
                s.rotation_count.load(Ordering::Relaxed),
            );
            let _ = ntp::system_unix_f64();
        }));
    }

    server::run_ntp_listener(state.clone(), udp);
    state.running.store(false, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}
