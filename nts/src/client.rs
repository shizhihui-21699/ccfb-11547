//! An NTS client session: cookie stock, NTS-KE refresh, and offset samples.
//!
//! One [`Client`] corresponds to one NTS association with one server.  It owns
//! the key material established by the last successful NTS-KE run and a stock of
//! cookies, uses each cookie exactly once (RFC 8915 section 5.7 asks clients to
//! avoid reuse for unlinkability), and refills the stock from the cookies the
//! server returns with every authenticated response.
//!
//! When the stock runs out, or the server answers with an NTS NAK, the session
//! re-runs NTS-KE.  Retries are rate limited per RFC 8915 section 4.2.

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::aead::Aead;
use crate::cookie::CookieContents;
use crate::ke::{self, ClientConfig, KeError, KeOutcome, KeRequest};
use crate::ntp::{self, Packet};
use crate::nts_ntp::{self, NtsError, TARGET_COOKIE_STOCK};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("NTS-KE failed: {0}")]
    Ke(#[from] KeError),
    #[error("packet error: {0}")]
    Nts(#[from] NtsError),
    #[error("malformed packet: {0}")]
    Packet(#[from] crate::ntp::PacketError),
    #[error("network error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no cookies left and NTS-KE is not allowed yet (backoff until {0:?})")]
    Backoff(Instant),
    #[error("timed out waiting for a response")]
    Timeout,
    #[error("server response is not a reply to our request")]
    Unsolicited,
}

/// One measurement, computed exactly as RFC 5905 section 8 describes.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Clock offset: positive means the local clock is behind the server.
    pub offset: f64,
    /// Round-trip delay.
    pub delay: f64,
    /// Total time from sending to receiving.
    pub rtt: f64,
    /// Server stratum, for diagnostics.
    pub stratum: u8,
    /// Number of fresh cookies received.
    pub cookies_received: usize,
}

/// A cookie plus the key material it encodes.
struct StockedCookie {
    bytes: Vec<u8>,
}

pub struct Client {
    ke_cfg: ClientConfig,
    ntp_addr: SocketAddr,
    aeads: Vec<Aead>,

    contents: Option<CookieContents>,
    cookie_len: usize,
    cookies: VecDeque<StockedCookie>,

    /// Unique identifier of the request currently in flight.
    pending_uid: Option<Vec<u8>>,
    /// Transmit timestamp of the request currently in flight.
    pending_t1: Option<u64>,

    /// Backoff state for NTS-KE retries (RFC 8915 section 4.2).
    ke_failures: u32,
    next_ke_attempt: Option<Instant>,
    /// Set once a full volley (KE + authenticated NTP) has succeeded, which is
    /// what RFC 8915 section 4.2 requires before resetting the backoff.
    volley_ok: bool,

    pub stats: Stats,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub ke_runs: u64,
    pub ke_failures: u64,
    pub requests: u64,
    pub responses: u64,
    pub auth_failures: u64,
    pub naks: u64,
    pub cookies_consumed: u64,
    pub cookies_received: u64,
}

impl Client {
    /// Prepare a session.  Does not contact the server; call [`Client::key_establish`].
    pub fn new(ke_cfg: ClientConfig, ntp_addr: SocketAddr, aeads: Vec<Aead>) -> Self {
        Self {
            ke_cfg,
            ntp_addr,
            aeads: if aeads.is_empty() {
                vec![Aead::AesSivCmac256]
            } else {
                aeads
            },
            contents: None,
            cookie_len: 0,
            cookies: VecDeque::new(),
            pending_uid: None,
            pending_t1: None,
            ke_failures: 0,
            next_ke_attempt: None,
            volley_ok: false,
            stats: Stats::default(),
        }
    }

    pub fn aead(&self) -> Option<Aead> {
        self.contents.as_ref().map(|c| c.aead)
    }

    /// Where the NTP packets actually go, after any server-side redirection.
    pub fn ntp_target(&self) -> SocketAddr {
        self.ntp_addr
    }

    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    /// Run NTS-KE and replace all cookies and keys.  RFC 8915 section 5.7: after
    /// a successful handshake the old parameters MUST be discarded.
    pub fn key_establish(&mut self) -> Result<(), ClientError> {
        if let Some(t) = self.next_ke_attempt {
            if Instant::now() < t {
                return Err(ClientError::Backoff(t));
            }
        }
        let req = KeRequest::ntpv4(&self.aeads);
        match ke::run_client(&self.ke_cfg, &req) {
            Ok(outcome) => {
                self.adopt(outcome);
                self.stats.ke_runs += 1;
                self.ke_failures = 0;
                self.next_ke_attempt = None;
                Ok(())
            }
            Err(e) => {
                self.stats.ke_failures += 1;
                self.ke_failures += 1;
                self.next_ke_attempt = Some(Instant::now() + ke_backoff(self.ke_failures));
                Err(ClientError::Ke(e))
            }
        }
    }

    fn adopt(&mut self, outcome: KeOutcome) {
        let KeOutcome {
            aead,
            cookies,
            ntp_server,
            ntp_port,
            keys,
        } = outcome;
        // A server may direct us elsewhere (RFC 8915 section 4.1.7/4.1.8).  In
        // practice a site runs KE and NTP on the same host; only follow a
        // different port, which is what unprivileged deployments need.
        if ntp_port != self.ntp_addr.port() {
            self.ntp_addr.set_port(ntp_port);
        }
        if let Some(name) = ntp_server {
            if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(name.as_str(), ntp_port)) {
                if let Some(a) = addrs.into_iter().next() {
                    self.ntp_addr = a;
                }
            }
        }
        self.cookie_len = crate::cookie::cookie_len(aead);
        self.contents = Some(CookieContents {
            aead,
            c2s_key: keys.c2s.clone(),
            s2c_key: keys.s2c.clone(),
        });
        self.cookies.clear();
        for c in cookies {
            self.cookies.push_back(StockedCookie { bytes: c });
        }
        self.stats.cookies_received += self.cookies.len() as u64;
        self.pending_uid = None;
        self.pending_t1 = None;
    }

    /// Perform one NTS volley.  Sends a request, waits for the authenticated
    /// response, and returns the measurement.
    ///
    /// Refills the cookie stock as a side effect.  Re-runs NTS-KE when needed.
    pub fn poll(&mut self) -> Result<Sample, ClientError> {
        // A previous poll may have failed after consuming a cookie, so the stock
        // can be empty with key material still valid.  Replenish before sending
        // rather than falling through to an unprotected request.
        if self.cookies.is_empty() {
            self.key_establish()?;
        }

        let cookie = self
            .cookies
            .pop_front()
            .ok_or(ClientError::Timeout)?;
        self.stats.cookies_consumed += 1;
        let remaining = self.cookies.len();
        // One cookie comes back for the one just sent, so N placeholders brings
        // the stock back to TARGET_COOKIE_STOCK (RFC 8915 section 5.7).
        let placeholders = TARGET_COOKIE_STOCK
            .saturating_sub(remaining + 1)
            .min(nts_ntp::MAX_PLACEHOLDERS);

        let contents = self.contents.as_ref().ok_or(ClientError::Timeout)?;
        let mut packet = Packet::new();
        let t1 = ntp::ntp_now();
        packet.set_transmit_ts(t1);
        nts_ntp::build_request(&mut packet, contents, &cookie.bytes, placeholders)?;
        let uid = packet
            .find(crate::ntp::EF_UNIQUE_ID)
            .expect("build_request always adds a unique identifier")
            .body
            .clone();
        self.pending_uid = Some(uid);
        self.pending_t1 = Some(t1);

        let wire = packet.encode();
        let sock = UdpSocket::bind(if self.ntp_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        sock.connect(self.ntp_addr)?;
        sock.set_read_timeout(Some(Duration::from_secs(3)))?;

        let t1_instant = Instant::now();
        let t1_unix = ntp::system_unix_f64();
        sock.send(&wire)?;
        self.stats.requests += 1;

        let mut buf = [0u8; 2048];
        let n = sock.recv(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
            {
                ClientError::Timeout
            } else {
                ClientError::Io(e)
            }
        })?;
        let t4_unix = ntp::system_unix_f64();
        let t4_instant = Instant::now();

        let response = Packet::parse(&buf[..n])?;
        let contents = self.contents.as_ref().expect("checked above");
        let verified = match nts_ntp::verify_response(
            &response,
            contents,
            self.pending_uid.as_deref().unwrap_or(&[]),
        ) {
            Ok(v) => v,
            Err(NtsError::NtsNak) => {
                // Discard everything and re-establish, but respect the backoff.
                self.stats.naks += 1;
                self.contents = None;
                self.cookies.clear();
                self.key_establish()?;
                return Err(ClientError::Nts(NtsError::NtsNak));
            }
            Err(e) => {
                self.stats.auth_failures += 1;
                return Err(ClientError::Nts(e));
            }
        };
        self.stats.responses += 1;

        for c in verified.cookies {
            if self.cookies.len() < TARGET_COOKIE_STOCK {
                self.cookies.push_back(StockedCookie { bytes: c });
                self.stats.cookies_received += 1;
            }
        }

        // RFC 5905 section 8 on-wire offset and delay.  Timestamps come off the
        // wire in NTP form and are converted with an era pivot taken from the
        // local clock, so the values stay correct across 2036.
        let pivot = t4_unix;
        let t2 = ntp::ntp_to_unix(response.receive_ts(), pivot);
        let t3 = ntp::ntp_to_unix(response.transmit_ts(), pivot);
        let t1 = ntp::ntp_to_unix(t1, t1_unix);
        let t4 = t4_unix;

        let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
        let delay = (t4 - t1) - (t3 - t2);
        let rtt = t4_instant.duration_since(t1_instant).as_secs_f64();

        self.pending_uid = None;
        self.pending_t1 = None;
        // A complete volley with an authenticated response is the condition in
        // RFC 8915 section 4.2 for resetting the NTS-KE backoff.
        if !self.volley_ok {
            self.volley_ok = true;
            self.ke_failures = 0;
            self.next_ke_attempt = None;
        }

        Ok(Sample {
            offset,
            delay,
            rtt,
            stratum: response.stratum(),
            cookies_received: self.stats.cookies_received as usize,
        })
    }

    /// Whether the client currently holds usable key material and cookies.
    pub fn ready(&self) -> bool {
        self.contents.is_some() && !self.cookies.is_empty()
    }
}

/// RFC 8915 section 4.2: `t = min(10 * 1.5^(n-1), 432000)` seconds.
pub fn ke_backoff(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let t = 10.0 * 1.5_f64.powi(failures.saturating_sub(1) as i32);
    // Whole seconds, per the formula's integer framing.
    Duration::from_secs(t.min(432_000.0) as u64)
}

/// A jittered request interval for benchmarking: sleep `delay ± spread`.
pub fn jitter(delay: Duration, spread: f64) -> Duration {
    let mut r = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut r);
    let u = (u64::from_le_bytes(r) as f64) / (u64::MAX as f64);
    let factor = 1.0 + spread * (2.0 * u - 1.0);
    delay.mul_f64(factor.max(0.01))
}

/// Parse "host:port", "host", "[v6]:port" or a bare "v6", defaulting the port.
pub fn resolve(spec: &str, default_port: u16) -> Result<SocketAddr, ClientError> {
    use std::net::ToSocketAddrs;

    // Anything that already parses as a socket address needs no help.  Doing
    // this first keeps a bare IPv6 literal such as "::1" from being mistaken
    // for host+port by the rsplit below.
    if let Ok(a) = spec.parse::<SocketAddr>() {
        return Ok(a);
    }
    // "host:port" where the port is numeric, but only when there is exactly one
    // colon (a bare IPv6 has several and will have fallen through above).
    let has_port = spec.matches(':').count() == 1
        && spec
            .rsplit_once(':')
            .map(|(_, p)| p.parse::<u16>().is_ok())
            .unwrap_or(false);
    let s = if has_port {
        spec.to_string()
    } else {
        format!("{spec}:{default_port}")
    };
    let mut addrs = s.to_socket_addrs().map_err(|_| {
        ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("could not resolve {spec}"),
        ))
    })?;
    addrs.next().ok_or_else(|| {
        ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no address for {spec}"),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_matches_rfc_table() {
        // t = min(10 * 1.5^(n-1), 432000)
        assert_eq!(ke_backoff(0), Duration::ZERO);
        assert_eq!(ke_backoff(1), Duration::from_secs(10));
        assert_eq!(ke_backoff(2), Duration::from_secs(15));
        assert_eq!(ke_backoff(3), Duration::from_secs(22)); // 22.5 truncated
        let cap = ke_backoff(1000);
        assert_eq!(cap, Duration::from_secs(432_000));
    }

    #[test]
    fn resolve_handles_host_port_and_bare_addresses() {
        assert_eq!(resolve("127.0.0.1:1234", 999).unwrap().to_string(), "127.0.0.1:1234");
        assert_eq!(resolve("127.0.0.1", 1234).unwrap().to_string(), "127.0.0.1:1234");
        // A bare IPv6 literal has multiple colons and must not be read as
        // host:port.
        let v6 = resolve("::1", 1234).unwrap();
        assert_eq!(v6.port(), 1234);
        assert!(v6.is_ipv6());
        // Bracketed with a port.
        assert_eq!(resolve("[::1]:1234", 999).unwrap().port(), 1234);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        for _ in 0..1000 {
            let d = jitter(Duration::from_millis(1000), 0.1);
            assert!(d >= Duration::from_millis(900), "{d:?}");
            assert!(d <= Duration::from_millis(1100), "{d:?}");
        }
    }
}
