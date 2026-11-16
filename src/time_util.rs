//! Clock and NTP timestamp helpers.
//!
//! NTP timestamps are 64-bit: 32 bits of seconds since 1900-01-01 and
//! 32 bits of fraction (2^-32 s). The seconds field wraps in 2036; the
//! [`Clock`] trait lets tests inject a fixed reference while production code
//! uses [`SystemClock`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ntp::NtpTimestamp;
use crate::{Error, Result};

/// Seconds between 1900-01-01 (NTP epoch) and 1970-01-01 (Unix epoch).
pub const NTP_UNIX_DELTA: u64 = 2_208_988_800;

/// A monotonic-ish clock used for both NTP timestamps and RTT measurement.
pub trait Clock: Send + Sync {
    /// Current wall time as an NTP timestamp.
    fn now_ntp(&self) -> NtpTimestamp;
    /// Arbitrary monotonic reading in nanoseconds (only differences matter).
    fn instant_nanos(&self) -> u128;
}

#[derive(Debug, Clone)]
pub struct SystemClock {
    anchor: std::time::Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            anchor: std::time::Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now_ntp(&self) -> NtpTimestamp {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        unix_to_ntp(d.as_secs(), d.subsec_nanos())
    }

    fn instant_nanos(&self) -> u128 {
        std::time::Instant::now()
            .duration_since(self.anchor)
            .as_nanos()
    }
}

/// Convert Unix seconds + subsecond nanos to an NTP timestamp (current era).
pub fn unix_to_ntp(secs: u64, nanos: u32) -> NtpTimestamp {
    let ntp_secs = secs.wrapping_add(NTP_UNIX_DELTA) as u32 as u64;
    let frac = ((nanos as u64) << 32) / 1_000_000_000;
    NtpTimestamp((ntp_secs << 32) | frac)
}

/// NTP timestamp → Unix `Duration` since the epoch, resolving the 2036 wrap
/// by picking the NTP era closest to the supplied reference Unix time
/// (RFC 5905 §6 / era numbering).
pub fn ntp_to_unix(ts: NtpTimestamp, ref_unix_secs: u64) -> Duration {
    let ntp_secs32 = (ts.0 >> 32) as u32 as u64;
    let frac = ts.0 & 0xffff_ffff;
    let ref_ntp = ref_unix_secs.wrapping_add(NTP_UNIX_DELTA);
    let ref_era = ref_ntp >> 32;
    // Try the reference era and its neighbour, take the closest seconds value.
    let cand_a = (ref_era << 32) | ntp_secs32;
    let cand_b = cand_a.wrapping_sub(1u64 << 32);
    let cand = if abs_diff(cand_a, ref_ntp) <= abs_diff(cand_b, ref_ntp) {
        cand_a
    } else {
        cand_b
    };
    let unix_secs = cand.wrapping_sub(NTP_UNIX_DELTA);
    let nanos = frac_to_nanos(frac);
    Duration::new(unix_secs, nanos)
}

/// Fraction (2^-32 s) → nanoseconds, rounded to nearest.
pub fn frac_to_nanos(frac: u64) -> u32 {
    ((((frac & 0xffff_ffff) * 1_000_000_000) + (1u64 << 31)) >> 32) as u32
}

/// Signed offset between two NTP timestamps in nanoseconds (a − b).
pub fn ntp_diff_nanos(a: NtpTimestamp, b: NtpTimestamp) -> i128 {
    let a_ns = ntp_to_nanos(a);
    let b_ns = ntp_to_nanos(b);
    a_ns as i128 - b_ns as i128
}

fn ntp_to_nanos(ts: NtpTimestamp) -> u128 {
    let secs = (ts.0 >> 32) as u128;
    let frac = (ts.0 & 0xffff_ffff) as u128;
    secs * 1_000_000_000 + (frac * 1_000_000_000) / (1u128 << 32)
}

fn abs_diff(a: u64, b: u64) -> u64 {
    a.abs_diff(b)
}

/// Standard NTP client offset/dispersion math (RFC 5905 §8 / on-wire formula).
///
/// Given the four timestamps:
///   t1 = client transmit, t2 = server receive, t3 = server transmit,
///   t4 = client receive (all NTP timestamps except t4, which is measured
///   locally), returns `(offset_nanos, rtt_nanos)`.
pub fn on_wire_calculation(
    t1: NtpTimestamp,
    t2: NtpTimestamp,
    t3: NtpTimestamp,
    t4: NtpTimestamp,
) -> Result<(i128, u128)> {
    let t1n = ntp_to_nanos(t1);
    let t2n = ntp_to_nanos(t2);
    let t3n = ntp_to_nanos(t3);
    let t4n = ntp_to_nanos(t4);
    let rtt = t4n
        .checked_sub(t1n)
        .ok_or_else(|| Error::Clock("response arrived before request was sent".into()))?;
    // offset = ((t2-t1) + (t3-t4)) / 2
    let offset = ((t2n as i128 - t1n as i128) + (t3n as i128 - t4n as i128)) / 2;
    Ok((offset, rtt))
}

/// Test clock with scripted wall time and monotonic readings.
pub mod testutil {
    use std::sync::Mutex;

    use super::*;

    pub struct FakeClock {
        pub wall: Mutex<u64>, // unix secs
        pub nanos: Mutex<u128>,
    }

    impl FakeClock {
        pub fn new(unix_secs: u64) -> Self {
            Self {
                wall: Mutex::new(unix_secs),
                nanos: Mutex::new(0),
            }
        }
    }

    impl Clock for FakeClock {
        fn now_ntp(&self) -> NtpTimestamp {
            unix_to_ntp(*self.wall.lock().unwrap(), 0)
        }
        fn instant_nanos(&self) -> u128 {
            *self.nanos.lock().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_ntp_roundtrip_known_epoch() {
        // 2024-01-01T00:00:00Z = 1704067200 unix
        let ts = unix_to_ntp(1_704_067_200, 0);
        let d = ntp_to_unix(ts, 1_704_067_200);
        assert_eq!(d.as_secs(), 1_704_067_200);
        assert_eq!(d.subsec_nanos(), 0);
        // NTP seconds = unix + delta
        assert_eq!(ts.0 >> 32, 1_704_067_200 + NTP_UNIX_DELTA);
    }

    #[test]
    fn fractional_roundtrip() {
        let ts = unix_to_ntp(1_700_000_000, 123_456_789);
        let d = ntp_to_unix(ts, 1_700_000_000);
        assert_eq!(d.as_secs(), 1_700_000_000);
        // 2^-32 resolution ≈ 0.23 ns; allow one unit of rounding slack
        let diff = d.subsec_nanos().abs_diff(123_456_789);
        assert!(diff <= 1, "nanos {} diff {diff}", d.subsec_nanos());
    }

    /// Build an NTP timestamp at whole-second `secs` plus an exact
    /// number of 2^-32-second fractional units (no nanosecond rounding).
    fn ntp_at(secs: u64, frac_units: u64) -> NtpTimestamp {
        NtpTimestamp(((secs + NTP_UNIX_DELTA) << 32) | frac_units)
    }

    #[test]
    fn on_wire_zero_offset_symmetric() {
        let ten_ms = (0.010f64 * (1u64 << 32) as f64) as u64; // 10 ms in frac units
        let twenty_ms = ten_ms * 2;
        let t1 = ntp_at(1000, 0);
        let t2 = ntp_at(1000, ten_ms);
        let t3 = ntp_at(1000, ten_ms);
        let t4 = ntp_at(1000, twenty_ms);
        let (off, rtt) = on_wire_calculation(t1, t2, t3, t4).unwrap();
        assert_eq!(off, 0);
        // RTT is 20 ms; the fractional->ns conversion may lose at most ~1 ns.
        assert!((rtt as i128 - 20_000_000).abs() <= 1, "rtt={rtt}");
    }

    #[test]
    fn on_wire_clock_ahead_detected() {
        // Client clock runs 5ms fast; true one-way delay is 5ms each way.
        // True timeline: send@10, server recv/send@15(true)=20(client),
        // client recv@20(true)=25(client). Server stamps true time.
        let five_ms = (0.005f64 * (1u64 << 32) as f64) as u64;
        let ten_ms = five_ms * 2;
        let fifteen_ms = five_ms * 3;
        let twenty_ms = five_ms * 4;
        let twentyfive_ms = five_ms * 5;
        let t1 = ntp_at(1000, fifteen_ms); // client tx, client clock 15ms
        let t2 = ntp_at(1000, fifteen_ms); // server rx, true 15ms
        let t3 = ntp_at(1000, fifteen_ms);
        let t4 = ntp_at(1000, twentyfive_ms); // client rx, client clock 25ms
        // Silence unused warnings while keeping the derivation readable.
        let _ = (ten_ms, twenty_ms);
        let (off, rtt) = on_wire_calculation(t1, t2, t3, t4).unwrap();
        // ((15-15) + (15-25))/2 = -5ms: client is 5ms ahead.
        assert!((off + 5_000_000).abs() <= 2, "off={off}");
        // RTT = 25-15 = 10ms on the client clock.
        assert!((rtt as i128 - 10_000_000).abs() <= 2, "rtt={rtt}");
    }
}
