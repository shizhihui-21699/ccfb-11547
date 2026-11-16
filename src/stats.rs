//! Time-sample statistics for the offset/jitter comparison report.
//!
//! Jitter follows the NTP convention (RFC 5905 §4): exponential RMS average
//! of successive offset differences, `J(n) = J(n-1) + (|d| - J(n-1))/16`.
//! We additionally compute ordinary sample standard deviation and the RTT
//! percentile table for the report.

use crate::ntp_client::TimeSample;

#[derive(Debug, Clone, Default)]
pub struct SampleStats {
    pub count: usize,
    /// Mean clock offset in nanoseconds (client relative to server).
    pub mean_offset_ns: f64,
    pub min_offset_ns: i128,
    pub max_offset_ns: i128,
    pub stddev_offset_ns: f64,
    /// NTP-style jitter (RFC 5905).
    pub jitter_ns: f64,
    pub mean_rtt_ns: f64,
    pub min_rtt_ns: u128,
    pub median_rtt_ns: u128,
    pub max_rtt_ns: u128,
    pub p95_rtt_ns: u128,
}

pub fn summarize(samples: &[TimeSample]) -> SampleStats {
    let n = samples.len();
    if n == 0 {
        return SampleStats::default();
    }
    let offsets: Vec<f64> = samples.iter().map(|s| s.offset_nanos as f64).collect();
    let rtts: Vec<u128> = samples.iter().map(|s| s.rtt_nanos).collect();

    let mean_offset = offsets.iter().sum::<f64>() / n as f64;
    let variance = offsets
        .iter()
        .map(|o| (o - mean_offset).powi(2))
        .sum::<f64>()
        / n.max(2) as f64; // population-ish; stable for n=1
    let stddev = variance.sqrt();

    let mut jitter = 0.0f64;
    for w in offsets.windows(2) {
        let d = (w[1] - w[0]).abs();
        jitter += (d - jitter) / 16.0;
    }

    let mut sorted_rtt = rtts.clone();
    sorted_rtt.sort();
    let mean_rtt = rtts.iter().sum::<u128>() as f64 / n as f64;

    SampleStats {
        count: n,
        mean_offset_ns: mean_offset,
        min_offset_ns: samples.iter().map(|s| s.offset_nanos).min().unwrap(),
        max_offset_ns: samples.iter().map(|s| s.offset_nanos).max().unwrap(),
        stddev_offset_ns: stddev,
        jitter_ns: jitter,
        mean_rtt_ns: mean_rtt,
        min_rtt_ns: sorted_rtt[0],
        median_rtt_ns: percentile_sorted(&sorted_rtt, 50.0),
        max_rtt_ns: *sorted_rtt.last().unwrap(),
        p95_rtt_ns: percentile_sorted(&sorted_rtt, 95.0),
    }
}

fn percentile_sorted(sorted: &[u128], pct: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Human-friendly nanoseconds → µs/ms string.
pub fn fmt_ns(ns: f64) -> String {
    let abs = ns.abs();
    if abs < 1_000.0 {
        format!("{ns:.1} ns")
    } else if abs < 1_000_000.0 {
        format!("{:.3} µs", ns / 1_000.0)
    } else {
        format!("{:.3} ms", ns / 1_000_000.0)
    }
}

pub fn fmt_u128_ns(ns: u128) -> String {
    fmt_ns(ns as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp::NtpTimestamp;

    fn sample(offset: i128, rtt: u128) -> TimeSample {
        TimeSample {
            offset_nanos: offset,
            rtt_nanos: rtt,
            t1: NtpTimestamp(1),
            t2: NtpTimestamp(2),
            t3: NtpTimestamp(3),
            t4: NtpTimestamp(4),
            stratum: 3,
            cookies_remaining: 7,
        }
    }

    #[test]
    fn basic_summary() {
        let s = vec![
            sample(1_000, 10_000),
            sample(-2_000, 20_000),
            sample(3_000, 30_000),
            sample(0, 40_000),
        ];
        let st = summarize(&s);
        assert_eq!(st.count, 4);
        assert_eq!(st.mean_offset_ns, 500.0);
        assert_eq!(st.min_offset_ns, -2_000);
        assert_eq!(st.max_offset_ns, 3_000);
        assert_eq!(st.min_rtt_ns, 10_000);
        // nearest-rank percentile at p=50, index = round(0.5*3) = 2
        assert_eq!(st.median_rtt_ns, 30_000);
        assert_eq!(st.max_rtt_ns, 40_000);
        assert!(st.stddev_offset_ns > 0.0);
        assert!(st.jitter_ns > 0.0);
    }

    #[test]
    fn empty_is_default() {
        let st = summarize(&[]);
        assert_eq!(st.count, 0);
    }

    #[test]
    fn formatter_picks_units() {
        assert!(fmt_ns(500.0).ends_with("ns"));
        assert!(fmt_ns(12_345.0).contains("µs"));
        assert!(fmt_ns(5_000_000.0).contains("ms"));
    }
}
