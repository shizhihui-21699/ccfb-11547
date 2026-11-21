//! A small, dependency-free microbenchmark for the costs `sealedmem` adds.
//!
//! Run with: `cargo run -p residue --example bench --release 2>/dev/null` is not
//! the intended shape; instead: `cargo bench` is unavailable offline without
//! criterion, so this example prints medians and the verification script can
//! include them.  Usage: `cargo run -p residue --example bench --release`.

use std::time::{Duration, Instant};

use sealedmem::{SealedBytes, SealedString};

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn main() {
    const N: usize = 20_000;
    const PAYLOAD: usize = 64;

    // Plain String read, for a baseline that includes the same allocation churn.
    let plain: String = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".to_string();
    let mut samples = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        let n = plain.len();
        std::hint::black_box(&plain[..n]);
        samples.push(t.elapsed());
    }
    println!(
        "read  plain String      : {:>8.1} ns",
        median(samples).as_secs_f64() * 1e9
    );

    // Sealed read: unseal, read, reseal per access.
    let sealed =
        SealedString::from_callback(PAYLOAD, |dst| {
            dst[..plain.len()].copy_from_slice(plain.as_bytes());
            plain.len()
        })
        .expect("sealed");
    let mut samples = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        sealed.with_str(|s| std::hint::black_box(s.len()));
        samples.push(t.elapsed());
    }
    println!(
        "read  SealedString view : {:>8.1} ns  (includes 2 mprotect)",
        median(samples).as_secs_f64() * 1e9
    );

    // Allocate + fill + wipe, i.e. the full lifetime of a short-lived token.
    let mut samples = Vec::with_capacity(N / 4);
    for _ in 0..(N / 4) {
        let t = Instant::now();
        let raw = vec![7u8; PAYLOAD];
        let mut s = SealedBytes::from_callback(PAYLOAD, |dst| {
            dst[..PAYLOAD].copy_from_slice(&raw);
            PAYLOAD
        })
        .expect("sealed");
        s.wipe().expect("wipe");
        samples.push(t.elapsed());
    }
    println!(
        "cycle alloc+fill+wipe  : {:>8.1} ns  (mmap, mlock, inherit, 2 mprotect, wipe)",
        median(samples).as_secs_f64() * 1e9
    );

    // The comparison that matters for auth paths: constant-time compare.
    let probe = [0u8; 32];
    let mut samples = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        std::hint::black_box(sealed.eq_ct(&plain));
        std::hint::black_box(&probe);
        samples.push(t.elapsed());
    }
    println!(
        "eq_ct  expected 32 B    : {:>8.1} ns",
        median(samples).as_secs_f64() * 1e9
    );

    println!("(medians over {N} iterations; debug numbers are worse, run --release)");
}
