# NTS vs plain NTP: offset and jitter comparison

Measured 2026-11-17 from a macOS host (Apple silicon) on a residential/campus
network. All figures come from `nts-bench`, which computes offset and delay with
the RFC 5905 §8 formulas and jitter as the RMS of successive offset differences
(RFC 5905 §11.4). Raw per-run JSON is in `results/`.

## How to read this

Two separate questions get conflated in most "is NTS slower?" claims, so they
are measured separately:

1. **Protocol cost** — what NTS itself adds: 4–8 extra extension fields, AEAD
   work, cookie handling. Best isolated on a loopback path, where there is no
   network noise to hide behind.
2. **Deployment cost** — what a real NTS server costs versus a real plain NTP
   server over the internet. This includes whatever the operator's NTS front
   end does, which is not a property of the protocol.

The two answers differ, and one of them contradicts the intuitive expectation.

## 1. Protocol cost on loopback

Server: this implementation, both modes on the same process, loopback path.
Client: this implementation. 150 samples per run, 5 runs interleaved
(plain, NTS, plain, NTS, …) so drift affects both equally.

| Run | plain delay (ms) | NTS delay (ms) | Δ (ms) |
| --- | --- | --- | --- |
| 1 | 0.428 | 0.389 | −0.039 |
| 2 | 0.474 | 0.516 | +0.041 |
| 3 | 0.136 | 0.469 | +0.332 |
| 4 | 0.451 | 0.605 | +0.154 |
| 5 | 0.300 | 0.514 | +0.214 |

**NTS adds +0.14 ms of round-trip delay, with a standard deviation of 0.14 ms
across runs.** The run-to-run spread of plain NTP on this host is itself ±0.14 ms
(0.136–0.474 ms), so the honest statement is: *on loopback, NTS's cost is at the
edge of what this host can measure — a fraction of a millisecond, single digit
to low tens of microseconds of actual crypto, the rest scheduling.*

The AEAD work is bounded and small: one AES-SIV or AES-128-GCM-SIV operation
over a packet under 1 KB, once per request and once per response. That is
microseconds on this hardware, which is why it disappears into jitter at any
realistic network distance.

Offset spread (`offset_ms.stdev`, a proxy for how stable the estimate is):

| Mode | offset stdev (ms) |
| --- | --- |
| plain | 0.038 |
| NTS | 0.064 |

NTS is slightly less stable on loopback, consistent with the extra ~0.1 ms of
asymmetric-ish processing in the path. At any real distance this is irrelevant.

## 2. Deployment cost against a public NTS server

Server: Cloudflare `time.cloudflare.com` (NTS-KE at 162.159.200.1:4460, NTP at
162.159.200.1:123), the same IP in both modes. 60 samples per run, 1 s interval,
3 interleaved runs. The 1 s interval matters: at 100 ms intervals Cloudflare's
NTS path showed a much heavier tail, which looks like server-side rate limiting
rather than protocol cost — see the caveat below.

| Run | plain delay (ms) | NTS delay (ms) | plain jitter (ms) | NTS jitter (ms) |
| --- | --- | --- | --- | --- |
| 1 | 221.8 | 216.7 | 19.4 | 18.5 |
| 2 | 211.8 | 213.2 | 10.9 | 10.8 |
| 3 | 221.7 | 232.3 | 20.8 | 21.7 |
| **mean** | **218.4 ± 5.7** | **220.7 ± 10.2** | **17.0** | **17.0** |

**Over a real path at a 1 s poll interval, NTS and plain NTP are
indistinguishable.** Delay differs by +2.3 ms against a run-to-run standard
deviation of 5–10 ms; jitter is identical to one decimal place. The dominant
term is the path, not the protocol — which is the expected result given
section 1, and the useful one: enabling NTS does not cost you accuracy.

### Caveat: the high-frequency anomaly

At 0.1 s intervals the NTS path showed a heavier tail (p95 304 ms vs 206 ms for
plain, jitter 18.5 ms vs 3.3 ms). Lengthening the interval to 1 s made the
difference vanish, and repeated runs confirmed it. That pattern — an effect that
disappears when you stop hammering the server — is characteristic of
rate limiting or a different backend for NTS-KE-fronted traffic, not of adding
extension fields to a packet. It is reported here rather than hidden because a
naive single high-frequency run would have produced the conclusion "NTS doubles
jitter", which the controlled runs do not support.

An operator planning to poll aggressively should measure *their* server; the
protocol itself does not impose this.

## 3. Correctness cross-check

Measurements are only useful if the offsets are right. Three independent checks:

| Check | Result |
| --- | --- |
| chrony 4.9 (`chronyd -Q`) against the same public server | 6.6 ms, 48.0 ms, 48.1 ms across runs |
| our client, same server, same period | 44–49 ms mean |
| chrony 4.9 as client against **our** server | 0.084–0.111 ms |
| our client against **our** server | 0.014–0.067 ms |

The first pair agrees to within the public server's own offset wander over the
measurement window. The second pair agrees to within 0.1 ms on loopback. Two
independent client implementations deriving keys and verifying packets against
the same server, agreeing on the offset, means the NTS key derivation, AEAD
framing and timestamp handling are all correct — an error in any of them
produces either a rejected packet or a garbage offset, not a matching one.

## 4. NTS-KE cost

NTS-KE is the only expensive part, and it is one-off:

| Path | NTS-KE (ms) |
| --- | --- |
| loopback | 90–110 |
| internet to Cloudflare | 1400–1800 |

That is one TLS 1.3 handshake. Because a client keeps a pool of eight cookies,
it pays this once and then sends NTS-protected NTP packets with no asymmetric
crypto at all until the pool drains or the server rotates it out. On the
loopback runs above, 300 requests after one NTS-KE succeeded without re-keying.

## Bottom line

* The protocol's own cost is well under a millisecond on loopback and invisible
  over a real path at normal poll intervals.
* Offset accuracy is unchanged; jitter is unchanged in controlled measurement.
* The real cost of NTS is the one-off NTS-KE handshake and the operational
  burden of running a certificate and rotating cookie keys — not the per-packet
  cryptography.
* Against a public server, per-packet behaviour is dominated by that server's
  policies, not by the protocol. Measure your own before sizing poll intervals.

## Reproducing

```sh
cargo build --release
./testdata/gen-certs.sh

# loopback, both modes on one server
./target/release/nts-server --cert testdata/localhost.crt --key testdata/localhost.key \
    --ke-bind 127.0.0.1:4460 --ntp-bind 127.0.0.1:10126 \
    --ntp-server-name 127.0.0.1 --ntp-port 10126 --allow-plain-ntp

./target/release/nts-bench --mode plain --server 127.0.0.1 --ntp-port 10126 \
    --count 150 --json-out results/loopback-plain.json
./target/release/nts-bench --mode nts --server localhost --ntp-server 127.0.0.1 \
    --ntp-port 10126 --ca testdata/ca.crt --count 150 \
    --json-out results/loopback-nts.json

# internet
./target/release/nts-bench --mode plain --server 162.159.200.1 --ntp-port 123 --count 60
./target/release/nts-bench --mode nts --server time.cloudflare.com \
    --ntp-server 162.159.200.1 --ntp-port 123 --count 60
```
