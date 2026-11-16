# nts — RFC 8915 Network Time Security in Rust

A client, a server, and a measurement harness for Network Time Security, implemented
from [RFC 8915](https://www.rfc-editor.org/rfc/rfc8915.html).

The problem this solves: plain NTP is unauthenticated.  Anyone who can reach the
path — or who can spoof a source address — can rewrite the timestamps in a reply
and move a host's clock.  A host whose clock is off by years will reject every
certificate that is not yet valid or already expired, which turns a time problem
into an outage across the whole stack.  NTS fixes the authentication problem
without giving up NTP's cost profile: TLS 1.3 is used once, to bootstrap keys and
cookies, and the per-packet cost stays symmetric.

## What is implemented

| RFC 8915 section | Feature |
|---|---|
| 4 | NTS-KE over TLS 1.3 on TCP 4460, ALPN `ntske/1` |
| 4.1 | All record types 0–7, critical-bit handling, in-band error codes |
| 4.2 | NTS-KE retry backoff, `min(10 × 1.5^(n-1), 432000)` seconds |
| 4.3, 5.1 | Exporter-derived C2S/S2C keys, correct per-association context |
| 5.3–5.6 | Unique Identifier, Cookie, Cookie Placeholder, Authenticator EFs |
| 5.6 | Additional Padding rules, including the amplification guard |
| 5.7 | Full volley, cookie stock management, NTS NAK handling |
| 6 | Cookie format `(I, N, C)`, master-key rotation and retirement |
| 8.4 | Response is never larger than the request |

AEAD algorithms:

* **AEAD_AES_SIV_CMAC_256 (15)** — mandatory to implement for servers
  (RFC 8915 §4.1.5).  Variable-length nonce, tag prepended
  (`tag ‖ ciphertext`, RFC 5297 §2.6).
* **AEAD_AES_128_GCM_SIV (30)** — chrony's first preference.  Fixed 12-octet
  nonce, tag appended (`ciphertext ‖ tag`, RFC 8452 §4).

Both are verified against the official test vectors: RFC 5297 appendix A and
RFC 8452 appendix C.1.

Why these two: AES-SIV is the one every server must speak, and AES-GCM-SIV is
what chrony offers first by default, so supporting both is what makes
interoperability demonstrable in both directions rather than on paper.

## Cookie and key rotation

A cookie carries the negotiated AEAD and both NTP keys, sealed under a
long-lived master key, so the NTP responder holds no per-client state:

```
cookie = key_id(2) ‖ nonce(16) ‖ AES-SIV(master_key, nonce, aead_id ‖ c2s ‖ s2c)
```

* **Rotation.**  A new master key is derived from its predecessor by HKDF
  (a one-way ratchet, RFC 8915 §6), so several server instances that share a
  seed stay in step without any key-distribution infrastructure.
* **Transition.**  New cookies always use the current key; cookies minted under
  older keys keep working until that generation is retired
  (`--keep-old-cookie-keys`, default 2).  Retirement is what gives forward
  secrecy to old cookies.
* **Compromise.**  Rotating a key out stops it minting or verifying cookies,
  which forces the affected clients through NTS-KE again.

## Usage

Generate a CA and a server certificate, then start the server:

```sh
./target/release/nts-server \
    --ntp 0.0.0.0:12300 --ke 0.0.0.0:14460 \
    --cert server.crt --key server.key \
    --cookie-seed "$(openssl rand -hex 32)" \
    --rotate-every 86400
```

`--cookie-seed` is what lets a restarted or second server accept cookies minted
before it started; without it a fresh seed is generated and printed.  In
production, serve NTS-KE on 4460 and NTP on 123 (both require privileges) and
put the seed in a secret store.

Query it:

```sh
./target/release/nts-client --server nts.example.net --ca ca.crt --count 10 --verbose
```

Measure and compare:

```sh
./target/release/nts-bench \
    --mode both --server nts.example.net --ntp 192.0.2.1 \
    --count 200 --interval 0.2 --compare
```

## Design notes

**Why TLS is used once, not per packet.**  The asymmetric work happens in
NTS-KE; NTP packets are protected with symmetric AEAD keys that cost the same as
the checksum they replace.  This is also what makes the deployment in
RFC 8915 §8.3 practical: an attacker exhausting the NTS-KE listener cannot stop
time service for clients that already hold cookies.

**Why AES-SIV is used for cookies regardless of the negotiated algorithm.**
SIV tolerates an accidental nonce reuse, which is exactly the failure mode a
stateless cookie server risks.  RFC 8915 §6 recommends it for this purpose.

**Why the client discards each cookie after one use.**  A reused cookie is a
linkability handle: an observer can tie two requests to one session.  RFC 8915
§5.7 asks clients to prefer unlinkability and only reuse for resilience.

**Why responses may not exceed requests.**  NTS must not become a DDoS
amplifier.  Cookie placeholders reserve exactly the space the returned cookies
occupy, so a server can return cookies without the reply outgrowing the request.

## Limits and non-goals

* The server does not discipline a local clock; it reports its own time and lets
  clients offset against it.  It is a time server, not a time *client*.
* NTS for NTP modes other than client/server (3 and 4) is out of scope, as the
  RFC specifies.
* No persistent cookie cache across client restarts (RFC 8915 §5.7 suggests it;
  it is a resilience feature, not a correctness one).
* Interleaved mode, NTP symmetric keys and broadcast are untouched.
* The NTS-KE listener does not implement the optional rate limiter.

## Testing

```sh
cargo test              # unit tests + loopback end-to-end tests
cargo clippy --all-targets
```

The unit tests pin every wire format against the RFCs' own vectors.  The
end-to-end tests run a real TLS handshake and real UDP packets on loopback,
including key rotation and retirement.  Interoperability against chrony and
Cloudflare is covered in `REPORT.md`.
