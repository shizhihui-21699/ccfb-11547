# NTS in Rust — client and server per RFC 8915

A Network Time Security implementation: NTS-KE over TLS 1.3, NTS-protected
NTPv4, rotating cookies, and a server-side master-key ring that keeps old
cookies valid across a rotation window.

Written because bare NTP has no authentication: anyone on the path can forge
the timestamp, and a forged clock breaks certificate validation everywhere
that depends on it. NTS fixes that by binding the time protocol to TLS, while
leaving NTP itself cheap enough to keep running at poll intervals.

## What is implemented

| RFC 8915 requirement | Where |
| --- | --- |
| NTS-KE records, End-of-Message framing, body-length semantics | `nts-core/src/ke.rs` |
| TLS 1.3 + ALPN `ntske/1`, exporter key derivation | `nts-ke/src/lib.rs` |
| Cookies: AES-SIV-encrypted, key id, nonce, rotation | `nts-core/src/cookie.rs` |
| Unique Identifier, Cookie, Placeholder EFs | `nts-core/src/ntp.rs` |
| Authenticator EF: nonce/ciphertext framing, AAD rules | `nts-core/src/auth.rs` |
| AEAD: AES-SIV-CMAC-256 (15) and AES-128-GCM-SIV (30) | `nts-core/src/aead.rs` |
| Client cookie pool, placeholders, NAK recovery | `nts-core/src/keyring.rs`, `nts-client/` |
| NTS-KE server, NTP server, NAK replies, rotation | `nts-server/` |
| Offset/delay/jitter measurement, NTS vs plain comparison | `nts-client/`, `nts-bench/` |

### AEAD support

Two algorithms, both usable in either role:

* **AEAD_AES_SIV_CMAC_256 (id 15)** — mandatory to implement per RFC 8915 §4.1.5,
  so it is offered first by default. Its 32-octet key is AES-128-CMAC plus
  AES-128-CTR (`K_LEN = 32`, RFC 5297 §6.1); the "256" in the name is the
  total key length, not AES-256.
* **AEAD_AES_128_GCM_SIV (id 30)** — RFC 8452. Half the key material, which
  makes cookies shorter and NTS packets smaller, and it is what chrony prefers
  by default.

Everything else in the IANA AEAD registry is rejected at negotiation. Both are
misuse-resistant constructions, which matters here because server cookies outlive
a single exchange.

## Building and running

```sh
cargo build --release
cargo test --workspace          # 51 tests, including RFC 5297 vectors and e2e

# Test certificate (throwaway, gitignored)
./testdata/gen-certs.sh

# Server: NTS-KE on 4460/tcp, NTP on 123/udp (needs root for :123)
./target/release/nts-server \
    --cert testdata/localhost.crt --key testdata/localhost.key \
    --ntp-server-name localhost

# Client
./target/release/nts-client --server time.cloudflare.com --count 8
./target/release/nts-client --server localhost --ke-port 4460 --ca testdata/ca.crt ...
```

Useful server flags: `--rotate-secs` (master-key rotation period, default daily),
`--key-retain` (how many old generations stay valid), `--cookie-max-age`,
`--aead`, `--test-rotation-secs` (rotate quickly to exercise the transition path).

Useful client flags: `--aead` (offer order), `--ca` (extra trust anchor),
`--ntp-server`/`--ntp-port` (override the address the KE server advertises,
which is needed when DNS cannot be trusted), `--insecure` (lab only).

## Design notes worth knowing

### Why cookies carry the state

The server keeps no per-client table. A cookie is the negotiated algorithm plus
both directional keys, encrypted under a master key the server holds. Any NTP
node that has the master key can answer a request, so load balancing and
restarts do not force clients back through NTS-KE.

Cookies are padded so their total length is a multiple of four: they travel in
an NTP extension field, and RFC 7822 requires word alignment. chrony rejects
unaligned fields.

### Rotation

`KeyRing` keeps the current generation plus `key_retain` previous ones. On
rotation a new key becomes current immediately and cookies from retained
generations keep working; erased generations fail closed and the server answers
with an NTS NAK, which tells the client to re-run NTS-KE. Old keys are zeroized
when they fall out of the ring. A separate age ceiling (`cookie_max_age`) stops
a cookie from outliving the key material regardless of generation count.

The NTS-KE and NTP sides share one `KeyRing`, so a rotation is visible to both
at the same instant — the property RFC 8915 §6 calls out as the hard part of
automatic rotation.

### Tag placement differs between the two AEADs

This is a real interop trap and cost us a debugging cycle:

* AES-SIV outputs `tag || ciphertext` (RFC 5297 §2.6, `IV || C`).
* AES-128-GCM-SIV outputs `ciphertext || tag` (RFC 5116 convention).

A symmetric mistake — using the same layout for both — is invisible in
self-interop and only shows up against another implementation. `seal`/`open`
follow each RFC, and `aead::tests::tag_placement_matches_each_rfc` pins it.

### AES-128-GCM-SIV exporter compatibility (chrony record 1024)

When implementations first added AEAD 30, some derived the TLS exporter context
with algorithm id 15 instead of 30. chrony negotiates this with a private,
non-critical record type 1024: if the server echoes it, chrony uses the
spec-compliant context; if not, chrony derives the legacy one.

This implementation sends 1024 in requests and echoes it in responses when it
picks 30, and falls back to the legacy identifier when a client did not ask.
Without this, keys silently disagree and every NTP packet fails authentication
after a successful NTS-KE.

### Downgrade protection

Plain NTP requests are **not** answered by default. A server that advertises
NTS but also serves unauthenticated time lets an on-path attacker strip the
extension fields and get a valid-looking answer. `--allow-plain-ntp` exists
only so the benchmark can measure protocol overhead on the same host.

### Interop fixes found against chrony

Three problems only appeared against a second implementation:

1. GCM-SIV tag placement (above).
2. Record 1024 / exporter context (above).
3. `localhost` resolving to `::1` first, so a client that handed a `host:port`
   string to the connector failed against IPv4-only servers. The client now
   resolves explicitly and prefers IPv4.

## Interoperability status

Verified against **chrony 4.9** (`+NTS`, nettle SIV, GnuTLS TLS) on macOS:

| Direction | Algorithm | Result |
| --- | --- | --- |
| our client → chrony server | 15 | time sample OK |
| our client → chrony server | 30 | time sample OK |
| chrony client → our server | 15 | time sample OK |
| chrony client → our server | 30 | time sample OK |
| our client → Cloudflare `time.cloudflare.com` | 15, 30 | time samples OK |

chrony as the server needs `chronyd -U` to bypass its root check; NTS-KE and
NTP both then work unprivileged.

## Known limitations

* The server reports the stratum from `--stratum` and does not run a clock
  discipline loop of its own. It is an NTS front end, not a time source; run
  it in front of a real reference or feed it a disciplined system clock.
* No persistence across restarts: cookies die with the process unless a master
  key is supplied out of band (`KeyRing::from_key`). A cluster can share a key
  this way, but nothing loads or saves it yet.
* Leap seconds are not handled specially; timestamps are plain NTP 32.32 fixed
  point over a UNIX-epoch clock.
* No root can mean the NTP port must be non-standard; pass `--ntp-port` so the
  server advertises what clients should use.
* Only AEAD 15 and 30 are implemented, which is the interoperable set in
  practice.

See [docs/nts-comparison-report.md](docs/nts-comparison-report.md) for measured offset and jitter, and for
what the numbers do and do not show.
