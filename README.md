# secretmem + memcanary

A Rust library for sensitive values that must not survive their use, and the tool
that proves they don't.

The starting point was a real finding: a memory dump of one of our services
contained the database password and live session keys in clear. The values had
been used and dropped, but "dropped" in Rust means *freed*, not *cleared* — the
bytes sat in the allocator, in stack frames, and in copies nobody tracked, until
the next allocation reused them.

Two pieces:

* **`secretmem`** — containers for passwords, keys and tokens. Guarded pages,
  wired into RAM, wiped on every exit path including the ones that don't unwind.
* **`memcanary`** — an auditor that walks the process's address space and looks
  for the bytes. It is the reason the claims in this repository mean anything.

```
crates/secretmem      containers + process hardening
crates/memcanary      memory scanner, needle fingerprints, reports
crates/demo-service   an auth service in naive and hardened form, with a CLI
docs/MEMORY-MODEL.md  platform capabilities, exit paths, and the limits
scripts/demo.sh       runs everything and writes reports/
```

## Try it

```sh
./scripts/demo.sh          # tests, stage-by-stage audit, comparison, attach demo
```

or piece by piece:

```sh
cargo run --release -p demo-service --bin memcanary-cli -- audit --mode hardened
cargo run --release -p demo-service --bin memcanary-cli -- audit --mode naive
cargo run --release -p demo-service --bin memcanary-cli -- compare
cargo run --release -p demo-service --bin memcanary-cli -- scan --pid <pid>
```

`audit` exits non-zero when a hardened run leaves residue, so it works as a CI
gate.

## The result

Same request flow, same crypto, same binary layout; the only difference is where
the values live. Each row is a scan of the whole address space at that lifecycle
stage.

| stage | naive | hardened |
|---|---|---|
| loaded | db-password, session-key, user-password | clean (2 inside containers) |
| login-in-flight | db-password, session-key, user-password | clean (3 inside containers) |
| login-settled | db-password, session-key | clean (2 inside containers) |
| token-verified | db-password, session-key | clean (2 inside containers) |
| shutdown | db-password, session-key | clean (2 inside containers) |

"clean (N inside containers)" means the value *is* present — the service needs it
— but inside a range that will be wiped, and the auditor says so instead of
hiding it. A hit outside a container is a leak; a hit inside one is the design
working.

Attaching from outside (`scan --pid`) gives the same verdict: 8 leaks in the
naive process, 0 in the hardened one.

## Using the containers

```rust
use secretmem::{harden_process, HardeningOptions, SecretKey, SecretString};

// Once, at startup, before any secret exists.
let report = harden_process(HardeningOptions::default())?;
assert!(report.is_complete(), "some leak paths remain: {report:?}");

// A password from the wire.
let mut pw = SecretString::from_str(request.password)?;
if verify(user.salt, user.verifier.expose(), pw.expose()) { /* ... */ }
pw.wipe();                      // or just drop; both wipe

// A key derived from a seed without ever landing on the stack.
let key: SecretKey<32> = secretmem::derive_key(master_seed, &[b"session"])?;
let token = sign(key.expose(), claims);
```

What you get:

* no `Clone`, no `Display`, redacting `Debug` — a copy is an explicit,
  tracked act (`duplicate()`), and `{:?}` in a log prints `redacted`;
* growth moves the bytes into a new mapping and wipes the old one, so a
  reallocation never leaves a readable prefix;
* guard pages on both sides, so an overrun faults immediately on the offending
  thread instead of corrupting the allocator;
* pages wired with `mlock` — never in swap;
* `fork()` isolation: on macOS a child process cannot even see the range; on
  Linux it sees zeroes;
* a fatal-signal handler that wipes registered ranges and then lets the process
  die *from* the original signal, so crash reporting is unaffected;
* core dumps disabled for the process, or the range excluded per-platform.

## Verifying your own code

The auditor finds values, not patterns, so it must know what to look for. It
never holds the secret: each registered value is expanded into its encodings
(raw, hex, base64, url-encoded, sha256) inside protected memory, reduced to a
keyed digest, and the derivations wiped.

```rust
use memcanary::{Auditor, Needle};

let mut auditor = Auditor::new()?;
auditor.watch(Needle::label("db-password").from_bytes(db_password)?);

{
    let secret = do_something_naive();   // the code under test
    let report = auditor.checkpoint("after-request")?;
    assert!(report.is_clean(), "{}", report.findings_markdown());
}
```

Two properties make a clean result trustworthy:

* **The instrument is proven to work.** A dedicated test keeps a live copy and
  requires the auditor to find it. If that ever fails, every clean result is
  meaningless, and the suite says so loudly.
* **The instrument does not excuse itself.** A hit inside a container is
  classified `protected` and allowed; a hit anywhere else is a leak. A separate
  test holds the same value in both places and requires the classifier to get it
  right, so "everything came back clean" cannot be caused by a classifier that
  quietly labels everything protected.

Each scan also reports where a hit lives — heap, stack, file-backed, or inside a
container — because the remedy differs. A `file-backed` hit is almost always a
secret compiled into the binary, which no runtime library can fix.

## What it cannot do

Read `docs/MEMORY-MODEL.md` for the full list and the evidence. The short
version:

1. **A `const` or literal secret is already in the binary.** Derive at runtime.
2. **Your own buffer is yours to wipe.** `from_slice` copies; it does not clean
   the argument.
3. **Derivation intermediates live in the derivation's frame.** `sha2` 0.10 has
   no `Zeroize`. Use `secretmem::derive_key`, or wipe your own frames.
4. **Once the value leaves the container it is gone from the guarantee.** Find
   those boundaries and make them small; the demo marks one.

## Platforms

macOS and Linux have real backends. Anything else gets a portable fallback that
still zeroizes but has no guard pages, no locking and no fork isolation;
`secretmem::capabilities()` says which you have, rather than leaving you to
assume.

The platform behaviour in `docs/MEMORY-MODEL.md` was measured, not assumed —
including the two facts that shaped the design: macOS has no `MADV_DONTDUMP` or
`MADV_WIPEONFORK`, and `task_for_pid` is refused unless the target carries
`com.apple.security.get-task-allow`.
