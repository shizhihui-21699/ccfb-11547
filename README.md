# sealedmem

Secrets that are wiped on every exit path, never paged out, never inherited by a
child process, and not present in a crash dump.

Built after finding a database password and a session key verbatim in a service's
memory dump. Three copies existed — the parsed `String`, the environment, and the
crash dump — and none of them had been cleaned up. This crate closes those
paths, and `scripts/verify.sh` proves it with a scanner that reads the process
from outside, before and after.

```
crate:    crates/sealedmem   the library
tool:     crates/residue     scan a live process or a Mach-O core for canaries
demo:     examples/service-demo   a naive auth service vs the sealed version
proof:    scripts/verify.sh  runs both modes and scans at every stage
docs:     docs/THREAT-MODEL.md, docs/PLATFORM-NOTES.md
```

## Quick start

```rust
use sealedmem::{SealedString, SealedBytes};

// Prefer reading straight into the page so no String/Vec copy exists.
let password = SealedString::from_env("DB_PASSWORD")?.expect("set by supervisor");
sealedmem::scrub::scrub_env_var("DB_PASSWORD"); // drop libc's + the kernel's copy

password.with_str(|p| { /* use it for the duration of this closure only */ });
assert!(password.eq_ct("expected"));        // constant-time

let key = SealedBytes::from_callback(64, |dst| {
    dst[..32].copy_from_slice(&raw);        // raw is your caller's input copy
    32
})?;

// Wipe now, or let Drop do it.  Both use the same sequence.
password.wipe();
```

`SealedString`/`SealedBytes` are not `Clone`, not `Copy`, not `Display`, not
`Serialize`, and not `Sync`. Reading requires a scoped closure so every copy site
is visible. `duplicate()` is explicit and allocates a second independent page.

## What is guaranteed, and how

| Promise | Mechanism |
|---|---|
| never swapped out | `mlock` |
| not in a core dump / crash report | `PROT_NONE` at rest (measured: present in a 5.5 GB `--style full` core in naive mode, absent in sealed mode) |
| not inherited by `fork` | `mach_vm_inherit(VM_INHERIT_NONE)` + `pthread_atfork` child hook |
| no residue on page reuse | volatile overwrite → `MADV_ZERO` → `MADV_ZERO_WIRED_PAGES` → `munlock` → `munmap` |
| no copies on copy/clone/grow/format | no `Clone`/`Copy`/`Display`; growth reallocates into a new sealed page and wipes the old; explicit `duplicate()` |
| wiped on every reachable exit | `Drop`, `atexit` sweeper, fatal-signal handler (wipes, restores default, re-raises), opt-in termination signals |

Not guaranteed: a live attacker holding a task port can lift `PROT_NONE` and read
the page. See `docs/THREAT-MODEL.md` § "Observers we defend against" — this
limitation is demonstrated by `residue live --include-sealed` rather than hidden.

## Run the proof

```sh
cargo test --workspace            # kernel-contract + exit-path + page-reuse tests
./scripts/verify.sh               # end-to-end contrast, exits 0 only if it holds
```

`verify.sh` prints one line per (mode, stage). The claim it verifies is a
*contrast*, so both halves must hold:

```
== mode: plain
  [ OK ] plain load:    secret found in live memory (4 hits)
  [ OK ] plain use:     secret found in live memory (4 hits)
  [ OK ] plain erased:  secret found in live memory (2 hits)
  [ OK ] plain crash:   crash secret present in core (3 hits)
== mode: sealed
  [ OK ] sealed load:   secret absent from live memory (0 hits)
  [ OK ] sealed use:    secret absent from live memory (0 hits)
  [ OK ] sealed erased: secret absent from live memory (0 hits)
  [ OK ] sealed crash:  crash secret absent from core (0 hits)
  checks passed: 8   checks failed: 0
```

Stages: *load* (secret just read), *use* (HMAC + compare; plain mode also
"debug logs" it), *erased* (explicit wipe), *crash* (lldb launches the process,
lets it fault, and saves a core while lldb has the crash stopped). Live scans use
`task_for_pid` from a different process, i.e. a debugger's-eye view.

## The demo, concretely

`examples/service-demo` models an auth service that loads a database password and
a session key.

* `--stay` pauses at each stage so the scanner can look; `sealed` reads the env
  by pointer and scrubs it immediately, naive mode copies it into a `String` and
  keeps it in `environ`.
* Naive mode logs the session key with `format!` (a real pattern, and the copy
  that survives the "wipe" stage).
* Sealed mode prints the kernel's own view of each region:
  `sealed=true wired=true inherit=2`.
* `--crash` (used under lldb) holds a fresh key live and faults; naive mode's
  heap copy lands in the core, sealed mode's page does not.

## The scanner

```
residue live <pid> --needle S [--needle S] [--include-sealed] [--scan-readonly]
residue core <file> --needle S
```

* `live` walks `vm_region_recurse` and reads writable regions (and, with
  `--include-sealed`, `PROT_NONE` regions after lifting them with
  `mach_vm_protect`, reproducing the task-port attack). Read-only regions are
  skipped unless `--scan-readonly`; a secret can only be in memory the process can
  write.
* `core` parses `LC_SEGMENT_64` commands and scans each segment, reporting the
  virtual address of every hit.
* Exit status: 0 clean, 1 residue found, 2 error. An attach failure is an error,
  never a pass.

## Limits worth reading before adoption

* `Sync` is intentionally absent; a scoped view unseals the page.
* Feeding a `String` into `from_utf8` leaves that `String` on the heap. Use
  `from_env`/`from_callback` at trust boundaries.
* A debugger stopped at the fault *before* the handler runs sees pre-wipe memory;
  the protection there is `PROT_NONE`, not the handler.
* This is macOS-first. On other platforms the Mach mechanisms degrade to
  wipe-on-drop + `mlock`, and `diag::mach_available()` reports it.
