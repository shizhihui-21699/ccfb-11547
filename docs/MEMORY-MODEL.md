# Memory model and platform capabilities

This document records what the library relies on, what the OS actually provides,
and — importantly — where the guarantees stop. Every claim here was checked on
the machine described below; the probes that established them are summarised so
you can re-run them on your target.

Checked on: macOS 26.5.1 (build 25F80), Apple silicon (arm64), Rust 1.99.1.

## The address-space view

One `SecretBytes` / `SecretKey<N>` owns one mapping:

```
        low address                                    high address
        ┌──────────┬──────────────────────┬──────────┐
        │  guard   │       usable         │  guard   │
        │ PROT_NONE│   PROT_READ|WRITE    │ PROT_NONE│
        └──────────┴──────────────────────┴──────────┘
        ^          ^                                   ^
        │          │                                   │
      munmap     ptr                                 ptr+usable+page
```

* `usable` is rounded up to a whole number of **16384-byte** pages on Apple
  silicon. Hard-coding 4096 is wrong here; `sysconf(_SC_PAGESIZE)` is the only
  source.
* The guard pages turn a one-past-the-end write into an immediate `SIGSEGV` on
  the thread that did it, rather than silent corruption of the allocator.
* Because the usable range is its own VM entry, the per-entry calls
  (`mach_vm_inherit`, `mach_vm_behavior_set`) apply to exactly the secret and
  nothing else.

## Capabilities by platform

| Capability | macOS 26 / arm64 | Linux | Portable fallback |
|---|---|---|---|
| `mlock` (keep out of swap) | yes, unprivileged; `RLIMIT_MEMLOCK` is unlimited | yes; may need `ulimit -l` or `CAP_IPC_LOCK` | no |
| Verify residency (`mincore`) | yes | yes | no |
| Guard pages | yes | yes | no |
| Keep out of core dumps | process-wide `RLIMIT_CORE=0` | per-range `MADV_DONTDUMP` **and** `RLIMIT_CORE=0` | no |
| Keep out of forked children | `mach_vm_inherit(VM_INHERIT_NONE)` — the child has **no mapping** | `MADV_WIPEONFORK` — the child sees zeroes | no (registry wipe only) |
| Kernel scrubs pages on abnormal exit | `VM_BEHAVIOR_ZERO_WIRED_PAGES` | no | no |
| Non-elidable zeroing primitive | `memset_s` | `explicit_bzero` | volatile writes |
| Attach to another process | `task_for_pid`, **requires `get-task-allow`** | `ptrace`/`process_vm_readv`, subject to `yama/ptrace_scope` | no |

### Flags that do *not* exist on macOS

Checked against the SDK headers rather than assumed:

* `MAP_NOCORE` — absent. There is no per-mapping "exclude from core" flag, which
  is why dump exclusion is process-wide (`RLIMIT_CORE = 0`).
* `MADV_DONTDUMP` — absent (Linux has it).
* `MADV_WIPEONFORK` — absent (Linux 4.14+ has it).
* `explicit_bzero` — not exported; `memset_s` is the C11 Annex K equivalent.

### `user_wired_count` is not trustworthy

A natural way to recognise a `secretmem` range from *another* process would be
to look for wired pages in `vm_region` output. It does not work on this
platform: `vm_region_recurse` reports `user_wired_count == 0` even for a range
that `mlock` returned success on, and `inheritance` does not report
`VM_INHERIT_NONE` either. The auditor therefore does **not** infer "protected"
from mapping shape — see "External scanning" below.

## Exit paths

| Path | What runs | What is guaranteed |
|---|---|---|
| `Drop` (normal, including panic unwind) | `Region::drop` → wipe, unregister, `munlock`, `munmap` | zeroed before the pages are returned |
| growth / reallocation | copy to new region, wipe old, unmap old | no readable prefix left behind |
| `fork()` | `pthread_atfork` child handler wipes every range the child inherited; `VM_INHERIT_NONE` removes the rest entirely | on macOS the child cannot even fault the range into existence; on Linux it reads zeroes |
| fatal signal (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`, `SIGABRT`, `SIGSYS`, `SIGTRAP`) | `sigaction` handler: wipe all registered ranges, restore default, unblock, re-raise | the process still dies *from* the original signal (crash reporters see the right thing), but the secrets are zero first |
| `SIGKILL` / power loss | nothing runs | macOS: the kernel scrubs wired pages when the VM entry is destroyed (`VM_BEHAVIOR_ZERO_WIRED_PAGES`); other platforms: pages may contain data until reused — but they were never in swap and never in a core |

### Why the fatal-signal handler unblocks the signal

The first version called `signal(SIG_DFL)` then `raise(sig)`. The kernel blocks
the delivered signal for the duration of its handler, so `raise` merely queued
it and control fell through to `_exit(134)`. A crash reporter, a core-dump
policy and a supervisor all distinguish "exited 134" from "killed by signal 6".
The handler now unblocks the signal explicitly before re-raising. The
`crash_paths` test asserts the child dies from the signal, not with an exit code.

### Why the fork handler skips some ranges

`VM_INHERIT_NONE` means the child's address space does not contain the range at
all. The child still inherits the *registry* (it is plain memory), so a naive
`pthread_atfork` handler would `memset_s` an address that is not mapped — a
`SIGSEGV` inside the handler, which recursed into the fatal-signal handler and
hung the child. The registry therefore records, per range, whether the child
actually sees it, and the child handler skips the ones it does not. The
fatal-signal handler runs in the *owning* process, where every range exists, so
it wipes everything.

## What no library can do for you

These are the boundaries the auditor will expose if you cross them. They are not
bugs; they are the reason the verification tool matters.

1. **Values compiled into the binary.** A `const` or a literal secret is in the
   file's read-only data segment before `main` runs. It cannot be wiped, and the
   auditor will report it in a `file-backed` region at every stage. Derive
   secrets at runtime from a seed, or read them from the environment or a secret
   manager. (`demo_config` originally had this bug; it is now derived.)
2. **The caller's own buffer.** `from_slice` copies into protected memory but
   cannot wipe the argument — that memory belongs to the caller. If a `Vec<u8>`
   holding the plaintext stays alive, it will be found. This is why the demo
   builds hardened secrets *directly into containers* (`derive_key`,
   `SecretKey::from_fn`) instead of through a `Config` full of `Vec`s.
3. **Derivation intermediates.** `sha2` 0.10 does not implement `Zeroize`: a bare
   `Sha256` keeps the absorbed seed in its block buffer, and `finalize()` returns
   a stack `GenericArray`. A 32-byte key is exactly one SHA-256 digest, so that
   stack copy is a perfect match for the needle. `secretmem::derive_key` fixes it
   by keeping the hasher in protected memory; a hand-rolled derivation must wipe
   its own frames. The demo shows both — `derive_naive_into` leaks, `derive_key`
   does not.
4. **Anything after the value leaves the container.** Once you hand the plaintext
   to an untracked API (`to_string()`, a `Vec` for the connection pool, the
   network stack's send buffer), that copy is outside the guarantee. The right
   move is to minimise and bound that window, and to *know* where it is. The demo
   keeps one such boundary (`connection_string`) and marks it.

## External scanning

`memcanary::Auditor::for_pid` reads another process through the same kernel
interface a debugger uses (`task_for_pid` + `mach_vm_read_overwrite` on macOS,
`process_vm_readv` on Linux).

* On macOS the target must be signed with `com.apple.security.get-task-allow`.
  Without it, `task_for_pid` returns `KERN_FAILURE` and the auditor reports the
  exact remedy rather than a vague failure. A real service carries that
  entitlement in staging only, and never in production.
* The container registry is private to the owning process, and the mapping-shape
  signals do not work (see above). An external scan therefore classifies hits
  inside the target as `foreign` and *counts them as leaks* — conservative and
  over-reporting.
* To classify precisely, the target can publish its ranges
  (`secretmem::protected_ranges`, printed as `PROTECTED <start> <len>`), and the
  scanner declares them with `Auditor::declare_protected`. That is cooperation,
  not detection: a target that lies about its ranges defeats its own audit, which
  is worth remembering when the target is not yours.

## Verification methodology

A clean result is only evidence if the same instrument *does* find the bytes when
they are there. The tests are ordered accordingly:

* `auditor_detects_a_live_leak` keeps a plain `Vec` copy alive and requires a
  finding. If this ever passes silently, every other "clean" is meaningless.
* The provenance test holds the same value in a container *and* in a plain
  buffer in one process, and requires the classifier to label one `protected`
  and the other a leak — catching a classifier that has degenerated into calling
  everything protected.
* Each scenario runs in its own process. `cargo test` runs test functions as
  threads of one process, so a live leak in one test is visible to a scan in
  another; the first version of the suite failed for exactly that reason.
* Secrets are built at runtime, never from a `const`.

## Cost

* A container is at least three pages (two guards + one usable), so a 32-byte key
  costs 3 × 16 KiB = 48 KiB of address space on Apple silicon. That is the price
  of the guard pages; `mlock` is charged for the usable pages only.
* Wiping is one `memset_s` over the usable range, once on `Drop` and once more
  before unmap. For a handful of long-lived keys this is negligible; for
  per-request values at high rate, measure — a page-size allocation and two
  `mmap`/`munmap` pairs per request is not free.
* The registry is a fixed 4096-slot table of atomics. Creation fails with
  `RegistryFull` beyond that, which is far above the "handful of keys" this is
  designed for but worth knowing if you route every request through a container.
