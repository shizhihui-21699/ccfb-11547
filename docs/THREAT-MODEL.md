# Threat model

This document is the contract `sealedmem` makes. Read it before trusting the
library with a value that matters.

## The incident this came from

A service's memory was dumped and a database password and a session key were
found in it verbatim. Nothing had gone wrong with the *logic*; the values had
simply outlived their use. Three copies existed:

* the `String` the password was parsed into,
* the copy the environment held (visible to anyone with the same uid),
* the copy the crash dump captured.

The library attacks exactly those three, plus the exit paths and the reallocation
path that leak the fourth and fifth copies.

## Observers we defend against

| Observer | What they get | Does `sealedmem` help? |
|---|---|---|
| A crash dump / core file written by the OS or a debugger (`lldb process save-core`, `--style full` included) | the process's readable memory plus the crash frame | **Yes.** Secrets at rest are in `PROT_NONE` pages, and a `PROT_NONE` page is absent from the core. Verified: a 5.5 GB `--style full` core contains zero hits in sealed mode, while naive mode's core contains the secret. |
| A swap file (`vm.swapusage` / a slept laptop's encrypted swap) | pages evicted by the pager | **Yes.** The pages are `mlock`ed, so the pager never considers them. |
| A `fork(2)` child of the service | its inherited address space | **Yes.** The mapping is `VM_INHERIT_NONE`; the child has an unmapped hole and faults on access. A `pthread_atfork` child hook also marks the inherited registry dead so a child crash handler cannot dereference dangling addresses. |
| A later allocation that recycles the freed physical pages | whatever the allocator hands out | **Yes.** Wipe is a volatile byte overwrite followed by `madvise(MADV_ZERO)` and `madvise(MADV_ZERO_WIRED_PAGES)`; the pages are zeroed *before* `munmap`, so a subsequent mapping starts blank. Tested by tiling a page range with a canary, wiping, and re-scanning. |
| `KERN_PROCARGS2` (the kernel's argv/env snapshot, readable by same-uid processes) | the environment and command line the service was started with | **Only if you act.** The demo's sealed mode reads the environment by pointer and calls `scrub_env_var`, which zeroes libc's copy and the kernel snapshot. There is still a window between `execve` and the scrub; see `docs/PLATFORM-NOTES.md`. |
| A **different process holding a task port** (`task_for_pid`, i.e. `ptrace` class) | it can `mach_vm_protect` the sealed page and read it | **No.** This is the important honest limitation. Verified: `residue live --include-sealed` reads the canary out of a sealed page. `PROT_NONE` stops a *dump writer*, not an attacker who can change the page's protection. Remove `com.apple.security.get-task-allow` from production builds; without it `task_for_pid` is refused. |
| A same-uid process reading `ps` | the command line | **Never** safe for a secret, with or without this library. Do not pass secrets as arguments. |
| Someone with root | everything | No userspace technique helps. |

## What the library itself does not do

* It does not stop the compiler from keeping a copy of the **input** you gave it.
  If you do `let p = std::env::var("X")?; SealedString::from_utf8(p.as_bytes())`,
  the `String` is still on the heap. Use `SealedString::from_env` (sealed mode in
  the demo) or `from_callback` (write straight into the page).
* It does not cover every allocation in your program. It covers the bytes it
  owns. A format string, a `println!`, a telemetry envelope, or a `Clone` you
  wrote yourself are your responsibility. That is why the type has no
  `Display`, no `Serialize`, no `Copy`, and no `AsRef`.
* It does not provide `Sync`. A scoped view unseals the page, so two threads
  reading at once would race the seal. Keep the container per-task or behind a
  lock *you* control, and keep the view short.
* It does not defend against a compromised allocator, a hypervisor-level debug,
  or a signal handler that some other component installed over ours.
* It does not make the process un-debuggable. `ptrace(PT_DENY_ATTACH)` blocks
  `task_for_pid` of that process in some configurations, but it did **not** stop
  `lldb -p` on this machine, and pretending otherwise would be security theatre.

## The four mechanisms, and why each is there

1. **`mlock`** — keeps the pages out of swap. Without it, "wiped in memory" can be
   contradicted by a page the kernel wrote to disk first.
2. **`mprotect(PROT_NONE)` at rest** — the only mechanism found that actually
   keeps a secret out of a core dump on this platform. `mlock` alone does **not**:
   a wired, readable page is still written to the core. This was measured, not
   assumed; see `docs/PLATFORM-NOTES.md`.
3. **`mach_vm_inherit(VM_INHERIT_NONE)`** — stops `fork` duplication. On non-Mach
   platforms the library degrades to wipe-on-drop and says so.
4. **Volatile overwrite + `MADV_ZERO` + `MADV_ZERO_WIRED_PAGES` + `munlock` +
   `munmap`** — the wipe. Ordering matters: `MADV_ZERO_WIRED_PAGES` only marks
   wired pages for zeroing when the mapping is deleted, it does not zero a live
   mapping, and it is refused while the page is `PROT_NONE`. The volatile
   overwrite is the step that survives if anything else is refused.

## Exit paths

| Path | Covered by | When it does not run |
|---|---|---|
| normal return, `?`, panic, unwind | `Drop` | — |
| `std::process::exit` | `atexit` sweeper | if the process is SIGKILLed |
| `SIGSEGV`/`SIGBUS`/`SIGABRT`/`SIGILL`/`SIGFPE`/`SIGTRAP` | fatal-signal handler (wipes, restores `SIG_DFL`, re-raises) | if a debugger stops on the signal and never resumes, or another component replaced our handler |
| `SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT` (opt-in via `install_termination`) | same handler, then re-raise | — |
| `SIGKILL`, power loss, kernel panic | nothing | unavoidable |
| `fork` child | `pthread_atfork` child hook marks the registry dead | — |

The debugger caveat is real and was observed: `lldb` with a `stop true` signal
disposition stops at the fault *before* the handler runs, so a core written at
that instant sees whatever the page held. `sealedmem`'s protection against that is
mechanism 2 (`PROT_NONE`), not the handler. The handler is a second line of
defence for the case where the debugger resumes and the process dies normally.

## How the claim is checked

`scripts/verify.sh` runs the demo twice — naive handling and `sealedmem` — and
scans a **different process's** view of it with `task_for_pid` at four stages,
then scans a core written at the crash. It passes only when the naive run leaks at
every stage and the sealed run is clean at every stage. The scanner has a
`--include-sealed` mode that reproduces the task-port attack, so the limitation
above is demonstrated rather than buried.

`cargo test` covers the kernel-level contract independently: sealed/wired/
not-inherited state read back from Mach, a direct read of a sealed page dying by
SIGSEGV, a `fork` child faulting on the parent's secret, and the page-reuse wipe.
