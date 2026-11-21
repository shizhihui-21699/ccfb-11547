# Platform notes (macOS 26.5.1, arm64)

Every claim in this repository was measured on the machine below. This file
records the measurements that shaped the design, including the ones that
contradicted the obvious approach. Dates: 2026-11-21.

```
Darwin 25.5.0 arm64 (Apple silicon), macOS 26.5.1, rustc 1.99.1, lldb-2100
page size 16384
ulimit -l unlimited, RLIMIT_CORE 0, kern.corefile /cores/core.%P
```

## 1. `mlock` does not keep a secret out of a core dump

A wired, readable (`PROT_READ|PROT_WRITE`) anonymous mapping **is** included in
`lldb process save-core`. Canary bytes were found in the resulting 851 KB core.

Consequence: wiring is for swap, not for dumps. Something else has to hide the
page from the core writer.

## 2. `PROT_NONE` does keep a secret out of a core dump

Same test with the data page `mprotect(PROT_NONE)`:

* default `save-core`: canary absent;
* `--style full` (5.5 GB, all process memory): canary absent;
* a 5.5 GB `--style full` core of the sealed demo: **0 hits**, while the same
  core of the naive demo contains the secret.

The core writer collects readable/dirty pages; a `PROT_NONE` page is neither.
This is the empirical basis for sealing at rest and is the single most important
result here.

## 3. `madvise` semantics that tripped us up

* `MADV_ZERO_WIRED_PAGES` (6) **does not zero a live mapping.** After the call,
  reading the page still returns the secret; the kernel zeroes it only when the
  mapping is deleted (`munmap`). It also returns `EINVAL` while the range is
  `PROT_NONE`.
* `MADV_ZERO` (11) **does** zero in place, including wired pages, and returns
  `EINVAL` on a `PROT_NONE` range.
* Therefore the wipe sequence must unseal first, overwrite with volatile stores,
  then call both `madvise` variants, then `munlock` and `munmap` (which is where
  `MADV_ZERO_WIRED_PAGES` actually takes effect).
* `MADV_DONTNEED` does **not** zero a mapped anonymous page on this version; the
  data was still readable afterwards. Do not use it as a wipe.

## 4. `VM_INHERIT_NONE` removes the mapping from the child

`mach_vm_inherit(mach_task_self(), addr, len, VM_INHERIT_NONE)` then `fork()`:
the child faults (`SIGSEGV`) on the address. The parent's registry array is copied
by `fork`, but the addresses in it are invalid in the child, which is why the
library registers a `pthread_atfork` child hook that marks every slot dead.
Without it, a child that crashed would run the wipe handler on unmapped addresses
and fault recursively.

## 5. A task port defeats `PROT_NONE`

Given `com.apple.security.get-task-allow` on the target (which ad-hoc-signed
debug builds carry), a sibling process can:

1. `task_for_pid(pid)` → success,
2. `mach_vm_read_overwrite` on the sealed page → `KERN_INVALID_ADDRESS`,
3. `mach_vm_protect(task, page, len, 0, VM_PROT_READ|VM_PROT_WRITE)` → success,
4. `mach_vm_read_overwrite` again → the secret.

`residue live --include-sealed` performs exactly this and finds the canary. This is
why the library never claims to stop a live attacker and why production builds
must not carry `get-task-allow`. Verified by `scripts/verify.sh`'s sibling scan:
in default mode the two sealed regions are listed (`prot=0 wired=true inherit=2`)
and produce **0 hits**.

## 6. Environment and argv

`sysctl(KERN_PROCARGS2)` returns a kernel-owned copy of `argv`/`environ` to any
same-uid process. A secret placed in the environment was visible there (2 hits)
before the scrub and gone after (`scrub_env_var` zeroes libc's copy and `unsetenv`s
the variable; the kernel snapshot follows the process's own storage). `scrub_argv`
does the same for `argv`, but `ps` still shows arguments for the whole window
before the scrub, so arguments remain an unsafe channel.

## 7. `ptrace(PT_DENY_ATTACH)` is not an anti-debug guarantee

It blocked `task_for_pid` of that process, but `lldb -p` still attached. Not used.

## 8. Debuggers stop at the fault before handlers run

With `process handle SIGSEGV --stop true`, lldb stops at `EXC_BAD_ACCESS` and has
not yet let the signal handler run. A core saved at that point reflects the page
contents *before* the wipe. This is why the demo's crash test relies on
`PROT_NONE`, and why the verification harness runs the crash under lldb with the
signal passed through (`--pass true --stop false`) and saves the core after the
handler has wiped and the process has died.

## 9. `mlock` limits

`mlock` succeeded for 1 GiB with `ulimit -l unlimited` (the default on this
machine). The library treats `mlock` failure as a hard error rather than ignoring
it: a page that might be paged out is a security failure worth surfacing.

## 10. RustCrypto zeroize coverage

The offline cargo cache has `sha2` 0.10.9 and 0.11.1, `hmac` 0.12.1 and 0.13.0.
Only the 0.11-era `digest` has a `zeroize` feature, which the demo enables:
`sha2 = { version = "0.11", features = ["zeroize"] }`. The 0.10-era crates leave
HMAC pad buffers and hash state unzeroized on drop, so do not use them for
keyed material. `hmac::Hmac::new_from_slice` still materialises a temporary
`Block<D>`; the demo keeps the *key* inside a sealed page and only hands it to
HMAC inside a scoped view, so the temporary pad buffer is the HMAC inner/outer
key state (which the `zeroize` feature does wipe on drop), not the raw secret.

## 11. Page reuse

Tiling a 256 MB page range with a canary, wiping via the library, `munmap`ping,
then re-mapping and re-scanning found **0** canary hits. A naive `munmap` without
the wipe is not guaranteed to leave nothing (this machine's allocator did zero the
fresh mapping, but that is an allocator property, not a security property; the
library does not rely on it).
