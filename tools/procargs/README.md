# procargs

A tiny helper that reads `sysctl(KERN_PROCARGS2)` for a pid and reports the
number of occurrences of a string in the kernel's argv/environment snapshot.
Used by `scripts/verify.sh` to prove that `sealedmem`'s environment scrub removes
the secret from that snapshot, and that naive handling leaves it there.

Build: `cc -O1 procargs.c -o /usr/local/bin/...` is not assumed; the verify
script compiles it into `target/verify/` on demand.
