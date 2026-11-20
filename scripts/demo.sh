#!/usr/bin/env bash
# End-to-end demonstration of the wipe guarantees and the evidence for them.
#
# Runs, in order:
#   1. unit + integration tests (the library's own assertions)
#   2. a stage-by-stage audit of the hardend service
#   3. the naive-vs-hardened side-by-side comparison
#   4. an external attach against a live process that is deliberately leaking
#   5. a fork test proving a child cannot read the parent's secret
#   6. a fatal-signal test proving the wipe runs before the process dies
#
# Everything writes under ./reports. Exit status is non-zero if any hardened run
# leaves residue, so this can be a CI gate.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

reports="$root/reports"
mkdir -p "$reports"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

say "build"
cargo build --release --bins 2>&1 | tail -3
cli="$root/target/release/memcanary-cli"

say "1/6 library and integration tests"
cargo test --release -q 2>&1 | tail -15

say "2/6 hardened service, stage by stage"
"$cli" audit --mode hardened \
  --markdown "$reports/audit-hardened.md" \
  --json "$reports/audit-hardened.json"

say "3/6 naive service, stage by stage"
set +e
"$cli" audit --mode naive \
  --markdown "$reports/audit-naive.md" \
  --json "$reports/audit-naive.json"
naive_status=$?
set -e
# The naive run is *expected* to fail its own gate; that is the point.
if [ "$naive_status" -eq 0 ]; then
  echo "note: naive run reported clean — the control did not leak, which makes the comparison weaker"
else
  echo "naive run reported residue, as expected (exit $naive_status)"
fi

say "4/6 side-by-side comparison"
"$cli" compare \
  --markdown "$reports/compare.md" \
  --json "$reports/compare.json"

say "5/6 external attach against a live, leaking process"
"$root/scripts/attach-demo.sh" "$reports/attach.txt" || {
  echo "external attach unavailable in this environment (see the message above); continuing"
}

say "6/6 fork and fatal-signal guarantees"
cargo test --release -q -p memcanary --test crash_paths 2>&1 | tail -8

say "reports written to $reports"
ls -1 "$reports"
