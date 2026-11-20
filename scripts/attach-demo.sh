#!/usr/bin/env bash
# Attach to a live service instance and report what is in its memory.
#
# This is the "production" use of the auditor: no instrumentation in the target,
# no cooperation from it, just the kernel's task interface. It is also the only
# honest way to check a third-party binary you cannot rebuild.
#
# macOS requires the target to be signed with com.apple.security.get-task-allow.
# The demo copies and signs a throwaway binary; the README explains why a real
# service would carry that entitlement only in staging.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/reports/attach.txt}"
cli="$root/target/release/memcanary-cli"
[ -x "$cli" ] || { echo "build first: cargo build --release --bins"; exit 1; }

work="$(mktemp -d)"
victim_pid=""
cleanup() {
  [ -n "$victim_pid" ] && kill "$victim_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

for mode in naive hardened; do
  cp "$cli" "$work/memcanary-$mode"
  if [ "$(uname)" = "Darwin" ]; then
    cat > "$work/ent.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
EOF
    codesign -s - --force --entitlements "$work/ent.plist" "$work/memcanary-$mode" 2>/dev/null || true
  fi
  echo "### scanning the $mode service" | tee -a "$out"
  "$work/memcanary-$mode" serve --mode "$mode" --seconds 30 --self-report \
    > "$work/$mode.out" 2>/dev/null &
  victim_pid=$!
  for _ in $(seq 1 50); do
    grep -q '^PID ' "$work/$mode.out" 2>/dev/null && break
    sleep 0.1
  done
  read -r _ pid < "$work/$mode.out"
  echo "target pid: $pid" | tee -a "$out"
  prot=()
  if grep -q '^PROTECTED ' "$work/$mode.out" 2>/dev/null; then
    grep '^PROTECTED ' "$work/$mode.out" > "$work/$mode.protected"
    prot=(--protected-file "$work/$mode.protected")
    echo "target declared $(wc -l < "$work/$mode.protected" | tr -d ' ') protected range(s)" | tee -a "$out"
  fi
  "$cli" scan --pid "$pid" --repeats 2 --interval-ms 100 ${prot[@]+"${prot[@]}"} 2>&1 | tee -a "$out" || true
  kill "$victim_pid" 2>/dev/null || true
  victim_pid=""
  echo | tee -a "$out"
done

echo "wrote $out"
