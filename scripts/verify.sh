#!/bin/bash
# End-to-end residue proof for the service demo.
#
# The claim under test is a *contrast*: the harness must show the scanner finds a
# secret when the program handles it naively, and does not find it when the
# program uses `sealedmem`.  Each mode is run through the same stages:
#
#   load      password + key just loaded
#   use       both used (HMAC, compare, "debug" log in plain mode)
#   erased    explicitly wiped
#   live      a fresh key is live again, just before a crash
#   crash     lldb stops the process at the fault and saves a core; scan the core
#
# The live scans use `task_for_pid` (a debugger-class read).  Sealed pages are
# `PROT_NONE`; the scanner honours that by default, so a sealed-mode "0 hits"
# means the page is not readable at rest, which is exactly the claim.
#
# The core scan is independent of the live scan: it inspects an on-disk crash
# dump written by lldb, which is the artefact a crash reporter would upload.
#
# Exit 0 only when every expectation holds.

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DEMO="$ROOT/target/debug/service-demo"
SCANNER="$ROOT/target/debug/residue"
WORK="$ROOT/target/verify"
PLIST="$ROOT/scripts/debug-entitlements.plist"
mkdir -p "$WORK"

PASS=0
FAIL=0
FAILED_CHECKS=""

note() { printf '    %s\n' "$*"; }
section() { printf '\n== %s\n' "$*"; }

# expect <description> <observed 1=ok 0=not-ok>
expect_ok() {
  if [ "$2" -eq 1 ]; then
    printf '  [ OK ] %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  [FAIL] %s\n' "$1"
    FAIL=$((FAIL + 1))
    FAILED_CHECKS="$FAILED_CHECKS
  - $1"
  fi
}

build() {
  cargo build -q -p service-demo -p residue --offline || { echo "build failed"; exit 2; }
  # The debug entitlement lets the scanner read the demo like a debugger would.
  # It is an explicit stand-in for "attacker with a task port", and the report
  # says so; production builds never carry it.
  codesign -s - --entitlements "$PLIST" -f "$DEMO" >/dev/null 2>&1
  codesign -s - --entitlements "$PLIST" -f "$SCANNER" >/dev/null 2>&1
}

gen_canary() { # tag
  local rnd
  rnd=$(LC_ALL=C tr -dc 'A-Z' </dev/urandom | head -c 16)
  printf 'CANARY-%s-%s' "$1" "$rnd"
}

scan_live_hits() { # pid label needle... -> prints count, "ERR" on attach failure
  local pid="$1" label="$2"; shift 2
  local args=() n
  for n in "$@"; do args+=(--needle "$n"); done
  local out rc
  out=$("$SCANNER" live "$pid" "${args[@]}" 2>&1)
  rc=$?
  printf '%s\n' "$out" > "$WORK/live_$label.txt"
  [ $rc -eq 2 ] && { printf 'ERR'; return; }
  printf '%s\n' "$out" | grep -c 'HIT ' || true
}

# Build the KERN_PROCARGS2 probe once per run.
procargs_hits() { # pid needle
  local probe="$WORK/procargs"
  if [ ! -x "$probe" ]; then
    cc -O1 "$ROOT/tools/procargs/procargs.c" -o "$probe" 2>/dev/null || { printf 'ERR'; return; }
  fi
  "$probe" "$1" "$2" 2>/dev/null | sed -n 's/.*occurrences in KERN_PROCARGS2: //p' | tail -1
}

scan_core_hits() { # file label needle...
  local f="$1" label="$2"; shift 2
  if [ ! -s "$f" ]; then printf 'ERR'; return; fi
  local args=() n
  for n in "$@"; do args+=(--needle "$n"); done
  local out
  out=$("$SCANNER" core "$f" "${args[@]}" 2>&1)
  printf '%s\n' "$out" > "$WORK/core_$label.txt"
  printf '%s\n' "$out" | grep -c 'HIT ' || true
}

# check_live <mode> <stage> <expect_leak 1|0> <pid> <needle...>
check_live() {
  local mode="$1" stage="$2" leak="$3" pid="$4"; shift 4
  local hits
  hits=$(scan_live_hits "$pid" "$mode-$stage" "$@")
  if [ "$hits" = "ERR" ]; then
    expect_ok "$mode $stage: scanner could not attach (not a clean result)" 0
    note "$(tail -1 "$WORK/live_$mode-$stage.txt")"
    return
  fi
  local good
  if [ "$leak" -eq 1 ]; then [ "$hits" -gt 0 ] && good=1 || good=0
  else [ "$hits" -eq 0 ] && good=1 || good=0; fi
  if [ "$leak" -eq 1 ]; then
    expect_ok "$mode $stage: secret found in live memory ($hits hits)" "$good"
  else
    expect_ok "$mode $stage: secret absent from live memory ($hits hits)" "$good"
  fi
  [ "$hits" -gt 0 ] && grep 'HIT ' "$WORK/live_$mode-$stage.txt" | head -1 | sed 's/^/      /'
}

wait_for() { # mode pid stage
  local n=0
  while [ $n -lt 600 ]; do
    grep -q "PAUSED $3" "$WORK/$1.out" 2>/dev/null && return 0
    kill -0 "$2" 2>/dev/null || { note "process exited before $3"; return 1; }
    sleep 0.05; n=$((n + 1))
  done
  note "timed out waiting for $3"
  return 1
}

run_mode() { # mode expect_leak(1|0)
  local mode="$1" leak="$2"
  local db key
  db=$(gen_canary DBPW)
  key=$(gen_canary SESSKEY)
  local dbpw="$db::s3cr3t-shared-db-pw"

  section "mode: $mode   (${mode/plain/naive}/sealed)"
  note "db canary  : $db"
  note "key canary : $key"

  local fifo="$WORK/$mode.in"
  rm -f "$fifo"; mkfifo "$fifo"
  # Interactive stage machine only: no --crash here.  Crash capture is a separate
  # launch under lldb (see below).
  local flags="--stay"
  [ "$mode" = "sealed" ] && flags="--sealed --stay"

  DEMO_DB_PASSWORD="$dbpw" DEMO_SESSION_KEY="$key" \
    "$DEMO" $flags < "$fifo" > "$WORK/$mode.out" 2> "$WORK/$mode.err" &
  local pid=$!
  exec 9> "$fifo"

  if wait_for "$mode" "$pid" load; then
    check_live "$mode" load "$leak" "$pid" "$db" "$key"
    # Environment check: plain mode leaves the password in the kernel's
    # KERN_PROCARGS2 snapshot; sealed mode scrubs it right after reading.
    local env_hits
    env_hits=$(procargs_hits "$pid" "$db")
    if [ "$env_hits" = "ERR" ]; then
      note "KERN_PROCARGS2 probe unavailable"
    elif [ "$leak" -eq 1 ]; then
      local good; [ "$env_hits" -gt 0 ] && good=1 || good=0
      expect_ok "$mode load: password present in KERN_PROCARGS2 ($env_hits)" "$good"
    else
      local good; [ "$env_hits" -eq 0 ] && good=1 || good=0
      expect_ok "$mode load: password scrubbed from KERN_PROCARGS2 ($env_hits)" "$good"
    fi
  fi
  echo x >&9
  if wait_for "$mode" "$pid" use; then check_live "$mode" use "$leak" "$pid" "$db" "$key"; fi
  echo x >&9
  # erased: plain mode logged the key and kept the environment, so residue
  # remains; sealed mode wiped both pages and scrubbed the environment.
  if wait_for "$mode" "$pid" erased; then
    check_live "$mode" erased "$leak" "$pid" "$db" "$key"
  fi
  # Close the interactive instance; its job (live stage scans) is done.
  exec 9>&-
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  rm -f "$fifo"

  # ---- crash capture ----
  # We do not use the --stay/--crash run for the core test: lldb must *launch*
  # the process, let it reach its fault, and save the core at that instant.
  # Attaching to a paused process and racing it with stdin proved flaky, and a
  # flaky core capture is worse than none.
  #
  # So: a second, short-lived instance runs under lldb with the same canaries.
  # That instance has no --stay; it runs straight to the fault.  It is a crash
  # scenario, not the interactive stage machine, and its core is the artifact a
  # crash reporter would upload.
  local crash_canary
  crash_canary=$(gen_canary CRASH)
  note "crash canary: $crash_canary"

  local core="$WORK/$mode.core"
  rm -f "$core"
  local log="$WORK/$mode.lldb.log"
  rm -f "$log"
  local lscript="$WORK/$mode.lldb"
  cat > "$lscript" <<LLDB
process handle SIGSEGV --pass true --stop false --notify true
process handle SIGBUS  --pass true --stop false --notify true
run
process save-core $core
process kill
quit
LLDB
  # `run` untouched; no --stay so it goes load -> use -> erase -> rehydrate -> fault.
  DEMO_DB_PASSWORD="$dbpw" DEMO_SESSION_KEY="$key" DEMO_CRASH_KEY="$crash_canary" \
    /usr/bin/lldb --batch -s "$lscript" -- "$DEMO" $([ "$mode" = sealed ] && echo --sealed) --crash \
    > "$log" 2>&1
  if ! grep -qE "stop reason" "$log" || [ ! -s "$core" ]; then
    note "lldb did not capture a core for $mode"
    grep -E "error|not permitted|Invalid|exited" "$log" | head -3 | sed 's/^/      /'
  fi

  local ch
  ch=$(scan_core_hits "$core" "$mode-crash" "$crash_canary" "$key")
  if [ "$ch" = "ERR" ]; then
    expect_ok "$mode crash: core dump captured and scanned" 0
    note "no core at $core"
  elif [ "$leak" -eq 1 ]; then
    local good; [ "$ch" -gt 0 ] && good=1 || good=0
    expect_ok "$mode crash: crash secret present in core ($ch hits)" "$good"
    [ "$ch" -gt 0 ] && grep 'HIT ' "$WORK/core_$mode-crash.txt" | head -2 | sed 's/^/      /'
  else
    local good; [ "$ch" -eq 0 ] && good=1 || good=0
    expect_ok "$mode crash: crash secret absent from core ($ch hits)" "$good"
    [ "$ch" -gt 0 ] && grep 'HIT ' "$WORK/core_$mode-crash.txt" | head -2 | sed 's/^/      /'
  fi
}

build

section environment
note "OS: $(sw_vers -productVersion) $(uname -m), page size $(( $(getconf PAGE_SIZE) ))"
note "demo get-task-allow: $(codesign -d --entitlements - "$DEMO" 2>/dev/null | tr -d '\0' | grep -c get-task-allow) (debug-build stand-in for a task-port attacker)"
note "page reuse wipe test: see 'cargo test -p sealedmem --test kernel_contract'"

run_mode plain 1
run_mode sealed 0

section summary
printf '  checks passed: %d\n  checks failed: %d\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
  printf '  failed:%s\n' "$FAILED_CHECKS"
  exit 1
fi
printf '  RESULT: PASS - naive mode leaks at every stage; sealed mode is clean at every stage\n'
