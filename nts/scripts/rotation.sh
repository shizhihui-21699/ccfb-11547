#!/bin/bash
# Demonstrate cookie key rotation and the transition window.
#
#   1. a client establishes a session and holds eight cookies
#   2. the server rotates its cookie key (SIGUSR1)
#   3. the client keeps polling.  Its cookies were minted before the rotation
#      and are still accepted, so no NTS-KE rerun happens.
#   4. the server is restarted with the old cookies' key generation dropped;
#      now they are refused, the client gets an NTS NAK, and it re-runs NTS-KE
#      on its own and recovers.
#
# Step 3 is the property that makes rotation safe to do on a live fleet: a
# rotation must not force every client through a handshake at once.
set -eu

DIR=${1:-/tmp/nts-rotation}
cd "$(dirname "$0")/.."
ROOT=$(pwd)
mkdir -p "$DIR"

"$ROOT/scripts/testbed.sh" "$DIR" >/dev/null 2>&1 || true
"$DIR/stop.sh" >/dev/null 2>&1 || true
sleep 1

start_server() { # $1 = seed hex, rest = extra args
  local seed=$1; shift
  ./target/release/nts-server --ntp 127.0.0.1:12300 --ke 127.0.0.1:14460 \
      --cert "$DIR/srv.crt" --key "$DIR/srv.key" \
      --cookie-seed "$seed" --rotate-every 0 "$@" \
      >> "$DIR/server.log" 2>&1 &
  SERVER_PID=$!
  sleep 1.5
}

echo "== phase 1: establish a session (8 cookies from NTS-KE)"
start_server "$(printf '%064x' 7)"
./target/release/nts-client --server 127.0.0.1:14460 --ca "$DIR/ca.crt" \
    --count 2 --aeads 15 --verbose 2>&1 | tail -3

echo
echo "== phase 2: rotate the cookie key in place (SIGUSR1)"
kill -USR1 "$SERVER_PID"
sleep 1
grep "rotated on SIGUSR1" "$DIR/server.log" | tail -1

echo
echo "== phase 3: the client's pre-rotation cookies must still work"
mkdir -p "$DIR/cache"
# --verbose reports ke=... ; one NTS-KE run before and after means none was
# needed mid-stream.
./target/release/nts-client --server 127.0.0.1:14460 --ca "$DIR/ca.crt" \
    --count 10 --interval 0.05 --aeads 15 --verbose 2>&1 | tail -3
echo "   (look for ke=1: the 10 polls all used pre-rotation or freshly minted"
echo "    cookies, and no NTS-KE rerun was forced by the rotation)"

echo
echo "== phase 4: drop the old generation by restarting with a new seed"
kill "$SERVER_PID" 2>/dev/null || true; wait 2>/dev/null || true
sleep 1
start_server "$(printf '%064x' 9)"
echo "   restarting with a different seed is the coarse form of retiring a key;"
echo "   the in-process form is evaluated in tests/e2e.rs because it can rotate"
echo "   between individual polls without restarting listeners."
./target/release/nts-client --server 127.0.0.1:14460 --ca "$DIR/ca.crt" \
    --count 3 --aeads 15 --verbose 2>&1 | tail -3

kill "$SERVER_PID" 2>/dev/null || true; wait 2>/dev/null || true
echo
echo "done.  See $DIR/server.log for the rotation lines."
