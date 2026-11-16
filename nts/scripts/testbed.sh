#!/bin/bash
# Set up a local NTS test bed: a private CA, a server certificate, a chrony
# instance that serves both plain NTP and NTS, and our own server.  When this
# finishes, four endpoints are up:
#
#   127.0.0.1:12301  chrony plain NTP      (comparison baseline)
#   127.0.0.1:14461  chrony NTS-KE   \
#                    chrony NTS NTP  /     (one process, fair comparison)
#   127.0.0.1:12300  our plain-side NTP server
#   127.0.0.1:14460  our NTS-KE
#
# Everything runs unprivileged on high ports.  chrony needs -U -x: -U skips the
# root check, -x stops it from touching the system clock (it can still serve
# time).
set -eu

DIR=${1:-/tmp/nts-testbed}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$DIR"
cd "$DIR"

# ---------------------------------------------------------------- certificates
if [ ! -f ca.crt ]; then
  echo "== generating CA and server certificate in $DIR"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout ca.key -out ca.crt -days 365 -subj "/CN=NTS Test CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
  cat > ext.cnf <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
  openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -out srv.crt -days 30 -extfile ext.cnf 2>/dev/null
  openssl verify -CAfile ca.crt srv.crt
fi

# ---------------------------------------------------------------------- chrony
# A chronyd from an earlier run would hold both ports and serve an old
# certificate, so it has to go before the new one starts.
pkill -f "chrony/srv.conf" 2>/dev/null || true
sleep 0.5

mkdir -p chrony && chmod 700 chrony
cat > chrony/srv.conf <<EOF
port 12301
local stratum 3
allow all
bindaddress 127.0.0.1
pidfile $DIR/chrony/srv.pid
driftfile $DIR/chrony/srv.drift
logdir $DIR/chrony
ntsport 14461
ntsservercert $DIR/srv.crt
ntsserverkey $DIR/srv.key
ntsdumpdir $DIR/chrony/keys
ntsrotate 3600
EOF

echo "== starting chronyd (plain 12301, NTS-KE 14461)"
/opt/homebrew/sbin/chronyd -U -x -f "$DIR/chrony/srv.conf" -d -L 2 \
    > "$DIR/chrony/srv.log" 2>&1 &
echo $! > "$DIR/chrony/srv.shell.pid"

# ------------------------------------------------------------------- our server
pkill -f "nts-server --ntp 127.0.0.1:12300" 2>/dev/null || true
sleep 0.5
echo "== starting our nts-server (NTP 12300, NTS-KE 14460)"
"$ROOT/target/release/nts-server" \
    --ntp 127.0.0.1:12300 --ke 127.0.0.1:14460 \
    --cert "$DIR/srv.crt" --key "$DIR/srv.key" \
    --cookie-seed "$(printf '%064x' 7)" \
    --rotate-every 3600 \
    > "$DIR/nts-server.log" 2>&1 &
echo $! > "$DIR/nts-server.pid"

sleep 2

echo
echo "ready.  try:"
echo "  $ROOT/target/release/nts-client --server 127.0.0.1:14461 --ca $DIR/ca.crt --count 5 --verbose"
echo "  $ROOT/target/release/nts-bench  --mode both --server 127.0.0.1:14461 --ntp 127.0.0.1:12301 --ca $DIR/ca.crt --count 200 --interval 0.02"
echo
echo "stop with: $DIR/stop.sh"
cat > "$DIR/stop.sh" <<EOF
#!/bin/bash
kill \$(cat "$DIR/nts-server.pid" 2>/dev/null) 2>/dev/null
kill \$(cat "$DIR/chrony/srv.shell.pid" 2>/dev/null) 2>/dev/null
pkill -f "$DIR/chrony/srv.conf" 2>/dev/null
echo stopped
EOF
chmod +x "$DIR/stop.sh"
