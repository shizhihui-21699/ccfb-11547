#!/bin/sh
# Generate a throwaway CA and a server certificate for local NTS testing.
#
# Everything written here is gitignored. Do not reuse these keys anywhere real:
# they exist so `nts-server` can be started without touching a PKI.
#
# Usage:
#   ./testdata/gen-certs.sh [output-dir]
#
# Produces:
#   ca.crt / ca.key         — test CA, trust this on the client with `--ca`
#   localhost.crt / .key    — server certificate for DNS:localhost, IP:127.0.0.1

set -eu

DIR="${1:-testdata}"
mkdir -p "$DIR"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$DIR/ca.key" -out "$DIR/ca.crt" -days 365 -nodes \
    -subj "/CN=NTS Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$DIR/localhost.key" -out "$DIR/localhost.csr" -nodes \
    -subj "/CN=localhost"

openssl x509 -req -in "$DIR/localhost.csr" \
    -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
    -out "$DIR/localhost.crt" -days 30 \
    -extfile - <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EXT

echo "wrote $DIR/ca.crt, $DIR/localhost.crt, $DIR/localhost.key"
