#!/usr/bin/env bash
set -euo pipefail

mkdir -p certs

openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 \
  -subj "/CN=qsr-example-ca" \
  -out certs/ca.crt

make_cert() {
  local name="$1"
  local cn="$2"
  local usage="$3"
  openssl genrsa -out "certs/${name}.key" 2048
  openssl req -new -key "certs/${name}.key" -subj "/CN=${cn}" -out "certs/${name}.csr"
  cat >"certs/${name}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=${usage}
subjectAltName=DNS:${cn}
EOF
  openssl x509 -req -in "certs/${name}.csr" -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
    -out "certs/${name}.crt" -days 365 -sha256 -extfile "certs/${name}.ext"
}

make_cert rvr-a rvr-a.flightdeck.example.test serverAuth
make_cert rvr-b rvr-b.flightdeck.example.test serverAuth
make_cert client qsr-example-client clientAuth

rm -f certs/*.csr certs/*.ext certs/ca.srl
chmod 600 certs/*.key
