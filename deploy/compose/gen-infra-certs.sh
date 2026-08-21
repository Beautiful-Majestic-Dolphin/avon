#!/usr/bin/env bash
# Local CA for the Postgres and Redis TLS listeners.
#
# These cannot be AVON-issued: both databases have to be up before avon-ca can
# run at all. The CA created here is only ever trusted by the compose stack.
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)/infra-certs"
mkdir -p "$dir"
cd "$dir"

if [ -f ca.crt ]; then
  echo "infra certs already present in $dir"
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=AVON Compose Infra CA" >/dev/null 2>&1

for svc in postgres redis; do
  openssl req -newkey rsa:2048 -nodes -keyout "$svc.key" -out "$svc.csr" \
    -subj "/CN=$svc" >/dev/null 2>&1
  openssl x509 -req -in "$svc.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$svc.crt" -days 825 -sha256 \
    -extfile <(printf "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" "$svc") \
    >/dev/null 2>&1
  rm -f "$svc.csr"
  chmod 644 "$svc.crt"
  chmod 600 "$svc.key"
done

echo "wrote infra certs to $dir"
