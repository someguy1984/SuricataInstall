#!/bin/bash
# Create a self-signed TLS certificate for the mock environment, once per container.
#
#   mock-tls NAME SAN        e.g. mock-tls web.dev.local "DNS:web.dev.local,DNS:localhost,IP:127.0.0.1"
#
# Writes /etc/ssl/mock/NAME.crt (0644) and NAME.key (0600). Does nothing if both exist, so the key
# survives restarts of the container but is never baked into the image.
# FOR LOCAL TESTING ONLY: browsers will warn, and nothing should trust this certificate.
set -euo pipefail

name=${1:?usage: mock-tls NAME SAN}
san=${2:?usage: mock-tls NAME SAN}
dir=/etc/ssl/mock
crt=$dir/$name.crt
key=$dir/$name.key

[[ -s $crt && -s $key ]] && exit 0

install -d -m 0755 "$dir"
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -days 825 -subj "/CN=$name" -addext "subjectAltName=$san" \
    -keyout "$key.tmp" -out "$crt.tmp" 2>/dev/null
chmod 0600 "$key.tmp"
chmod 0644 "$crt.tmp"
mv "$key.tmp" "$key"
mv "$crt.tmp" "$crt"
echo "mock-tls: created $crt ($san)"
