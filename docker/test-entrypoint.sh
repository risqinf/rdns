#!/bin/sh
# test-entrypoint.sh — mints a throwaway PKI into /pki for the local smoke
# test (docker-compose.test.yml). These certs are TEST-ONLY, ephemeral, and
# never used in production. The volume is wiped with `compose down -v`.
set -eu

PKI=/pki
mkdir -p "$PKI/certs"

rdns-certs ca     -name rdns-test-ca -out "$PKI"
rdns-certs client -ca "$PKI/ca.crt" -cakey "$PKI/ca.key" \
  -name node-test -out "$PKI/certs"
# Server cert SAN must match the client's profiles[].server_name ("exit-my").
rdns-certs server -ca "$PKI/ca.crt" -cakey "$PKI/ca.key" \
  -name exit-my -dns exit-my -ip 172.28.0.20 -out "$PKI/certs"

# The exit/client containers run as uid 10001 and must read these. Test-only
# volume, throwaway keys → world-readable is acceptable here (NOT for prod).
chmod -R a+rX "$PKI"

echo "test PKI minted:"
ls -l "$PKI" "$PKI/certs"
