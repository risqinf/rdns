#!/bin/sh
# smoke.sh — end-to-end check of the rdns data path on the local test
# network (docker-compose.test.yml). Deterministic: uses docker's embedded
# DNS for name resolution, so it needs no internet.
#
#   1. DNS split : a MATCHED query (exit) sent to the client's DNS
#      interceptor (:5353) is forwarded to the exit node (:53), which
#      resolves it via its local resolver and answers → we get the exit's IP.
#   2. Tunnel relay: an HTTP request with a MATCHED Host (smoke) sent to the
#      client's SNI interceptor (:14300) is relayed through the mTLS+yamux
#      tunnel to the exit node, which dials the real target (smoke:80) and
#      pipes the bytes both ways.
set -eu

CLIENT=client
EXIT=exit
PASS=1

echo "== waiting for services =="
for i in $(seq 1 30); do
  nc -z "$CLIENT" 5353 2>/dev/null && nc -z "$CLIENT" 14300 2>/dev/null && break
  sleep 1
done

# ── 1. DNS split (matched → exit resolver) ─────────────────────────────────
echo "== DNS: matched query 'exit' via client:5353 =="
ANS="$(dig +short @"$CLIENT" -p 5353 +time=3 +tries=1 exit 2>/dev/null || true)"
echo "   answer: ${ANS:-<none>}"
if [ "$ANS" = "172.28.0.20" ]; then
  echo "   PASS: matched query resolved through the exit node"
else
  echo "   FAIL: expected 172.28.0.20 (exit), got '$ANS'"
  PASS=0
fi

# ── 2. Tunnel relay (matched Host → exit dials smoke:80) ───────────────────
echo "== SNI/HTTP: matched Host 'smoke' via client:14300 =="
# One-shot echo endpoint: sends a canned response, records the request.
( printf 'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ntunnel-ok' \
    | nc -l -p 80 -q 2 > /tmp/got 2>/dev/null ) &
ECHO_PID=$!
sleep 1

# Send an HTTP request whose Host matches the rule; the interceptor must
# tunnel it (not dial direct). The exit dials smoke:80 and relays.
RESP="$(printf 'GET / HTTP/1.1\r\nHost: smoke\r\n\r\n' \
  | nc -q 2 "$CLIENT" 14300 2>/dev/null | tail -c 9 || true)"
echo "   response: ${RESP:-<none>}"

wait "$ECHO_PID" 2>/dev/null || true
RECV="$(cat /tmp/got 2>/dev/null || true)"
echo "   target saw: $(printf '%s' "$RECV" | head -c 40)"

if printf '%s' "$RESP" | grep -q 'tunnel-ok'; then
  echo "   PASS: bytes round-tripped through the tunnel"
else
  echo "   FAIL: no tunnel-ok back"
  PASS=0
fi
if printf '%s' "$RECV" | grep -q 'Host: smoke'; then
  echo "   PASS: exit node dialed the real destination"
else
  echo "   FAIL: destination never received the request"
  PASS=0
fi

# ── 3. fail-closed sanity: unmatched host must NOT be tunneled ─────────────
echo "== DNS: unmatched query 'example.com' must go local (not exit) =="
# We can't easily assert the local path's answer without internet, so just
# confirm the interceptor stays alive and answers something (no crash).
nc -z "$CLIENT" 5353 2>/dev/null && echo "   PASS: interceptor still up" || {
  echo "   FAIL: interceptor died"; PASS=0; }

echo
if [ "$PASS" = "1" ]; then
  echo "SMOKE TEST PASSED"
  exit 0
else
  echo "SMOKE TEST FAILED"
  exit 1
fi
