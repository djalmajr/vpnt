#!/usr/bin/env bash
# Proves that a compiled openfortivpn requires the --trusted-cert pin even when
# the gateway certificate also passes PKI validation (VPT-29, finding F4).
#
# usage: scripts/linux/check-openfortivpn-pin.sh <path-to-openfortivpn>
#
# Everything is local and synthetic: a throwaway CA, a server certificate for
# "localhost" signed by it, a self-signed certificate and an `openssl s_server`
# on 127.0.0.1. The login request is observed in the server's own log; the
# client stops at the login, so pppd is not needed. No network, no sudo: the
# client needs uid 0 only to pass its start-up check, which an unprivileged user
# namespace (`unshare -Ur`) provides without touching the host.
#
# Exit status: 0 when every case behaves as required, 1 when one does not
# (a binary without the pin patch fails case 1), 2 when the setup cannot run.

set -uo pipefail

if [ "$#" -ne 1 ] || [ ! -x "$1" ]; then
  echo "usage: $0 <path-to-openfortivpn>" >&2
  exit 2
fi
BIN=$(readlink -f -- "$1")
for tool in openssl timeout mkfifo mktemp readlink sed grep tr cut; do
  command -v "$tool" > /dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 2; }
done
command -v python3 > /dev/null 2>&1 || { echo "missing tool: python3 (free port)" >&2; exit 2; }

if [ "$(id -u)" -eq 0 ]; then
  AS_ROOT=()
else
  command -v unshare > /dev/null 2>&1 || { echo "missing tool: unshare" >&2; exit 2; }
  unshare -Ur true 2> /dev/null || { echo "unprivileged user namespaces are unavailable" >&2; exit 2; }
  AS_ROOT=(unshare -Ur)
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/vpnt-ofv-pin.XXXXXX") || exit 2
SERVER_PID=""
stop_server() {
  # Only the s_server this script started, by its recorded PID.
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2> /dev/null; then
    kill "$SERVER_PID" 2> /dev/null
    wait "$SERVER_PID" 2> /dev/null
  fi
  SERVER_PID=""
}
cleanup() {
  stop_server
  exec 3>&-
  rm -rf -- "$T"
}
trap cleanup EXIT
cd "$T" || exit 2

PASSWORD="synthetic-pw-$(openssl rand -hex 8)"
: > empty.conf

# --- synthetic PKI ---------------------------------------------------------
fail_setup() { echo "setup failed: $1" >&2; exit 2; }
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 \
  -subj "/CN=vpnt pin test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" > /dev/null 2>&1 || fail_setup "ca"
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr \
  -subj "/CN=localhost" > /dev/null 2>&1 || fail_setup "server key"
printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > srv.ext
openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -out srv.pem -extfile srv.ext > /dev/null 2>&1 || fail_setup "server cert"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ss.key -out ss.pem -days 2 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" > /dev/null 2>&1 \
  || fail_setup "self-signed cert"

digest() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
}
SRV_DIGEST=$(digest srv.pem)
SS_DIGEST=$(digest ss.pem)
[ "${#SRV_DIGEST}" -eq 64 ] && [ "${#SS_DIGEST}" -eq 64 ] && [ "$SRV_DIGEST" != "$SS_DIGEST" ] \
  || fail_setup "digests"
# Premises: the server certificate passes PKI for localhost, the other does not.
openssl verify -CAfile ca.pem -verify_hostname localhost srv.pem > /dev/null 2>&1 \
  || fail_setup "server certificate does not validate against the test CA"
if openssl verify -CAfile ca.pem ss.pem > /dev/null 2>&1; then
  fail_setup "self-signed certificate unexpectedly validates"
fi

# --- one s_server + one client run per case --------------------------------
mkfifo reply.fifo || fail_setup "fifo"
exec 3<> reply.fifo # keeps the server's stdin open; closed on exit

start_server() { # $1 = cert prefix; sets PORT, SERVER_PID, server.log
  local attempt
  for attempt in 1 2 3 4 5; do
    PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])') \
      || return 1
    : > server.log
    openssl s_server -accept "127.0.0.1:$PORT" -cert "$1.pem" -key "$1.key" -naccept 1 \
      < reply.fifo > server.log 2>&1 &
    SERVER_PID=$!
    local waited=0
    while [ "$waited" -lt 50 ]; do
      grep -q '^ACCEPT' server.log && return 0
      kill -0 "$SERVER_PID" 2> /dev/null || break
      sleep 0.1
      waited=$((waited + 1))
    done
    stop_server
  done
  return 1
}

FAILURES=0
# run_case <label> <cert prefix> <expect: login|refused> [trusted digest...]
run_case() {
  local label=$1 cert=$2 expect=$3
  shift 3
  start_server "$cert" || { echo "FAIL  $label: s_server did not start"; FAILURES=$((FAILURES + 1)); return; }
  local args=(localhost:"$PORT" -c "$T/empty.conf" -u tester --password "$PASSWORD"
    --ca-file "$T/ca.pem" --no-routes --no-dns)
  local pin
  for pin in "$@"; do args+=(--trusted-cert "$pin"); done
  # A canned 401 lets the client finish quickly once it has sent its login.
  printf 'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' >&3
  HOME="$T" timeout 15 "${AS_ROOT[@]}" "$BIN" "${args[@]}" > client.log 2>&1
  local rc=$?
  sleep 0.3
  stop_server
  local login=no leaked=no
  grep -q '^POST /remote/logincheck' server.log && login=yes
  grep -q -F -- "$PASSWORD" server.log && leaked=yes
  local verdict=PASS reason
  if [ "$rc" -eq 124 ]; then
    verdict=FAIL; reason="client timed out"
  elif [ "$expect" = login ]; then
    if [ "$login" = yes ] && [ "$leaked" = yes ]; then
      reason="login request reached the server (client exit $rc)"
    else
      verdict=FAIL; reason="expected a login request, server saw none (client exit $rc)"
    fi
  else
    if [ "$login" = no ] && [ "$leaked" = no ] && [ "$rc" -ne 0 ] \
      && grep -q 'certificate digest is not in the local whitelist\|Gateway certificate validation failed' client.log; then
      reason="refused before login, no request or credential at the server (client exit $rc)"
    else
      verdict=FAIL
      reason="login=$login credential_leaked=$leaked client_exit=$rc: the gateway was accepted"
    fi
  fi
  [ "$verdict" = PASS ] || FAILURES=$((FAILURES + 1))
  printf '%-5s %s: %s\n' "$verdict" "$label" "$reason"
  if [ "$verdict" = FAIL ]; then
    sed -n '/Gateway certificate/p;/^ERROR/p' client.log | head -5 | sed 's/^/        client: /'
  fi
}

echo "binary: $BIN"
echo "server cert sha256: $SRV_DIGEST (PKI valid for localhost)"
echo "other  cert sha256: $SS_DIGEST (self-signed)"
run_case "1 PKI valid + wrong digest     -> refuse" srv refused "$SS_DIGEST"
run_case "2 PKI valid + right digest     -> login " srv login "$SRV_DIGEST"
run_case "3 self-signed + right digest   -> login " ss login "$SS_DIGEST"
run_case "4 PKI valid, no --trusted-cert -> login " srv login
run_case "c1 control: self-signed + wrong digest -> refuse" ss refused "$SRV_DIGEST"
run_case "c2 control: self-signed, no --trusted-cert -> refuse" ss refused
run_case "c3 PKI valid + two pins (wrong, right) -> login" srv login "$SS_DIGEST" "$SRV_DIGEST"
run_case "c4 PKI valid + malformed pin   -> refuse" srv refused "${SRV_DIGEST:0:40}"

if [ "$FAILURES" -eq 0 ]; then
  echo "RESULT: all cases behave as required"
  exit 0
fi
echo "RESULT: $FAILURES case(s) failed"
exit 1
