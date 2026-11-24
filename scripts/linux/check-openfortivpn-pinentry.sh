#!/usr/bin/env bash
# Proves, on a compiled openfortivpn, two properties of the pinentry password
# (VPT-29 S2 review, findings F2 and F3):
#
#   F3  the password is asked from the pinentry only after the gateway's
#       --trusted-cert pin was accepted: a wrong pin never starts the pinentry;
#   F2  once the password was read, the pinentry's one-shot descriptor 3 is
#       closed in the client, so no process it starts afterwards (the pppd) can
#       inherit it; and the pinentry itself did get it.
#
# usage: scripts/linux/check-openfortivpn-pinentry.sh <path-to-openfortivpn>
#
# Everything is local and synthetic, like check-openfortivpn-pin.sh: a throwaway
# CA and certificates, an `openssl s_server` on 127.0.0.1 whose reply is held
# until the client's descriptors were read, and a fake pinentry that speaks the
# few Assuan lines the client uses. pppd is never needed: the client stops at
# the login. No network, no sudo (an unprivileged user namespace gives the
# client the uid 0 it checks for).
#
# Exit status: 0 when every case behaves as required, 1 when one does not
# (a binary without the defer-password patch fails), 2 when the setup cannot run.

set -uo pipefail

if [ "$#" -ne 1 ] || [ ! -x "$1" ]; then
  echo "usage: $0 <path-to-openfortivpn>" >&2
  exit 2
fi
BIN=$(readlink -f -- "$1")
for tool in openssl timeout mkfifo mktemp readlink sed grep tr cut python3; do
  command -v "$tool" > /dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 2; }
done
if [ "$(id -u)" -eq 0 ]; then
  AS_ROOT=""
else
  command -v unshare > /dev/null 2>&1 || { echo "missing tool: unshare" >&2; exit 2; }
  unshare -Ur true 2> /dev/null || { echo "unprivileged user namespaces are unavailable" >&2; exit 2; }
  AS_ROOT="unshare -Ur"
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/vpnt-ofv-pinentry.XXXXXX") || exit 2
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
  exec 4>&-
  rm -rf -- "$T"
}
trap cleanup EXIT
cd "$T" || exit 2

PASSWORD="synthetic-pw-$(openssl rand -hex 8)"
: > empty.conf
fail_setup() { echo "setup failed: $1" >&2; exit 2; }

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 \
  -subj "/CN=vpnt pinentry test CA" \
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

# The fake pinentry: records that it ran, whether it was given descriptor 3 as a
# socket, then answers the Assuan exchange of the client with the password.
cat > pinentry.py << 'PY'
#!/usr/bin/env python3
import json, os, stat, sys
state = {"ran": True, "fd3_socket": False}
try:
    state["fd3_socket"] = stat.S_ISSOCK(os.fstat(3).st_mode)
except OSError:
    pass
with open(sys.argv[1], "w") as mark:
    json.dump(state, mark)
password = sys.argv[2]
sys.stdout.write("OK Pleased to meet you\n"); sys.stdout.flush()
for line in sys.stdin:
    word = line.strip().split(" ")[0]
    if word == "GETPIN":
        sys.stdout.write("D " + password + "\nOK\n")
    elif word in ("BYE", ""):
        break
    else:
        sys.stdout.write("OK\n")
    sys.stdout.flush()
PY
chmod +x pinentry.py
printf '#!/bin/sh\nexec python3 %s/pinentry.py %s/pinentry.mark %s\n' "$T" "$T" "$PASSWORD" > pinentry
chmod +x pinentry

mkfifo reply.fifo || fail_setup "fifo"
exec 4<> reply.fifo # keeps the server's stdin open; closed on exit

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

# Runs the client with descriptor 3 an AF_UNIX socket (the capability the
# supervisor installs), holds the server's reply until the client's descriptors
# were read, and prints: `fd3=<open|closed|unreadable> rc=<exit status>`.
drive() { # $1 = port, remaining arguments = --trusted-cert pins
  local port=$1
  shift
  python3 - "$port" "$BIN" "$T" "$AS_ROOT" "$@" << 'PY'
import os, socket, subprocess, sys, time
port, binary, tmp, as_root = sys.argv[1:5]
pins = sys.argv[5:]
argv = as_root.split() + [binary, "localhost:" + port, "-c", tmp + "/empty.conf",
    "-u", "tester", "--pinentry=" + tmp + "/pinentry", "--ca-file", tmp + "/ca.pem",
    "--no-routes", "--no-dns"]
for pin in pins:
    argv += ["--trusted-cert", pin]
mine, theirs = socket.socketpair()
def install():
    os.dup2(theirs.fileno(), 3)
    os.set_inheritable(3, True)
child = subprocess.Popen(argv, pass_fds=(3,), preexec_fn=install, stdin=subprocess.DEVNULL,
    stdout=open(tmp + "/client.log", "w"), stderr=subprocess.STDOUT,
    env={"HOME": tmp, "PATH": os.environ["PATH"]})
theirs.close()
fd3 = "unreadable"
deadline = time.time() + 15
posted = False
while time.time() < deadline and child.poll() is None:
    if "POST /remote/logincheck" in open(tmp + "/server.log", errors="replace").read():
        posted = True
        break
    time.sleep(0.05)
if posted:
    # The client now waits for the login reply: its descriptors are stable.
    try:
        os.stat("/proc/%d/fd" % child.pid)
        fd3 = "open" if os.path.lexists("/proc/%d/fd/3" % child.pid) else "closed"
    except OSError:
        pass
    reply = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    with open(tmp + "/reply.fifo", "wb", buffering=0) as fifo:
        fifo.write(reply)
try:
    rc = child.wait(timeout=15)
except subprocess.TimeoutExpired:
    child.kill()
    child.wait()
    rc = 124
print("fd3=%s rc=%d" % (fd3, rc))
PY
}

FAILURES=0
verdict() { # $1 = label, $2 = PASS|FAIL, $3 = reason
  printf '%-5s %s: %s\n' "$2" "$1" "$3"
  [ "$2" = PASS ] || FAILURES=$((FAILURES + 1))
}

# run_case <label> <cert prefix> <expect: login|refused> <pin>
run_case() {
  local label=$1 cert=$2 expect=$3 pin=$4 result fd3 rc ran=no secret=no login=no
  rm -f pinentry.mark
  start_server "$cert" || { verdict "$label" FAIL "s_server did not start"; return; }
  result=$(drive "$PORT" "$pin")
  sleep 0.3
  stop_server
  fd3=$(printf '%s' "$result" | sed -n 's/.*fd3=\([a-z]*\).*/\1/p')
  rc=$(printf '%s' "$result" | sed -n 's/.*rc=\([0-9]*\).*/\1/p')
  [ -e pinentry.mark ] && ran=yes
  grep -q '^POST /remote/logincheck' server.log && login=yes
  grep -q -F -- "$PASSWORD" server.log && secret=yes
  if [ "$expect" = refused ]; then
    if [ "$ran" = no ] && [ "$login" = no ] && [ "$secret" = no ] && [ "$rc" != 0 ] && [ "$rc" != 124 ]; then
      verdict "$label" PASS "refused; the pinentry never ran, no credential left the client (exit $rc)"
    else
      verdict "$label" FAIL "pinentry_ran=$ran login=$login credential_at_server=$secret exit=$rc"
    fi
    return
  fi
  if [ "$ran" = yes ] && grep -q '"fd3_socket": true' pinentry.mark \
    && [ "$login" = yes ] && [ "$secret" = yes ]; then
    verdict "$label (pinentry got fd 3, login sent)" PASS "after the pin was accepted"
  else
    verdict "$label (pinentry got fd 3, login sent)" FAIL "pinentry_ran=$ran login=$login credential_at_server=$secret exit=$rc: $(cat pinentry.mark 2> /dev/null)"
  fi
  if [ "$fd3" = closed ]; then
    verdict "$label (fd 3 after the read)" PASS "descriptor 3 is closed in the client while it waits for the login reply"
  else
    verdict "$label (fd 3 after the read)" FAIL "descriptor 3 is $fd3 in the client: a process it starts inherits it"
  fi
}

echo "binary: $BIN"
run_case "1 PKI valid + wrong digest   -> pinentry not asked" srv refused "$SS_DIGEST"
run_case "2 self-signed + wrong digest -> pinentry not asked" ss refused "$SRV_DIGEST"
run_case "3 PKI valid + right digest   -> asked after the pin" srv login "$SRV_DIGEST"
run_case "4 self-signed + right digest -> asked after the pin" ss login "$SS_DIGEST"

if [ "$FAILURES" -eq 0 ]; then
  echo "RESULT: all cases behave as required"
  exit 0
fi
echo "RESULT: $FAILURES check(s) failed"
exit 1
