#!/usr/bin/env bash
# Contract and behaviour check for the VPT-29 local-IPCP scope. It compiles
# tests/fixtures/openfortivpn/local_ipcp_scope.c against the real
# src/vpnt_ipcp_policy.{h,c} of a source tree already prepared by the Arch
# PKGBUILD, in a throwaway directory. It then runs the real client of that tree
# (built, with PPP_PATH pointed at a fake pppd in a private copy) against a
# loopback TLS gateway and checks what reaches the pppd side of the pty and
# which options pppd is given. No real pppd, daemon, network beyond 127.0.0.1,
# sudo, service, profile, credential, privilege change or write into that tree.
#
# usage: scripts/linux/check-openfortivpn-local-cidr.sh <prepared-source-tree>
#
# The behaviour part needs the tree to be built (configure and make already
# run, as check.sh and the PKGBUILD do), python3 and openssl.
#
# Exit status: 0 = all cases passed; 1 = a case failed or the helper did not
# compile; 2 = BLOCKED (the prepared tree has no helper or no build, or a tool
# is missing). A missing helper or build is never reported as PASS: the Green
# depends on the patch.

set -uo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <prepared-openfortivpn-source-tree>" >&2
  exit 2
fi
SRC=$1
if [ ! -d "$SRC" ]; then
  echo "BLOCKED: source tree is not a directory: $SRC" >&2
  exit 2
fi
SRC=$(cd -- "$SRC" && pwd -P) || { echo "BLOCKED: cannot resolve source tree: $1" >&2; exit 2; }

HEADER="$SRC/src/vpnt_ipcp_policy.h"
IMPL="$SRC/src/vpnt_ipcp_policy.c"
for file in "$HEADER" "$IMPL"; do
  if [ ! -f "$file" ]; then
    echo "BLOCKED: helper not present in the prepared tree: $file" >&2
    echo "BLOCKED: the production patch must add the real header and implementation; no PASS without them." >&2
    exit 2
  fi
done
if ! command -v cc > /dev/null 2>&1; then
  echo "BLOCKED: missing tool: cc" >&2
  exit 2
fi

ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd -P) || { echo "BLOCKED: cannot resolve fixture root" >&2; exit 2; }
FIXTURE="$ROOT/tests/fixtures/openfortivpn/local_ipcp_scope.c"
if [ ! -f "$FIXTURE" ]; then
  echo "BLOCKED: fixture is missing: $FIXTURE" >&2
  exit 2
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/vpnt-local-cidr.XXXXXX") || { echo "BLOCKED: mktemp failed" >&2; exit 2; }
cleanup() { rm -rf -- "$T"; }
trap cleanup EXIT

echo "source tree: $SRC"
echo "helper: $HEADER"
echo "helper: $IMPL"
echo "fixture: $FIXTURE"
if ! cc -std=c11 -Wall -Wextra -Werror -I"$SRC/src" \
  "$IMPL" "$FIXTURE" -o "$T/local_ipcp_scope" > "$T/build.log" 2>&1; then
  echo "FAIL: fixture did not compile or link against the production helper" >&2
  cat "$T/build.log" >&2
  exit 1
fi

"$T/local_ipcp_scope"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "RESULT: contract FAIL (fixture exit $rc)"
  exit "$rc"
fi

# Boundary and hostile frames, under the address and undefined-behaviour
# sanitizers: a read past the end of a frame fails even when the bytes beyond
# it look harmless. A toolchain without the sanitizers is a BLOCKED setup, never
# a PASS.
BOUNDARIES="$ROOT/tests/fixtures/openfortivpn/local_ipcp_scope_boundaries.c"
if [ ! -f "$BOUNDARIES" ]; then
  echo "BLOCKED: fixture is missing: $BOUNDARIES" >&2
  exit 2
fi
echo "fixture: $BOUNDARIES"
if ! cc -std=c11 -Wall -Wextra -Werror -g -O1 -fno-omit-frame-pointer \
  -fsanitize=address,undefined -fno-sanitize-recover=undefined -I"$SRC/src" \
  "$IMPL" "$BOUNDARIES" -o "$T/local_ipcp_scope_boundaries" > "$T/build-boundaries.log" 2>&1; then
  echo "BLOCKED: the boundary fixture did not build with the sanitizers" >&2
  cat "$T/build-boundaries.log" >&2
  exit 2
fi
ASAN_OPTIONS=detect_leaks=1:abort_on_error=0 "$T/local_ipcp_scope_boundaries"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "RESULT: contract FAIL (boundary fixture exit $rc)"
  exit 1
fi

# Behaviour of the real client. A private copy of the built tree is rebuilt with
# PPP_PATH pointing at a fake pppd; a loopback TLS gateway then logs in and
# sends PPP frames. The fake pppd records its argv and every frame that reaches
# the pty, so a client that drops every frame, forwards a frame it should refuse
# or starts pppd without a scope fails here, which no reading of the sources
# can show. The line checks below stay as a second, structural guard.
FIXTURE_PY="$ROOT/tests/fixtures/openfortivpn/local_cidr_wiring.py"
for tool in python3 openssl make; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo "BLOCKED: missing tool for the behaviour check: $tool" >&2
    exit 2
  fi
done
if [ ! -f "$FIXTURE_PY" ]; then
  echo "BLOCKED: fixture is missing: $FIXTURE_PY" >&2
  exit 2
fi
if [ ! -f "$SRC/Makefile" ] || [ ! -x "$SRC/openfortivpn" ]; then
  echo "BLOCKED: the prepared tree is not built (no Makefile or openfortivpn): $SRC" >&2
  echo "BLOCKED: configure and make the tree before this check; no PASS without the behaviour run." >&2
  exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
  AS_ROOT=()
else
  if ! command -v unshare > /dev/null 2>&1 || ! unshare -Ur true 2> /dev/null; then
    echo "BLOCKED: unprivileged user namespaces are unavailable (the client needs uid 0)" >&2
    exit 2
  fi
  AS_ROOT=(unshare -Ur)
fi
BUILD="$T/build"
cp -a -- "$SRC" "$BUILD" || { echo "BLOCKED: cannot copy the prepared tree" >&2; exit 2; }
python3 -I "$FIXTURE_PY" --print-fake-pppd > "$T/fake-pppd" || { echo "BLOCKED: no fake pppd" >&2; exit 2; }
chmod 700 "$T/fake-pppd"
if ! grep -q -F -- '/usr/sbin/pppd' "$BUILD/Makefile"; then
  echo "BLOCKED: the copied Makefile has no PPP_PATH to repoint" >&2
  exit 2
fi
sed -i "s|/usr/sbin/pppd|$T/fake-pppd|g" "$BUILD/Makefile"
touch "$BUILD/src/tunnel.c"
if ! make -s -C "$BUILD" openfortivpn > "$T/make.log" 2>&1; then
  echo "BLOCKED: the private copy did not build" >&2
  tail -n 20 "$T/make.log" >&2
  exit 2
fi
if ! grep -a -q -F -- "$T/fake-pppd" "$BUILD/openfortivpn"; then
  echo "BLOCKED: the private build does not call the fake pppd" >&2
  exit 2
fi
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/gateway.key" -out "$T/gateway.pem" \
  -days 2 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" > /dev/null 2>&1 \
  || { echo "BLOCKED: cannot create the loopback gateway certificate" >&2; exit 2; }
PIN=$(openssl x509 -in "$T/gateway.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
mkdir -p "$T/wiring"
python3 -I "$FIXTURE_PY" "$BUILD/openfortivpn" "$T/wiring" "$T/gateway.pem" "$T/gateway.key" \
  "$PIN" 10.99.0.0/24 "${AS_ROOT[@]}"
rc=$?
if [ "$rc" -eq 2 ]; then
  echo "BLOCKED: the behaviour fixture could not run" >&2
  exit 2
fi
if [ "$rc" -ne 0 ]; then
  echo "RESULT: contract FAIL (behaviour)"
  exit 1
fi
echo "PASS behaviour: the real client delivers, refuses and configures pppd as required"

# Structural wiring check (it reads the sources; it does not run the client):
# in ssl_read() the policy check must come before the pool_push() that hands a
# gateway frame to pppd, and pppd_run() must refuse to start without a scope.
IO="$SRC/src/io.c"
TUNNEL="$SRC/src/tunnel.c"
wired=$(awk '
  /^static void \*ssl_read\(/ { inside = 1 }
  inside && /vpnt_ipcp_check\(/ && !check { check = NR }
  inside && /pool_push\(&tunnel->ssl_to_pty_pool/ && !push { push = NR }
  inside && /^}/ { inside = 0 }
  END { print (check && push && check < push) ? "ok" : "no" }
' "$IO" 2> /dev/null)
if [ "$wired" != "ok" ]; then
  echo "FAIL wiring: ssl_read() in $IO does not check the IPCP frame before pool_push()"
  echo "RESULT: contract FAIL (wiring)"
  exit 1
fi
echo "PASS wiring: ssl_read() checks every gateway frame before pool_push()"
refused=$(awk '
  /^static int pppd_run\(/ { inside = 1 }
  inside && /fortinet_local_cidr\.prefix/ && !scope { scope = NR }
  inside && /execv\(|forkpty\(/ && !spawn { spawn = NR }
  inside && /^}/ { inside = 0 }
  END { print (scope && spawn && scope < spawn) ? "ok" : "no" }
' "$TUNNEL" 2> /dev/null)
if [ "$refused" != "ok" ]; then
  echo "FAIL wiring: pppd_run() in $TUNNEL does not require the scope before spawning pppd"
  echo "RESULT: contract FAIL (wiring)"
  exit 1
fi
echo "PASS wiring: pppd_run() requires the scope before spawning pppd"
echo "RESULT: contract PASS"
exit 0
