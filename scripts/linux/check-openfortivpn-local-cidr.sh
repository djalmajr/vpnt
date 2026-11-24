#!/usr/bin/env bash
# Pure contract check for the VPT-29 local-IPCP scope helper. It compiles
# tests/fixtures/openfortivpn/local_ipcp_scope.c against the real
# src/vpnt_ipcp_policy.{h,c} of a source tree already prepared by the Arch
# PKGBUILD, in a throwaway directory. No pppd, daemon, network, sudo, service,
# profile, credential, privilege change or write into that tree.
#
# usage: scripts/linux/check-openfortivpn-local-cidr.sh <prepared-source-tree>
#
# Exit status: 0 = all cases passed; 1 = a case failed or the helper did not
# compile; 2 = BLOCKED (the prepared tree has no helper, or a tool is missing).
# A missing helper is never reported as PASS: the Green depends on the patch.

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
