#!/usr/bin/env python3
"""Exercise the PPP supervisor through pinned openfortivpn's actual forkpty/argv.

The PPP executable, configurations and data are fictional. This never invokes
system pppd, a VPN gateway, or an interface/route mutation, and must not run root.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE_SHA = "c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465"
FIXTURE = ROOT / "tests/fixtures/pppd"
REPORTS = ROOT / "output/fixtures/ppp-supervisor"
EXECUTIONS = {}


def run(label, command, expected=0):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=30)
    (REPORTS / f"{label}.log").write_bytes(result.stdout + result.stderr)
    EXECUTIONS[label] = {"exit": result.returncode, "command": list(map(str, command))}
    (REPORTS / "executions.json").write_text(json.dumps(EXECUTIONS, indent=2) + "\n")
    if result.returncode != expected:
        raise RuntimeError(f"{label}: expected exit {expected}, got {result.returncode}; see {REPORTS / (label+'.log')}")


def main():
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit("Run on macOS as an ordinary user; no system PPP or VPN is started")
    archive = ROOT / "target/runtime-sources/openfortivpn-1.24.1.tar.gz"
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA:
        raise SystemExit("Prepare the verified openfortivpn archive with build-runtime.py first")
    REPORTS.mkdir(parents=True, exist_ok=True)
    run("build", ["cargo", "build", "--locked", "--offline", "--no-default-features", "--lib", "--bin", "vpnt-pppd"])
    library = ["--edition=2024", "--extern", f"vpnt={ROOT}/target/debug/libvpnt.rlib", "-L", f"dependency={ROOT}/target/debug/deps"]
    # The read-only observer used by the fixture also needs this same libc.
    libc = max((ROOT / "target/debug/deps").glob("liblibc-*.rlib"), key=lambda path: path.stat().st_mtime)
    run("format", ["rustfmt", "--edition", "2024", "--check", FIXTURE / "adapter.rs", FIXTURE / "owner.rs"])
    cases = ["normal", "revoke", "ignore-term", "parent-exit", "hup", "extra-control", "deny-supervisor", "deny-child", "revoke-child", "wrong-peer", "exec-failure", "bad-argv", "extra-argv", "production-gate"]
    receipt = {"upstream": "openfortivpn 1.24.1 pppd_run", "archiveSha256": ARCHIVE_SHA, "systemPppdStarted": False, "vpnStarted": False, "cases": {}}
    with tempfile.TemporaryDirectory(prefix="consumer-", dir=REPORTS) as temporary:
        directory = Path(temporary)
        with tarfile.open(archive) as package:
            tunnel = package.extractfile("openfortivpn-1.24.1/src/tunnel.c").read().decode()
        builder = tunnel[tunnel.index("struct ofv_varr {"):tunnel.index("static int on_ppp_if_up(")]
        ppp = tunnel[tunnel.index("static int pppd_run("):tunnel.index("static const char * const ppp_message[]")]
        source = directory / "client.c"
        source.write_text((FIXTURE / "client-head.c").read_text() + builder + ppp + (FIXTURE / "client-tail.c").read_text())
        run("compile-child", ["/usr/bin/cc", "-Wall", "-Wextra", "-Werror", FIXTURE / "child.c", "-o", directory / "child"])
        run("compile-adapter", ["rustc", FIXTURE / "adapter.rs", *library, "-o", directory / "adapter"])
        run("compile-owner", ["rustc", FIXTURE / "owner.rs", *library, "--extern", f"libc={libc}", "-o", directory / "owner"])
        for mode in cases:
            adapter = directory / f"adapter-{mode}"
            if mode == "production-gate":
                adapter = ROOT / "target/debug/vpnt-pppd"
            else:
                shutil.copy2(directory / "adapter", adapter)
            client = directory / f"client-{mode}"
            run(f"compile-{mode}", ["/usr/bin/cc", "-Wall", "-Wextra", "-Werror", f'-DPPP_PATH="{adapter}"', source, "-o", client])
            command = [directory / "owner", client, adapter, directory / f"marker-{mode}", mode]
            run(mode, command)
            receipt["cases"][mode] = {"exit": 0}
    receipt["sourceSha256"] = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for prefix in ["src", "tests"] for path in sorted((ROOT / prefix).rglob("*")) if path.is_file()}
    (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"PPP supervisor: {len(cases)} actual forkpty/exec scenarios passed; no system PPP/VPN; copy removed")


if __name__ == "__main__":
    main()
