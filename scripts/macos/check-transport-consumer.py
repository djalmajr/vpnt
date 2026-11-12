#!/usr/bin/env python3
"""Exercise and mutate the patched openfortivpn TCP consumer on loopback only."""
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile

from runtime_sources import FORTI_SHA, FORTI_URL, FORTI_VERSION, verified_source

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "output/fixtures/transport-oracles"


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError(f"Mutation anchor changed: {before!r}")
    return source.replace(before, after, 1)


def execute(label, arguments, cwd, expected=0):
    result = subprocess.run(arguments, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=60)
    (REPORTS / f"{label}.log").write_text(result.stdout)
    if (expected == 0 and result.returncode != 0) or (expected != 0 and result.returncode == 0):
        raise RuntimeError(f"{label}: unexpected exit {result.returncode}")
    if expected != 0 and ("Assertion failed" not in result.stdout or result.returncode != -6):
        raise RuntimeError(f"{label}: expected an executed assertion, got {result.returncode}")
    print(f"{label}: exit {result.returncode}", flush=True)
    return {"command": list(map(str, arguments)), "exit": result.returncode}


def main():
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit("Run on macOS as an ordinary user; only loopback sockets are used.")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    REPORTS.mkdir(parents=True, exist_ok=True)
    openssl = Path(subprocess.check_output(["brew", "--prefix", "openssl@4"], text=True).strip())
    fixture = ROOT / "tests/fixtures/fortinet_transport.c"
    patches = [ROOT / "scripts/macos/patches" / name for name in [
        "openfortivpn-no-routes.patch", "openfortivpn-bound-transport.patch"]]
    receipt = {"archiveSha256": FORTI_SHA, "sourceSha256": {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [fixture, *patches]
    }, "scope": "ordinary user, actual TCP consumer, loopback only"}
    try:
        with tempfile.TemporaryDirectory(prefix="copy-", dir=REPORTS) as temporary:
            directory = Path(temporary)
            archive_name = f"openfortivpn-{FORTI_VERSION}.tar.gz"
            cached = ROOT / "target/runtime-sources" / archive_name
            if cached.is_file():
                shutil.copyfile(cached, directory / archive_name)
            source = verified_source(directory, "openfortivpn", FORTI_VERSION, "gz", FORTI_URL, FORTI_SHA)
            for index, patch in enumerate(patches):
                execute(f"patch-{index}", ["/usr/bin/patch", "-t", "-p1", "-i", patch], source)
            program = directory / "consumer"
            compile_command = ["/usr/bin/cc", "-ffunction-sections", "-Wl,-dead_strip",
                "-DHAVE_USR_SBIN_PPPD=1", "-DHAVE_UTIL_H=1", "-DHAVE_STRUCT_TERMIOS=1",
                '-DPPP_PATH="/usr/sbin/pppd"', f"-I{source}/src", f"-I{openssl}/include",
                f"-L{openssl}/lib", "-lssl", "-lcrypto", fixture, "-o", program]

            def run(label, expected=0):
                execute(f"{label}-compile", compile_command, directory)
                receipt[label] = execute(label, [program], directory, expected)

            run("baseline")
            tunnel = source / "src/tunnel.c"
            original = tunnel.read_text()
            mutations = [
                ("interface-binding-omitted",
                 "setsockopt(handle, IPPROTO_IP, IP_BOUND_IF,\n\t\t                  &bound_index, sizeof(bound_index))", "0"),
                ("expected-index-ignored", "bound_index != tunnel->config->vpnt_ifindex", "0"),
                ("gateway-resolved-again", "tunnel->config->vpnt_gateway_ip.s_addr != INADDR_ANY", "0"),
            ]
            for name, before, after in mutations:
                try:
                    tunnel.write_text(replace_once(original, before, after))
                    run(name, -6)
                finally:
                    tunnel.write_text(original)
            run("restored")
            receipt["casesPassed"] = 6
            receipt["mutationsDetected"] = len(mutations)
    finally:
        (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Patched TCP consumer: 6 scenarios and 3 mutations passed; no VPN or route changes")


if __name__ == "__main__":
    main()
