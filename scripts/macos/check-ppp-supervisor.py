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
    run("configuration", ["cargo", "test", "--locked", "--offline", "--no-default-features", "--lib", "helper::ppp_config"])
    library = ["--edition=2024", "--extern", f"vpnt={ROOT}/target/debug/libvpnt.rlib", "-L", f"dependency={ROOT}/target/debug/deps"]
    # The read-only observer used by the fixture also needs this same libc.
    libc = max((ROOT / "target/debug/deps").glob("liblibc-*.rlib"), key=lambda path: path.stat().st_mtime)
    run("format", ["rustfmt", "--edition", "2024", "--check", FIXTURE / "adapter.rs", FIXTURE / "owner.rs", FIXTURE / "owner-host.rs"])
    cases = ["normal", "revoke", "ignore-term", "parent-exit", "hup", "extra-control", "deny-supervisor", "deny-child", "revoke-child", "wrong-peer", "exec-failure", "bad-argv", "extra-argv", "production-gate", "silence-supervisor", "silence-child"]
    receipt = {"upstream": "openfortivpn 1.24.1 pppd_run", "archiveSha256": ARCHIVE_SHA, "systemPppdStarted": False, "vpnStarted": False, "cases": {}}
    with tempfile.TemporaryDirectory(prefix="consumer-", dir=REPORTS) as temporary:
        directory = Path(temporary)
        with tarfile.open(archive) as package:
            tunnel = package.extractfile("openfortivpn-1.24.1/src/tunnel.c").read().decode()
        (directory / "src").mkdir()
        (directory / "src/tunnel.c").write_text(tunnel)
        patched = subprocess.run(["/usr/bin/patch", "-t", "-p1", "-i", ROOT / "scripts/macos/patches/openfortivpn-ppp-supervisor.patch"], cwd=directory, capture_output=True)
        if patched.returncode:
            raise RuntimeError("Supervisor patch failed against pinned source: " + patched.stderr.decode())
        tunnel = (directory / "src/tunnel.c").read_text()
        # Fixture-only executable substitution. Keep patched control flow and
        # the full upstream argv builder, without touching the installed path.
        fixed = 'VPNT_PPP_SUPERVISOR'
        if tunnel.count(fixed) != 1:
            raise RuntimeError("Missing mandatory fixed supervisor path")
        tunnel = tunnel.replace(fixed, "PPP_PATH")
        builder = tunnel[tunnel.index("struct ofv_varr {"):tunnel.index("static int on_ppp_if_up(")]
        ppp = tunnel[tunnel.index("static int pppd_run("):tunnel.index("static const char * const ppp_message[]")]
        source = directory / "client.c"
        source.write_text((FIXTURE / "client-head.c").read_text() + builder + ppp + (FIXTURE / "client-tail.c").read_text())
        # Stage updated wire consumers privately: the original fixtures remain
        # untouched while this checker exercises the production UUID handshake.
        def replace_once(text, old, new):
            if text.count(old) != 1:
                raise RuntimeError(f"fixture anchor changed: {old!r}")
            return text.replace(old, new, 1)
        child = (FIXTURE / "child.c").read_text()
        child = replace_once(child, 'assert(argc==3+(int)(sizeof(expected)/sizeof(expected[0])));', 'assert(argc==5+(int)(sizeof(expected)/sizeof(expected[0])));')
        child = replace_once(child, 'for(int i=3;i<argc;i++) assert(strcmp(argv[i],expected[i-3])==0);', 'for(int i=3;i<argc-2;i++) assert(strcmp(argv[i],expected[i-3])==0);\n    assert(strcmp(argv[argc-2],"serviceid")==0);\n    assert(strlen(argv[argc-1])==36 && argv[argc-1][14]==\'4\');')
        child = replace_once(child, 'fprintf(marker,"%d\\n",getpid());', 'fprintf(marker,"%d\\n%s\\n",getpid(),argv[argc-1]);')
        (directory / "child.c").write_text(child)
        owner = (FIXTURE / "owner.rs").read_text()
        owner = replace_once(owner, '#[path = "../../../src/connection/macos/process.rs"]', f'#[path = "{ROOT}/src/connection/macos/process.rs"]')
        owner = replace_once(owner, 'value.trim().parse()', 'value.lines().next().unwrap_or("").parse()')
        owner = replace_once(owner, '        .write_all(&frame(b"VPA1", supervisor))\n        .unwrap();', '        .write_all(&frame(b"VPA1", supervisor))\n        .unwrap();\n    owner.channel.write_all(b"12345678-1234-4123-8123-123456789ABC").unwrap();')
        owner = replace_once(owner, '            .write_all(&frame(b"VPA1", supervisor + 1))\n            .unwrap();', '            .write_all(&frame(b"VPA1", supervisor + 1))\n            .unwrap();\n        owner.channel.write_all(b"12345678-1234-4123-8123-123456789ABC").unwrap();')
        (directory / "owner.rs").write_text(owner)
        host = (FIXTURE / "owner-host.rs").read_text()
        for file in ["src/helper/local_socket.rs", "src/connection/macos/ppp_control.rs", "src/connection/macos/process.rs"]:
            host = replace_once(host, f'#[path = "../../../{file}"]', f'#[path = "{ROOT}/{file}"]')
        host = replace_once(host, '    pub use super::local_socket;', '    pub use super::local_socket;\n    pub use vpnt::helper::ppp_supervisor;')
        host = replace_once(host, 's.trim().parse::<u32>().ok()', 's.lines().next().and_then(|line| line.parse::<u32>().ok())')
        host = replace_once(host, '            assert_eq!(proof.child().pid, pid);', '            assert_eq!(proof.child().pid, pid);\n            let marker = fs::read_to_string(&args[2]).unwrap();\n            assert_eq!(marker.lines().nth(1), Some(proof.child().service().as_str()));')
        (directory / "owner-host.rs").write_text(host)
        run("compile-child", ["/usr/bin/cc", "-Wall", "-Wextra", "-Werror", directory / "child.c", "-o", directory / "child"])
        run("compile-adapter", ["rustc", FIXTURE / "adapter.rs", *library, "-o", directory / "adapter"])
        run("compile-owner", ["rustc", directory / "owner.rs", *library, "--extern", f"libc={libc}", "-o", directory / "owner"])
        run("compile-host", ["rustc", directory / "owner-host.rs", *library, "--extern", f"libc={libc}", "-o", directory / "owner-host"])
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
        receipt["hostCases"] = {}
        for mode in ["normal", "revoke", "ignore-term", "parent-exit", "wrong-program", "foreign-parent", "exec-failure", "pre-cancel", "orphan"]:
            adapter = directory / f"adapter-host-{mode}"
            shutil.copy2(directory / "adapter", adapter)
            client = directory / f"client-host-{mode}"
            flags = [f'-DVPNT_KILL_MARKER="{directory}/marker-host-orphan"'] if mode == "orphan" else []
            run(f"compile-host-{mode}", ["/usr/bin/cc", "-Wall", "-Wextra", "-Werror", "-DVPNT_PINENTRY_FIXTURE", *flags, f'-DPPP_PATH="{adapter}"', source, "-o", client])
            run(f"host-{mode}", [directory / "owner-host", client, adapter, directory / f"marker-host-{mode}", mode])
            receipt["hostCases"][mode] = {"exit": 0}
    receipt["sourceSha256"] = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for prefix in ["src", "tests"] for path in sorted((ROOT / prefix).rglob("*")) if path.is_file()}
    (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"PPP supervisor: {len(cases)} wire + {len(receipt['hostCases'])} production-host forkpty/exec scenarios passed; no system PPP/VPN; copy removed")


if __name__ == "__main__":
    main()
