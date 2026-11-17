#!/usr/bin/env python3
"""Permanent original-TU protected-UDP gate (canonical source, no real BYPASS).

Extracts the pinned strongSwan archive to a private temporary tree, applies the
frozen strongswan-protected-udp.patch with --fuzz=0, compiles the whole patched
socket-default TU plus the independent SDK-shim fixture against the prepared
config.h, runs the seven cases and the twelve named mutants, and retains logs
and a receipt. It verifies the canonical sixth source; it does not claim the
installed/prepared runtime is six-patch and does not use a retained-runtime
receipt or CI environment bypass.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

COPY = Path(__file__).resolve().parents[2]
REPORTS = COPY / "output/fixtures/protected-udp-gate"
FIXTURES = COPY / "tests/fixtures"
DEFAULT_PATCH = COPY / "scripts/macos/patches/strongswan-protected-udp.patch"
PATCH_SHA = "147557bd04e5087ba1e25d90e14d482d4b4257660cac8b8515cfd4f2c7e2dcec"
ORIGINAL_TU_SHA = "e972cf88c4ac5c2566ca1aff50f7b571ec8b01d4c560e694ef3376fc0787dacb"
TU_SHA = "5da65db4d4ec1dd5f6eec46b7c4d0bf45d452dbaf71f31de89a411baa3b98691"
CASES = [
    "default_off_preserves_upstream",
    "protected_ipv4",
    "protected_ipv6",
    "invalid_index_matrix",
    "boundif_failure",
    "outbound_policy_failure",
    "inbound_policy_failure",
]
SOURCES = [
    "scripts/macos/check-protected-udp.py",
    "scripts/macos/protected_udp_mutations.py",
    "tests/fixtures/protected_udp.h",
    "tests/fixtures/protected_udp.c",
    "tests/fixtures/protected_udp_tests.c",
    "scripts/macos/patches/strongswan-protected-udp.patch",
]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fail(message):
    raise SystemExit(f"protected-udp: {message}")


def execute(label, command, cwd=None, timeout=180):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    log = result.stdout + result.stderr
    (REPORTS / f"{label}.log").write_text(log)
    if result.returncode != 0:
        fail(f"{label} failed ({result.returncode}); see {REPORTS / (label + '.log')}")
    return result


def runtime_build(copy):
    spec = importlib.util.spec_from_file_location(
        "runtime_build", copy / "scripts/macos/build-runtime.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract_and_patch(temp, runtime_root, patch):
    runtime = runtime_build(COPY)
    archive = runtime_root / "target/runtime-sources" / f"strongswan-{runtime.SWAN_VERSION}.tar.bz2"
    config = runtime_root / "target/runtime-build/strongswan/config.h"
    if not archive.is_file() or digest(archive) != runtime.SWAN_SHA:
        fail("pinned strongSwan archive is missing or has the wrong SHA-256 "
             "(pass --runtime-root with the pinned read-only target)")
    if not config.is_file():
        fail("prepared config.h is missing (pass --runtime-root with the prepared target)")
    if not patch.is_file() or digest(patch) != PATCH_SHA:
        fail("canonical strongswan-protected-udp.patch is missing or altered")
    with tarfile.open(archive, "r:bz2") as package:
        try:
            package.extractall(temp, filter="data")
        except TypeError:  # Python before 3.12
            package.extractall(temp)
    source = Path(temp) / f"strongswan-{runtime.SWAN_VERSION}"
    tu = source / "src/libcharon/plugins/socket_default/socket_default_socket.c"
    if not tu.is_file() or digest(tu) != ORIGINAL_TU_SHA:
        fail("original socket-default TU does not match the pinned archive hash")
    execute("patch", ["/usr/bin/patch", "-t", "-p1", "--fuzz=0", "-i", str(patch)],
            cwd=source)
    if not tu.is_file() or digest(tu) != TU_SHA:
        fail("patched TU does not match the frozen patched hash")
    return source, tu, config, archive, runtime.SWAN_SHA


def compile_fixture(source, tu, config, runtime_root, temp):
    fixtures = Path(temp) / "fixtures"
    fixtures.mkdir()
    for name in ["protected_udp.h", "protected_udp.c", "protected_udp_tests.c"]:
        (fixtures / name).write_bytes((FIXTURES / name).read_bytes())
    (fixtures / "socket_default_socket.c").write_bytes(tu.read_bytes())
    flags = [
        "-x", "c", "-O0", "-g", "-include", str(config),
        "-I", str(runtime_root / "target/runtime-build/strongswan"),
        "-I", str(source / "src/libstrongswan"),
        "-I", str(source / "src/libcharon"),
        "-I", str(source / "src/libipsec"),
        "-I", str(source / "src/libcharon/plugins/socket_default"),
        "-ffunction-sections", "-fdata-sections",
    ]
    objects = []
    for name in ["protected_udp.c", "protected_udp_tests.c"]:
        obj = Path(temp) / (Path(name).stem + ".o")
        result = subprocess.run(["cc", *flags, "-c", str(fixtures / name), "-o", str(obj)],
                                capture_output=True, text=True)
        log = result.stdout + result.stderr
        (REPORTS / f"compile-{Path(name).stem}.log").write_text(log)
        if result.returncode != 0:
            fail(f"compile {name} failed; see {REPORTS / ('compile-' + Path(name).stem + '.log')}")
        objects.append(obj)
    binary = Path(temp) / "fixture"
    execute("link", ["cc", *map(str, objects), "-Wl,-dead_strip", "-o", str(binary)])
    return flags, objects, binary


def run_cases(binary, label):
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
    log = result.stdout + result.stderr
    (REPORTS / f"{label}.log").write_text(log)
    if result.returncode != 0:
        fail(f"{label} failed ({result.returncode}); see {REPORTS / (label + '.log')}")
    names = [line[3:] for line in result.stdout.splitlines() if line.startswith("ok ")]
    if names != CASES:
        fail(f"{label} did not execute all seven cases in order: {names}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, default=COPY,
                        help="read-only root containing target/runtime-sources and prepared config")
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH,
                        help="canonical protected-UDP patch (frozen default)")
    args = parser.parse_args()
    if sys.platform != "darwin":
        fail("run on macOS; this gate requires the Darwin SDK fixture")
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        fail("run as an ordinary user; no root or installation")
    REPORTS.mkdir(parents=True, exist_ok=True)
    before = {name: digest(COPY / name) for name in SOURCES}
    runtime_root = args.runtime_root.resolve()
    with tempfile.TemporaryDirectory(prefix="build-", dir=REPORTS) as temp:
        source, tu, config, archive, archive_sha = extract_and_patch(
            temp, runtime_root, args.patch)
        config_before = digest(config)
        flags, objects, binary = compile_fixture(source, tu, config, runtime_root, temp)
        run_cases(binary, "cases")
        spec = importlib.util.spec_from_file_location(
            "protected_udp_mutations", COPY / "scripts/macos/protected_udp_mutations.py")
        mutations = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mutations)
        rows = mutations.run(tu, flags, FIXTURES, Path(temp) / "mutants")
        for row in rows:
            (REPORTS / f"mut-{row['label']}.log").write_text(
                (Path(temp) / "mutants" / row["label"] / "mutant.log").read_text())
        (REPORTS / "mutations.log").write_text(
            "\n".join(
                f"{row['label']} x {row['test']}: exit={row['exit']} "
                f"killed={row['killed']} assertion={row['assertion']}"
                for row in rows
            ) + "\n"
        )
        run_cases(binary, "restored")
    if digest(config) != config_before:
        fail("prepared config.h changed while the gate was running")
    after = {name: digest(COPY / name) for name in SOURCES}
    if before != after:
        fail("owned source changed while the gate was running")
    receipt = {
        "scope": "canonical sixth-patch source gate; not installed/prepared runtime admission",
        "archiveSha256": archive_sha,
        "canonicalPatchSha256": PATCH_SHA,
        "patchedTuSha256": TU_SHA,
        "configSha256": config_before,
        "runtimeRoot": str(runtime_root),
        "runtimeManifestChecked": False,
        "sourceSha256": before,
        "sourceUnchanged": before == after,
        "cases": len(CASES),
        "caseNames": CASES,
        "mutants": len(rows),
        "mutantLabels": [row["label"] for row in rows],
        "realVpn": False,
        "privilegedInstall": False,
        "limits": "Ordinary-user UDP loopback and pipe; SDK policy calls intercepted; no real BYPASS, packet send, charon, UTUN, PF_KEY, root, install or route mutation.",
    }
    (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"ok {len(CASES)} cases; {len(rows)} mutants; "
          f"source-gate; receipt={REPORTS / 'receipt.json'}")


if __name__ == "__main__":
    main()
