#!/usr/bin/env python3
"""Permanent original-TU handoff gate for the pinned strongSwan runtime.

The checker verifies the pinned archive and canonical patch, extracts the
original source to a private temporary tree (never the modified runtime-sources
cache), applies the canonical patch with --fuzz=0, compiles the whole patched TU
plus the independent fixture against the prepared config.h, runs the eight
cases and the thirteen named mutants, then writes retained logs and a receipt.
No daemon, VPN, UTUN, PF_KEY, root or install is used.
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "output/fixtures/utun-handoff"
ARCHIVE = ROOT / "target/runtime-sources/strongswan-6.1.0.tar.bz2"
PATCH = ROOT / "scripts/macos/patches/strongswan-retain-utun.patch"
CONFIG = ROOT / "target/runtime-build/strongswan/config.h"
MANIFEST = ROOT / "target/vpnt-runtime/manifest.json"
FIXTURES = ROOT / "tests/fixtures"
PATCH_SHA = "71c3a33d6dd41037508574d2ffe6d0895d8780aa765c297355f3daaefb07037a"
TU_SHA = "1439f17daddcdd665418709a207f9449d7ed10ed16bfe5d523286039bef59d3b"
CASES = [
    "default_off_leaves_channel_untouched",
    "enabled_sends_after_up_once",
    "stream_channel_fails_before_publication",
    "non_unix_channel_fails_before_publication",
    "closed_channel_fails_before_publication",
    "peer_closed_send_failure_destroys",
    "up_failure_sends_nothing",
    "mtu_failure_sends_nothing",
]
SOURCES = [
    "tests/fixtures/utun_handoff.h",
    "tests/fixtures/utun_handoff.c",
    "tests/fixtures/utun_handoff_tests.c",
    "scripts/macos/check-utun-handoff.py",
    "scripts/macos/utun_handoff_mutations.py",
    "scripts/macos/patches/strongswan-retain-utun.patch",
    ".github/workflows/check.yml",
    "tests/fixtures/charon_settings.c",
]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fail(message):
    raise SystemExit(f"utun-handoff: {message}")


def execute(label, command, cwd=None, timeout=180):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    log = result.stdout + result.stderr
    (REPORTS / f"{label}.log").write_text(log)
    if result.returncode != 0:
        fail(f"{label} failed ({result.returncode}); see {REPORTS / (label + '.log')}")
    return result


def check_manifest():
    if not CONFIG.is_file():
        fail("prepared config.h is missing; run the pinned runtime build first")
    if not MANIFEST.is_file():
        fail("prepared runtime manifest is missing; run the pinned runtime build first")
    try:
        manifest = json.loads(MANIFEST.read_text())
        patches = manifest["strongswan"]["patches"]
    except (OSError, ValueError, KeyError, TypeError):
        fail("prepared runtime manifest is malformed")
    if patches.get("strongswan-retain-utun.patch") != PATCH_SHA:
        fail("prepared runtime does not declare the frozen canonical retain-utun patch")
    return digest(MANIFEST)


def extract_and_patch(temp):
    runtime_spec = importlib.util.spec_from_file_location(
        "runtime_build", ROOT / "scripts/macos/build-runtime.py")
    runtime = importlib.util.module_from_spec(runtime_spec)
    runtime_spec.loader.exec_module(runtime)
    if not ARCHIVE.is_file() or digest(ARCHIVE) != runtime.SWAN_SHA:
        fail("pinned strongSwan archive is missing or has the wrong SHA-256")
    if not PATCH.is_file() or digest(PATCH) != PATCH_SHA:
        fail("canonical strongswan-retain-utun.patch is missing or not the frozen hash")
    with tarfile.open(ARCHIVE, "r:bz2") as archive:
        try:
            archive.extractall(temp, filter="data")
        except TypeError:  # Python before 3.12
            archive.extractall(temp)
    source = Path(temp) / f"strongswan-{runtime.SWAN_VERSION}"
    execute("patch", ["/usr/bin/patch", "-t", "-p1", "--fuzz=0", "-i", str(PATCH)],
            cwd=source)
    tu = source / "src/libcharon/plugins/kernel_libipsec/kernel_libipsec_plugin.c"
    if not tu.is_file() or digest(tu) != TU_SHA:
        fail("patched TU does not match the frozen patched hash")
    return source, tu, runtime.SWAN_SHA


def compile_fixture(source, tu, temp):
    flags = [
        "-x", "c", "-O0", "-g", "-include", str(CONFIG),
        "-I", str(ROOT / "target/runtime-build/strongswan"),
        "-I", str(source / "src/libstrongswan"),
        "-I", str(source / "src/libcharon"),
        "-I", str(source / "src/libipsec"),
        "-I", str(source / "src/libcharon/plugins/kernel_libipsec"),
    ]
    objects = []
    for name, source_file in [
        ("tu", tu),
        ("fixture", FIXTURES / "utun_handoff.c"),
        ("tests", FIXTURES / "utun_handoff_tests.c"),
    ]:
        obj = Path(temp) / f"{name}.o"
        result = subprocess.run(["cc", *flags, "-c", str(source_file), "-o", str(obj)],
                                capture_output=True, text=True)
        log = result.stdout + result.stderr
        (REPORTS / f"compile-{name}.log").write_text(log)
        if result.returncode != 0:
            fail(f"compile {name} failed; see {REPORTS / ('compile-' + name + '.log')}")
        objects.append(obj)
    binary = Path(temp) / "utun_handoff"
    execute("link", ["cc", *map(str, objects), "-o", str(binary)])
    return flags, objects, binary


def run_cases(binary, label):
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
    log = result.stdout + result.stderr
    (REPORTS / f"{label}.log").write_text(log)
    if result.returncode != 0:
        fail(f"{label} failed ({result.returncode}); see {REPORTS / (label + '.log')}")
    names = [line[3:] for line in result.stdout.splitlines() if line.startswith("ok ")]
    if names != CASES:
        fail(f"{label} did not execute all eight cases in order: {names}")


def main():
    if sys.platform != "darwin":
        fail("run on macOS; this checker requires the Darwin SDK fixture")
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        fail("run as an ordinary user; no root or installation")
    REPORTS.mkdir(parents=True, exist_ok=True)
    before = {name: digest(ROOT / name) for name in SOURCES}
    manifest_before = check_manifest()
    config_before = digest(CONFIG)
    with tempfile.TemporaryDirectory(prefix="build-", dir=REPORTS) as temp:
        source, tu, archive_sha = extract_and_patch(temp)
        flags, objects, binary = compile_fixture(source, tu, temp)
        run_cases(binary, "cases")
        import utun_handoff_mutations as mutations
        rows = mutations.run(tu, flags, [objects[1], objects[2]], Path(temp) / "mutants")
        for row in rows:
            (REPORTS / f"mut-{row['label']}.log").write_text(
                (Path(temp) / "mutants" / f"{row['label']}.log").read_text())
        (REPORTS / "mutations.log").write_text(
            "\n".join(
                f"{row['label']} x {row['test']}: exit={row['exit']} "
                f"killed={row['killed']} assertion={row['assertion']}"
                for row in rows
            ) + "\n"
        )
        run_cases(binary, "restored")
    if digest(CONFIG) != config_before:
        fail("prepared config.h changed while the gate was running")
    if not MANIFEST.is_file() or digest(MANIFEST) != manifest_before:
        fail("prepared runtime manifest changed while the gate was running")
    after = {name: digest(ROOT / name) for name in SOURCES}
    if before != after:
        fail("owned source changed while the gate was running")
    receipt = {
        "archiveSha256": archive_sha,
        "canonicalPatchSha256": PATCH_SHA,
        "patchedTuSha256": TU_SHA,
        "configSha256": config_before,
        "manifestSha256": manifest_before,
        "sourceSha256": before,
        "sourceUnchanged": before == after,
        "cases": len(CASES),
        "caseNames": CASES,
        "mutants": len(rows),
        "mutantLabels": [row["label"] for row in rows],
        "realVpn": False,
        "privilegedInstall": False,
        "limits": "Ordinary-user C fixture and pipe; no charon, UTUN, PF_KEY, VPN, root, install or daemon.",
    }
    (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"ok {len(CASES)} cases; {len(rows)} mutants; "
          f"prerequisites=pinned-config-and-manifest; receipt={REPORTS / 'receipt.json'}")


if __name__ == "__main__":
    main()
