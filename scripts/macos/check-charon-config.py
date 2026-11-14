#!/usr/bin/env python3
"""Canonical renderer + original-parser gate for the protected UDP setting.

Renders the old byte-identical production configuration and the bound
`render_bound` form (numeric index), then validates both with the original
libstrongswan settings parser. It is a source gate, not an installed-runtime
proof; no charon, plugin, socket, policy, route or kernel operation is used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

CHECKER_ROOT = Path(__file__).resolve().parents[2]
REPORTS = CHECKER_ROOT / "output/fixtures/charon-config"
spec = importlib.util.spec_from_file_location(
    "runtime_build", Path(__file__).with_name("build-runtime.py"))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def run(label, arguments, env=None, expected=0, assertion=None, cwd=None):
    result = subprocess.run(list(map(str, arguments)), cwd=cwd or CHECKER_ROOT,
                            env=env, capture_output=True, timeout=120)
    output = result.stdout + result.stderr
    (REPORTS / f"{label}.log").write_bytes(output)
    if result.returncode != expected:
        raise RuntimeError(
            f"{label}: exit {result.returncode}, expected {expected}; "
            f"see {REPORTS / (label + '.log')}")
    if assertion is not None and assertion.encode() not in output:
        raise RuntimeError(f"{label}: missing assertion {assertion!r}; "
                           f"see {REPORTS / (label + '.log')}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, default=CHECKER_ROOT,
                        help="read-only root with target/runtime-sources, build, library, crypto")
    args = parser.parse_args()
    if sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit("Run on macOS as an ordinary user; no VPN or installation")
    runtime_root = args.runtime_root.resolve()
    archive = runtime_root / f"target/runtime-sources/strongswan-{runtime.SWAN_VERSION}.tar.bz2"
    source = archive.parent / f"strongswan-{runtime.SWAN_VERSION}"
    build = runtime_root / "target/runtime-build/strongswan"
    library = build / "src/libstrongswan/.libs/libstrongswan.a"
    crypto = runtime_root / "target/vpnt-runtime/lib/libcrypto.4.dylib"
    if not archive.is_file() or runtime.digest(archive) != runtime.SWAN_SHA:
        raise SystemExit("Prepare verified strongSwan sources with build-runtime.py first")
    for path in [library, build / "config.h", crypto]:
        if not path.is_file():
            raise SystemExit(f"Missing prepared artifact: {path}")
    inputs = ["library.h", "settings/settings.h", "settings/settings.c",
              "settings/settings_parser.y", "settings/settings_lexer.l"]
    with tarfile.open(archive) as package:
        for name in inputs:
            path = source / "src/libstrongswan" / name
            member = f"strongswan-{runtime.SWAN_VERSION}/src/libstrongswan/{name}"
            if path.read_bytes() != package.extractfile(member).read():
                raise RuntimeError(f"Original settings source changed: {name}")
    REPORTS.mkdir(parents=True, exist_ok=True)
    source_files = [
        Path(__file__),
        CHECKER_ROOT / "tests/fixtures/charon_config.rs",
        CHECKER_ROOT / "tests/fixtures/charon_settings.c",
        CHECKER_ROOT / "src/connection/ipsec/producer/config.rs",
        CHECKER_ROOT / "src/connection/ipsec/producer/files.rs",
        CHECKER_ROOT / "src/fs_permissions.rs",
    ]
    before = {str(p.relative_to(CHECKER_ROOT)): runtime.digest(p) for p in source_files}
    run("build-renderer-library",
        ["cargo", "build", "--locked", "--offline", "--no-default-features", "--lib"],
        cwd=CHECKER_ROOT)
    with tempfile.TemporaryDirectory(prefix="vpnt-settings-", dir=REPORTS) as temporary:
        directory = Path(temporary)
        libc = max((CHECKER_ROOT / "target/debug/deps").glob("liblibc-*.rlib"),
                   key=lambda p: p.stat().st_mtime)
        env = dict(os.environ, CARGO_MANIFEST_DIR=str(CHECKER_ROOT))
        run("compile-renderer",
            ["rustc", "--edition=2024", CHECKER_ROOT / "tests/fixtures/charon_config.rs",
             "--extern", f"vpnt={CHECKER_ROOT}/target/debug/libvpnt.rlib",
             "--extern", f"libc={libc}",
             "-L", f"dependency={CHECKER_ROOT}/target/debug/deps",
             "-o", directory / "render"], env=env)
        run("compile-parser",
            ["/usr/bin/cc", "-I", build, "-I", source / "src/libstrongswan",
             "-include", build / "config.h", CHECKER_ROOT / "tests/fixtures/charon_settings.c",
             library, crypto, "-lm", "-o", directory / "parse"])
        # Loader override applies only to this parser fixture. Production clears
        # it and admits only the fixed root-owned runtime.
        env = dict(os.environ, DYLD_LIBRARY_PATH=str(crypto.parent))
        paths = ["/Library/Application Support/vpnt/ipsec/" + "a" * 32,
                 "/private/tmp/vpnt settings with spaces"]
        for i, path in enumerate(paths):
            rendered = run(f"render-{i}", [directory / "render", path])
            configuration = directory / f"{i}.conf"
            configuration.write_bytes(rendered)
            run(f"parse-{i}", [directory / "parse", configuration, path], env=env)
            needle = b"kernel-libipsec { vpnt_retain_utun"
            if rendered.count(needle) != 1:
                raise RuntimeError(f"render-{i}: expected one namespace anchor")
            mangled = directory / f"{i}.libipsec.conf"
            mangled.write_bytes(rendered.replace(needle, b"libipsec { vpnt_retain_utun", 1))
            run(f"parse-namespace-{i}", [directory / "parse", mangled, path], env=env,
                expected=1, assertion="settings assertion:")
        protected = [(1, paths[0]), (65535, paths[1])]
        for index, path in protected:
            rendered = run(f"render-protected-{index}",
                           [directory / "render", path, index])
            configuration = directory / f"protected-{index}.conf"
            configuration.write_bytes(rendered)
            run(f"parse-protected-{index}",
                [directory / "parse", configuration, path, index], env=env)
            for suffix, needle, replacement in [
                ("namespace", b"socket-default {",
                 b"socket_default {"),
                ("namespace-libipsec", b"socket-default {",
                 b"libipsec {"),
                ("index", f"vpnt_ifindex = {index}".encode(),
                 f"vpnt_ifindex = {index - 1 if index > 1 else 2}".encode()),
                ("flag", b"vpnt_protect_transport = yes",
                 b"vpnt_protect_transport = no"),
            ]:
                if rendered.count(needle) != 1:
                    raise RuntimeError(f"render-protected-{index}: anchor for {suffix}")
                changed = directory / f"protected-{index}-{suffix}.conf"
                changed.write_bytes(rendered.replace(needle, replacement, 1))
                run(f"parse-protected-{index}-{suffix}",
                    [directory / "parse", changed, path, index], env=env,
                    expected=1, assertion="settings assertion:")
            for invalid in [0, -1, 65536]:
                run(f"render-protected-{index}-invalid-{invalid}",
                    [directory / "render", path, invalid], expected=101)
        receipt = {
            "scope": "canonical renderer/parser source gate; not installed-runtime proof",
            "archiveSha256": runtime.SWAN_SHA,
            "runtimeRoot": str(runtime_root),
            "positiveCases": len(paths),
            "refusedNamespaceCases": len(paths),
            "protectedPositiveCases": len(protected),
            "protectedNamespaceRefusals": len(protected) * 2,
            "protectedIndexRefusals": len(protected),
            "protectedFlagRefusals": len(protected),
            "invalidIndexRefusals": len(protected) * 3,
            "charonStarted": False,
            "vpnStarted": False,
            "preparedArtifactSha256": {
                str(p.relative_to(runtime_root)): runtime.digest(p)
                for p in [library, build / "config.h", crypto]
            },
            "sourceSha256": before,
            "sourceUnchanged": before == {
                str(p.relative_to(CHECKER_ROOT)): runtime.digest(p) for p in source_files
            },
        }
        if not receipt["sourceUnchanged"]:
            raise RuntimeError("renderer/parser source changed during the gate")
    (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Original parser: 2 old positive + 2 old namespace refusals + "
          "2 protected positives + 2x(2 namespace + index + flag) refusals + "
          "invalid index matrix; no charon/VPN")


if __name__ == "__main__":
    main()
