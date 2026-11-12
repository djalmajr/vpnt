#!/usr/bin/env python3
"""Mutate supervisor guards only in a disposable build/source copy."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "output/fixtures/ppp-supervisor-oracles"


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError(f"Changed mutation anchor: {before!r}")
    return source.replace(before, after, 1)


def early_receipt(source):
    source = replace_once(source, "    let result = loop {", '    raw::write(fd, &raw::frame(*b"VPF1", child_pid), raw::deadline()?)?;\n    let result = loop {')
    return replace_once(source, "    finish(fd, child_pid, result)\n", "    result\n")


def run(copy, label, expected):
    result = subprocess.run([sys.executable, "scripts/macos/check-ppp-supervisor.py"], cwd=copy, capture_output=True, timeout=90)
    (REPORTS / f"{label}.log").write_bytes(result.stdout + result.stderr)
    executions = json.loads((copy / "output/fixtures/ppp-supervisor/executions.json").read_text())
    if result.returncode != expected:
        raise RuntimeError(f"{label}: expected script exit {expected}, got {result.returncode}")
    if any(result["exit"] for name, result in executions.items() if name.startswith("compile-") or name in ["build", "format"]):
        raise RuntimeError(f"{label}: compilation/format failure does not count")
    failed = {name: result for name, result in executions.items() if result["exit"] == 101}
    if expected and not failed:
        raise RuntimeError(f"{label}: no executed consumer assertion failed")
    if not expected:
        receipt = json.loads((copy / "output/fixtures/ppp-supervisor/receipt.json").read_text())
        if len(receipt["cases"]) != 14 or any(case["exit"] for case in receipt["cases"].values()):
            raise RuntimeError(f"{label}: incomplete baseline")
        if len(receipt.get("hostCases", {})) != 9 or any(case["exit"] for case in receipt["hostCases"].values()):
            raise RuntimeError(f"{label}: incomplete production-host baseline")
    shutil.copytree(copy / "output/fixtures/ppp-supervisor", REPORTS / label, dirs_exist_ok=True)
    print(f"{label}: script exit {result.returncode}, failed consumers {list(failed)}", flush=True)
    return {"exit": result.returncode, "failedConsumers": list(failed)}


def main():
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit("Run on macOS as an ordinary user; only fictional PPP processes run")
    REPORTS.mkdir(parents=True, exist_ok=True)
    supervisor = "src/helper/ppp_supervisor.rs"
    mutations = [
        ("supervisor-permission-skipped", supervisor, lambda s: replace_once(s, '    raw::exchange(fd, raw::frame(*b"VPS1", pid), *b"VPA1", pid)?;\n', "")),
        ("child-permission-skipped", supervisor, lambda s: replace_once(s, '            raw::exchange(fd, raw::frame(*b"VPB1", child), *b"VPC1", child)?;\n', "")),
        ("permission-pid-ignored", "src/helper/ppp_supervisor/raw.rs", lambda s: replace_once(s, "if reply != frame(magic, pid)", "if reply[..4] != magic")),
        ("supervision-fd-leaks-through-exec", supervisor, lambda s: replace_once(s, "if unsafe { libc::fcntl(INHERITED_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0", "if false")),
        ("password-capability-reaches-ppp", supervisor, lambda s: replace_once(s, "        libc::close(3);", "        // password capability was incorrectly retained")),
        ("hup-terminates-parent-without-wait", supervisor, lambda s: replace_once(s, "    let _signals = signals::Guard::install()?;\n", "")),
        ("final-receipt-before-child-wait", supervisor, early_receipt),
        ("ppp-stdio-replaced-with-pipes", "src/helper/process.rs", lambda s: replace_once(s, "Self::spawn_configured(command, Environment::System, true)", "Self::spawn_configured(command, Environment::System, false)")),
        ("extra-ppp-options-accepted", supervisor, lambda s: replace_once(s, "arguments.len() == ARGUMENTS.len()", "arguments.len() >= ARGUMENTS.len()")),
        ("host-foreign-parent-accepted", "src/connection/macos/ppp_control.rs", lambda s: replace_once(s, "(parent != 0 && value.parent != parent)", "false")),
        ("host-eof-substitutes-child-exit", "src/connection/macos/ppp_control.rs", lambda s: replace_once(s, "self.proof.as_ref().map_or(Ok(true), |proof| proof.exited())", "Ok(true)")),
    ]
    receipt = {"sourceSha256": {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for prefix in ["src", "tests"] for path in sorted((ROOT / prefix).rglob("*")) if path.is_file()}}
    try:
        with tempfile.TemporaryDirectory(prefix="copy-", dir=REPORTS) as temporary:
            copy = Path(temporary)
            for file in ["Cargo.toml", "Cargo.lock"]:
                shutil.copy2(ROOT / file, copy / file)
            for folder in ["src", "tests", "scripts/macos/patches"]:
                shutil.copytree(ROOT / folder, copy / folder)
            shutil.copy2(ROOT / "scripts/macos/check-ppp-supervisor.py", copy / "scripts/macos/check-ppp-supervisor.py")
            cache = copy / "target/runtime-sources"
            cache.mkdir(parents=True)
            shutil.copy2(ROOT / "target/runtime-sources/openfortivpn-1.24.1.tar.gz", cache / "openfortivpn-1.24.1.tar.gz")
            receipt["baseline"] = run(copy, "baseline", 0)
            for label, file, mutate in mutations:
                path = copy / file
                original = path.read_text()
                try:
                    path.write_text(mutate(original))
                    receipt[label] = run(copy, label, 1)
                finally:
                    path.write_text(original)
            receipt["restored"] = run(copy, "restored", 0)
    finally:
        (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Killed {len(mutations)} supervision mutations; both 14-wire/9-host baselines passed; copy removed")


if __name__ == "__main__":
    main()
