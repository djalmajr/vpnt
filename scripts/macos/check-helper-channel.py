#!/usr/bin/env python3
"""Verify helper admission/transport in a disposable unprivileged source copy."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "output/fixtures/helper-channel-oracles"


def replace(source, before, after, count=1):
    if source.count(before) != count:
        raise RuntimeError(f"Changed mutation anchor: {before!r}")
    return source.replace(before, after)


def run(copy, label, selector, failed=None):
    command = ["cargo", "test", "--locked", "--offline", "--no-default-features", *selector]
    result = subprocess.run(command, cwd=copy, capture_output=True, timeout=45)
    log = result.stdout + result.stderr
    (REPORTS / f"{label}.log").write_bytes(log)
    expected = 101 if failed else 0
    if result.returncode != expected:
        raise RuntimeError(f"{label}: expected {expected}, got {result.returncode}")
    if failed and (f"test {failed} ... FAILED".encode() not in log or b"panicked at" not in log or b"test result: FAILED." not in log):
        raise RuntimeError(f"{label}: expected executed assertion, not compilation or an unrelated failure")
    print(f"{label}: exit {result.returncode}", flush=True)
    return {"command": command, "exit": result.returncode, "assertion": failed}


def main():
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit("Run on macOS as an ordinary user; no elevation or system VPN resources")
    REPORTS.mkdir(parents=True, exist_ok=True)
    server = "src/helper/server.rs"
    caller = "src/helper/server/caller.rs"
    io = "src/helper/server/io.rs"
    tests = "helper::server::tests::"
    modes = tests + "only_closed_modes_and_connected_unix_stream_capabilities_are_admitted"
    admin = tests + "half_closed_administration_waits_for_eof_and_never_mutates_on_a_second_document"
    mutations = [
        ("extra-mode-arguments-accepted", server, lambda s: replace(s, "[arg] if arg ==", "[arg, ..] if arg ==", 2), modes),
        # On Darwin, getpeereid also rejects datagrams. Omitting SO_TYPE alone
        # is equivalent in these consumers; do not count it as a killed mutation.
        ("named-service-capability-accepted", caller, lambda s: replace(s, "!address.sun_path.iter().any(|byte| *byte != 0)", "true"), modes),
        ("capability-leaks-through-exec", caller, lambda s: replace(s, "libc::F_SETFD, libc::FD_CLOEXEC", "libc::F_SETFD, 0"), modes),
        ("caller-uid-substituted", server, lambda s: replace(s, "run(caller.uid, receive, output.clone())", "run(caller.uid + 1, receive, output.clone())"), tests + "runtime_carries_fragmented_requests_and_replies_and_closes_on_injection"),
        ("admin-eof-not-required", "src/helper/protocol.rs", lambda s: replace(s, "if read_frame(reader, MAX_REQUEST_BYTES)?.is_some()", "if false"), admin),
        ("admin-save-silently-accepted", server, lambda s: replace(s, "AdminCommand::SaveProfile { profile } => store.save(profile)", "AdminCommand::SaveProfile { profile: _ } => Ok(())"), admin),
        ("admin-remove-silently-accepted", server, lambda s: replace(s, "AdminCommand::RemoveProfile { id } => store.remove(&id)", "AdminCommand::RemoveProfile { id: _ } => Ok(())"), admin),
        ("admin-lock-not-revalidated", server, lambda s: replace(s, "lock\n        .validate()", "Ok::<(), super::controller_lock::LockError>(())"), admin),
        ("partial-reader-not-canceled", server, lambda s: replace(s, "self.0.store(true, Ordering::Release);", "// incorrectly kept an idle/partial reader alive"), tests + "early_controller_failure_cancels_a_buffered_partial_request_without_waiting_for_eof"),
        ("admin-silence-deadline-extended", io, lambda s: replace(s, "const DEADLINE: Duration = Duration::from_secs(5)", "const DEADLINE: Duration = Duration::from_secs(30)"), tests + "an_admin_channel_kept_open_in_silence_expires_without_applying_an_operation"),
        ("consumed-password-bytes-retained", io, lambda s: replace(s, "self.buffer[self.head..end].zeroize();", "let _ = &self.buffer[self.head..end];"), "helper::server::io::tests::consumed_secret_bytes_are_erased_without_corrupting_the_next_buffered_frame"),
    ]
    receipt = {"sourceSha256": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for base in ["src", "tests"] for p in sorted((ROOT / base).rglob("*")) if p.is_file()}}
    try:
        with tempfile.TemporaryDirectory(prefix="copy-", dir=REPORTS) as temporary:
            copy = Path(temporary)
            for file in ["Cargo.toml", "Cargo.lock"]:
                shutil.copy2(ROOT / file, copy / file)
            for folder in ["src", "tests", "scripts/macos/patches"]:
                shutil.copytree(ROOT / folder, copy / folder)
            baselines = [("transport", ["--lib", "helper::server"]), ("controller", ["--lib", "inherited_helper_channel"]), ("entrypoint", ["--test", "helper_entrypoint"])]
            for label, selector in baselines:
                receipt["baseline-" + label] = run(copy, "baseline-" + label, selector)
            for label, file, mutate, expected in mutations:
                path = copy / file
                original = path.read_text()
                try:
                    path.write_text(mutate(original))
                    receipt[label] = run(copy, label, ["--lib", "helper::server"], expected)
                finally:
                    path.write_text(original)
            for label, selector in baselines:
                receipt["restored-" + label] = run(copy, "restored-" + label, selector)
    finally:
        (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Killed {len(mutations)} helper-channel mutations; six baselines/restorations passed; source/build copy removed")


if __name__ == "__main__":
    main()
