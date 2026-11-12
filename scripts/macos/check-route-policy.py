#!/usr/bin/env python3
"""Run focused route-policy mutations in a disposable source/build copy."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "output/fixtures/route-oracles"


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError(f"Mutation anchor changed: {before!r}")
    return source.replace(before, after, 1)


def remove_pending_barrier(source):
    start = source.index("            if step.pending != 0 {")
    end = source.index("            if let Some(claim)", start)
    return source[:start] + source[end:]


def forward_cleanup(source):
    source = replace_once(source, "claim.keys.last()", "claim.keys.first()")
    return replace_once(source, "claim.keys.pop();", "claim.keys.remove(0);")


def run(copy, label, arguments, expected):
    command = ["cargo", "test", "--locked", "--no-default-features", "--offline", *arguments]
    # The child owns a fresh session; timeout cleanup signals only that group
    # while its direct child remains unreaped, never a searched/name-matched PID.
    process = subprocess.Popen(command, cwd=copy, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        (REPORTS / f"{label}.log").write_text(output)
        raise RuntimeError(f"{label}: timed out") from None
    (REPORTS / f"{label}.log").write_text(output)
    if process.returncode != expected or (expected == 101 and "test result: FAILED" not in output):
        raise RuntimeError(f"{label}: expected a test exit {expected}, got {process.returncode}")
    if expected == 0 and "test result: ok." not in output:
        raise RuntimeError(f"{label}: no executed test result")
    print(f"{label}: exit {process.returncode}", flush=True)
    return {"exit": process.returncode, "command": command}


def main():
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit("Run on macOS as an ordinary user. This never installs or changes routes.")
    REPORTS.mkdir(parents=True, exist_ok=True)
    lease = "src/connection/routes/lease.rs"
    cleanup = "src/connection/routes/lease/cleanup.rs"
    acquire = "src/connection/routes/lease/acquire.rs"
    codec = "src/connection/macos/routing/codec.rs"
    mutations = [
        ("shared-route-removed", cleanup,
         lambda s: replace_once(s, "        if !entry.users.is_empty() {\n            return Cleanup::default();\n        }\n", ""),
         ["--test", "route_leases", "borrowed_routes_and_shared"]),
        ("gateway-unpinned-before-networks", cleanup, forward_cleanup,
         ["--test", "route_flow", "connect_pins_transport"]),
        ("pending-cleanup-forgotten", cleanup, remove_pending_barrier,
         ["--test", "route_flow", "failed_network_cleanup"]),
        ("uid-scope-ignored", acquire,
         lambda s: replace_once(s, "claim.owner.uid == owner.uid && ", ""),
         ["--test", "route_leases", "manager_uid_profile"]),
        ("receipt-identity-ignored", lease,
         lambda s: replace_once(s, "Some(receipt) => self.backend.receipt_state(receipt)? == Presence::Owned,", "Some(_receipt) => true,"),
         ["--test", "route_leases", "replacement_even"]),
        ("extension-rollback-omitted", acquire,
         lambda s: replace_once(s, "let cleanup = self.release_tail(token, keep);", "let cleanup = super::Cleanup::default();"),
         ["--test", "route_flow", "failed_extension"]),
        ("incomplete-plan-accepted", acquire,
         lambda s: replace_once(s, "claim.failed = true;", "claim.failed = false;"),
         ["--test", "route_flow", "incomplete_extension"]),
        ("unsupported-family-unblocked", "src/connection/routes/plan.rs",
         lambda s: replace_once(s, "NextHop::Blackhole", "NextHop::Interface"),
         ["--test", "route_leases", "full_tunnel_plan"]),
        ("conflict-admission-omitted", lease,
         lambda s: replace_once(s, "Some(old) if old != route => Err(Error::Conflict),", "Some(_old) => Ok(()),"),
         ["--test", "route_leases", "a_conflict"]),
        ("ipv6-network-mask-omitted", "src/connection/routes/model.rs",
         lambda s: replace_once(s, "u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0)", "u128::MAX"),
         ["--test", "route_leases", "network_masks"]),
        ("native-interface-index-corrupted", codec,
         lambda s: replace_once(s, "let index = u16_at(bytes, offset_of!(libc::rt_msghdr, rtm_index))?;", "let index = u16_at(bytes, offset_of!(libc::rt_msghdr, rtm_index))?.saturating_add(1);"),
         ["--lib", "native_table_and_get_queries"]),
        # This mutation MUST run only the pure codec test. It never invokes
        # Reader/AF_ROUTE with the changed opcode, even as an unprivileged user.
        ("query-opcode-changed", codec,
         lambda s: replace_once(s, "bytes[3] = libc::RTM_GET as u8;", "bytes[3] = libc::RTM_DELETE as u8;"),
         ["--lib", "native_queries_are_get_only"]),
        ("noncontiguous-mask-accepted", codec,
         lambda s: replace_once(s, "if zero {", "if false && zero {"),
         ["--lib", "compact_masks_scope"]),
        ("foreign-query-pid-accepted", "src/connection/macos/routing/read.rs",
         lambda s: replace_once(s, "codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_pid))? != pid", "false"),
         ["--lib", "get_consumer_filters_foreign"]),
        ("egress-profile-binding-omitted", "src/connection/macos/egress.rs",
         lambda s: replace_once(s, "        if profile.kind != VpnKind::Ssl\n            || profile.id != self.profile\n            || profile.gateway != self.host\n            || profile.port != self.port\n        {\n            return Ok(false);\n        }\n", ""),
         ["--lib", "native_route_selection_is_read_only"]),
        ("probe-dns-unscoped", "src/connection/macos/resolve.rs",
         lambda s: replace_once(s, "    if index == 0 {\n        return Err(Error::Invalid);\n    }\n", ""),
         ["--lib", "native_localhost_queries"]),
    ]
    receipt = {"sourceSha256": {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for prefix in ["src", "tests"] for path in sorted((ROOT / prefix).rglob("*"))
        if path.is_file()
    }}
    try:
        with tempfile.TemporaryDirectory(prefix="copy-", dir=REPORTS) as temporary:
            copy = Path(temporary)
            for path in ["Cargo.toml", "Cargo.lock"]:
                shutil.copy2(ROOT / path, copy / path)
            for path in ["src", "tests", "ui/dist", "scripts/macos/patches"]:
                shutil.copytree(ROOT / path, copy / path)
            tests = ["--test", "route_flow", "--test", "route_leases"]
            native = ["--lib", "connection::macos"]
            receipt["baseline-policy"] = run(copy, "baseline-policy", tests, 0)
            receipt["baseline-native-read"] = run(copy, "baseline-native-read", native, 0)
            for name, path, mutation, arguments in mutations:
                file = copy / path
                original = file.read_text()
                try:
                    file.write_text(mutation(original))
                    receipt[name] = run(copy, name, arguments, 101)
                finally:
                    file.write_text(original)
            receipt["restored-policy"] = run(copy, "restored-policy", tests, 0)
            receipt["restored-native-read"] = run(copy, "restored-native-read", native, 0)
    finally:
        (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Killed {len(mutations)} mutations; copy removed. Reports: {REPORTS.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
