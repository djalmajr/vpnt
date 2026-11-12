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


def omit_scope_sweep(source):
    start = source.index("        for route in plan {")
    end = source.index("        self.entries.remove(&token.index);", start)
    return source[:start] + source[end:]


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
        ("controller-flock-bypassed", "src/helper/controller_lock.rs",
         lambda s: replace_once(s, "unsafe { libc::flock(guard.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0", "false"),
         ["--lib", "independent_process_cannot_enter"]),
        ("controller-inode-identity-ignored", "src/helper/controller_lock.rs",
         lambda s: replace_once(s, " || named.dev() != opened.dev() || named.ino() != opened.ino()", ""),
         ["--lib", "replaced_inode_and_changed_permissions"]),
        ("controller-acl-ignored", "src/helper/controller_lock.rs",
         lambda s: replace_once(s, "        crate::fs_permissions::check_file(&self.file, true)\n            .map_err(|_| LockError::UntrustedPath)?;\n", ""),
         ["--lib", "an_extended_acl_cannot_expose"]),
        ("controller-hardlink-accepted", "src/helper/controller_lock.rs",
         lambda s: replace_once(s, "        || metadata.nlink() != 1\n", ""),
         ["--lib", "absent_special_linked_or_exposed_lock"]),
        # ADD mutations execute only the C/private-AF_UNIX consumer. They never
        # call AddWriter::open or send any opcode to an actual PF_ROUTE socket.
        ("add-opcode-changed", "src/connection/macos/routing/add_codec.rs",
         lambda s: replace_once(s, "bytes[3] = libc::RTM_ADD as u8;", "bytes[3] = libc::RTM_DELETE as u8;"),
         ["--lib", "add_consumer_uses_sdk_abi"]),
        ("add-interface-corrupted", "src/connection/macos/routing/add_codec.rs",
         lambda s: replace_once(s, "put16(&mut link, 2, route.interface);", "put16(&mut link, 2, route.interface + 1);"),
         ["--lib", "add_consumer_uses_sdk_abi"]),
        ("add-source-zone-omitted", "src/connection/macos/routing/add_codec.rs",
         lambda s: replace_once(s, "put32(&mut bytes, 24, address.zone);", "put32(&mut bytes, 24, 0);"),
         ["--lib", "add_consumer_uses_sdk_abi"]),
        ("add-foreign-pid-accepted", "src/connection/macos/routing/write.rs",
         lambda s: replace_once(s, "codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_pid))? != pid", "false"),
         ["--lib", "add_consumer_uses_sdk_abi"]),
        ("add-foreign-sequence-accepted", "src/connection/macos/routing/write.rs",
         lambda s: replace_once(s, "codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_seq))? != sequence", "false"),
         ["--lib", "add_consumer_uses_sdk_abi"]),
        ("add-source-mismatch-ignored", "src/connection/macos/routing/write.rs",
         lambda s: replace_once(s, " || actual.source != Some(source)", ""),
         ["--lib", "add_consumer_uses_sdk_abi"]),
        ("add-lost-ack-accepted", "src/connection/macos/routing/write.rs",
         lambda s: replace_once(s, "        confirm(fd, route, source, pid, sequence, deadline, canceled)", "        match confirm(fd, route, source, pid, sequence, deadline, canceled) { Err(Error::TimedOut) => Ok(()), result => result }"),
         ["--lib", "add_consumer_uses_sdk_abi"]),
        ("add-canceled-attempt-forgotten", "src/connection/macos/routing/write.rs",
         lambda s: replace_once(s, "    Ok(AddReceipt {\n        route,\n        confirmation,\n    })", "    confirmation?;\n    Ok(AddReceipt { route, confirmation })"),
         ["--lib", "cancellation_after_dispatch"]),
        ("ppp-attachment-readback-omitted", "src/connection/macos/ppp_attachment.rs",
         lambda s: replace_once(s, "    socket.verify(api)?;\n", ""),
         ["--lib", "a_raced_or_mismatched_attachment"]),
        ("ppp-attachment-final-owner-check-omitted", "src/connection/macos/ppp_attachment.rs",
         lambda s: replace_once(s, "    socket.verify(api)?;\n    if !current()? {", "    socket.verify(api)?;\n    if false && !current()? {"),
         ["--lib", "a_raced_or_mismatched_attachment"]),
        ("native-coordinator-authorization-omitted", lease,
         lambda s: replace_once(s, "        self.backend.authorize(owner, route)?;\n", ""),
         ["--lib", "coordinator_admission_checks_the_registered"]),
        ("native-network-plan-guard-omitted", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "        if !entry.plan.contains(&route) {\n            return Err(Error::Invalid);\n        }\n", ""),
         ["--lib", "only_registered_networks"]),
        ("native-exact-postflight-omitted", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "Ok(_) => Err(Error::Changed),", "Ok(_) => Ok(()),"),
         ["--lib", "an_ack_without_an_observed_exact"]),
        ("native-unconfirmed-attempt-accepted", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "receipt.confirmation.is_err()", "false"),
         ["--lib", "lost_ack_or_postflight_read_failure"]),
        ("native-attempt-receipt-forgotten", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "        Ok(NativeReceipt {", "        attempt.confirmation?;\n        Ok(NativeReceipt {"),
         ["--lib", "lost_ack_or_postflight_read_failure"]),
        ("native-read-failure-clears-receipt", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "self.table.exact(key).map_err(|_| Error::Unavailable)", "self.table.exact(key)"),
         ["--lib", "lost_ack_or_postflight_read_failure"]),
        ("native-scope-sweep-forgotten", "src/connection/macos/routing/backend/registry.rs", omit_scope_sweep,
         ["--lib", "borrowed_routes_are_still_checked"]),
        ("native-detach-gate-omitted", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "if !entry.scope.detach_if_stopped()?", "if false && !entry.scope.detach_if_stopped()?"),
         ["--lib", "confirmed_routes_stay_pending"]),
        ("native-scope-generation-ignored", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, ".filter(|entry| entry.serial == token.scope)", ".filter(|_| true)"),
         ["--lib", "backend_and_generation_tokens"]),
        ("native-scope-backend-ignored", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "        if token.backend != self.id {\n            return Err(Error::Invalid);\n        }\n", ""),
         ["--lib", "backend_and_generation_tokens"]),
        ("native-same-index-change-called-foreign", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "        if now != receipt.route {\n            return Err(Error::Busy);\n        }", "        if now != receipt.route { return Ok(Presence::Replaced); }"),
         ["--lib", "replacements_are_preserved"]),
        ("native-secondary-target-ignored", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "&& self.entry(token)?.scope.owns(now.interface)", "&& now.interface == token.index"),
         ["--lib", "mixed_owned_targets_all"]),
        ("native-other-owned-target-called-foreign", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "return if still_ours {", "return if false && still_ours {"),
         ["--lib", "a_route_moved_to_another_owned_target"]),
        ("native-exact-key-approximated", "src/connection/macos/routing/read.rs",
         lambda s: replace_once(s, "record.key == key", "record.key.network.contains(key.network.address())"),
         ["--lib", "exact_snapshot_lookup_cannot_substitute"]),
        ("ppp-one-process-exit-accepted", "src/connection/macos/ppp.rs",
         lambda s: replace_once(s, "            && watches\n", "            || watches\n"),
         ["--lib", "owned_ppp_exit_requires_both_original"]),
        # UTUN mutations use injected syscalls/owned AF_UNIX descriptors and
        # the stdin-only SDK consumer. None creates an actual UTUN or alias.
        ("sink-packet-direction-left-enabled", "src/connection/macos/sink.rs",
         lambda s: replace_once(s, "api.set_flags(fd.as_raw_fd(), DROP_BOTH)", "api.set_flags(fd.as_raw_fd(), 1)"),
         ["--lib", "sink_disables_packets_before_alias"]),
        ("sink-preexisting-interface-accepted", "src/connection/macos/sink.rs",
         lambda s: replace_once(s, "entry.name == name || entry.index == interface.index", "false"),
         ["--lib", "sink_refuses_preexisting_names"]),
        ("sink-partial-alias-intent-forgotten", "src/connection/macos/sink.rs",
         lambda s: replace_once(s, "        retired.as_mut().unwrap().source = Some(source);\n", ""),
         ["--lib", "sink_failures_close_only_owned"]),
        ("sink-postflight-validation-omitted", "src/connection/macos/sink.rs",
         lambda s: replace_once(s, "        socket.validate(api)?;\n", ""),
         ["--lib", "sink_failures_close_only_owned"]),
        ("sink-host-route-collision-ignored", "src/connection/macos/sink.rs",
         lambda s: replace_once(s, ".any(|record| record.key.network == Network::host(source))", ".any(|_record| false)"),
         ["--lib", "sink_skips_addresses_and_host_routes"]),
        ("sink-ipv6-prefix-not-host", "src/connection/macos/sink/native.rs",
         lambda s: replace_once(s, "bytes[80..96].fill(255)", "bytes[80..96].fill(0)"),
         ["--lib", "sink_native_requests_match_independent"]),
        ("sink-ipv6-dad-not-disabled", "src/connection/macos/sink/native.rs",
         lambda s: replace_once(s, "&0x20u32.to_ne_bytes()", "&0u32.to_ne_bytes()"),
         ["--lib", "sink_native_requests_match_independent"]),
        ("sink-requests-existing-unit", "src/connection/macos/sink/native.rs",
         lambda s: replace_once(s, "sc_unit: 0,", "sc_unit: 1,"),
         ["--lib", "sink_native_requests_match_independent"]),
        ("native-implicit-cleanup-gate-omitted", "src/connection/macos/routing/backend/registry.rs",
         lambda s: replace_once(s, "        if !self\n            .entry(token)?", "        if false && !self\n            .entry(token)?"),
         ["--lib", "implicit_cleanup_keeps_full_tunnel"]),
        ("native-failed-scope-retirement-forgotten", "src/connection/macos/routing/backend/retirement.rs",
         lambda s: replace_once(s, ".push(resource);", ".extend(std::iter::empty::<Retirement>());"),
         ["--lib", "failed_scope_retains_retirement"]),
        ("native-implicit-ppp-local-route-ignored", "src/connection/macos/routing/backend/retirement.rs",
         lambda s: replace_once(s, ".any(|record| record.key.network == Network::host(source))", ".any(|_record| false)"),
         ["--lib", "retirement_waits_for_unplanned"]),
        ("native-pending-retirement-admitted", "src/connection/macos/routing/backend/retirement.rs",
         lambda s: replace_once(s, "if !queue.lock().map_err(|_| Error::Unavailable)?.is_empty()", "if false && !queue.lock().map_err(|_| Error::Unavailable)?.is_empty()"),
         ["--lib", "failed_scope_retains_retirement"]),
        ("controller-old-worker-status-accepted", "src/connection/controller/engine.rs",
         lambda s: replace_once(s, "worker.generation == slot.generation", "true"),
         ["--lib", "reconnect_waits_for_cleanup"]),
        ("controller-replacement-starts-before-cleanup", "src/connection/controller/engine.rs",
         lambda s: replace_once(s, "if !closing && slot.worker.is_none() && slot.pending.is_some()", "if !closing && slot.pending.is_some()"),
         ["--lib", "reconnect_waits_for_cleanup"]),
        ("controller-stale-operation-accepted", "src/connection/controller/engine/dispatch.rs",
         lambda s: replace_once(s, "generation <= slot.generation", "false"),
         ["--lib", "stale_operations_and_invalid_secrets"]),
        ("controller-cleanup-loop-forgotten", "src/connection/controller/worker.rs",
         lambda s: replace_once(s, "while !attempt.cleanup()", "while false && !attempt.cleanup()"),
         ["--lib", "controller_connects_only_after_leases"]),
        ("controller-retirement-exit-gate-omitted", "src/connection/controller/engine.rs",
         lambda s: replace_once(s, "&& factory.idle()", "&& true"),
         ["--lib", "profiles_run_concurrently_and_eof"]),
        ("controller-untested-tunnel-connected", "src/connection/controller/worker.rs",
         lambda s: replace_once(s, "send(ConnectionState::Verifying)", "send(ConnectionState::Connected)"),
         ["--lib", "controller_connects_only_after_leases"]),
        ("controller-unresponsive-probe-accepted", "src/connection/controller/worker.rs",
         lambda s: replace_once(s, "send(if responsive {", "send(if true {"),
         ["--lib", "controller_connects_only_after_leases"]),
        ("controller-queued-reconnect-survives-disconnect", "src/connection/controller/engine/dispatch.rs",
         lambda s: replace_once(s, "            slot.pending = None;\n", ""),
         ["--lib", "cancel_before_discovery_does_not_forget"]),
        ("early-unattributed-ppp-forgotten", "src/connection/macos/ppp_early_cleanup.rs",
         lambda s: replace_once(s, "before.entries.get(&interface.name) != Some(interface)", "false"),
         ["--lib", "early_cleanup_preserves_before"]),
        ("early-unknown-route-forgotten", "src/connection/macos/ppp_early_cleanup.rs",
         lambda s: replace_once(s, "        return false;\n    }\n    true\n}", "        return true;\n    }\n    true\n}"),
         ["--lib", "early_cleanup_requires_implicit"]),
    ]
    receipt = {"sourceSha256": {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for prefix in ["src", "tests", "ui/src/locales"] for path in sorted((ROOT / prefix).rglob("*"))
        if path.is_file()
    }}
    try:
        with tempfile.TemporaryDirectory(prefix="copy-", dir=REPORTS) as temporary:
            copy = Path(temporary)
            for path in ["Cargo.toml", "Cargo.lock"]:
                shutil.copy2(ROOT / path, copy / path)
            for path in ["src", "tests", "ui/dist", "scripts/macos/patches", "ui/src/locales"]:
                shutil.copytree(ROOT / path, copy / path)
            tests = ["--test", "route_flow", "--test", "route_leases"]
            native = ["--lib", "connection::macos"]
            lock = ["--lib", "helper::controller_lock"]
            controller = ["--lib", "connection::controller"]
            receipt["baseline-policy"] = run(copy, "baseline-policy", tests, 0)
            receipt["baseline-native-consumers"] = run(copy, "baseline-native-consumers", native, 0)
            receipt["baseline-controller-lock"] = run(copy, "baseline-controller-lock", lock, 0)
            receipt["baseline-controller"] = run(copy, "baseline-controller", controller, 0)
            for name, path, mutation, arguments in mutations:
                file = copy / path
                original = file.read_text()
                try:
                    file.write_text(mutation(original))
                    receipt[name] = run(copy, name, arguments, 101)
                finally:
                    file.write_text(original)
            receipt["restored-policy"] = run(copy, "restored-policy", tests, 0)
            receipt["restored-native-consumers"] = run(copy, "restored-native-consumers", native, 0)
            receipt["restored-controller-lock"] = run(copy, "restored-controller-lock", lock, 0)
            receipt["restored-controller"] = run(copy, "restored-controller", controller, 0)
    finally:
        (REPORTS / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Killed {len(mutations)} mutations; copy removed. Reports: {REPORTS.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
