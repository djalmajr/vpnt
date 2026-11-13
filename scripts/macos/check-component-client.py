#!/usr/bin/env python3
"""Component client and native actor oracles; ordinary-user fictional peers only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/component-client-oracles'
spec = importlib.util.spec_from_file_location('broker_oracles', Path(__file__).with_name('check-broker.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.REPORTS = REPORTS
replace = base.replace
spec = importlib.util.spec_from_file_location('rust_build_inputs', Path(__file__).with_name('rust_build_inputs.py'))
build_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_inputs)


def without_eof(source):
    start = source.index('    if read(stream, &mut input, deadline, state)?.is_some() {')
    end = source.index('    result\n', start)
    return source[:start] + source[end:]


def main():
    global REPORTS
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run as an ordinary macOS user; no Installer, sudo or VPN')
    selected = set(sys.argv[2:]) if sys.argv[1:2] == ['--only'] else set()
    if sys.argv[1:] and not selected:
        raise SystemExit('Use --only followed by mutation labels, or no arguments')
    if selected:
        REPORTS = REPORTS.with_name(REPORTS.name + '-selected')
        base.REPORTS = REPORTS
    REPORTS.mkdir(parents=True, exist_ok=True)
    client = 'install::client::tests::'
    broker = 'broker::component::tests::'
    lifecycle = broker + 'lifecycle::'
    gate = client + 'admitted_component_process_cannot_start_before_the_controller_releases_its_gate'
    timeout = client + 'deadline_or_cancel_before_handoff_never_launches_a_component_process'
    owned = client + 'removal_receipt_and_eof_do_not_report_success_before_the_owned_child_has_exited'
    invalid = client + 'incompatible_wrong_extra_or_excessive_removal_replies_never_commit_and_exit_must_succeed'
    late = client + 'expired_operation_is_reported_but_its_live_child_is_never_killed_or_treated_as_finished'
    flow = broker + 'installation_waits_for_runtime_cleanup_then_for_its_child_and_a_fresh_authenticated_snapshot'
    held = lifecycle + 'timeout_retains_exclusion_while_the_child_lives_and_never_replays_or_sends_late_success'
    removed = lifecycle + 'removal_preserves_secrets_and_never_restarts_a_runtime_for_the_unregistered_user'
    actor = 'desktop::worker::tests::component::component_reply_keeps_its_native_request_id_and_waits_without_blocking_snapshot_or_hide'
    worker = 'src/install/client/worker.rs'
    wire = 'src/install/client/removal.rs'
    coordinator = 'src/broker/component.rs'
    mutants = [
        ('relative-component-program-accepted', worker, lambda s: replace(s, 'if !std::path::Path::new(plan.command.get_program()).is_absolute()', 'if false'), lifecycle + 'artifact_admission_failure_does_not_disconnect_the_existing_runtime', False),
        ('cached-removal-authorization', 'src/install/client/plan.rs', lambda s: replace(s, '["-A", "-k", "--", paths::INSTALLER, "remove"]', '["-A", "--", paths::INSTALLER, "remove"]'), client + 'component_launches_have_fixed_programs_arguments_and_no_shell_or_saved_state_reset', False),
        ('handoff-gate-ignored', worker, lambda s: replace(s, 'while !state.proceed.load(Ordering::Acquire)', 'while false'), gate, False),
        ('cancel-ignored', 'src/install/client.rs', lambda s: replace(s, 'if state.stop.load(Ordering::Acquire)', 'if false'), timeout, False),
        ('deadline-ignored', 'src/install/client.rs', lambda s: replace(s, 'if Instant::now() >= expires', 'if false'), timeout, False),
        ('receipt-before-owned-child-exit', worker, lambda s: replace(s, '        if let Err(error) = receipt {', '        if let Ok(Some(r)) = &receipt { publish(&state, Ok(r.clone())); }\n        if let Err(error) = receipt {'), owned, False),
        ('failed-exit-accepted', worker, lambda s: replace(s, 'if !status.success()', 'if false'), invalid, False),
        ('inherited-environment', worker, lambda s: replace(s, '            .env_clear()\n', ''), owned, False),
        ('selected-locale-lost', worker, lambda s: replace(s, '.env("VPNT_AUTH_LOCALE", locale.code())', '.env("VPNT_AUTH_LOCALE", "en-US")'), owned, False),
        ('format-ignored', wire, lambda s: replace(s, 'format == protocol::FORMAT && ', ''), invalid, False),
        ('version-ignored', wire, lambda s: replace(s, 'version == env!("CARGO_PKG_VERSION")', 'true'), invalid, False),
        ('reply-id-ignored', wire, lambda s: s.replace('if got == id', 'if true'), invalid, False),
        ('extra-reply-accepted', wire, without_eof, invalid, False),
        ('request-eof-omitted', wire, lambda s: replace(s, '    stream\n        .shutdown(Shutdown::Write)\n        .map_err(|_| Error::Unavailable)?;\n', ''), owned, False),
        ('frame-bounds-broadened', wire, lambda s: s.replace('4096', '16384'), invalid, False),
        ('late-result-republished', 'src/install/client.rs', lambda s: replace(s, 'if !state.published.swap(true, Ordering::AcqRel)', 'if true'), late, False),
        ('old-runtime-reap-ignored', coordinator, lambda s: replace(s, 'self.client.as_ref().is_none_or(Client::finished)', 'true'), flow, False),
        ('retry-during-component-change', coordinator, lambda s: replace(s, '.is_some_and(|p| p.phase != Phase::Verifying)', '.is_some_and(|_| false)'), flow, False),
        ('timed-out-child-forgotten', coordinator, lambda s: replace(s, 'if op.reported {\n            if op.client.finished()', 'if op.reported {\n            if true'), held, False),
        ('settling-hidden-from-ui', coordinator, lambda s: replace(s, '                "settling"', '                "installing"'), held, False),
        ('fresh-snapshot-not-required', coordinator, lambda s: replace(s, 'op.phase == Phase::Verifying && self.ready && self.epoch > op.epoch', 'op.phase == Phase::Verifying'), lifecycle + 'an_incompatible_new_session_cannot_turn_installer_exit_into_installation_success', False),
        ('removed-user-reconnected', coordinator, lambda s: replace(s, 'self.component.disabled = true;', 'self.component.disabled = false;'), removed, False),
        ('removal-deletes-keychain', coordinator, lambda s: replace(s, '(Kind::Remove, Some(Ok(Receipt::Removed { .. }))) => {', '(Kind::Remove, Some(Ok(Receipt::Removed { .. }))) => {\n                        for c in self.connections.values() { let _ = self.secrets.remove(&c.view.profile.id, c.view.profile.kind); }'), removed, False),
        ('quit-allows-new-component-change', coordinator, lambda s: replace(s, '        self.closed = true;', '        self.closed = false;'), lifecycle + 'quitting_during_a_component_operation_never_restarts_runtime_or_admits_another_change', False),
        ('component-mutation-exclusion-omitted', 'src/broker/commands.rs', lambda s: replace(s, 'if self.component.busy()', 'if false'), held, False),
        ('native-reply-id-lost', 'src/desktop/worker.rs', lambda s: replace(s, 'if let Some((token, result)) = normal.take_component_result()\n                            && let Some(id) = administrative.remove(&token)\n                        {\n                            reply(response(id, result));', 'if let Some((token, result)) = normal.take_component_result()\n                            && let Some(_id) = administrative.remove(&token)\n                        {\n                            reply(response("wrong-id".into(), result));'), actor, True),
    ]
    if selected - {m[0] for m in mutants}:
        raise SystemExit('Unknown mutation label')
    if selected:
        mutants = [m for m in mutants if m[0] in selected]
    for label, file, mutate, _, _ in mutants:
        if mutate((ROOT / file).read_text()) == (ROOT / file).read_text():
            raise RuntimeError(f'{label}: unchanged mutation')
    inputs = [p for folder in ['src', 'tests', 'ui/src'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file()]
    inputs += [Path(__file__), Path(__file__).with_name('check-broker.py')]
    inputs += build_inputs.source_files(ROOT)
    unique, seen = [], set()
    for path in sorted(inputs, key=lambda p: str(p.relative_to(ROOT))):
        key = str(path.relative_to(ROOT))
        if key not in seen:
            seen.add(key)
            unique.append(path)
    inputs = unique
    receipt = {'sourceSha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}, 'limits': 'Ordinary-user processes/socketpairs, synthetic component admission. No root ownership positive gate, sudo/PAM/Installer/PackageKit, installed helper, real VPN, signals to a discovered PID or native GUI proof.'}
    baselines = [('client', 'install::client::tests', False), ('broker', 'broker::component::tests', False), ('actor', actor, True)]
    if selected:
        baselines = [b for b in baselines if any(m[3].startswith(b[1]) for m in mutants)]
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/dist', 'ui/src']: shutil.copytree(ROOT / name, copy / name)
            build_inputs.copy_into(ROOT, copy)
            for label, test, desktop in baselines: receipt['baseline-' + label] = base.run(copy, 'baseline-' + label, test, desktop=desktop)
            for label, file, mutate, test, desktop in mutants:
                path = copy / file
                original = path.read_text()
                try:
                    path.write_text(mutate(original))
                    receipt[label] = base.run(copy, label, test, test, desktop)
                finally: path.write_text(original)
            for label, test, desktop in baselines: receipt['restored-' + label] = base.run(copy, 'restored-' + label, test, desktop=desktop)
    finally: (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(mutants)} component mutations; {len(baselines) * 2} baselines/restorations passed; copy removed')


if __name__ == '__main__': main()
