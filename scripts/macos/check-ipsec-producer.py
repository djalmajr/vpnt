#!/usr/bin/env python3
"""Discriminating native producer mutations with owned C fixtures, never charon."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/ipsec-producer-oracles'
spec = importlib.util.spec_from_file_location('broker_oracles', Path(__file__).with_name('check-broker.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.REPORTS = REPORTS
replace = base.replace


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run as an ordinary macOS user; no charon/PF_KEY/installation/VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    prefix = 'connection::ipsec::producer::tests::'
    lifecycle = prefix + 'owned_native_child_is_bound_to_a_durable_attempt_and_completion_waits_for_absence'
    foreign = prefix + 'foreign_peer_process_and_exited_children_are_refused_without_respawn'
    altered = prefix + 'altered_configuration_denies_io_but_still_retires_only_the_owned_child'
    dormant = prefix + 'canceled_preflight_and_dropped_claims_remain_exclusive_across_context_restart'
    phases = prefix + 'admission::persistent_phase_transitions_never_reenter_a_spent_attempt'
    socket = prefix + 'admission::an_existing_runtime_socket_is_preserved_and_cannot_trigger_spawn'
    budgets = prefix + 'admission::socket_wait_honors_cancellation_and_deadline_and_retains_the_original_producer'
    binding = prefix + 'binding::native_admission_requires_the_original_reservation_and_configuration_and_excludes_durable_reqids'
    completion = 'connection::ipsec::tests::namespace::durable_completion_follows_both_observations_and_failure_keeps_the_slot_exclusive'
    context = 'src/connection/ipsec/producer/mod.rs'
    state = 'src/connection/ipsec/producer/state.rs'
    child = 'src/connection/ipsec/producer/child.rs'
    files = 'src/connection/ipsec/producer/files.rs'
    config = 'src/connection/ipsec/producer/config.rs'
    process = 'src/helper/process.rs'
    registry = 'src/connection/ipsec/namespace.rs'
    callback = '        self.observer\n            .completed(&reservation.owner, reservation.reqid)?;\n'
    phase_guard = '''        if !matches!(
            (self.record.stage, stage),
            (Stage::Prepared, Stage::Starting | Stage::Stopped)
                | (Stage::Starting, Stage::Running | Stage::Stopped)
                | (Stage::Running, Stage::Stopped)
        ) {
            return Err(Error::Changed);
        }
'''
    stop = '''        if let Some(child) = self.child.as_mut() {
            child
                .stop(Duration::from_secs(3))
                .map_err(|_| Error::Unavailable)?;
        }
'''
    prune = '''        self.active
            .lock()
            .map_err(|_| Error::Unavailable)?
            .remove(&p.lease.record.session);
'''
    mutations = [
        ('root-admission-omitted', context, lambda s: replace(s, 'if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {', 'if false {'), lifecycle),
        ('config-binding-omitted', context, lambda s: replace(s, '!configuration.matches(reservation)', 'false'), binding),
        ('reservation-authority-omitted', context, lambda s: replace(s, '        registry.validate(reservation)?;\n', ''), binding),
        ('durable-reqid-collision-ignored', state, lambda s: replace(s, 'r.reqid == reservation.reqid()', 'false'), binding),
        ('durable-profile-collision-ignored', state, lambda s: replace(s, '(r.uid == reservation.owner().uid && r.profile == reservation.owner().profile)', 'false'), dormant),
        ('dormant-reqid-forgotten', context, lambda s: replace(s, 'ids.extend(self.context.unrepresented()?);', 'let _ = self.context.unrepresented()?;'), dormant),
        ('drop-deletes-uncertain-claim', child, lambda s: replace(s, '        let _ = self.retire();', '        let _ = self.retire(); let _ = self.lease.complete();'), dormant),
        ('configuration-digest-unchecked', state, lambda s: replace(s, ' || digest(&conf) != self.record.configuration_hash', ''), altered),
        ('configuration-inode-unchecked', state, lambda s: replace(s, 'stamp != self.config_stamp || ', ''), altered),
        ('configuration-readable-by-others', files, lambda s: replace(s, '|| meta.mode() & 0o7777 != 0o600', '|| false'), altered),
        ('socket-peer-pid-unchecked', 'src/connection/ipsec/producer/socket.rs', lambda s: replace(s, '        || peer as u32 != pid\n', ''), foreign),
        ('foreign-owner-can-retire', context, lambda s: replace(s, 'p.lease.record.owner() != *owner', 'false'), lifecycle),
        ('owned-child-not-retired', child, lambda s: replace(s, stop, ''), lifecycle),
        ('admission-failure-skips-owned-retirement', child, lambda s: replace(s, '        // Stop only our unreaped Child,', '        self.context.validate()?; self.lease.validate()?;\n        // Stop only our unreaped Child,'), altered),
        ('persistent-phase-reentered', state, lambda s: replace(s, phase_guard, ''), phases),
        ('completed-claim-retained', context, lambda s: replace(s, '        p.lease.complete()?;\n', ''), lifecycle),
        ('completed-producer-retained', context, lambda s: replace(s, prune, ''), lifecycle),
        ('durable-completion-omitted', registry, lambda s: replace(s, callback, ''), completion),
        ('memory-slot-freed-before-durable-completion', registry, lambda s: replace(s, callback, '        self.entries.remove(&reservation.reqid);\n' + callback), completion),
        ('durable-completion-before-producer-observation', registry, lambda s: replace(s, '        if !self.observer.producer_stopped(&reservation.owner)? {', callback + '        if !self.observer.producer_stopped(&reservation.owner)? {'), completion),
        ('producer-cancellation-ignored', child, lambda s: replace(s, 'if cancel.load(Ordering::Acquire) {', 'if false {'), budgets),
        ('producer-deadline-extended', child, lambda s: replace(s, 'Instant::now() >= expires', 'Instant::now() >= expires + Duration::from_secs(1)'), budgets),
        ('preexisting-runtime-socket-admitted', child, lambda s: replace(s, 'for name in ["v", "pid"] {', 'for name in ["pid"] {'), socket),
        ('inherited-environment-admitted', process, lambda s: replace(s, '            .env_clear()\n', ''), lifecycle),
        ('charon-stdin-piped', process, lambda s: replace(s, '.stdin(Stdio::null())', '.stdin(Stdio::piped())'), lifecycle),
        ('charon-stdout-piped', process, lambda s: replace(s, '.stdout(Stdio::null())', '.stdout(Stdio::piped())'), lifecycle),
        ('charon-stderr-piped', process, lambda s: replace(s, '.stderr(Stdio::null())', '.stderr(Stdio::piped())'), lifecycle),
        ('charon-shared-ike-port', config, lambda s: replace(s, 'port = 0', 'port = 500'), lifecycle),
        ('charon-automatic-routes', config, lambda s: replace(s, 'install_routes = no', 'install_routes = yes'), lifecycle),
        ('charon-automatic-virtual-ip', config, lambda s: replace(s, 'install_virtual_ip = no', 'install_virtual_ip = yes'), lifecycle),
    ]
    for label, file, mutate, _ in mutations:
        source = (ROOT / file).read_text()
        if mutate(source) == source:
            raise RuntimeError(f'{label}: unchanged mutation')
    inputs = [p for folder in ['src', 'tests'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file()]
    inputs += [Path(__file__), Path(__file__).with_name('check-broker.py'), ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    receipt = {'sourceSha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
               'limits': 'Owned unprivileged Mach-O C producer; original process/UDS identity and filesystem admission. Kernel absence injected; no charon/PF_KEY/privilege/VPN.'}
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']:
                shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']:
                shutil.copytree(ROOT / name, copy / name)
            receipt['baseline'] = base.run(copy, 'baseline', 'connection::ipsec::')
            for label, file, mutate, expected in mutations:
                target = copy / file
                original = target.read_text()
                try:
                    target.write_text(mutate(original))
                    receipt[label] = base.run(copy, label, expected, expected)
                finally:
                    target.write_text(original)
            receipt['restored'] = base.run(copy, 'restored', 'connection::ipsec::')
    finally:
        (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(mutations)} native producer mutations; baseline/restoration passed; temporary copy removed')


if __name__ == '__main__':
    main()
