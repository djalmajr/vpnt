#!/usr/bin/env python3
"""Exercise IPsec VICI control through independent owned Python peers."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/ipsec-control-oracles'
spec = importlib.util.spec_from_file_location('broker_oracles', Path(__file__).with_name('check-broker.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.REPORTS = REPORTS
replace = base.replace


def main():
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run as an ordinary user; no charon, PF_KEY, elevation or VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    prefix = 'connection::ipsec::tests::control::'
    binding = prefix + 'constructor_returns_the_reservation_when_config_belongs_to_another_or_retired_admission'
    lifecycle = prefix + 'lifecycle_retains_uncertainty_and_requires_both_producer_and_kernel_absence_without_replay'
    failed = prefix + 'every_failed_start_prefix_is_redacted_consumed_and_targeted_for_cleanup'
    namespace = prefix + 'namespace_conflict_and_preflight_cancellation_cannot_reach_initiate'
    rekey = prefix + 'snapshots::rekey_candidates_are_complete_and_keep_transitional_children_out_of_the_installed_set'
    invalid = prefix + 'snapshots::malformed_or_foreign_snapshot_batches_never_publish_partial_candidates'
    positive = prefix + 'snapshots::ordinary_and_ipv6_candidates_preserve_scope_and_an_empty_query_proves_no_connection'
    cancel = prefix + 'io::cancellation_during_initiate_keeps_the_live_producer_reserved_and_does_not_replay'
    deadline = prefix + 'io::deadline_during_initiate_returns_while_the_producer_is_alive_and_cleanup_has_its_own_budget'
    retire = prefix + 'io::registry_failure_still_requests_producer_retirement_and_retains_the_claim'
    control = 'src/connection/ipsec/control.rs'
    io = 'src/connection/ipsec/control/io.rs'
    registry = 'src/connection/ipsec/namespace.rs'
    snapshot = 'src/connection/ipsec/snapshot.rs'
    fields = 'src/connection/ipsec/snapshot/fields.rs'
    mutations = [
        ('config-binding-omitted', control, lambda s: replace(s, '!config.matches(&reservation)', 'false'), binding),
        ('config-binding-authority-omitted', registry, lambda s: replace(s, 'Arc::ptr_eq(&self.authority, &reservation.authority) && self.serial == reservation.serial', 'self.serial == reservation.serial'), binding),
        ('config-binding-serial-omitted', registry, lambda s: replace(s, ' && self.serial == reservation.serial', ''), binding),
        ('wrong-daemon-admitted', control, lambda s: replace(s, 'version.get_text("daemon") != Some("charon")', 'false'), failed),
        ('wrong-version-admitted', control, lambda s: replace(s, 'version.get_text("version") != Some("6.1.0")', 'false'), failed),
        ('rejected-response-accepted', io, lambda s: replace(s, 'Some("no") => Err(Error::Rejected)', 'Some("no") => Ok(())'), failed),
        ('start-replayed', control, lambda s: replace(s, 'self.phase != Phase::Prepared', 'false'), lifecycle),
        ('load-uncertainty-after-reply', control, lambda s: replace(s, '        self.loaded = true;\n        self.ack(&call, "load-conn", self.config.connection())?;', '        self.ack(&call, "load-conn", self.config.connection())?;\n        self.loaded = true;'), failed),
        ('namespace-not-rechecked', control, lambda s: replace(s, '        self.registry\n            .lock()\n            .map_err(|_| Error::Unavailable)?\n            .ensure_clear(&self.reservation)?;\n', ''), namespace),
        ('cleanup-replayed', control, lambda s: replace(s, '!self.cleanup_sent && admission.is_ok()', 'admission.is_ok()'), lifecycle),
        ('producer-retirement-not-required', control, lambda s: replace(s, 'if !retired {', 'if false {'), lifecycle),
        ('kernel-absence-not-required', registry, lambda s: replace(s, '        self.ensure_clear(reservation)?;\n', ''), lifecycle),
        ('producer-observation-not-required', registry, lambda s: replace(s, '!self.observer.producer_stopped(&reservation.owner)?', 'false'), lifecycle),
        ('registry-failure-skips-retirement', control, lambda s: replace(s, 'let admission = self.validate();', 'self.validate()?; let admission: Result<(), Error> = Ok(());'), retire),
        ('transport-loses-cancellation', io, lambda s: replace(s, 'call.expires, call.cancel.clone()', 'call.expires, Arc::new(AtomicBool::new(false))'), cancel),
        ('transport-restarts-deadline', io, lambda s: replace(s, 'call.expires, call.cancel.clone()', 'Instant::now() + Duration::from_secs(5), call.cancel.clone()'), deadline),
        ('snapshot-before-initiation', control, lambda s: replace(s, 'self.phase != Phase::Initiated', 'false'), positive),
        ('nonempty-query-completion-accepted', snapshot, lambda s: replace(s, '!result.response.is_empty()', 'false'), invalid),
        ('extra-root-fields-ignored', snapshot, lambda s: replace(s, 'root.len() != 1', 'false'), invalid),
        ('foreign-config-root-admitted', snapshot, lambda s: replace(s, 'root.get_section(config.name()).ok_or(Error::Changed)?', 'root.sections().next().map(|(_, ike)| ike).ok_or(Error::Changed)?'), invalid),
        ('ikev1-candidate-admitted', snapshot, lambda s: replace(s, 'ike.get_text("version") != Some("2")', 'false'), invalid),
        ('foreign-endpoint-admitted', snapshot, lambda s: replace(s, 'local != config.local || remote != config.remote', 'false'), invalid),
        ('foreign-child-key-admitted', snapshot, lambda s: replace(s, 'key != format!("{}-{child_id}", config.child_name())', 'false'), invalid),
        ('foreign-child-name-admitted', snapshot, lambda s: replace(s, 'child.get_text("name") != Some(config.child_name())', 'false'), invalid),
        ('foreign-reqid-admitted', snapshot, lambda s: replace(s, 'reqid != u32::from(config.reqid) && reqid != 0', 'false'), invalid),
        ('transport-mode-admitted', snapshot, lambda s: replace(s, 'child.get_text("mode") != Some("TUNNEL")', 'false'), invalid),
        ('ah-protocol-admitted', snapshot, lambda s: replace(s, 'child.get_text("protocol") != Some("ESP")', 'false'), invalid),
        ('zero-installed-reqid-admitted', snapshot, lambda s: replace(s, 'if reqid == 0', 'if false'), invalid),
        ('zero-child-spi-admitted', fields, lambda s: replace(s, 'if !zero && parsed == 0 {', 'if false {'), invalid),
        ('short-child-spi-admitted', fields, lambda s: replace(s, 'value.len() != width', 'false'), invalid),
        ('noncanonical-id-admitted', fields, lambda s: replace(s, 'parsed.to_string() != value', 'false'), invalid),
        ('duplicate-ike-id-admitted', snapshot, lambda s: replace(s, '!ike_ids.insert(ike_id)', '{ ike_ids.insert(ike_id); false }'), invalid),
        ('duplicate-child-id-admitted', snapshot, lambda s: replace(s, '!child_ids.insert(child_id)', '{ child_ids.insert(child_id); false }'), invalid),
        ('duplicate-spi-admitted', snapshot, lambda s: replace(s, '!spis.insert((true, spi_in)) || !spis.insert((false, spi_out))', 'false && (!spis.insert((true, spi_in)) || !spis.insert((false, spi_out)))'), invalid),
        ('wide-local-selector-admitted', snapshot, lambda s: replace(s, '*ts == Network::host(*ip)', 'true'), invalid),
        ('wide-remote-selector-admitted', snapshot, lambda s: replace(s, 'n.prefix() <= ts.prefix() && ', ''), invalid),
        ('foreign-remote-selector-admitted', snapshot, lambda s: replace(s, 'n.contains(ts.address())', 'true'), invalid),
        ('unpaired-selector-families-admitted', snapshot, lambda s: replace(s, 'families(&local_ts) != families(&remote_ts)', 'false'), invalid),
        ('transitional-child-rejected', snapshot, lambda s: replace(s, '                    continue;\n', '                    return Err(Error::Invalid);\n'), rekey),
        ('old-rekeyed-candidate-active', snapshot, lambda s: replace(s, 'active: matches!(state, "ESTABLISHED" | "REKEYING")\n                    && matches!(child_state, "INSTALLED" | "REKEYING"),', 'active: true,'), rekey),
        ('complete-candidates-discarded', snapshot, lambda s: replace(s, '    Ok(output)\n', '    Ok(Vec::new())\n'), rekey),
        ('candidate-count-unbounded', snapshot, lambda s: replace(s, 'child_ids.len() > 256', 'false'), invalid),
        ('invalid-encapsulation-shape-admitted', fields, lambda s: replace(s, 'message.get_list(key).is_some() || message.get_section(key).is_some()', 'false'), invalid),
        ('unspecified-vip-admitted', fields, lambda s: replace(s, '!Address::unscoped(ip).valid_gateway()', 'false'), invalid),
        ('empty-query-rejected', snapshot, lambda s: replace(s, '    let mut ike_ids', '    if result.events.is_empty() { return Err(Error::Invalid); }\n    let mut ike_ids'), positive),
        ('ipv6-selector-rejected', fields, lambda s: replace(s, "    if value.contains('/') {", "    if value.contains(':') { return Err(Error::Invalid); }\n    if value.contains('/') {"), positive),
    ]
    for label, file, mutate, _ in mutations:
        source = (ROOT / file).read_text()
        if mutate(source) == source: raise RuntimeError(f'{label}: unchanged mutation')
    files = [p for folder in ['src', 'tests'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file()]
    files += [Path(__file__), Path(__file__).with_name('check-broker.py'), ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    receipt = {'sourceSha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
               'limits': 'Public Control lifecycle and complete VICI candidates over owned independent Python processes/sockets. Namespace observations injected. No charon/native PID admission/PF_KEY/probe, privileged installation or VPN.'}
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']: shutil.copytree(ROOT / name, copy / name)
            receipt['baseline'] = base.run(copy, 'baseline', prefix)
            for label, file, mutate, expected in mutations:
                target = copy / file
                original = target.read_text()
                try:
                    target.write_text(mutate(original))
                    receipt[label] = base.run(copy, label, expected, expected)
                finally: target.write_text(original)
            receipt['restored'] = base.run(copy, 'restored', prefix)
    finally: (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(mutations)} IPsec control mutations; baseline/restoration passed; copy removed')


if __name__ == '__main__': main()
