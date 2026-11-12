#!/usr/bin/env python3
"""Exercise transactional installation in private fixtures; never install/elevate."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/installation-engine-oracles'
spec = importlib.util.spec_from_file_location('payload_oracles', Path(__file__).with_name('check-installation.py'))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
shared.REPORTS = REPORTS
replace = shared.replace
run = shared.run


def mutations():
    base = 'src/install/engine'
    prefix = 'install::engine::tests::'
    invariant = prefix + 'invariants::'
    journal = prefix + 'journal::'
    persistence = prefix + 'install_repeat_and_remove_preserve_profiles_and_the_controller_lock_inode'
    active = invariant + 'active_controller_unknown_files_and_corrupted_receipts_refuse_mutation'
    foreign = invariant + 'observed_foreign_changes_and_a_policy_that_is_not_included_are_never_silently_adopted'
    inventory = invariant + 'installed_receipts_require_a_complete_canonical_inventory_and_matching_modes'
    links = invariant + 'destination_links_and_unsafe_permissions_are_rejected_before_mutation'
    namespace = invariant + 'no_key_in_a_payload_receipt_or_journal_can_address_a_profile_lock_or_arbitrary_path'
    damaged = journal + 'damaged_or_missing_backups_never_allow_partial_restoration'
    recovery = prefix + 'recovery::recovery_restores_interrupted_updates_but_never_overwrites_an_unrecognized_image'
    crashes = prefix + 'crash::abrupt_process_exit_is_recovered_under_the_persistent_lock'
    channel = prefix + 'channel::removal_channel_uses_kernel_identity_and_refuses_an_extra_uid_or_second_document'
    cases = [
        ('activation-lock-released-early', base + '.rs', lambda s: replace(s, 'let _guard = self.tree.bootstrap()?;\n        Journal::recover(&self.tree)?;\n        self.checks.installed(&[])?;\n        let old = Receipt::load(&self.tree)?;', 'drop(self.tree.bootstrap()?);\n        Journal::recover(&self.tree)?;\n        self.checks.installed(&[])?;\n        let old = Receipt::load(&self.tree)?;'), crashes),
        ('activation-lock-skipped', base + '.rs', lambda s: s.replace('let _guard = self.tree.bootstrap()?;', 'let _guard = ();', 1), active),
        ('unchanged-policy-replaced', base + '/plan.rs', lambda s: replace(s, 'if !changed {', 'if false {'), persistence),
        ('foreign-destination-adopted', base + '/plan.rs', lambda s: replace(s, 'return Err(Error::Conflict);', '{}'), active),
        ('installed-digest-not-checked', base + '/receipt.rs', lambda s: replace(s, 'if !image::same(image::snapshot(tree, &key)?.as_ref(), Some(&stamp)) {', 'if false {'), foreign),
        ('missing-adapter-in-receipt', base + '/receipt.rs', lambda s: replace(s, 'if !receipt.files.contains_key(&key) {', 'if false {'), inventory),
        ('receipt-modes-unchecked', base + '/receipt.rs', lambda s: replace(s, '|| stamp.mode != tree::mode(key)', '|| false'), inventory),
        ('noncanonical-receipt-accepted', base + '/receipt.rs', lambda s: replace(s, 'serde_json::to_vec(&receipt).map_err(|_| Error::Io)? != image.bytes', 'false'), inventory),
        ('hardlink-destination-accepted', base + '/image.rs', lambda s: replace(s, '        || metadata.nlink() != 1\n', ''), links),
        ('symlink-destination-followed', base + '/image.rs', lambda s: replace(s, '.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)', '.custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)'), links),
        ('unsafe-destination-mode-accepted', base + '/image.rs', lambda s: replace(s, '        || metadata.mode() & 0o7022 != 0\n', ''), links),
        ('runtime-path-escape', base + '/tree.rs', lambda s: replace(s, 'if !version_ok(version) || (name != "manifest.json" && !runtime::valid_name(name)) {', 'if false {'), namespace),
        ('policy-preservation-ignored', base + '.rs', lambda s: replace(s, 'for phase in [0, 1, 2] {', 'for phase in [2, 0, 1] {'), crashes),
        ('rollback-skipped', base + '.rs', lambda s: replace(s, '.rollback(&self.tree)', '.verify(&self.tree, false)'), prefix + 'recovery::every_injected_install_update_and_remove_failure_restores_the_previous_file_images'),
        ('foreign-recovery-overwritten', base + '/journal.rs', lambda s: replace(s, '// Refuse all restoration if any target has an unrecognized image.\n        for entry in &self.entries {', '// Mutant: skip recognized-image admission.\n        for entry in self.entries.iter().take(0) {'), recovery),
        ('backup-digest-ignored', base + '/journal.rs', lambda s: replace(s, 'if hash(&bytes) != stamp.hash {', 'if false {'), damaged),
        ('backup-preflight-skipped', base + '/journal.rs', lambda s: replace(s, 'for (index, entry) in self.entries.iter().enumerate() {\n            if entry.before.is_some()', 'for (index, entry) in self.entries.iter().enumerate().take(0) {\n            if entry.before.is_some()'), damaged),
        ('intact-before-state-not-recognized', base + '/journal.rs', lambda s: replace(s, 'if self.verify(tree, false).is_ok() {', 'if false {'), journal + 'incomplete_backup_preparation_is_discarded_only_when_live_images_are_unchanged'),
        ('committed-state-rolled-back', base + '/journal/settlement.rs', lambda s: replace(s, 'b"after\\n" => Ok(Some(true)),', 'b"after\\n" => Ok(None),'), journal + 'durable_commit_is_finalized_and_an_inconsistent_commit_marker_is_preserved'),
        ('committed-state-unverified', base + '/journal/settlement.rs', lambda s: replace(replace(s, 'journal.verify(tree, after)?;', 'let _ = after;'), 'self.verify(tree, after)?;', 'let _ = after;'), journal + 'durable_commit_is_finalized_and_an_inconsistent_commit_marker_is_preserved'),
        ('unknown-garbage-collected', base + '/journal/settlement.rs', lambda s: replace(s, 'return Err(Error::RecoveryRequired);\n            }\n            fs::remove_dir(&root)', 'fs::remove_dir_all(&root).map_err(|_| Error::RecoveryRequired)?;\n                return Ok(());\n            }\n            fs::remove_dir(&root)'), journal + 'interrupted_collection_accepts_only_recorded_terminal_contents'),
        ('ipc-unknown-fields-accepted', base + '/access/channel.rs', lambda s: replace(s, '#[serde(deny_unknown_fields)]\n', ''), channel),
        ('unregistered-user-admitted', base + '/access.rs', lambda s: replace(s, '|| !receipt.users.contains_key(&uid)', '|| false'), inventory),
    ]
    return [(label, file, mutate, ['--lib', test], test) for label, file, mutate, test in cases] + [
        ('root-admission-skipped', base + '.rs', lambda s: replace(s, 'libc::getuid() != 0 || libc::geteuid() != 0', 'false'), ['--test', 'install_preparation', 'read_only_preparation_has_no_environment_or_argument_switch_to_activation'], 'read_only_preparation_has_no_environment_or_argument_switch_to_activation'),
    ]


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run on macOS as an ordinary user; no installation, sudo or VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    mutants = mutations()
    for label, file, mutate, _, _ in mutants:
        original = (ROOT / file).read_text()
        if mutate(original) == original:
            raise RuntimeError(f'{label}: mutation changed nothing')
    inputs = [p for folder in ['src', 'tests', 'ui/src/locales'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file()]
    inputs += [ROOT / 'scripts/macos' / name for name in ['check-installation-engine.py', 'check-installation.py', 'prepare-installation.py']]
    receipt = {'sourceSha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}, 'limits': 'Same executor and native visudo, ordinary-user private filesystem/socket fixtures, owned child crash and recovery. No root activation, effective sudo policy, installation or VPN.'}
    baselines = [('engine', ['--lib', 'install::engine::tests']), ('preparation', ['--test', 'install_preparation'])]
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']: shutil.copytree(ROOT / name, copy / name)
            shutil.copy2(ROOT / 'scripts/macos/prepare-installation.py', copy / 'scripts/macos/prepare-installation.py')
            for label, selector in baselines: receipt['baseline-' + label] = run(copy, 'baseline-' + label, selector)
            for label, file, mutate, selector, expected in mutants:
                source = copy / file
                original = source.read_text()
                try:
                    source.write_text(mutate(original))
                    receipt[label] = run(copy, label, selector, expected)
                finally: source.write_text(original)
            for label, selector in baselines: receipt['restored-' + label] = run(copy, 'restored-' + label, selector)
    finally:
        (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(mutants)} executor mutations; four baselines/restorations passed; copy removed')


if __name__ == '__main__': main()
