#!/usr/bin/env python3
"""Administrative client/actor oracles; fictional peers, no sudo or installation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/admin-client-oracles'
spec = importlib.util.spec_from_file_location('broker_oracles', Path(__file__).with_name('check-broker.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.REPORTS = REPORTS
replace = base.replace

def without_eof(source):
    a = source.index('    if read(channel, &mut input, deadline, state)?.is_some() {')
    b = source.index('    result\n', a)
    return source[:a] + source[b:]

def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit('Run on macOS as an ordinary user; no privileged resources')
    REPORTS.mkdir(parents=True, exist_ok=True)
    worker = 'src/helper/admin_client/worker.rs'
    client = 'helper::admin_client::tests::'
    broker = 'broker::admin::tests::'
    owned = client + 'document_waits_for_ready_and_eof_then_success_waits_for_the_owned_child'
    denied = client + 'incompatible_or_late_authorization_never_receives_the_document'
    invalid = client + 'mismatched_duplicate_failed_and_unsuccessful_exit_are_not_success'
    confirmed = broker + 'acceptance_without_persistence_or_a_rejected_operation_never_deletes_credentials'
    active = broker + 'active_profiles_do_not_prompt_and_secrets_are_removed_only_after_confirmed_removal'
    actor = 'desktop::worker::tests::administration::administrative_reply_waits_for_commit_while_native_commands_and_the_keychain_keep_working'
    mutants = [
        ('document-before-readiness', worker, lambda s: replace(s, '    let mut input = Vec::new();', '    channel.write_all(bytes).unwrap();\n    let mut input = Vec::new();'), owned, False),
        ('application-version-ignored', worker, lambda s: replace(s, 'if version == env!("CARGO_PKG_VERSION")', 'if true'), denied, False),
        ('reply-id-ignored', worker, lambda s: s.replace('if got == id', 'if true'), invalid, False),
        ('reply-eof-and-duplicates-ignored', worker, without_eof, invalid, False),
        ('document-eof-omitted', worker, lambda s: replace(s, '    channel\n        .shutdown(Shutdown::Write)\n        .map_err(|_| Error::Unavailable)?;', ''), owned, False),
        ('child-not-reaped', worker, lambda s: replace(s, 'let exited = child.wait().map_err(|_| Error::Unavailable)?;', 'let exited = { use std::os::unix::process::ExitStatusExt; std::process::ExitStatus::from_raw(0) }; drop(child);'), owned, False),
        ('unsuccessful-exit-accepted', worker, lambda s: replace(s, 'if exited.success()', 'if true'), invalid, False),
        ('inherited-environment-reaches-admin', worker, lambda s: replace(s, '            .env_clear()\n', ''), owned, False),
        ('authorization-locale-lost', worker, lambda s: replace(s, '.env("VPNT_AUTH_LOCALE", locale.code())', '.env("VPNT_AUTH_LOCALE", "en-US")'), owned, False),
        ('cached-authentication-permitted', 'src/helper/admin_client.rs', lambda s: replace(s, '["-A", "-k", "--", paths::HELPER, "admin"]', '["-A", "--", paths::HELPER, "admin"]'), client + 'elevation_command_is_closed_and_never_uses_shell_or_cached_authentication', False),
        ('active-profile-administration-admitted', 'src/broker/admin.rs', lambda s: replace(s, '        if self\n            .connections', '        if false && self\n            .connections'), active, False),
        ('edited-profile-can-connect', 'src/broker/commands.rs', lambda s: replace(s, '        if self.editing(id) {', '        if false {'), active, False),
        ('edited-profile-can-save-secrets', 'src/broker/commands.rs', lambda s: replace(s, '                if self.editing(&id) {', '                if false {'), active, False),
        ('metadata-confirmation-ignored', 'src/broker/admin.rs', lambda s: replace(s, 'let mut result = if confirmed', 'let mut result = if true'), confirmed, False),
        ('keychain-removal-omitted', 'src/broker/admin.rs', lambda s: replace(s, 'self.secrets.remove(id, *kind).is_err()', 'false'), active, False),
        ('keychain-cleanup-failure-hidden', 'src/broker/admin.rs', lambda s: replace(s, 'result = Err("secret_cleanup_failed");', 'result = Ok(());'), broker + 'a_partial_keychain_cleanup_reports_failure_after_the_profile_was_removed', False),
        ('administration-blocks-native-actor', 'src/desktop/worker.rs', lambda s: replace(s, '                                            administrative.insert(token, work.request.id);', '                                            administrative.insert(token, work.request.id);\n                                            loop {\n                                                normal.poll();\n                                                if let Some((_, result)) = normal.take_admin_result() {\n                                                    reply(response(administrative.remove(&token).unwrap(), result)); break;\n                                                }\n                                                std::thread::sleep(Duration::from_millis(5));\n                                            }'), actor, True),
    ]
    receipt = {'sourceSha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for folder in ['src', 'tests', 'ui/src'] for p in sorted((ROOT/folder).rglob('*')) if p.is_file()}, 'limits': 'No sudo/PAM/native authorization window; fixed command assertion is static. Peer IO and actor use ordinary-user processes and an isolated Keychain.'}
    try:
        with tempfile.TemporaryDirectory(prefix='copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT/name, copy/name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/dist', 'ui/src']: shutil.copytree(ROOT/name, copy/name)
            baselines = [('client', 'helper::admin_client', False), ('broker', 'broker::admin', False), ('actor', actor, True)]
            for label, selector, desktop in baselines: receipt['baseline-'+label] = base.run(copy, 'baseline-'+label, selector, desktop=desktop)
            for label, file, mutate, expected, desktop in mutants:
                path = copy/file
                original = path.read_text()
                try:
                    path.write_text(mutate(original))
                    receipt[label] = base.run(copy, label, expected, expected, desktop)
                finally: path.write_text(original)
            for label, selector, desktop in baselines: receipt['restored-'+label] = base.run(copy, 'restored-'+label, selector, desktop=desktop)
    finally: (REPORTS/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(f'Killed {len(mutants)} administrative mutations; six baselines/restorations passed; copy removed')

if __name__ == '__main__': main()
