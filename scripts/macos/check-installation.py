#!/usr/bin/env python3
"""Payload/policy/preparer oracles in a disposable copy; never elevate/install."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/installation-oracles'
spec = importlib.util.spec_from_file_location('rust_build_inputs', Path(__file__).with_name('rust_build_inputs.py'))
build_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_inputs)


def replace(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError(f'Changed mutation anchor: {before!r}')
    return source.replace(before, after)


def run(copy, label, selector, failed=None):
    command = ['cargo', 'test', '--locked', '--offline', '--no-default-features', *selector]
    result = subprocess.run(command, cwd=copy, capture_output=True, timeout=120)
    log = result.stdout + result.stderr
    (REPORTS / (label + '.log')).write_bytes(log)
    if result.returncode != (101 if failed else 0):
        raise RuntimeError(f'{label}: unexpected exit {result.returncode}')
    if failed and (f'test {failed} ... FAILED'.encode() not in log or b'panicked at' not in log or b'test result: FAILED.' not in log):
        raise RuntimeError(f'{label}: expected executed consumer assertion, not a build error')
    print(f'{label}: exit {result.returncode}', flush=True)
    return {'command': command, 'exit': result.returncode, 'assertion': failed}


def unbounded(source):
    source = replace(source, '        || metadata.len() > limit\n', '')
    source = replace(source, 'file.take(limit + 1)', 'file.take(u64::MAX)')
    return replace(source, 'if bytes.len() as u64 > limit {', 'if false {')


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run on macOS as an ordinary user; no installation, sudo or VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    payload = 'src/install/payload.rs'
    files = 'src/install/payload/files.rs'
    policy = 'src/install/policy.rs'
    prefix = 'install::payload::tests::'
    schema = prefix + 'recipient_schema_and_file_set_cannot_be_broadened_by_a_new_manifest'
    changed = prefix + 'unexpected_or_missing_content_and_changed_build_identity_cannot_be_admitted'
    path = prefix + 'linking_exposure_special_files_and_untrusted_dependencies_cannot_be_packaged'
    canon = prefix + 'changing_the_policy_or_a_declared_runtime_patch_is_not_authorized_by_rehashing'
    acl = prefix + 'extended_acl_write_grants_are_rejected_before_any_payload_is_trusted'
    grants = 'install::policy::tests::only_runtime_is_passwordless_and_all_commands_have_fixed_paths_arguments_and_digests'
    preparation = 'preparation_is_repeatable_parses_its_own_policy_and_refuses_to_replace_a_corrupted_build'
    mutants = [
        ('payload-version-ignored', payload, lambda s: replace(s, '|| manifest.app_version != env!("CARGO_PKG_VERSION")', '|| false'), ['--lib', schema], schema),
        ('file-set-incomplete', payload, lambda s: replace(s, 'if expected != manifest.files.keys().cloned().collect()', 'if false'), ['--lib', schema], schema),
        ('unknown-manifest-fields-accepted', 'src/install/payload/manifest.rs', lambda s: replace(s, ', deny_unknown_fields', ''), ['--lib', schema], schema),
        ('duplicate-paths-accepted', 'src/install/payload/manifest.rs', lambda s: replace(s, 'files.insert(name, value).is_some()', '{ files.insert(name, value); false }'), ['--lib', schema], schema),
        ('metadata-read-unbounded', files, unbounded, ['--lib', schema], schema),
        ('payload-digest-ignored', payload, lambda s: replace(s, 'if hash(&files::read(&root.join(name), owner, 64 * 1024 * 1024)?) != *expected', 'if false'), ['--lib', changed], changed),
        ('unlisted-content-accepted', payload, lambda s: replace(s, 'if actual != all || actual_dirs != dirs', 'if false'), ['--lib', changed], changed),
        ('old-build-admission-reused', payload, lambda s: replace(s, 'if current.summary.id != self.summary.id', 'if false'), ['--lib', changed], changed),
        ('hardlinks-accepted', files, lambda s: replace(s, '        || metadata.nlink() != 1\n', ''), ['--lib', path], path),
        ('directory-write-grants-accepted', files, lambda s: replace(s, '            || metadata.mode() & 0o7022 != 0\n', ''), ['--lib', path], path),
        ('file-write-grants-accepted', files, lambda s: replace(s, '\n        || metadata.mode() & 0o7022 != 0\n', '\n'), ['--lib', path], path),
        ('adapter-admission-omitted', payload, lambda s: replace(s, 'for name in ADAPTERS {', 'for name in [] as [&str; 0] {'), ['--lib', path], path),
        ('canonical-policy-not-required', payload, lambda s: replace(s, 'if files::read(&root.join("policy/sudoers"), owner, 16_384)? != expected_policy.as_bytes()', 'if false'), ['--lib', canon], canon),
        ('runtime-integrity-not-required', 'src/helper/runtime.rs', lambda s: replace(s, 'if format!("{:x}", Sha256::digest(&bytes)) != *hash', 'if false'), ['--lib', canon], canon),
        ('directory-acl-not-checked', files, lambda s: replace(s, '        crate::fs_permissions::check_path(ancestor, own && private)\n            .map_err(|_| Error::UntrustedPath)?;\n', ''), ['--lib', acl], acl),
        ('file-acl-not-checked', files, lambda s: replace(s, '    crate::fs_permissions::check_file(&file, false).map_err(|_| Error::UntrustedPath)?;\n', ''), ['--lib', acl], acl),
        ('administration-is-passwordless', policy, lambda s: replace(s, 'ALL=(root) PASSWD:', 'ALL=(root) NOPASSWD:'), ['--lib', grants], grants),
        ('runtime-policy-allows-extra-arguments', policy, lambda s: replace(s, '{} runtime\\n', '{} runtime *\\n'), ['--lib', grants], grants),
        ('runtime-uses-a-pty', policy, lambda s: replace(s, '!use_pty,', 'use_pty,'), ['--lib', grants], grants),
        ('admin-digest-substituted', policy, lambda s: replace(s, 'Cmnd_Alias {admin} = sha256:{helper} {} admin', 'Cmnd_Alias {admin} = sha256:{installer} {} admin'), ['--lib', grants], grants),
        ('existing-corrupted-output-reused', 'scripts/macos/prepare-installation.py', lambda s: replace(s, 'final.is_symlink() or inspect(binary, final) != summary', 'final.is_symlink()'), ['--test', 'install_preparation', preparation], preparation),
        ('preparation-claims-installation', 'scripts/macos/prepare-installation.py', lambda s: replace(s, "summary['installationPerformed'] = False", "summary['installationPerformed'] = True"), ['--test', 'install_preparation', preparation], preparation),
        ('output-overlaps-source', 'scripts/macos/prepare-installation.py', lambda s: replace(s, 'if canonical == source or source in canonical.parents or canonical in source.parents:', 'if False:'), ['--test','install_preparation','read_only_preparation_has_no_environment_or_argument_switch_to_activation'], 'read_only_preparation_has_no_environment_or_argument_switch_to_activation'),
        ('unknown-command-reports-success', 'src/bin/vpnt-install.rs', lambda s: replace(s, '_ => std::process::exit(64),', '_ => Ok("granted".into()),'), ['--test', 'install_preparation', 'read_only_preparation_has_no_environment_or_argument_switch_to_activation'], 'read_only_preparation_has_no_environment_or_argument_switch_to_activation'),
    ]
    for label, file, mutate, _, _ in mutants:
        original = (ROOT / file).read_text()
        if mutate(original) == original:
            raise RuntimeError(f'{label}: mutation changed nothing')
    hashes = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for folder in ['src', 'tests', 'ui/src/locales'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file()}
    hashes['scripts/macos/prepare-installation.py'] = hashlib.sha256((ROOT / 'scripts/macos/prepare-installation.py').read_bytes()).hexdigest()
    for key, digest in build_inputs.source_hashes(ROOT).items():
        if key in hashes and hashes[key] != digest:
            raise RuntimeError(f'conflicting build input hash: {key}')
        hashes[key] = digest
    receipt = {'sourceSha256': dict(sorted(hashes.items())), 'limits': 'Read-only inspector; source/layout and policy assertions, native visudo syntax and fictional preparation. No effective sudo privileges, root activation or VPN.'}
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']: shutil.copytree(ROOT / name, copy / name)
            shutil.copy2(ROOT / 'scripts/macos/prepare-installation.py', copy / 'scripts/macos/prepare-installation.py')
            build_inputs.copy_into(ROOT, copy)
            baselines = [('admission', ['--lib', 'install::']), ('preparation', ['--test', 'install_preparation'])]
            for label, selector in baselines: receipt['baseline-' + label] = run(copy, 'baseline-' + label, selector)
            for label, file, mutate, selector, expected in mutants:
                source = copy / file
                original = source.read_text()
                try:
                    source.write_text(mutate(original))
                    receipt[label] = run(copy, label, selector, expected)
                finally: source.write_text(original)
            for label, selector in baselines: receipt['restored-' + label] = run(copy, 'restored-' + label, selector)
    finally: (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(mutants)} installation-preparation mutations; four baselines/restorations passed; copy removed')


if __name__ == '__main__': main()
