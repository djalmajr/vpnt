#!/usr/bin/env python3
"""Prove app/component admission in disposable files, never open Installer."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/app-component-oracles'
spec = importlib.util.spec_from_file_location('payload_oracles', Path(__file__).with_name('check-installation.py'))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
shared.REPORTS = REPORTS
replace, run = shared.replace, shared.run
spec = importlib.util.spec_from_file_location('rust_build_inputs', Path(__file__).with_name('rust_build_inputs.py'))
build_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_inputs)


def remove_after_admission(source):
    deletion = '    if args.output.exists():\n        shutil.rmtree(args.output)\n'
    source = replace(source, deletion, '')
    return replace(source, 'args.output.parent.mkdir(parents=True, exist_ok=True)\n', 'args.output.parent.mkdir(parents=True, exist_ok=True)\nif args.output.exists():\n    shutil.rmtree(args.output)\n')


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run as an ordinary macOS user; no Installer, sudo or VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    source = 'src/install/bundle.rs'
    prefix = 'install::bundle::tests::'
    schema = prefix + 'recipient_version_schema_and_digest_fields_cannot_select_another_component'
    changed = prefix + 'changing_host_or_rewriting_metadata_after_admission_invalidates_the_original_seal'
    binding = prefix + 'packaged_component_is_bound_to_the_running_host_recipient_and_unchanged_bytes'
    files = prefix + 'linked_special_writable_or_oversized_bundle_inputs_are_rejected_without_reading_forever'
    acl = prefix + 'bundle_admission_rejects_extended_write_grants_on_the_package_or_its_directory'
    layout = prefix + 'executable_layout_cannot_redirect_to_a_debug_binary_or_linked_bundle'
    integration = 'native_packaged_host_admits_only_its_audited_component_and_preserves_the_app_on_failed_replacement'
    mutants = [
        ('recipient-ignored', source, lambda s: replace(s, '|| metadata.uid != uid', '|| false'), ['--lib', schema], schema),
        ('version-ignored', source, lambda s: replace(s, '|| metadata.app_version != env!("CARGO_PKG_VERSION")', '|| false'), ['--lib', schema], schema),
        ('unknown-fields-accepted', source, lambda s: replace(s, ', deny_unknown_fields', ''), ['--lib', schema], schema),
        ('digest-schema-unchecked', source, lambda s: replace(s, '.any(|h| !valid_hash(h))', '.any(|_| false)'), ['--lib', schema], schema),
        ('metadata-seal-ignored', source, lambda s: replace(s, 'if hash(&read(\n            &self.package.with_file_name("component.json"),\n            uid,\n            8192,\n        )?) != self.seal', 'if false'), ['--lib', changed], changed),
        ('host-checksum-ignored', source, lambda s: replace(s, '|| hash(&read(&self.executable, uid, 128 * 1024 * 1024)?) != self.metadata.host_sha256', '|| false'), ['--lib', changed], changed),
        ('package-checksum-ignored', source, lambda s: replace(s, '|| hash(&read(&self.package, uid, 300 * 1024 * 1024)?) != self.metadata.package_sha256', '|| false'), ['--lib', binding], binding),
        ('hardlinks-accepted', source, lambda s: replace(s, '        || m.nlink() != 1\n', ''), ['--lib', files], files),
        ('leaf-symlink-followed', source, lambda s: replace(s, 'libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK', 'libc::O_CLOEXEC | libc::O_NONBLOCK'), ['--lib', files], files),
        ('file-write-mode-unchecked', source, lambda s: replace(s, '        || m.mode() & 0o7022 != 0\n', ''), ['--lib', files], files),
        ('directory-write-mode-unchecked', source, lambda s: replace(s, '(m.mode() & 0o7022 != 0 && !applications)', 'false'), ['--lib', files], files),
        ('directory-acl-unchecked', source, lambda s: replace(s, 'crate::fs_permissions::check_path(path, false).map_err(|_| Error::UntrustedPath)', 'Ok(())'), ['--lib', acl], acl),
        ('file-acl-unchecked', source, lambda s: replace(s, '    crate::fs_permissions::check_file(&file, false).map_err(|_| Error::UntrustedPath)?;\n', ''), ['--lib', acl], acl),
        ('executable-name-unchecked', source, lambda s: replace(s, 'executable.file_name().is_none_or(|n| n != "vpnt")', 'false'), ['--lib', layout], layout),
        ('old-app-deleted-before-admission', 'scripts/macos/package-app.py', remove_after_admission, ['--test', 'app_component', integration], integration),
        ('bundle-minimum-disagrees-with-host', 'scripts/macos/app_component.py', lambda s: replace(s, "'minimumMacOS': minimum", "'minimumMacOS': '10.0'"), ['--test', 'app_component', integration], integration),
    ]
    applications = Path('/Applications').stat()
    if applications.st_uid == 0 and applications.st_gid == 80 and stat.S_IMODE(applications.st_mode) == 0o775:
        test = prefix + 'native_applications_parent_is_admitted_without_weakening_bundle_directory_permissions'
        mutants.append(('standard-applications-parent-rejected', source, lambda s: replace(s, '&& m.mode() & 0o7777 == 0o775', '&& false'), ['--lib', test], test))
    for label, file, mutate, _, _ in mutants:
        original = (ROOT / file).read_text()
        if mutate(original) == original: raise RuntimeError(f'{label}: unchanged mutation')
    scripts = ['check-installation.py', 'check-app-component.py', 'prepare-installation.py', 'package-installation.py', 'installation_package.py', 'package-app.py', 'app_component.py']
    inputs = [p for folder in ['src', 'tests', 'ui/src/locales'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file() and '__pycache__' not in p.parts]
    inputs += [ROOT / 'scripts/macos' / name for name in scripts]
    inputs += build_inputs.source_files(ROOT)
    unique, seen = [], set()
    for path in sorted(inputs, key=lambda p: str(p.relative_to(ROOT))):
        key = str(path.relative_to(ROOT))
        if key not in seen:
            seen.add(key)
            unique.append(path)
    inputs = unique
    receipt = {'sourceSha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}, 'limits': 'Native headless packaged host and package tools, synthetic roles/runtime, own files/ACLs, read-only Applications metadata. No GUI/Installer, elevation, installation or VPN.'}
    baselines = [('admission', ['--lib', 'install::bundle::tests']), ('app', ['--test', 'app_component'])]
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock', 'LICENSE']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']: shutil.copytree(ROOT / name, copy / name, ignore=shutil.ignore_patterns('__pycache__'))
            for name in scripts: shutil.copy2(ROOT / 'scripts/macos' / name, copy / 'scripts/macos' / name)
            build_inputs.copy_into(ROOT, copy)
            for label, selector in baselines: receipt['baseline-' + label] = run(copy, 'baseline-' + label, selector)
            for label, file, mutate, selector, test in mutants:
                path = copy / file
                original = path.read_text()
                try:
                    path.write_text(mutate(original))
                    receipt[label] = run(copy, label, selector, test)
                finally: path.write_text(original)
            for label, selector in baselines: receipt['restored-' + label] = run(copy, 'restored-' + label, selector)
    finally: (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(mutants)} app admission mutations; four baselines/restorations passed; copy removed')


if __name__ == '__main__': main()
