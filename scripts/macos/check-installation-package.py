#!/usr/bin/env python3
"""Package contract mutations in a disposable copy, without elevation/install."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/installation-package-oracles'
spec = importlib.util.spec_from_file_location('payload_oracles', Path(__file__).with_name('check-installation.py'))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
shared.REPORTS = REPORTS
replace, run = shared.replace, shared.run


def omit_guard(source, token):
    lines = [line for line in source.splitlines(keepends=True) if token in line]
    if len(lines) != 1:
        raise RuntimeError('Changed script guard anchor')
    return replace(source, lines[0], "    guard += ''\n")


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run on macOS as an ordinary user, without sudo/install/VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    contract = 'scripts/macos/installation_package.py'
    builder = 'scripts/macos/package-installation.py'
    normal = 'native_package_is_repeatable_audited_and_scripts_refuse_volume_or_unprivileged_execution'
    metadata = 'native_archive_audit_rejects_changed_authority_destination_actions_and_ownership'
    content = 'content::well_formed_archives_with_changed_script_payload_mode_or_extra_content_are_rejected'
    overlap = 'packaging_cannot_write_into_inputs_or_enable_installation_by_argument'
    mutants = [
        ('volume-guard-omitted', contract, lambda s: omit_guard(s, '"$#" -ge 3'), normal),
        ('root-guard-omitted', contract, lambda s: omit_guard(s, '/usr/bin/id -ru'), normal),
        ('wrong-postinstall-operation', contract, lambda s: replace(s, '} activate\\n', '} remove\\n'), normal),
        ('distribution-contract-unchecked', contract, lambda s: replace(s, 'if normalized(root) != normalized(ET.fromstring(distribution(summary))):', 'if False:'), metadata),
        ('component-authority-unchecked', contract, lambda s: replace(s, 'if info.get(key) != wanted:', 'if False:'), metadata),
        ('component-root-tag-unchecked', contract, lambda s: replace(s, "info.tag != 'pkg-info' or ", ''), metadata),
        ('unexpected-bundle-actions-accepted', contract, lambda s: replace(s, "elif child.attrib or len(child) or (child.text or '').strip():", 'elif False:'), metadata),
        ('script-actions-unchecked', contract, lambda s: replace(s, 'if child.attrib or [normalized(action) for action in child] != expected_actions:', 'if False:'), metadata),
        ('script-bytes-unchecked', contract, lambda s: replace(s, 'path.read_bytes() != content', 'False'), content),
        ('extracted-payload-unchecked', contract, lambda s: replace(s, "if inventory(component / 'Payload', exact=True) != expected:", 'if False:'), content),
        ('bom-ownership-unchecked', contract, lambda s: replace(s, '(int(mode, 8), int(uid), int(gid)) != (expected[key][0], 0, 0)', 'False'), metadata),
        ('package-claims-installation', builder, lambda s: replace(s, "'installationPerformed': False", "'installationPerformed': True"), normal),
        ('package-records-user-ownership', builder, lambda s: replace(s, "'--ownership', 'recommended'", "'--ownership', 'preserve'"), normal),
        ('output-overlaps-inputs', builder, lambda s: replace(s, 'if canonical == source or source in canonical.parents or canonical in source.parents:', 'if False:'), overlap),
        ('restricted-umask-not-normalized', builder, lambda s: replace(s, 'if path.is_dir():\n                path.chmod(0o755)', 'if path.is_dir():\n                pass'), normal),
    ]
    for label, file, mutate, _ in mutants:
        original = (ROOT / file).read_text()
        if mutate(original) == original:
            raise RuntimeError(f'{label}: mutation changed nothing')
    scripts = ['check-installation.py', 'check-installation-package.py', 'prepare-installation.py', 'package-installation.py', 'installation_package.py']
    inputs = [p for folder in ['src', 'tests', 'ui/src/locales'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file() and '__pycache__' not in p.parts]
    inputs += [ROOT / 'scripts/macos' / name for name in scripts]
    receipt = {'sourceSha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}, 'limits': 'Native package build/extraction/BOM and ordinary-user script rejection. No positive root script, Installer, policy/PAM, install or VPN proof.'}
    baselines = [('package', ['--test', 'install_package']), ('preparation', ['--test', 'install_preparation'])]
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']: shutil.copytree(ROOT / name, copy / name, ignore=shutil.ignore_patterns('__pycache__'))
            for name in scripts: shutil.copy2(ROOT / 'scripts/macos' / name, copy / 'scripts/macos' / name)
            for label, selector in baselines: receipt['baseline-' + label] = run(copy, 'baseline-' + label, selector)
            for label, file, mutate, test in mutants:
                source = copy / file
                original = source.read_text()
                try:
                    source.write_text(mutate(original))
                    receipt[label] = run(copy, label, ['--test', 'install_package', test], test)
                finally: source.write_text(original)
            for label, selector in baselines: receipt['restored-' + label] = run(copy, 'restored-' + label, selector)
    finally:
        (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(mutants)} package mutations; four baselines/restorations passed; copy removed')


if __name__ == '__main__': main()
