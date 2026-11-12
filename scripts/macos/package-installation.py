#!/usr/bin/env python3
"""Build/audit an unsigned development .pkg locally. Never install or elevate."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from installation_package import COMPONENT, STAGING, audit, distribution, identifier, inventory, scripts

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('payload_preparer', Path(__file__).with_name('prepare-installation.py'))
preparer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparer)


def inspect(payload):
    return preparer.inspect(ROOT / 'target/debug/vpnt-install', payload)


def verify(package, payload, directory):
    summary = inspect(payload)
    result = audit(package, directory, summary, inventory(payload))
    admitted = inspect(Path(result.pop('extracted')))
    if admitted != summary or inspect(payload) != summary:
        raise RuntimeError('Extracted payload failed native admission')
    return {**summary, **result, 'package': str(package), 'packageSha256': preparer.digest(package), 'installationPerformed': False, 'signed': False}


def build(payload, output):
    payload = payload.resolve()
    summary = inspect(payload)
    output = output.absolute()
    canonical = output.resolve()
    for source in [payload, ROOT / 'target/debug', ROOT / 'target/vpnt-runtime']:
        if canonical == source or source in canonical.parents or canonical in source.parents:
            raise RuntimeError('Package output overlaps an input')
    if output.is_symlink():
        raise RuntimeError('Package output cannot be linked')
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = output.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError('Package output must be private and owned by this user')
    final = output / summary['id']
    package_name = f"vpnt-component-{summary['appVersion']}-{summary['uid']}.pkg"
    if final.exists() or final.is_symlink():
        if final.is_symlink() or not final.is_dir() or {p.name for p in final.iterdir()} != {package_name}:
            raise RuntimeError('Unexpected existing package output')
        with tempfile.TemporaryDirectory(prefix='vpnt-pkg-audit-', dir=output) as temporary:
            return verify(final / package_name, payload, Path(temporary) / 'expanded')
    with tempfile.TemporaryDirectory(prefix='vpnt-pkg-build-', dir=output) as temporary:
        work = Path(temporary)
        frozen = work / 'payload'
        frozen.mkdir(mode=0o700)
        expected = inventory(payload)
        for name, (_, digest) in expected.items():
            if digest is not None:
                preparer.copy_file(payload / name, frozen / name)
        for path in frozen.rglob('*'):
            if path.is_dir():
                path.chmod(0o755)
        if inspect(frozen) != summary or inspect(payload) != summary:
            raise RuntimeError('Package source changed during preparation')
        script_dir = work / 'scripts'
        script_dir.mkdir()
        for name, content in scripts(summary, expected).items():
            path = script_dir / name
            path.write_bytes(content)
            path.chmod(0o755)
        component = work / COMPONENT
        subprocess.run(['/usr/bin/pkgbuild', '--root', str(frozen), '--scripts', str(script_dir), '--ownership', 'recommended', '--install-location', STAGING + '/' + summary['id'], '--identifier', identifier(summary), '--version', summary['appVersion'], str(component)], check=True, capture_output=True, timeout=45)
        dist = work / 'Distribution'
        dist.write_bytes(distribution(summary))
        result_dir = work / 'result'
        result_dir.mkdir(mode=0o700)
        package = result_dir / package_name
        subprocess.run(['/usr/bin/productbuild', '--distribution', str(dist), '--package-path', str(work), str(package)], check=True, capture_output=True, timeout=45)
        result = verify(package, payload, work / 'expanded')
        os.rename(result_dir, final)
        result['package'] = str(final / package_name)
        return result


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Package on macOS as an ordinary user; never install/elevate')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/vpnt-packages')
    parser.add_argument('--verify', type=Path, help='Audit this existing package without rebuilding it')
    args = parser.parse_args()
    if args.verify:
        with tempfile.TemporaryDirectory(prefix='vpnt-pkg-audit-') as temporary:
            result = verify(args.verify.absolute(), args.payload.resolve(), Path(temporary).resolve() / 'expanded')
    else:
        result = build(args.payload, args.output)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
