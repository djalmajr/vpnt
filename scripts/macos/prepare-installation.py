#!/usr/bin/env python3
"""Prepare and inspect a closed installation payload. Never install or elevate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
VERSION = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']
ADAPTERS = {'helper': 'vpnt-helper', 'installer': 'vpnt-install', 'pinentry': 'vpnt-pinentry', 'pppd': 'vpnt-pppd', 'askpass': 'vpnt-askpass'}


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def copy_file(source, destination):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as input:
        info = os.fstat(input.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o7022 or info.st_size > 64 * 1024 * 1024:
            raise RuntimeError('Untrusted source file')
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as output:
            data = input.read(64 * 1024 * 1024 + 1)
            if len(data) > 64 * 1024 * 1024:
                raise RuntimeError('Excessive source file')
            output.write(data)
        os.chmod(destination, 0o555 if info.st_mode & stat.S_IXUSR else 0o444)


def inspect(binary, directory):
    result = subprocess.run([str(binary), 'inspect', str(directory)], capture_output=True, check=True)
    return json.loads(result.stdout)


def prepare(uid, output):
    binary = ROOT / 'target/debug/vpnt-install'
    runtime = ROOT / 'target/vpnt-runtime'
    output = output.absolute()
    canonical = output.resolve()
    for source in [runtime, ROOT / 'target/debug']:
        source = source.resolve()
        if canonical == source or source in canonical.parents or canonical in source.parents:
            raise RuntimeError('Output overlaps a build input')
    if output.is_symlink():
        raise RuntimeError('Output cannot be a symlink')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = output.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError('Output must be private and owned by this user')
    with tempfile.TemporaryDirectory(prefix='vpnt-install-payload-', dir=output) as temporary:
        payload = Path(temporary)
        for name, executable in ADAPTERS.items():
            copy_file(ROOT / 'target/debug' / executable, payload / 'adapters' / name)
        # Copy the complete tree, including empty directories: the Rust consumer
        # rejects anything outside the manifest, rather than hiding extra files.
        for directory, folders, files in os.walk(runtime, followlinks=False):
            parent = Path(directory)
            if parent.is_symlink() or not parent.is_dir() or any((parent / name).is_symlink() for name in folders):
                raise RuntimeError('Runtime cannot contain linked directories')
            relative = parent.relative_to(runtime)
            (payload / 'runtime' / relative).mkdir(parents=True, exist_ok=True)
            for name in files:
                copy_file(parent / name, payload / 'runtime' / relative / name)
        helper = digest(payload / 'adapters/helper')
        installer = digest(payload / 'adapters/installer')
        policy = subprocess.check_output([str(binary), 'policy', str(uid), helper, installer])
        (payload / 'policy').mkdir()
        (payload / 'policy/sudoers').write_bytes(policy)
        os.chmod(payload / 'policy/sudoers', 0o444)
        files = {p.relative_to(payload).as_posix(): digest(p) for p in sorted(payload.rglob('*')) if p.is_file()}
        manifest = {'format': 1, 'appVersion': VERSION, 'uid': uid, 'files': files}
        (payload / 'payload.json').write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n')
        os.chmod(payload / 'payload.json', 0o444)
        summary = inspect(binary, payload)
        # Parse only this fixture. Do not read or modify the machine's sudoers.
        validation = subprocess.run(['/usr/sbin/visudo', '-c', '-s', '-f', str(payload / 'policy/sudoers')], capture_output=True, check=True)
        final = output / summary['id']
        if final.exists() or final.is_symlink():
            if final.is_symlink() or inspect(binary, final) != summary:
                raise RuntimeError('Existing payload is not the identical admitted build')
        else:
            os.rename(payload, final)
        summary['payload'] = str(final)
        summary['visudoParsed'] = validation.returncode == 0
        summary['installationPerformed'] = False
        summary['activationAvailable'] = False
        return summary


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Prepare on macOS as an ordinary user; no elevation')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, default=os.getuid())
    parser.add_argument('--output', type=Path, default=ROOT / 'target/vpnt-installation')
    args = parser.parse_args()
    print(json.dumps(prepare(args.uid, args.output), indent=2))


if __name__ == '__main__':
    main()
