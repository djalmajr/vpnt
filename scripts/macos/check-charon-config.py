#!/usr/bin/env python3
"""Validate production configuration with the prepared original settings parser.

Requires build-runtime.py's verified local artifacts. No charon, plugin loading,
installation, socket or kernel mutation. Missing prerequisites are a hard error.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/charon-config'
spec = importlib.util.spec_from_file_location('runtime_build', Path(__file__).with_name('build-runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def run(label, args, env=None, expected=0, assertion=None):
    result = subprocess.run(list(map(str, args)), cwd=ROOT, env=env, capture_output=True, timeout=90)
    output = result.stdout + result.stderr
    (REPORTS / f'{label}.log').write_bytes(output)
    if result.returncode != expected:
        raise RuntimeError(f'{label}: exit {result.returncode}, expected {expected}; see {REPORTS / (label + ".log")}')
    if assertion is not None and assertion.encode() not in output:
        raise RuntimeError(f'{label}: missing assertion {assertion!r}; see {REPORTS / (label + ".log")}')
    return result.stdout


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run on macOS as an ordinary user; no VPN or installation')
    archive = ROOT / f'target/runtime-sources/strongswan-{runtime.SWAN_VERSION}.tar.bz2'
    source = archive.parent / f'strongswan-{runtime.SWAN_VERSION}'
    build = ROOT / 'target/runtime-build/strongswan'
    library = build / 'src/libstrongswan/.libs/libstrongswan.a'
    crypto = ROOT / 'target/vpnt-runtime/lib/libcrypto.4.dylib'
    if not archive.is_file() or runtime.digest(archive) != runtime.SWAN_SHA:
        raise SystemExit('Prepare verified strongSwan sources with build-runtime.py first')
    for path in [library, build / 'config.h', crypto]:
        if not path.is_file():
            raise SystemExit(f'Missing prepared artifact: {path}')
    # These original parser inputs must still match the pinned archive. The
    # static library/configuration hashes identify the prepared build separately.
    inputs = ['library.h', 'settings/settings.h', 'settings/settings.c',
              'settings/settings_parser.y', 'settings/settings_lexer.l']
    with tarfile.open(archive) as package:
        for name in inputs:
            path = source / 'src/libstrongswan' / name
            member = f'strongswan-{runtime.SWAN_VERSION}/src/libstrongswan/{name}'
            if path.read_bytes() != package.extractfile(member).read():
                raise RuntimeError(f'Original settings source changed: {name}')
    REPORTS.mkdir(parents=True, exist_ok=True)
    run('build-renderer-library', ['cargo', 'build', '--locked', '--offline', '--no-default-features', '--lib'])
    with tempfile.TemporaryDirectory(prefix='vpnt-settings-', dir=REPORTS) as temporary:
        directory = Path(temporary)
        libc = max((ROOT / 'target/debug/deps').glob('liblibc-*.rlib'), key=lambda p: p.stat().st_mtime)
        env = dict(os.environ, CARGO_MANIFEST_DIR=str(ROOT))
        run('compile-renderer', ['rustc', '--edition=2024', ROOT / 'tests/fixtures/charon_config.rs',
            '--extern', f'vpnt={ROOT}/target/debug/libvpnt.rlib', '--extern', f'libc={libc}',
            '-L', f'dependency={ROOT}/target/debug/deps', '-o', directory / 'render'], env)
        run('compile-parser', ['/usr/bin/cc', '-I', build, '-I', source / 'src/libstrongswan',
            '-include', build / 'config.h', ROOT / 'tests/fixtures/charon_settings.c', library,
            crypto, '-lm', '-o', directory / 'parse'])
        # Loader override applies only to this parser fixture. Production clears
        # it and admits only the fixed root-owned runtime.
        env = dict(os.environ, DYLD_LIBRARY_PATH=str(crypto.parent))
        paths = ['/Library/Application Support/vpnt/ipsec/' + 'a' * 32,
                 '/private/tmp/vpnt settings with spaces']
        for i, path in enumerate(paths):
            rendered = run(f'render-{i}', [directory / 'render', path])
            configuration = directory / f'{i}.conf'
            configuration.write_bytes(rendered)
            run(f'parse-{i}', [directory / 'parse', configuration, path], env)
            # The original parser must refuse the same rendered input after the
            # only kernel-libipsec plugin section is renamed to libipsec. The
            # key stays; the namespace assertion in the parser fixture fails.
            needle = b'kernel-libipsec { vpnt_retain_utun'
            if rendered.count(needle) != 1:
                raise RuntimeError(f'render-{i}: expected one namespace anchor')
            mangled = directory / f'{i}.libipsec.conf'
            mangled.write_bytes(rendered.replace(needle, b'libipsec { vpnt_retain_utun', 1))
            run(f'parse-namespace-{i}', [directory / 'parse', mangled, path], env,
                expected=1, assertion='settings assertion:')
        receipt = {'archiveSha256': runtime.SWAN_SHA, 'cases': len(paths),
                   'positiveCases': len(paths), 'refusedNamespaceCases': len(paths),
                   'charonStarted': False, 'vpnStarted': False,
                   'preparedArtifactSha256': {str(p.relative_to(ROOT)): runtime.digest(p) for p in [library, build / 'config.h', crypto]},
                   'sourceSha256': {str(p.relative_to(ROOT)): runtime.digest(p) for p in [
                       Path(__file__), ROOT / 'tests/fixtures/charon_config.rs', ROOT / 'tests/fixtures/charon_settings.c',
                       ROOT / 'src/connection/ipsec/producer/config.rs', ROOT / 'src/connection/ipsec/producer/files.rs', ROOT / 'src/fs_permissions.rs']}}
    (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('Original strongSwan settings parser: two production-renderer cases passed and two namespace refusals; temporary files removed; no charon/VPN')


if __name__ == '__main__':
    main()
