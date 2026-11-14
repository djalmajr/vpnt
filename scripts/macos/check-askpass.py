#!/usr/bin/env python3
"""Private, UI-free parent-gate checks; never invoke sudo or the GUI entry."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'scripts/macos/askpass.m'
FIXTURE = ROOT / 'tests/fixtures/askpass-parent/parent-check.m'
SCENARIOS = (
    'positive', 'changed-parent', 'changed-seconds', 'changed-microseconds',
    'zombie', 'unknown-status', 'out-of-range-status', 'sleeping', 'stopped', 'wrong-pid', 'wrong-path', 'path-suffix', 'failed-path',
    'unterminated-path', 'failed-sysctl', 'empty-sysctl', 'partial-sysctl',
    'oversized-sysctl', 'zero-seconds', 'negative-seconds',
    'negative-microseconds', 'overflow-microseconds', 'zero-microseconds',
    'reparent-during-sysctl', 'reparent-during-path', 'reparent-after-path',
)


def run(command):
    return subprocess.run(command, check=True, capture_output=True, timeout=60)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_inputs():
    """Every canonical input the runner must treat as read-only."""
    return (SOURCE, FIXTURE, ROOT / 'scripts/macos/build-askpass.py',
            ROOT / 'ui/src/locales/native.json')


def snapshot():
    return {str(path): sha256(path) for path in canonical_inputs()}


def compile_fixture(layout):
    """Compile the copied fixture, which includes the copied adapter source."""
    binary = layout['binaries'] / 'parent-check'
    run(['/usr/bin/clang', '-fobjc-arc', '-fblocks', '-Wall', '-Wextra',
         '-Werror', '-O2', '-mmacosx-version-min=13.0', '-I', str(layout['include']),
         str(layout['fixture']), '-framework', 'AppKit', '-o', str(binary)])
    return binary


def disposable_layout(directory, source_bytes, fixture_bytes):
    """Minimal copy of the tree: the fixture's relative include resolves to the copied adapter."""
    layout = {
        'source': directory / 'scripts/macos/askpass.m',
        'fixture': directory / 'tests/fixtures/askpass-parent/parent-check.m',
        'include': directory / 'include',
        'binaries': directory / 'bin',
    }
    for path in (layout['source'], layout['fixture']):
        path.parent.mkdir(parents=True)
    layout['include'].mkdir()
    layout['binaries'].mkdir()
    layout['source'].write_bytes(source_bytes)
    layout['fixture'].write_bytes(fixture_bytes)
    catalogs = json.loads((ROOT / 'ui/src/locales/native.json').read_bytes())
    data = json.dumps(catalogs, ensure_ascii=False).encode()
    (layout['include'] / 'native-catalogs.h').write_text(
        'static const unsigned char vpnt_native_catalogs[] = {' +
        ','.join(map(str, data)) + '};\n')
    return layout


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit('Run on macOS as an ordinary user')
    before = snapshot()
    try:
        check()
    finally:
        # Also holds when a mutant fails or compilation raises: canonical inputs never change.
        after = snapshot()
        if after != before:
            raise SystemExit(f'canonical input changed: {before} -> {after}')
    print('PASS canonical inputs unchanged: ' + ', '.join(
        f'{Path(path).relative_to(ROOT)}={value}' for path, value in after.items()))


def check():
    print(run([sys.executable, str(ROOT / 'scripts/macos/build-askpass.py')]).stdout.decode(), end='')
    print('PASS native build and direct-invocation exit1 / empty stdout+stderr (existing build check)')
    original = SOURCE.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    # Mutations are written only to the copy below; a killed run may leave a faulty temporary copy, never ROOT.
    with tempfile.TemporaryDirectory(prefix='vpnt-parent-check-') as temporary:
        layout = disposable_layout(Path(temporary), original, FIXTURE.read_bytes())
        copy = layout['source']
        assert copy != SOURCE and copy.read_bytes() == original
        binary = compile_fixture(layout)
        for scenario in SCENARIOS:
            print(run([str(binary), scenario]).stdout.decode(), end='')
        mutants = (
            ('changed-start-accepted',
             b'info.kp_proc.p_starttime.tv_usec!=original->kp_proc.p_starttime.tv_usec',
             b'0', 'changed-microseconds'),
            ('failed-observation-accepted',
             b'if (!parent_snapshot(pid,&info)) return NO;',
             b'if (!parent_snapshot(pid,&info)) return YES;', 'failed-sysctl'),
        )
        for name, before, after, scenario in mutants:
            assert original.count(before) == 1
            try:
                copy.write_bytes(original.replace(before, after))
                binary = compile_fixture(layout)
                result = subprocess.run([str(binary), scenario], capture_output=True, timeout=5)
                expected_error = f'FAIL {scenario}: parent_matches=1 expected=0\n'.encode()
                assert result.returncode == 1 and result.stdout == b'' and result.stderr == expected_error, result
                print(f'KILLED {name}: {result.stderr.decode().strip()}')
            finally:
                copy.write_bytes(original)
                assert copy.read_bytes() == original
            print(f'RESTORED byte-identical sha256={digest}')
        # Recompile and rerun after restoration, including both mutant oracles.
        binary = compile_fixture(layout)
        for scenario in SCENARIOS:
            run([str(binary), scenario])
        assert copy.read_bytes() == original and SOURCE.read_bytes() == original
        print(f'PASS restored baseline: {len(SCENARIOS)} scenarios; sha256={digest}')


if __name__ == '__main__':
    main()
