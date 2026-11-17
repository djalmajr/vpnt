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
DEADLINE_FIXTURE = r'''#import <AppKit/AppKit.h>
#include <stdint.h>
#include <stdio.h>
#define main unused_adapter_main
#include "../../../scripts/macos/askpass.m"
#undef main
static uint64_t fixture_clock(void) { return 1000000000ULL; }
static uint64_t zero_clock(void) { return 0; }
static int check(const char *name, const char *raw, uint64_t (*clock)(void), BOOL expected, uint64_t expected_until) {
    uint64_t until=0;
    BOOL actual=valid_deadline(raw,clock,&until);
    if (actual!=expected || (actual && until!=expected_until)) {
        fprintf(stderr,"FAIL %s: accepted=%d expected=%d\n",name,actual,expected);
        return 1;
    }
    return 0;
}
int main(void) {
    if (check("deadline-599","600000000000",fixture_clock,YES,600000000000ULL)) return 1;
    if (check("deadline-600","601000000000",fixture_clock,YES,601000000000ULL)) return 1;
    if (check("deadline-601","602000000000",fixture_clock,NO,0)) return 1;
    if (check("deadline-zero","0",fixture_clock,NO,0)) return 1;
    if (check("deadline-now","1000000000",fixture_clock,NO,0)) return 1;
    if (check("deadline-empty","",fixture_clock,NO,0)) return 1;
    if (check("deadline-nonnumeric","not-a-number",fixture_clock,NO,0)) return 1;
    if (check("deadline-suffix","600000000000x",fixture_clock,NO,0)) return 1;
    if (check("deadline-negative","-1",fixture_clock,NO,0)) return 1;
    if (check("deadline-overflow","18446744073709551616",fixture_clock,NO,0)) return 1;
    if (check("deadline-clock-zero","600000000000",zero_clock,NO,0)) return 1;
    printf("PASS deadline: 599/600 accepted; 601/zero/invalid refused\n");
    return 0;
}
'''

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


def compile_deadline_fixture(layout):
    source = layout['fixture'].with_name('deadline-check.m')
    source.write_text(DEADLINE_FIXTURE)
    binary = layout['binaries'] / 'deadline-check'
    run(['/usr/bin/clang', '-fobjc-arc', '-fblocks', '-Wall', '-Wextra',
         '-Werror', '-O2', '-mmacosx-version-min=13.0', '-I', str(layout['include']),
         str(source), '-framework', 'AppKit', '-o', str(binary)])
    return binary


def run_deadline(binary):
    result = subprocess.run([str(binary)], capture_output=True, timeout=5)
    if result.returncode:
        sys.stderr.write(result.stderr.decode())
        raise AssertionError(f'deadline fixture exit={result.returncode}')
    return result.stdout.decode()


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
        print(run_deadline(compile_deadline_fixture(layout)), end='')
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
        # The deadline ceiling is a separate mechanism and mutant.
        before = b'until-now>600000000000ULL'
        after = b'until-now>120000000000ULL'
        assert original.count(before) == 1
        try:
            copy.write_bytes(original.replace(before, after))
            deadline_binary = compile_deadline_fixture(layout)
            result = subprocess.run([str(deadline_binary)], capture_output=True, timeout=5)
            assert result.returncode == 1 and result.stdout == b'' and result.stderr == b'FAIL deadline-599: accepted=0 expected=1\n', result
            print(f'KILLED deadline-120s: {result.stderr.decode().strip()}')
        finally:
            copy.write_bytes(original)
            assert copy.read_bytes() == original
        print(f'RESTORED byte-identical sha256={digest}')
        # Recompile and rerun after restoration, including both mutant oracles.
        binary = compile_fixture(layout)
        for scenario in SCENARIOS:
            run([str(binary), scenario])
        print(run_deadline(compile_deadline_fixture(layout)), end='')
        assert copy.read_bytes() == original and SOURCE.read_bytes() == original
        print(f'PASS restored baseline: {len(SCENARIOS)} scenarios; sha256={digest}')


if __name__ == '__main__':
    main()
