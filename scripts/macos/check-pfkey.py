#!/usr/bin/env python3
"""Validate Darwin PF_KEY metadata using SDK and pinned original NAT-T sources.

Only owned fictional frames are decoded. No PF_KEY socket, daemon, plugin,
kernel table, privilege, installation or VPN is used.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/pfkey-codec-oracles'
spec = importlib.util.spec_from_file_location('runtime_build', Path(__file__).with_name('build-runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
spec = importlib.util.spec_from_file_location('broker_oracles', Path(__file__).with_name('check-broker.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.REPORTS = REPORTS
replace = base.replace
spec = importlib.util.spec_from_file_location('rust_build_inputs', Path(__file__).with_name('rust_build_inputs.py'))
build_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_inputs)


def mutations():
    prefix = 'connection::ipsec::pfkey::tests::'
    sa = prefix + 'sdk_sa_records_preserve_mixed_endianness_lifetimes_and_scoped_ipv6_without_key_payloads'
    policy = prefix + 'sdk_policies_preserve_requests_selectors_ranges_and_explicit_errors'
    frames = prefix + 'invalid::malformed_envelopes_and_extensions_never_publish_metadata'
    addresses = prefix + 'invalid::selectors_and_scopes_are_validated_without_normalizing_away_ambiguity'
    requests = prefix + 'invalid::malformed_policy_requests_are_rejected_as_a_whole'
    limits = prefix + 'invalid::unknown_metadata_is_marked_and_limits_do_not_drop_a_valid_prefix'
    entry = 'src/connection/ipsec/pfkey/entry.rs'
    address = 'src/connection/ipsec/pfkey/address.rs'
    wire = 'src/connection/ipsec/pfkey/wire.rs'
    cases = [
        ('wrong-pfkey-version', wire, lambda s: replace(s, 'bytes[0] != 2', 'false'), frames),
        ('message-length-unchecked', wire, lambda s: replace(s, 'usize::from(u16_at(bytes, 4)?) * 8 != bytes.len()', 'false'), frames),
        ('wrong-sad-satype', wire, lambda s: replace(s, '![2, 3, 9].contains(&bytes[3])', 'false'), frames),
        ('wrong-spd-satype', wire, lambda s: replace(s, 'kind == Kind::Spd && bytes[3] != 0', 'false'), frames),
        ('duplicate-extension-admitted', wire, lambda s: replace(s, 'map.insert(kind, ext).is_some()', '{ map.insert(kind, ext); false }'), frames),
        ('unknown-extension-type-lost', wire, lambda s: replace(s, '.filter(|k| !known.contains(k))', '.filter(|k| false && !known.contains(k))'), limits),
        ('extension-count-unbounded', wire, lambda s: replace(s, 'map.len() >= 64', 'false'), limits),
        ('current-lifetime-size-unchecked', wire, lambda s: replace(s, '2..=4 if len != 32', '2..=4 if false'), frames),
        ('malformed-key-shape-admitted', wire, lambda s: replace(s, '(8 + key_bytes).div_ceil(8) * 8 != len', 'false'), frames),
        ('reserved-refcount-rejected', wire, lambda s: replace(s, '        let kind = match bytes[1] {', '        if u16_at(bytes, 6)? != 0 { return Err(Error::Invalid); }\n        let kind = match bytes[1] {'), sa),
        ('spi-native-endian', entry, lambda s: replace(s, 'spi: wire::net32(sa, 4)?', 'spi: wire::u32_at(sa, 4)?'), sa),
        ('reqid-truncated-to-16-bits', entry, lambda s: replace(s, 'reqid: wire::u32_at(sa2, 12)?', 'reqid: u32::from(wire::u16_at(sa2, 12)?)'), sa),
        ('sa-size-unchecked', entry, lambda s: replace(s, '![16, 24].contains(&sa.len())', 'false'), frames),
        ('sa2-size-unchecked', entry, lambda s: replace(s, 'sa2.len() != 16', 'false'), frames),
        ('sa-state-unchecked', entry, lambda s: replace(s, 'sa[9] > 3', 'false'), frames),
        ('sa-mode-unchecked', entry, lambda s: replace(s, 'sa2[4] > 2', 'false'), frames),
        ('policy-extension-in-sad', entry, lambda s: replace(s, 'ext.optional(18).is_some()', 'false'), frames),
        ('sa-extension-in-spd', entry, lambda s: replace(s, '[1, 8, 9, 19].iter().any(|k| ext.optional(*k).is_some())', 'false'), frames),
        ('sockaddr-port-native-endian', address, lambda s: replace(s, 'port: wire::net16(value, 2)?', 'port: wire::u16_at(value, 2)?'), sa),
        ('sockaddr-padding-unchecked', address, lambda s: replace(s, 'bytes.len() != 8 + n.div_ceil(8) * 8', 'false'), addresses),
        ('scope-conflict-admitted', address, lambda s: replace(s, 'embedded != 0 && embedded != zone', 'false'), addresses),
        ('embedded-scope-not-cleared', address, lambda s: replace(s, '                ip[2] = 0;\n                ip[3] = 0;\n', ''), sa),
        ('range-alias-admitted', address, lambda s: replace(s, 'ext.optional(first).is_some() || ext.optional(last).is_some()', 'false'), addresses),
        ('range-protocol-unchecked', address, lambda s: replace(s, 'start.protocol != end.protocol', 'false'), addresses),
        ('range-prefix-unchecked', address, lambda s: replace(s, 'start.prefix != end.prefix', 'false'), addresses),
        ('range-order-unchecked', address, lambda s: replace(s, '(start.start.address.ip, start.start.port) > (end.start.address.ip, end.start.port)', 'false'), addresses),
        ('range-end-discarded', address, lambda s: replace(s, 'start.end = Some(end.start);', 'start.end = None;'), policy),
        ('sa-endpoint-family-unchecked', entry, lambda s: replace(s, 'source.address.ip.is_ipv4() != destination.address.ip.is_ipv4()', 'false'), addresses),
        ('selector-protocol-unchecked', entry, lambda s: replace(s, 'source.protocol != destination.protocol', 'false'), addresses),
        ('selector-family-unchecked', entry, lambda s: replace(s, 'source.start.address.ip.is_ipv4() != destination.start.address.ip.is_ipv4()', 'false'), addresses),
        ('request-length-in-words', entry, lambda s: replace(s, 'usize::from(wire::u16_at(remaining, 0)?)', 'usize::from(wire::u16_at(remaining, 0)?) * 8'), policy),
        ('request-count-unbounded', entry, lambda s: replace(s, 'requests.len() >= 64', 'false'), limits),
        ('request-protocol-unchecked', entry, lambda s: replace(s, '![50, 51, 108].contains(&protocol)', 'false'), requests),
        ('request-mode-unchecked', entry, lambda s: replace(s, '![1, 2].contains(&r[4])', 'false'), requests),
        ('request-level-unchecked', entry, lambda s: replace(s, 'r[5] > 3', 'false'), requests),
        ('transport-with-tunnel-addresses', entry, lambda s: replace(s, 'if r[4] != 2 {', 'if false {'), requests),
        ('non-ipsec-with-requests', entry, lambda s: replace(s, '(kind != 2 && value.len() != 16)', 'false'), requests),
        ('policy-kind-unchecked', entry, lambda s: replace(s, 'kind > 5', 'false'), requests),
        ('policy-direction-unchecked', entry, lambda s: replace(s, 'direction > 2', 'false'), requests),
        ('errno-payload-ignored', 'src/connection/ipsec/pfkey.rs', lambda s: replace(s, 'if bytes.len() != 16 {', 'if false {'), frames),
    ]
    native = [
        ('natt-port-network-endian', entry, lambda s: replace(s, 'Some(wire::u16_at(sa, 16)?)', 'Some(wire::net16(sa, 16)?)')),
        ('natt-flag-lost', entry, lambda s: replace(s, 'if flags & 2 != 0 {', 'if flags & 4 != 0 {')),
    ]
    return cases, native


def run(label, command, cwd=ROOT, input=None):
    result = subprocess.run(list(map(str, command)), cwd=cwd, input=input, capture_output=True, timeout=240)
    (REPORTS / f'{label}.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'{label}: exit {result.returncode}; see {REPORTS / (label + ".log")}')
    return result


def original_header():
    archive = ROOT / f'target/runtime-sources/strongswan-{runtime.SWAN_VERSION}.tar.bz2'
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        with urlopen(runtime.SWAN_URL, timeout=30) as response:
            data = response.read(80_000_001)
        if len(data) > 80_000_000 or hashlib.sha256(data).hexdigest() != runtime.SWAN_SHA:
            raise RuntimeError('StrongSwan archive digest mismatch')
        archive.write_bytes(data)
    if runtime.digest(archive) != runtime.SWAN_SHA:
        raise RuntimeError('StrongSwan archive digest mismatch')
    with tarfile.open(archive) as package:
        source = package.extractfile(f'strongswan-{runtime.SWAN_VERSION}/src/libcharon/plugins/kernel_pfkey/kernel_pfkey_ipsec.c').read().decode()
    start = source.index('#define SADB_X_EXT_NATT 0x002')
    declaration = source[start:source.index('\n#endif', start)]
    assignment = 'sa_2->sadb_sa_natt_port = id->dst->get_port(id->dst);'
    if source.count(assignment) != 1 or declaration.count('struct sadb_sa_2') != 1:
        raise RuntimeError('Original NAT-T declaration/assignment changed')
    # Compile the original consumer statement with a fictional host method.
    # The source's get_port() assignment deliberately has no htons().
    stubs = '''
struct vpnt_fixture_host { uint16_t (*get_port)(struct vpnt_fixture_host*); uint16_t value; };
static uint16_t vpnt_fixture_port(struct vpnt_fixture_host *host) { return host->value; }
static void vpnt_original_natt_port(struct sadb_sa_2 *sa_2, uint16_t value) {
    struct vpnt_fixture_host host={vpnt_fixture_port,value};
    struct { struct vpnt_fixture_host *dst; } binding={&host}, *id=&binding;
    ASSIGNMENT
}
'''.replace('ASSIGNMENT', assignment)
    return declaration + '\n' + stubs


def consumer(copy, directory, label):
    run(label + '-build', ['cargo', 'build', '--locked', '--offline', '--no-default-features', '--lib'], copy)
    zeroize = max((copy / 'target/debug/deps').glob('libzeroize-*.rlib'), key=lambda p: p.stat().st_mtime)
    binary = directory / 'consumer'
    run(label + '-compile', ['rustc', '--edition=2024', copy / 'tests/fixtures/ipsec/pfkey_consumer.rs',
        '--extern', f'vpnt={copy}/target/debug/libvpnt.rlib', '--extern', f'zeroize={zeroize}',
        '-L', f'dependency={copy}/target/debug/deps', '-o', binary])
    return binary


def native_cases(binary, frames, label, failed=False):
    results = {}
    for mode, data in frames.items():
        result = subprocess.run([binary, mode], input=data, capture_output=True, timeout=10)
        log = result.stdout + result.stderr
        (REPORTS / f'{label}-{mode}.log').write_bytes(log)
        if result.returncode != (101 if failed else 0):
            raise RuntimeError(f'{label}/{mode}: unexpected exit {result.returncode}')
        if failed and (b'panicked at' not in log or b'native-endian NAT-T port' not in log or b'assertion' not in log):
            raise RuntimeError(f'{label}/{mode}: expected executed NAT-T assertion')
        results[mode] = {'exit': result.returncode, 'assertion': 'native-endian NAT-T port' if failed else None}
    print(label + ': native assertions verified', flush=True)
    return results


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run as an ordinary macOS user; fictional frames only, no PF_KEY or VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    header = original_header()
    cases, native = mutations()
    for label, file, mutate, *_ in cases + native:
        if mutate((ROOT / file).read_text()) == (ROOT / file).read_text():
            raise RuntimeError(f'{label}: unchanged mutation')
    inputs = [p for folder in ['src', 'tests'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file()]
    inputs += [Path(__file__), Path(__file__).with_name('check-broker.py'), Path(__file__).with_name('build-runtime.py'), ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    inputs += build_inputs.source_files(ROOT)
    unique, seen = [], set()
    for path in sorted(inputs, key=lambda p: str(p.relative_to(ROOT))):
        key = str(path.relative_to(ROOT))
        if key not in seen:
            seen.add(key)
            unique.append(path)
    inputs = unique
    receipt = {'archiveSha256': runtime.SWAN_SHA, 'headerSha256': hashlib.sha256(header.encode()).hexdigest(),
               'originalNattCases': 2, 'pfkeySocketOpened': False, 'vpnStarted': False,
               'sourceSha256': {str(p.relative_to(ROOT)): runtime.digest(p) for p in inputs},
               'limits': 'SDK binary producer plus original pinned NAT-T declaration/assignment with fictional host. Sanitized packet metadata only; no dump, kernel tables, claims, routes, probe, privilege or VPN.'}
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']: shutil.copytree(ROOT / name, copy / name)
            build_inputs.copy_into(ROOT, copy)
            directory = copy / 'native-fixture'
            directory.mkdir()
            (directory / 'original-natt.h').write_text(header)
            fixture = directory / 'fixture'
            run('compile-original', ['/usr/bin/xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-DVPNT_ORIGINAL_NATT', '-I', directory, ROOT / 'tests/fixtures/ipsec/pfkey.c', '-o', fixture])
            frames = {mode: subprocess.run([fixture, mode], capture_output=True, check=True, timeout=10).stdout for mode in ['natt4', 'natt6']}
            receipt['baseline'] = base.run(copy, 'baseline', 'connection::ipsec::pfkey')
            receipt['native-baseline'] = native_cases(consumer(copy, directory, 'native-baseline'), frames, 'native-baseline')
            for label, file, mutate, expected in cases:
                target = copy / file
                original = target.read_text()
                try:
                    target.write_text(mutate(original))
                    receipt[label] = base.run(copy, label, expected, expected)
                finally: target.write_text(original)
            for label, file, mutate in native:
                target = copy / file
                original = target.read_text()
                try:
                    target.write_text(mutate(original))
                    receipt[label] = native_cases(consumer(copy, directory, label), frames, label, True)
                finally: target.write_text(original)
            receipt['restored'] = base.run(copy, 'restored', 'connection::ipsec::pfkey')
            receipt['native-restored'] = native_cases(consumer(copy, directory, 'native-restored'), frames, 'native-restored')
    finally: (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(cases) + len(native)} PF_KEY metadata mutations; SDK/original NAT-T baseline/restoration passed; copy removed; no PF_KEY/VPN')


if __name__ == '__main__':
    main()
