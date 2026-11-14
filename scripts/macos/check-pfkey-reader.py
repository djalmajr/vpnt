#!/usr/bin/env python3
"""Exercise the read-only collector with owned C/AF_UNIX and memory fixtures.

No PF_KEY socket, installed helper, root process, kernel table or VPN is used.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/pfkey-reader-oracles'
spec = importlib.util.spec_from_file_location('broker_oracles', Path(__file__).with_name('check-broker.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.REPORTS = REPORTS
replace = base.replace
spec = importlib.util.spec_from_file_location('rust_build_inputs', Path(__file__).with_name('rust_build_inputs.py'))
build_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_inputs)


def collector_preflight(source):
    at = source.index('fn collect_transport(')
    tail = source[at:]
    before = '\n    budget.check().map_err(socket::map)?;\n'
    if tail.count(before) != 1:
        raise RuntimeError('Changed collector preflight anchor')
    return source[:at] + tail.replace(before, '\n', 1)


def deadline_rebased_after_send(source):
    """Shadow the absolute budget with a fresh 150 ms one right after the send.

    Only `collect_transport` changes, and the shadow has no cancellation, so the
    only reachable difference is a re-based receive deadline.
    """
    at = source.index('fn collect_transport(')
    tail = source[at:]
    send = '    io.send(&request(kind, pid, sequence), budget)?;\n'
    if tail.count(send) != 1:
        raise RuntimeError('Changed collector send anchor')
    rebase = send + ('    let budget = &Budget::new('
                     'std::time::Duration::from_millis(150)).unwrap();\n')
    return source[:at] + tail.replace(send, rebase, 1)


def mutations():
    prefix = 'connection::ipsec::pfkey::read::tests::'
    positive = prefix + 'independent_peer_observes_fixed_queries_and_collector_filters_foreign_records'
    errors = prefix + 'explicit_empty_and_suffix_are_protocol_observations_and_errors_stay_errors'
    broken = prefix + 'broken_countdowns_and_queued_extras_never_publish_a_prefix'
    pacing = prefix + 'incomplete_live_peers_obey_absolute_deadlines_and_cancellation'
    expired = prefix + 'expired_send_never_rebases_deadline_before_receive'
    limits = prefix + 'limits::packet_and_byte_limits_include_foreign_traffic_without_rejecting_the_boundary'
    buffers = prefix + 'limits::raw_receive_storage_is_cleared_before_reuse_and_preflight_cancellation_stops_io'
    admission = prefix + 'boundaries::ordinary_uid_cannot_admit_a_reader_and_nonces_never_wrap_or_repeat'
    native = prefix + 'boundaries::native_recvmsg_rejects_truncation_and_userspace_sources_with_private_descriptor_flags'
    read = 'src/connection/ipsec/pfkey/read.rs'
    batch = 'src/connection/ipsec/pfkey/read/batch.rs'
    socket = 'src/connection/ipsec/pfkey/read/socket.rs'
    return [
        ('query-version-wrong', read, lambda s: replace(s, 'bytes[0] = 2;', 'bytes[0] = 1;'), positive),
        ('query-kind-confused', read, lambda s: replace(s, 'Kind::Spd => 18,', 'Kind::Spd => 10,'), positive),
        ('query-pid-lost', read, lambda s: replace(s, '&pid.to_ne_bytes()', '&0u32.to_ne_bytes()'), positive),
        ('query-nonce-lost', read, lambda s: replace(s, '&sequence.to_ne_bytes()', '&0u32.to_ne_bytes()'), positive),
        ('query-satype-not-unspecified', read, lambda s: replace(s, 'bytes[1] = kind_byte(kind);', 'bytes[1] = kind_byte(kind); bytes[3] = 3;'), positive),
        ('query-length-wrong', read, lambda s: replace(s, '&2u16.to_ne_bytes()', '&3u16.to_ne_bytes()'), positive),
        ('query-never-sent', read, lambda s: replace(s, '    io.send(&request(kind, pid, sequence), budget)?;\n', ''), buffers),
        ('preflight-cancellation-ignored', read, collector_preflight, buffers),
        ('raw-buffer-not-cleared', read, lambda s: replace(s, '        raw.zeroize();\n', ''), buffers),
        ('queued-extra-not-checked', read, lambda s: replace(s, 'batch.finished() && !io.pending(budget)?', 'batch.finished()'), broken),
        ('ordinary-uid-admitted', read, lambda s: replace(s, 'libc::getuid() != 0 || libc::geteuid() != 0', 'false'), admission),
        ('zero-nonce-admitted', read, lambda s: replace(s, 'if value == 0 {', 'if false {'), admission),
        ('nonce-wraps', read, lambda s: replace(s, 'value.checked_add(1).ok_or(Error::Exhausted)?', 'value.wrapping_add(1)'), admission),
        ('nonce-reused', read, lambda s: replace(s, 'compare_exchange_weak(value, next,', 'compare_exchange_weak(value, value,'), admission),
        ('foreign-pid-admitted', batch, lambda s: replace(s, 'wire::u32_at(bytes, 12)? != self.pid', 'false'), positive),
        ('foreign-kind-admitted', batch, lambda s: replace(s, 'bytes[1] != kind_byte(self.kind)', 'false'), positive),
        ('foreign-envelope-unchecked', batch, lambda s: replace(s, '        wire::check_datagram(bytes)?;\n', ''), limits),
        ('packet-limit-omitted', batch, lambda s: replace(s, 'self.count > 4096', 'false'), limits),
        ('packet-boundary-rejected', batch, lambda s: replace(s, 'self.count > 4096', 'self.count >= 4096'), limits),
        ('byte-limit-omitted', batch, lambda s: replace(s, 'self.bytes > 16 * 1024 * 1024', 'false'), limits),
        ('byte-boundary-rejected', batch, lambda s: replace(s, 'self.bytes > 16 * 1024 * 1024', 'self.bytes >= 16 * 1024 * 1024'), limits),
        ('unfinished-batch-published', batch, lambda s: replace(s, 'self.end.ok_or(Error::Changed)?', 'self.end.unwrap_or(ProtocolEnd::EmptyReply)'), limits),
        ('extra-matching-packet-admitted', batch, lambda s: replace(s, 'if self.finished() {', 'if false {'), broken),
        ('empty-nonce-unchecked', batch, lambda s: replace(s, 'packet.sequence != self.nonce', 'false'), errors),
        ('prefix-error-becomes-empty', batch, lambda s: replace(s, '!self.entries.is_empty()', 'false'), broken),
        ('all-errors-become-empty', batch, lambda s: replace(s, 'i32::from(errno) == libc::ENOENT', 'true'), errors),
        ('permission-error-lost', batch, lambda s: replace(s, '                Error::PermissionDenied', '                Error::Unavailable'), errors),
        ('countdown-size-unbounded', batch, lambda s: replace(s, 'packet.sequence >= 4096', 'false'), broken),
        ('countdown-continuity-unchecked', batch, lambda s: replace(s, 'self.next.is_some_and(|next| packet.sequence != next)', 'false'), broken),
        ('countdown-not-decremented', batch, lambda s: replace(s, 'Some(packet.sequence - 1)', 'Some(packet.sequence)'), positive),
        ('first-entry-discarded', batch, lambda s: replace(s, 'self.entries.push(packet.entry);', 'if packet.sequence == 0 { self.entries.push(packet.entry); }'), positive),
        ('descriptor-inherited', socket, lambda s: replace(s, 'libc::F_SETFD, libc::FD_CLOEXEC', 'libc::F_SETFD, 0'), native),
        ('descriptor-blocking', socket, lambda s: replace(s, 'libc::F_SETFL, libc::O_NONBLOCK', 'libc::F_SETFL, 0'), native),
        ('userspace-origin-admitted', socket, lambda s: replace(s, 'if !received.kernel_source() {', 'if false {'), native),
        ('source-length-unchecked', socket, lambda s: replace(s, 'self.source_length == 2', 'true'), native),
        ('sockaddr-length-unchecked', socket, lambda s: replace(s, 'self.source.ss_len == 2', 'true'), native),
        ('source-family-unchecked', socket, lambda s: replace(s, 'i32::from(self.source.ss_family) == libc::PF_KEY', 'true'), native),
        ('recvmsg-truncation-ignored', socket, lambda s: replace(s, 'message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0', 'false'), native),
        ('cancellation-error-lost', socket, lambda s: replace(s, 'crate::helper::vici::Error::Canceled => Error::Canceled', 'crate::helper::vici::Error::Canceled => Error::Unavailable'), pacing),
        ('deadline-error-lost', socket, lambda s: replace(s, 'crate::helper::vici::Error::Timeout => Error::Timeout', 'crate::helper::vici::Error::Timeout => Error::Unavailable'), pacing),
        ('deadline-rebased-after-send', read, deadline_rebased_after_send, expired),
    ]


def receipt_inputs():
    """Every file the baseline/mutation build reads, without duplicates.

    Beyond `src`/`tests`, the build copy includes the localization catalogue
    (`include_str!` in `src/localization.rs`) and the audited patch files quoted
    by the runtime manifest, so both are build inputs and are hashed here.
    """
    inputs = [p for folder in ['src', 'tests', 'ui/src/locales', 'scripts/macos/patches']
              for p in sorted((ROOT / folder).rglob('*')) if p.is_file()]
    inputs += [Path(__file__), Path(__file__).with_name('check-broker.py'), ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    inputs += build_inputs.source_files(ROOT)
    unique, seen = [], set()
    for path in sorted(inputs, key=lambda p: str(p.relative_to(ROOT))):
        key = str(path.relative_to(ROOT))
        if key not in seen:
            seen.add(key)
            unique.append(path)
    inputs = unique
    if len({str(p.relative_to(ROOT)) for p in inputs}) != len(inputs):
        raise RuntimeError('Duplicate input path in receipt')
    return inputs


def main():
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run as an ordinary macOS user; no PF_KEY, elevation or VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    cases = mutations()
    for label, file, mutate, _ in cases:
        if mutate((ROOT / file).read_text()) == (ROOT / file).read_text():
            raise RuntimeError(f'{label}: unchanged mutation')
    inputs = receipt_inputs()
    receipt = {'sourceSha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
               'pfkeySocketOpened': False, 'vpnStarted': False,
               'limits': 'Same collector/send/recvmsg with private independent C SDK peer over AF_UNIX; memory fixtures for limits and buffer reuse. Root admission negative only; AF_KEY source layout synthetic. No live PF_KEY, kernel completeness, ownership, cleanup, daemon, routes, privileged installation or VPN.'}
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']: shutil.copytree(ROOT / name, copy / name)
            build_inputs.copy_into(ROOT, copy)
            receipt['baseline'] = base.run(copy, 'baseline', 'connection::ipsec::pfkey::read')
            for label, file, mutate, expected in cases:
                target = copy / file
                original = target.read_text()
                try:
                    target.write_text(mutate(original))
                    receipt[label] = base.run(copy, label, expected, expected)
                finally: target.write_text(original)
            receipt['restored'] = base.run(copy, 'restored', 'connection::ipsec::pfkey::read')
    finally:
        (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(cases)} reader mutations; baseline/restoration passed; copy removed; no PF_KEY/VPN')


if __name__ == '__main__': main()
