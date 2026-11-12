#!/usr/bin/env python3
"""Check deadline/cancellation at the public VICI consumer with owned peers."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/vici-deadline-oracles'
spec = importlib.util.spec_from_file_location('broker_oracles', Path(__file__).with_name('check-broker.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
replace = base.replace


def run(copy, label, test='', failure=False):
    command = ['cargo', 'test', '--locked', '--offline', '--no-default-features', '--test', 'vici_deadlines', test]
    result = subprocess.run(command, cwd=copy, capture_output=True, timeout=180)
    log = result.stdout + result.stderr
    (REPORTS / f'{label}.log').write_bytes(log)
    if result.returncode != (101 if failure else 0):
        raise RuntimeError(f'{label}: unexpected exit {result.returncode}')
    if failure and (f'test {test} ... FAILED'.encode() not in log or b'panicked at' not in log or b'test result: FAILED.' not in log):
        raise RuntimeError(f'{label}: no executed assertion in the intended test')
    print(f'{label}: exit {result.returncode}', flush=True)
    return {'command': command, 'exit': result.returncode, 'assertion': test if failure else None}


def main():
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run as an ordinary user; no charon, privileges or VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    budget = 'src/helper/local_socket/budget.rs'
    client = 'src/helper/vici/client.rs'
    canceled = 'cancellation_interrupts_response_header_subscription_and_blocked_write_before_peer_exit'
    expired = 'a_client_cannot_restart_its_budget_or_send_a_request_after_expiry'
    preflight = 'preflight_denies_canceled_expired_and_foreign_peers_without_sending_bytes'
    deadline = 'an_independent_peer_cannot_extend_the_callers_deadline_and_a_reply_still_succeeds'
    path = 'path_connection_keeps_the_callers_budget_and_rejects_unadmitted_peers'
    mutations = [
        ('command-restarts-expired-budget', client, lambda s: replace(s, 'let budget = self.budget;', 'let budget = Budget::new(Duration::from_secs(5))?;'), expired),
        ('cancellation-ignored', budget, lambda s: replace(s, '.is_some_and(|flag| flag.load(Ordering::Acquire))', '.is_some_and(|flag| { let _ = flag.load(Ordering::Acquire); false })'), canceled),
        ('cancellation-waits-whole-deadline', budget, lambda s: replace(s, 'milliseconds.min(25)', 'milliseconds'), canceled),
        ('expired-budget-accepted', budget, lambda s: replace(s, 'Instant::now() >= self.expires', 'false'), expired),
        ('caller-deadline-extended', budget, lambda s: replace(s, 'let budget = Self { expires, cancel };', 'let budget = Self { expires: expires + Duration::from_secs(5), cancel };'), deadline),
        ('cancel-reported-as-timeout', 'src/helper/vici.rs', lambda s: replace(s, '            Self::Canceled\n', '            Self::Timeout\n'), canceled),
        ('os-abort-reported-as-cancel', 'src/helper/vici.rs', lambda s: replace(s, 'if error\n            .get_ref()', 'if error.kind() == io::ErrorKind::ConnectionAborted || error\n            .get_ref()'), preflight),
        ('peer-uid-unchecked', client, lambda s: replace(s, 'peer_uid(&stream)? != owner', 'peer_uid(&stream)? == owner.wrapping_add(2)'), preflight),
        ('path-connection-loses-cancel', client, lambda s: replace(s, 'Self::open(path, owner, Budget::until(expires, Some(cancel))?)', 'Self::open(path, owner, Budget::until(expires, { let _ = cancel; None })?)'), path),
        ('relative-socket-path-admitted', client, lambda s: replace(s, '!path.is_absolute()', 'false'), path),
    ]
    for label, file, mutate, _ in mutations:
        if mutate((ROOT / file).read_text()) == (ROOT / file).read_text():
            raise RuntimeError(f'{label}: unchanged mutation')
    files = [p for folder in ['src', 'tests'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file()]
    files += [Path(__file__), Path(__file__).with_name('check-broker.py'), ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    receipt = {'sourceSha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
               'limits': 'Public VICI client with own Unix sockets and independent Python peers. No charon, native peer PID/socket admission, PF_KEY, privileged installation or VPN.'}
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']: shutil.copytree(ROOT / name, copy / name)
            receipt['baseline'] = run(copy, 'baseline')
            for label, file, mutate, test in mutations:
                target = copy / file
                original = target.read_text()
                try:
                    target.write_text(mutate(original))
                    receipt[label] = run(copy, label, test, True)
                finally: target.write_text(original)
            receipt['restored'] = run(copy, 'restored')
    finally: (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(mutations)} VICI deadline mutations; baseline/restoration passed; copy removed')


if __name__ == '__main__': main()
