#!/usr/bin/env python3
"""IPsec namespace and VICI request contracts, without charon or kernel writes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/ipsec-oracles'
spec = importlib.util.spec_from_file_location('broker_oracles', Path(__file__).with_name('check-broker.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.REPORTS = REPORTS
replace = base.replace
spec = importlib.util.spec_from_file_location('rust_build_inputs', Path(__file__).with_name('rust_build_inputs.py'))
build_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_inputs)


def main():
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run as an ordinary user; no charon, PF_KEY, sudo or VPN')
    REPORTS.mkdir(parents=True, exist_ok=True)
    prefix = 'connection::ipsec::tests::'
    namespace = 'src/connection/ipsec/namespace.rs'
    config = 'src/connection/ipsec/config.rs'
    scope = prefix + 'private_ike_configuration_has_fixed_scope_and_only_shared_messages_carry_credentials'
    invalid = prefix + 'configuration_cannot_cross_a_profile_or_reservation_or_use_an_invalid_endpoint_or_deadline'
    identity = prefix + 'identity::names_preserve_uid_generation_case_and_the_full_profile_and_default_selectors_cover_both_families'
    reserve = prefix + 'namespace::reservations_exclude_kernel_ids_and_other_generations_until_the_producer_and_kernel_are_clear'
    tokens = prefix + 'namespace::foreign_and_stale_tokens_cannot_release_a_new_reservation_and_failed_observation_changes_nothing'
    bounds = prefix + 'namespace::exhausted_or_invalid_namespaces_never_truncate_or_admit_an_invalid_owner'
    capacity = prefix + 'namespace::the_profile_capacity_is_bounded_without_reusing_dropped_or_unconfirmed_reservations'
    mutations = [
        ('root-owner-accepted', namespace, lambda s: replace(s, 'owner.uid == 0 || ', ''), bounds),
        ('zero-generation-accepted', namespace, lambda s: replace(s, 'owner.generation == 0 || ', ''), bounds),
        ('invalid-profile-id-accepted', namespace, lambda s: replace(s, '!valid_profile_id(&owner.profile)', 'false'), bounds),
        ('kernel-occupied-id-reused', namespace, lambda s: replace(s, '!occupied.contains(&u32::from(*id))', 'true'), reserve),
        ('local-reservation-overwritten', namespace, lambda s: replace(s, '!self.entries.contains_key(id)', 'true'), reserve),
        ('generation-overlaps-old-profile', namespace, lambda s: replace(s, '.any(|(_, current)| current.uid == owner.uid && current.profile == owner.profile)', '.any(|_| false)'), reserve),
        ('zero-reqid-issued', namespace, lambda s: replace(s, '(1..=MAX_MANUAL_REQID)', '(0..=MAX_MANUAL_REQID)'), bounds),
        ('kernel-reassigns-out-of-manual-range', namespace, lambda s: replace(s, 'const MAX_MANUAL_REQID: u16 = 0x3fff;', 'const MAX_MANUAL_REQID: u16 = u16::MAX;'), prefix + 'sdk::darwin_sdk_and_allocator_agree_on_the_manual_reqid_limit'),
        ('wide-reqid-silently-accepted', namespace, lambda s: replace(s, 'occupied.iter().any(|id| *id > u32::from(u16::MAX))', 'false'), bounds),
        ('foreign-registry-token-accepted', namespace, lambda s: replace(s, '!Arc::ptr_eq(&self.authority, &reservation.authority)', 'false'), tokens),
        ('stale-token-accepted', namespace, lambda s: replace(s, '*serial == reservation.serial && ', ''), tokens),
        ('producer-stop-not-required', namespace, lambda s: replace(s, '!self.observer.producer_stopped(&reservation.owner)?', 'false'), reserve),
        ('kernel-conflict-not-rechecked', namespace, lambda s: replace(s, 'self.occupied()?.contains(&u32::from(reservation.reqid))', 'false'), reserve),
        ('release-skips-kernel-confirmation', namespace, lambda s: replace(s, '        self.ensure_clear(reservation)?;\n', ''), reserve),
        ('failed-observation-becomes-empty', namespace, lambda s: replace(s, 'let occupied = self.observer.occupied()?;', 'let occupied = self.observer.occupied().unwrap_or_default();'), tokens),
        ('capacity-off-by-one', namespace, lambda s: replace(s, 'self.entries.len() >= 64', 'self.entries.len() > 64'), capacity),
        ('reservation-unlinked-before-confirmation', namespace, lambda s: replace(s, '        if !self.observer.producer_stopped', '        self.entries.remove(&reservation.reqid);\n        if !self.observer.producer_stopped'), reserve),
        ('config-accepts-foreign-token', config, lambda s: replace(s, '        registry.validate(reservation)?;\n', ''), invalid),
        ('config-crosses-profile', config, lambda s: replace(s, '            || profile.id != reservation.owner().profile\n', ''), invalid),
        ('ssl-profile-sent-to-ipsec', config, lambda s: replace(s, 'profile.kind != VpnKind::Ipsec', 'false'), invalid),
        ('empty-eap-identity-accepted', config, lambda s: replace(s, '            || profile.username.is_empty()\n', ''), invalid),
        ('endpoint-family-unchecked', config, lambda s: replace(s, '            || local.is_ipv4() != remote.is_ipv4()\n', ''), invalid),
        ('multicast-endpoint-accepted', config, lambda s: replace(s, '        && !ip.is_multicast()\n', ''), invalid),
        ('wrong-reqid-configured', config, lambda s: replace(s, '.value("reqid", self.reqid.to_string().as_bytes())', '.value("reqid", b"1")'), scope),
        ('ikev1-configured', config, lambda s: replace(s, '.value("version", b"2")', '.value("version", b"1")'), scope),
        ('automatic-start-configured', config, lambda s: replace(s, '.value("start_action", b"none")', '.value("start_action", b"trap")'), scope),
        ('automatic-reconnect-configured', config, lambda s: replace(s, '.value("dpd_action", b"clear")', '.value("dpd_action", b"restart")'), scope),
        ('psk-owner-is-wildcard', config, lambda s: replace(s, '.list("owners", [self.gateway.as_bytes()]);', '.list("owners", [b"%any".as_slice()]);'), scope),
        ('eap-key-type-substituted', config, lambda s: replace(s, '.value("type", b"EAP")', '.value("type", b"IKE")'), scope),
        ('eap-secret-substituted', config, lambda s: replace(s, '.value("data", credentials.password.expose().as_bytes())', '.value("data", credentials.psk.expose().as_bytes())'), scope),
        ('termination-scope-broadened', config, lambda s: replace(s, '.value("ike", self.name.as_bytes())', '.value("ike", b"%any")'), scope),
        ('zero-timeout-becomes-infinite', config, lambda s: replace(s, 'timeout.is_zero() || ', ''), invalid),
        ('excessive-timeout-accepted', config, lambda s: replace(s, 'timeout > Duration::from_secs(120)', 'false'), invalid),
        ('submillisecond-timeout-becomes-infinite', config, lambda s: replace(s, 'timeout.as_nanos().div_ceil(1_000_000)', 'timeout.as_nanos() / 1_000_000'), scope),
        ('uid-omitted-from-name', config, lambda s: replace(s, 'owner.uid, encoded, owner.generation', '502, encoded, owner.generation'), identity),
        ('generation-omitted-from-name', config, lambda s: replace(s, 'owner.uid, encoded, owner.generation', 'owner.uid, encoded, 1'), identity),
        ('profile-name-case-collision', config, lambda s: replace(s, 'hex(&profile.id)?', 'hex(&profile.id.to_ascii_lowercase())?'), identity),
        ('profile-name-truncated', config, lambda s: replace(s, 'hex(&profile.id)?', 'hex(&profile.id.chars().take(8).collect::<String>())?'), identity),
        ('ipv6-default-selector-omitted', config, lambda s: replace(s, 'vec!["0.0.0.0/0".into(), "::/0".into()]', 'vec!["0.0.0.0/0".into()]'), identity),
        ('resolved-endpoint-not-pinned', config, lambda s: replace(s, '[self.remote.to_string().as_bytes()]', '[self.gateway.as_bytes()]'), identity),
        ('username-reinterpreted-as-identity-pattern', config, lambda s: replace(s, 'identity: format!("keyid:#{}", hex(&profile.username)?),', 'identity: profile.username.clone(),'), prefix + 'identity::usernames_are_opaque_key_id_bytes_even_when_they_look_like_identity_patterns'),
        ('unspecified-gateway-identity-accepted', config, lambda s: replace(s, '            || profile\n                .gateway\n                .parse::<IpAddr>()\n                .is_ok_and(|ip| ip.is_unspecified())\n', ''), prefix + 'identity::usernames_are_opaque_key_id_bytes_even_when_they_look_like_identity_patterns'),
    ]
    for label, file, mutate, _ in mutations:
        source = (ROOT / file).read_text()
        if mutate(source) == source: raise RuntimeError(f'{label}: unchanged mutation')
    files = [p for folder in ['src', 'tests'] for p in sorted((ROOT / folder).rglob('*')) if p.is_file()]
    files += [Path(__file__), Path(__file__).with_name('check-broker.py')]
    files += build_inputs.source_files(ROOT)
    unique, seen = [], set()
    for path in sorted(files, key=lambda p: str(p.relative_to(ROOT))):
        key = str(path.relative_to(ROOT))
        if key not in seen:
            seen.add(key)
            unique.append(path)
    files = unique
    receipt = {'sourceSha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}, 'limits': 'Namespace and VICI schema mutations with injected observations. The full IPsec baseline also includes independent owned VICI fixture peers. No native SA/SPD observer, charon, authorization, privileged installation or VPN. No kernel mutation/deletion.'}
    try:
        with tempfile.TemporaryDirectory(prefix='vpnt-copy-', dir=REPORTS) as temporary:
            copy = Path(temporary)
            for name in ['Cargo.toml', 'Cargo.lock']: shutil.copy2(ROOT / name, copy / name)
            for name in ['src', 'tests', 'scripts/macos/patches', 'ui/src/locales']: shutil.copytree(ROOT / name, copy / name)
            build_inputs.copy_into(ROOT, copy)
            receipt['baseline'] = base.run(copy, 'baseline', prefix)
            for label, file, mutate, expected in mutations:
                path = copy / file
                original = path.read_text()
                try:
                    path.write_text(mutate(original))
                    receipt[label] = base.run(copy, label, expected, expected)
                finally: path.write_text(original)
            receipt['restored'] = base.run(copy, 'restored', prefix)
    finally: (REPORTS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'Killed {len(mutations)} IPsec contract mutations; two baselines/restorations passed; copy removed')


if __name__ == '__main__': main()
