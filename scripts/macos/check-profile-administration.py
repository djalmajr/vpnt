#!/usr/bin/env python3
"""Profile admission/admin isolation oracles, without root or VPN resources."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'output/fixtures/profile-admin-oracles'
spec = importlib.util.spec_from_file_location('rust_build_inputs', Path(__file__).with_name('rust_build_inputs.py'))
build_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_inputs)

def replace(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError(f'Changed mutation anchor: {before!r}')
    return source.replace(before, after)

def without_reservation(source, start, end):
    at=source.index(start);stop=source.index(end,at)
    part=source[at:stop]
    begin=part.index('        let reservation = self.reserve(')
    finish=part.index('\n',begin)
    part=part[:begin]+part[finish+1:]
    part=replace(part,'        reservation.validate()?;\n','')
    return source[:at]+part+source[stop:]

def no_validation(source):
    at=source.index('    pub fn validate(&self) -> Result<(), StoreError> {')
    return source[:at]+'    pub fn validate(&self) -> Result<(), StoreError> { Ok(()) }\n}\n'

def partial_refresh(source):
    source=replace(source,'for (id, slot) in slots.iter() {','for (id, slot) in slots.iter_mut() {')
    return replace(source,'        if slot.worker.is_some() || slot.pending.is_some() {','        if slot.worker.is_none() && slot.pending.is_none() { if let Some(profile) = next.get(id) { slot.profile = profile.clone(); slot.generation += 1; } }\n        if slot.worker.is_some() || slot.pending.is_some() {')

def leak_fd(source):
    anchor='        guard.validate()?;'
    if source.count(anchor)!=2: raise RuntimeError('Changed descriptor admission')
    return source.replace(anchor,'        unsafe { libc::fcntl(guard.file.as_raw_fd(), libc::F_SETFD, 0); }\n'+anchor,1)

def run(copy,label,selector,expected=None):
    command=['cargo','test','--locked','--offline','--no-default-features',*selector]
    result=subprocess.run(command,cwd=copy,capture_output=True,timeout=90)
    log=result.stdout+result.stderr
    (REPORTS/(label+'.log')).write_bytes(log)
    if result.returncode!=(101 if expected else 0):
        raise RuntimeError(f'{label}: unexpected exit {result.returncode}')
    if expected and (f'test {expected} ... FAILED'.encode() not in log or b'panicked at' not in log or b'test result: FAILED.' not in log):
        raise RuntimeError(f'{label}: expected consumer assertion, not build failure')
    print(f'{label}: exit {result.returncode}',flush=True)
    return {'command':command,'exit':result.returncode,'assertion':expected}

def main():
    if sys.platform!='darwin' or os.getuid()==0 or os.geteuid()==0:
        raise SystemExit('Run on macOS as an ordinary user; no sudo, installed helper or VPN')
    REPORTS.mkdir(parents=True,exist_ok=True)
    store='src/storage.rs';reservation='src/storage/reservation.rs';profiles='src/connection/controller/profiles.rs';metadata='src/connection/controller/engine/metadata.rs'
    isolated='a_reserved_profile_cannot_be_edited_or_removed_but_another_profile_can'
    independent='a_different_process_observes_flock_and_release_preserves_the_inode'
    tampered='exposed_replaced_or_linked_reservation_inodes_are_not_trusted'
    retained='connection::controller::profiles::tests::controller_retains_a_reservation_after_worker_unwind_until_explicit_cleanup_proof'
    cached='connection::controller::profiles::tests::changed_or_removed_metadata_cannot_start_the_cached_profile'
    refresh='connection::controller::engine::metadata_tests::snapshot_refresh_preserves_a_live_profile_and_exposes_edited_new_and_removed_metadata'
    atomic='connection::controller::engine::metadata_tests::a_rejected_refresh_cannot_partially_edit_idle_slots_or_cancel_a_live_slot'
    capable='connection::controller::engine::tests::capabilities_tests::capability_factory_accepts_valid_ipsec'
    missing_psk='connection::controller::engine::tests::capabilities_tests::ipsec_missing_psk_is_invalid_secret'
    revocation='connection::controller::engine::tests::capabilities_tests::revocation_keeps_active_generation_and_route'
    mutants=[
        ('reservation-release-waits-for-fork',reservation,lambda s:replace(s,'let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };','let _ = self.file.as_raw_fd();'),['--lib','storage::reservation::tests::release_does_not_wait_for_a_transient_duplicate_of_the_owned_descriptor'],'storage::reservation::tests::release_does_not_wait_for_a_transient_duplicate_of_the_owned_descriptor'),
        ('save-without-target-reservation',store,lambda s:without_reservation(s,'    pub fn save(','    pub fn remove('),['--test','profile_reservations',isolated],isolated),
        ('remove-without-target-reservation',store,lambda s:without_reservation(s,'    pub fn remove(','    fn check_directory('),['--test','profile_reservations',isolated],isolated),
        ('reservation-flock-omitted',reservation,lambda s:replace(s,'if unsafe { libc::flock(guard.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0','if false'),['--test','profile_reservations',independent],independent),
        ('profile-id-case-folded',reservation,lambda s:replace(s,'let name: String = id.bytes().map(|byte| format!("{byte:02x}")).collect();','let name = id.to_string();'),['--test','profile_reservations','profile_identity_does_not_fold_case_on_case_insensitive_filesystems'],'profile_identity_does_not_fold_case_on_case_insensitive_filesystems'),
        ('reservation-validation-omitted',reservation,no_validation,['--test','profile_reservations',tampered],tampered),
        ('reservation-inode-binding-omitted',reservation,lambda s:replace(s,'if !named.is_file() || named.dev() != opened.dev() || named.ino() != opened.ino()','if false'),['--test','profile_reservations',tampered],tampered),
        ('reservation-hardlinks-accepted',store,lambda s:replace(s,'            || metadata.nlink() != 1\n',''),['--test','profile_reservations',tampered],tampered),
        ('reservation-acl-grant-accepted',reservation,lambda s:replace(s,'        crate::fs_permissions::check_file(&self.file, true)\n            .map_err(|_| StoreError::UntrustedPath)?;\n',''),['--test','profile_reservations','profile_reservations_reject_acl_read_grants_even_with_private_mode'],'profile_reservations_reject_acl_read_grants_even_with_private_mode'),
        ('reservation-inherited-through-exec',reservation,leak_fd,['--test','profile_reservations',independent],independent),
        ('cached-metadata-used-after-edit',profiles,lambda s:replace(s,'if current != *profile {','if false {'),['--lib',cached],cached),
        ('worker-unwind-releases-reservation',profiles,lambda s:s+'\nimpl Drop for ProfileUse { fn drop(&mut self) { if let Ok(mut all) = self.reservations.lock() { all.remove(&self.key); } } }\n',['--lib',retained],retained),
        ('cleanup-releases-invalid-reservation',profiles,lambda s:replace(s,'        all.get(&self.key)\n            .ok_or(StoreError::InvalidData)?\n            .validate()?;\n',''),['--lib',cached],cached),
        ('snapshot-does-not-refresh-catalog','src/connection/controller/engine.rs',lambda s:replace(s,'metadata::refresh(&mut slots, profiles)?;','let _ = profiles;'),['--lib',refresh],refresh),
        ('changed-metadata-keeps-generation',metadata,lambda s:replace(s,'                slot.generation += 1;\n',''),['--lib',refresh],refresh),
        ('removed-profile-remains-visible',metadata,lambda s:replace(s,'    slots.retain(|id, _| next.contains_key(id));\n',''),['--lib',refresh],refresh),
        ('queued-profile-can-change',metadata,lambda s:replace(s,' || slot.pending.is_some()',''),['--lib','connection::controller::engine::metadata::tests::a_queued_connection_protects_its_profile_before_the_worker_is_launched'],'connection::controller::engine::metadata::tests::a_queued_connection_protects_its_profile_before_the_worker_is_launched'),
        ('refresh-mutates-live-slot',metadata,lambda s:replace(s,'if slot.worker.is_some() || slot.pending.is_some() {','if false {'),['--lib',atomic],atomic),
        ('failed-refresh-partially-mutates-idle-slot',metadata,partial_refresh,['--lib',atomic],atomic),
        ('ipsec-dispatched-to-ssl','src/connection/controller/engine/dispatch.rs',lambda s:replace(s,'if !factory.supports(slot.profile.kind) {','if false {'),['--lib','connection::controller::engine::metadata_tests::ipsec_metadata_is_visible_without_dispatching_it_to_the_ssl_worker'],'connection::controller::engine::metadata_tests::ipsec_metadata_is_visible_without_dispatching_it_to_the_ssl_worker'),
        ('hardcoded-ssl-support','src/connection/controller/engine/dispatch.rs',lambda s:replace(s,'if !factory.supports(slot.profile.kind) {','if slot.profile.kind != VpnKind::Ssl {'),['--lib',capable],capable),
        ('ssl-validation-for-ipsec','src/connection/controller/engine/dispatch.rs',lambda s:replace(s,'if credentials.validate(slot.profile.kind).is_err() {','if credentials.validate(VpnKind::Ssl).is_err() {'),['--lib',missing_psk],missing_psk),
        ('cancel-before-capability-denial','src/connection/controller/engine/dispatch.rs',lambda s:replace(s,'            if !factory.supports(slot.profile.kind) {','            slot.cancel();\n            if !factory.supports(slot.profile.kind) {'),['--lib',revocation],revocation),
    ]
    source={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for base in ['src','tests','ui/src/locales'] for p in sorted((ROOT/base).rglob('*')) if p.is_file()}
    for key, digest in build_inputs.source_hashes(ROOT).items():
        if key in source and source[key]!=digest:
            raise RuntimeError(f'conflicting build input hash: {key}')
        source[key]=digest
    receipt={'sourceSha256':dict(sorted(source.items()))}
    try:
        with tempfile.TemporaryDirectory(prefix='copy-',dir=REPORTS) as temporary:
            copy=Path(temporary)
            for name in ['Cargo.toml','Cargo.lock']:shutil.copy2(ROOT/name,copy/name)
            for name in ['src','tests','scripts/macos/patches','ui/src/locales']:shutil.copytree(ROOT/name,copy/name)
            build_inputs.copy_into(ROOT, copy)
            baselines=[('release',['--lib','storage::reservation']),('filesystem',['--test','profile_reservations','--test','storage']),('custody',['--lib','connection::controller::profiles']),('metadata',['--lib','connection::controller::engine::metadata']),('admin-wire',['--lib','helper::server::tests::profiles'])]
            for label,args in baselines:receipt['baseline-'+label]=run(copy,'baseline-'+label,args)
            for label,file,mutate,args,expected in mutants:
                path=copy/file;original=path.read_text()
                try:
                    path.write_text(mutate(original));receipt[label]=run(copy,label,args,expected)
                finally:path.write_text(original)
            for label,args in baselines:receipt['restored-'+label]=run(copy,'restored-'+label,args)
    finally:(REPORTS/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(f'Killed {len(mutants)} profile/admin mutations; ten baselines/restorations passed; copy removed')

if __name__=='__main__':main()
