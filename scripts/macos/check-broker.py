#!/usr/bin/env python3
"""Discriminating broker/client mutations with an unprivileged fictional peer."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "output/fixtures/broker-oracles"

def replace(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError(f"Changed mutation anchor: {before!r}")
    return source.replace(before, after)

def expiry(source):
    start=source.index("    fn connect(")
    return source[:start]+replace(source[start:], "if Instant::now() >= expires {", "if false {")

def early_fault(source):
    start=source.index("        if let Err(error) = result {")
    end=source.index("        let _ = stream.shutdown",start)
    return source[:start]+source[end:]

def run(copy,label,filter,failed=None,desktop=False):
    command=["cargo","test","--locked","--offline", "--all-features" if desktop else "--no-default-features","--lib",filter]
    result=subprocess.run(command,cwd=copy,capture_output=True,timeout=240)
    log=result.stdout+result.stderr
    (REPORTS/(label+".log")).write_bytes(log)
    expected=101 if failed else 0
    if result.returncode!=expected:
        raise RuntimeError(f"{label}: expected {expected}, got {result.returncode}")
    if failed and (f"test {failed} ... FAILED".encode() not in log or b"panicked at" not in log or b"test result: FAILED." not in log):
        raise RuntimeError(f"{label}: expected executed assertion, not compilation/unrelated failure")
    print(f"{label}: exit {result.returncode}",flush=True)
    return {"exit":result.returncode,"command":command,"assertion":failed}

def main():
    if sys.platform!="darwin" or os.getuid()==0 or os.geteuid()==0:
        raise SystemExit("Run on macOS as an ordinary user; no sudo, helper installation or real VPN")
    REPORTS.mkdir(parents=True,exist_ok=True)
    model="src/broker/mod.rs";commands="src/broker/commands.rs";worker="src/helper/client/worker.rs"
    flow="broker::tests::helper_acceptance_never_claims_traffic_and_cancel_rejects_late_connected_generations"
    denied="broker::tests::incompatible_helper_or_expired_keychain_load_cannot_receive_credentials_or_start_a_tunnel"
    cleanup="helper::client::tests::a_private_child_receives_the_request_and_shutdown_waits_for_its_cleanup_without_killing_it"
    actor="desktop::worker::tests::expired_native_requests_cannot_start_a_demo_or_replay_after_a_ui_timeout"
    mutations=[
        ("version-admission-omitted",model,lambda s:replace(s,'if version != env!("CARGO_PKG_VERSION") {','if false {'),denied,False),
        ("accepted-substitutes-traffic-proof",model,lambda s:replace(s,"p.accepted = true;","p.accepted = true; set_state(c, State::Connected);"),flow,False),
        ("stale-generation-invalidates-session",model,lambda s:replace(s,"                if generation < c.generation {\n                    return Ok(());\n                }\n",""),flow,False),
        ("disconnect-all-only-first-profile",commands,lambda s:replace(s,"for id in ids {","for id in ids.into_iter().take(1) {"),flow,False),
        ("probe-disconnects-tunnel",commands,lambda s:replace(s,"protocol::Command::Probe {","protocol::Command::Disconnect {"),flow,False),
        ("expired-keychain-result-starts-tunnel",commands,expiry,denied,False),
        ("process-exit-becomes-off",model,lambda s:replace(s,"set_state(connection, State::HelperMissing);","set_state(connection, State::Off);"),"broker::tests::helper_loss_removes_connected_indications_without_turning_process_exit_into_off",False),
        ("initial-active-snapshot-accepted",model,lambda s:replace(s,"s.generation != 0 || s.state != State::Off","false"),"broker::tests::an_initial_connected_snapshot_is_rejected_before_any_credential_load",False),
        ("owned-helper-killed-during-cleanup",worker,lambda s:replace(s,"let waited = child.wait()","let _ = child.kill(); let waited = child.wait()"),cleanup,False),
        ("channel-fault-delayed-until-child-exit",worker,early_fault,"helper::client::tests::malformed_and_incompatible_replies_fail_the_channel_instead_of_becoming_snapshots",False),
        ("inherited-environment-reaches-helper",worker,lambda s:replace(s,"            .env_clear()\n",""),cleanup,False),
        ("expired-native-job-executed","src/desktop/worker.rs",lambda s:replace(s,"if Instant::now() >= work.expires {","if false {"),actor,True),
    ]
    receipt={"sourceSha256":{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for base in ["src","tests","ui/src"] for p in sorted((ROOT/base).rglob("*")) if p.is_file()}}
    try:
        with tempfile.TemporaryDirectory(prefix="copy-",dir=REPORTS) as temporary:
            copy=Path(temporary)
            for name in ["Cargo.toml","Cargo.lock"]:shutil.copy2(ROOT/name,copy/name)
            for name in ["src","tests","scripts/macos/patches","ui/dist"]:shutil.copytree(ROOT/name,copy/name)
            baselines=[("broker","broker::tests",False),("client","helper::client",False),("actor",actor,True)]
            for label,filter,desktop in baselines:receipt["baseline-"+label]=run(copy,"baseline-"+label,filter,desktop=desktop)
            for label,file,mutate,expected,desktop in mutations:
                path=copy/file;original=path.read_text()
                try:
                    path.write_text(mutate(original));receipt[label]=run(copy,label,expected,expected,desktop)
                finally:path.write_text(original)
            for label,filter,desktop in baselines:receipt["restored-"+label]=run(copy,"restored-"+label,filter,desktop=desktop)
    finally:(REPORTS/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(f"Killed {len(mutations)} broker mutations; six baselines/restorations passed; copy removed")

if __name__=="__main__":main()
