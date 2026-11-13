//! Real Control consumer over the existing VICI fixture: selection, coverage
//! and owner metadata only, never native ownership or traffic proof.
use super::*;
use crate::connection::routes::Network;
use std::net::IpAddr;

fn started(mode: &str) -> (Controller, Harness, Observation, RegistryHandle) {
    let (mut control, harness, observation, registry) = setup(mode, false);
    control.start(creds(), until(), token()).unwrap();
    (control, harness, observation, registry)
}

#[test]
fn before_start_selected_denies_and_audits_nothing() {
    let (mut control, harness, observation, registry) = setup("normal", false);
    assert_eq!(control.selected(until(), token()), Err(Error::Changed));
    assert!(harness.audit().is_empty());
    settle(&mut control, &harness, &observation, &registry);
}

#[test]
fn normal_selected_returns_the_exact_candidate_and_canonical_plan() {
    let (mut control, harness, observation, registry) = started("normal");
    let before = harness.audit();
    let (candidate, plan) = control.selected(until(), token()).unwrap();
    // Every public Candidate field, independent of the Python fixture and with
    // the fixture's literal values checked in this file.
    let v4: IpAddr = "10.8.0.2".parse().unwrap();
    assert_eq!(candidate.ike_id, 1);
    assert_eq!(candidate.child_id, 1);
    assert_eq!(candidate.reqid, 16383);
    assert_eq!(candidate.local, "192.0.2.2".parse::<IpAddr>().unwrap());
    assert_eq!(candidate.remote, "198.51.100.3".parse::<IpAddr>().unwrap());
    assert_eq!(candidate.local_port, 45000);
    assert_eq!(candidate.remote_port, 500);
    assert!(!candidate.udp_encap);
    assert_eq!(candidate.spi_in, 0xabcd0102);
    assert_eq!(candidate.spi_out, 0xabcd0103);
    assert_eq!(candidate.local_ts, vec![Network::host(v4)]);
    assert_eq!(
        candidate.remote_ts,
        vec![Network::new("10.20.0.0".parse().unwrap(), 24).unwrap()]
    );
    assert_eq!(candidate.vips, vec![v4]);
    assert!(candidate.active);
    assert_eq!(plan, vec!["10.20.0.0/24"]);
    // G4: selected adds exactly one list-sas and never replays loads/initiate.
    let after = harness.audit();
    assert_eq!(&after[..before.len()], before.as_slice());
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(after.last().map(String::as_str), Some("list-sas"));
    let owner = control.owner();
    assert_eq!(owner.uid, 502);
    assert_eq!(owner.profile, "Case");
    assert_eq!(owner.generation, 7);
    settle(&mut control, &harness, &observation, &registry);
}

#[test]
fn ipv6_selected_returns_the_exact_family_plan() {
    let (mut control, harness, observation, registry) = started("ipv6");
    let (candidate, plan) = control.selected(until(), token()).unwrap();
    assert_eq!(plan, vec!["2001:db8:20::/64"]);
    assert_eq!(
        candidate.vips,
        vec!["2001:db8:8::2".parse::<IpAddr>().unwrap()]
    );
    settle(&mut control, &harness, &observation, &registry);
}

#[test]
fn empty_and_inactive_only_batches_are_busy() {
    for mode in ["empty", "inactive-only"] {
        let (mut control, harness, observation, registry) = started(mode);
        assert_eq!(
            control.selected(until(), token()),
            Err(Error::Busy),
            "{mode}"
        );
        settle(&mut control, &harness, &observation, &registry);
    }
}

#[test]
fn rekey_ignores_the_inactive_old_candidate() {
    let (mut control, harness, observation, registry) = started("rekey");
    let (candidate, plan) = control.selected(until(), token()).unwrap();
    assert_eq!(candidate.child_id, 2);
    assert_eq!(plan, vec!["10.20.0.0/24"]);
    settle(&mut control, &harness, &observation, &registry);
}

#[test]
fn compatible_overlap_picks_the_higher_child_id_deterministically() {
    let (mut control, harness, observation, registry) = started("compatible-overlap");
    let (candidate, _) = control.selected(until(), token()).unwrap();
    assert_eq!(candidate.child_id, 2);
    assert_eq!(candidate.spi_in, 0xabcd0104);
    assert_eq!(candidate.spi_out, 0xabcd0105);
    // A second call is a fresh batch, not a replay of the first selection.
    let (again, _) = control.selected(until(), token()).unwrap();
    assert_eq!(again.child_id, 2);
    assert_eq!(
        harness.audit().iter().filter(|s| **s == "list-sas").count(),
        2
    );
    settle(&mut control, &harness, &observation, &registry);
}

#[test]
fn overlap_conflict_rejects_the_entire_batch() {
    let (mut control, harness, observation, registry) = started("overlap-conflict");
    assert_eq!(control.selected(until(), token()), Err(Error::Changed));
    settle(&mut control, &harness, &observation, &registry);
}

#[test]
fn narrowed_remote_ts_refuses_the_broad_route_plan() {
    let (mut control, harness, observation, registry) = started("narrowed");
    assert_eq!(control.selected(until(), token()), Err(Error::Changed));
    settle(&mut control, &harness, &observation, &registry);
}

#[test]
fn expired_or_canceled_selected_performs_no_vici() {
    let (mut control, harness, observation, registry) = started("normal");
    let audit = harness.audit().len();
    assert_eq!(
        control.selected(Instant::now(), token()),
        Err(Error::Timeout)
    );
    assert_eq!(
        control.selected(until(), Arc::new(AtomicBool::new(true))),
        Err(Error::Canceled)
    );
    assert_eq!(harness.audit().len(), audit);
    settle(&mut control, &harness, &observation, &registry);
}

#[test]
fn released_control_denies_selected_again() {
    let (mut control, harness, observation, registry) = started("normal");
    settle(&mut control, &harness, &observation, &registry);
    assert_eq!(control.selected(until(), token()), Err(Error::Changed));
}

// G2: a Dirty control (failed initiate, no new VICI) cannot leak selection.
#[test]
fn dirty_control_denies_selected_without_a_new_vici() {
    let (mut control, harness, observation, registry) = setup("initiate:1", false);
    assert_eq!(
        control.start(creds(), until(), token()),
        Err(Error::Rejected)
    );
    assert_eq!(control.phase(), Phase::Dirty);
    let audit = harness.audit();
    assert_eq!(audit.len(), 6);
    assert_eq!(control.selected(until(), token()), Err(Error::Changed));
    assert_eq!(harness.audit(), audit, "dirty selected issued VICI");
    settle(&mut control, &harness, &observation, &registry);
}
