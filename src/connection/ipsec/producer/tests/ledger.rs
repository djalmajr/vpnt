//! Ledger tests over the ordinary C producer and synthetic absence. The
//! synthetic absence is labelled; native kernel absence is NOT RUN.
use super::bound::{egress, profile};
use super::*;
use crate::connection::ipsec::producer::ledger::Absence;
use crate::connection::ipsec::{NativeLedger, Peer, ResourceClaims, UserspaceObserver};
use crate::helper::vici::Message;
use crate::model::VpnKind;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, atomic::AtomicBool},
};

struct Scripted {
    answers: Mutex<VecDeque<Result<bool, Error>>>,
}

impl Scripted {
    fn new(answers: Vec<Result<bool, Error>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
        })
    }
}

impl Absence for Scripted {
    fn complete(&self) -> Result<bool, Error> {
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(false))
    }
}

type LedgerRegistry<'a> = Registry<UserspaceObserver<'a, NativeLedger<'a>>>;

fn prepared<'a>(
    ledger: &NativeLedger<'a>,
    registry: &LedgerRegistry<'a>,
    reservation: &Reservation,
    profile: &Profile,
) -> (Config, Admission<'a>) {
    ledger
        .prepare(
            registry,
            reservation,
            profile,
            egress(profile),
            (until(), token()),
        )
        .unwrap()
}

#[test]
fn prepare_open_version_wrong_owner_and_completed_cleanup() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![Ok(true)]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("ledger", 31)).unwrap();
    let profile = profile("ledger");
    let (config, mut admission) = prepared(&ledger, &registry, &reservation, &profile);
    assert_eq!(config.name(), "vpnt-502-6c6564676572-31");
    let wrong = owner("other", 31);
    assert_eq!(
        admission.open(&wrong, until(), token()).err(),
        Some(Error::Changed)
    );
    assert_eq!(admission.retire(&wrong), Err(Error::Changed));
    let opened = admission
        .open(reservation.owner(), until(), token())
        .unwrap();
    let response = opened
        .command("version", Message::new(), &[])
        .unwrap()
        .response;
    assert_eq!(response.get_text("version"), Some("6.1.0"));
    assert_eq!(admission.retire(reservation.owner()), Ok(true));
    admission.begin_cleanup().unwrap();
    assert_eq!(
        admission.open(reservation.owner(), until(), token()).err(),
        Some(Error::Changed)
    );
    ledger.reap().unwrap();
    registry.release(&reservation).unwrap();
    assert_eq!(
        admission.open(reservation.owner(), until(), token()).err(),
        Some(Error::Changed)
    );
    assert!(admission.native_peer(until(), token()).is_err());
    assert_eq!(admission.retire(reservation.owner()), Ok(true));
    assert!(!ledger.has_resources());
}

#[test]
fn last_admission_drop_keeps_strong_claim_and_reap_stops_original() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut ledger =
        NativeLedger::scripted(context.clone(), Scripted::new(vec![Ok(true), Ok(true)]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("strong", 32)).unwrap();
    let profile = profile("strong");
    let (_, admission) = prepared(&ledger, &registry, &reservation, &profile);
    let owner = reservation.owner().clone();
    assert_eq!(ledger.pending_owners().unwrap(), vec![owner.clone()]);
    drop(admission);
    assert!(ledger.has_resources());
    assert_eq!(ledger.pending_owners().unwrap(), vec![owner.clone()]);
    ledger.reap().unwrap();
    assert!(ledger.pending_owners().unwrap().is_empty());
    registry.release(&reservation).unwrap();
    assert!(!ledger.has_resources());
}

#[test]
fn draining_false_absence_blocks_release_until_true() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut ledger = NativeLedger::scripted(
        context.clone(),
        Scripted::new(vec![Ok(false), Ok(false), Ok(true)]),
    );
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("absence", 33)).unwrap();
    let profile = profile("absence");
    let (_, admission) = prepared(&ledger, &registry, &reservation, &profile);
    drop(admission);
    ledger.reap().unwrap();
    assert_eq!(registry.release(&reservation), Err(Error::Busy));
    assert_eq!(
        ledger.pending_owners().unwrap(),
        vec![reservation.owner().clone()]
    );
    registry.release(&reservation).unwrap();
    assert!(!ledger.has_resources());
}

#[test]
fn ssl_wrong_profile_expired_and_cancel_leave_no_entry() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let ssl_reservation = registry.reserve(owner("ledger-ssl", 34)).unwrap();
    let mut ssl = profile("ledger-ssl");
    ssl.kind = VpnKind::Ssl;
    assert_eq!(
        ledger
            .prepare(
                &registry,
                &ssl_reservation,
                &ssl,
                egress(&profile("ledger-ssl")),
                (until(), token())
            )
            .map(|_| ()),
        Err(Error::Invalid)
    );
    assert!(!ledger.has_resources());
    let expired_reservation = registry.reserve(owner("ledger-expired", 35)).unwrap();
    let expired = profile("ledger-expired");
    assert_eq!(
        ledger
            .prepare(
                &registry,
                &expired_reservation,
                &expired,
                egress(&expired),
                (Instant::now(), token())
            )
            .map(|_| ()),
        Err(Error::Timeout)
    );
    let cancel = Arc::new(AtomicBool::new(true));
    assert_eq!(
        ledger
            .prepare(
                &registry,
                &expired_reservation,
                &expired,
                egress(&expired),
                (until(), cancel)
            )
            .map(|_| ()),
        Err(Error::Canceled)
    );
    assert!(!ledger.has_resources());
    let dup_reservation = registry.reserve(owner("ledger-dup", 40)).unwrap();
    let dup = profile("ledger-dup");
    let (_, _admission) = prepared(&ledger, &registry, &dup_reservation, &dup);
    let mut other = Registry::new(context.userspace_observer(ledger.clone()));
    let duplicate = other.reserve(owner("ledger-dup", 41)).unwrap();
    assert_eq!(
        ledger
            .prepare(&other, &duplicate, &dup, egress(&dup), (until(), token()))
            .map(|_| ()),
        Err(Error::Busy)
    );
    let mismatch_reservation = registry.reserve(owner("ledger-mismatch", 41)).unwrap();
    let mismatch = profile("ledger-other");
    assert_eq!(
        ledger
            .prepare(
                &registry,
                &mismatch_reservation,
                &mismatch,
                egress(&mismatch),
                (until(), token())
            )
            .map(|_| ()),
        Err(Error::Changed)
    );
}

#[test]
fn absence_read_error_and_version_race_never_return_empty() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut ledger = NativeLedger::scripted(
        context.clone(),
        Scripted::new(vec![Err(Error::Unavailable)]),
    );
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("readerror", 36)).unwrap();
    let readerror = profile("readerror");
    let (_, admission) = prepared(&ledger, &registry, &reservation, &readerror);
    drop(admission);
    ledger.reap().unwrap();
    assert_eq!(ledger.pending_owners().err(), Some(Error::Unavailable));

    let fixture = Fixture::new();
    let context = fixture.context();
    let mut ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("race", 37)).unwrap();
    let race = profile("race");
    let (_, _admission) = prepared(&ledger, &registry, &reservation, &race);
    ledger.arm_version_race();
    assert_eq!(ledger.pending_owners().err(), Some(Error::Changed));
}

#[test]
fn unknown_old_record_blocks_its_reqid_with_an_empty_ledger() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("unknown", 38)).unwrap();
    let profile = profile("unknown");
    let configuration = Config::new(
        &registry,
        &reservation,
        &profile,
        "192.0.2.2".parse().unwrap(),
        "198.51.100.3".parse().unwrap(),
    )
    .unwrap();
    let peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    drop(peer);
    assert!(
        context
            .unrepresented()
            .unwrap()
            .contains(&u32::from(reservation.reqid()))
    );
    assert!(ledger.pending_owners().unwrap().is_empty());
    assert!(ledger.has_resources());
}

#[test]
fn begin_cleanup_is_monotonic_and_blocks_open() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("draining", 39)).unwrap();
    let profile = profile("draining");
    let (_, mut admission) = prepared(&ledger, &registry, &reservation, &profile);
    admission.begin_cleanup().unwrap();
    admission.begin_cleanup().unwrap();
    assert_eq!(
        admission.open(reservation.owner(), until(), token()).err(),
        Some(Error::Changed)
    );
    assert!(admission.native_peer(until(), token()).is_err());
}

#[path = "ledger_lifecycle.rs"]
mod lifecycle;
#[path = "ledger_resources.rs"]
mod resources;
