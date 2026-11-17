use super::*;
use crate::helper::runtime::cleanup::Reason;
use record::{Birth, Record, Stage};
use state::{Lease, ObserveOrphan, Store};

const OLD_CONTROLLER: Birth = Birth {
    pid: 123,
    start: (1, 0),
};
const OLD_CHILD: Birth = Birth {
    pid: 124,
    start: (2, 0),
};
const CURRENT: Birth = Birth {
    pid: 125,
    start: (3, 0),
};

#[derive(Default)]
struct Observation {
    live: Option<u32>,
    resources: Option<Result<bool, Reason>>,
    queried: Vec<u32>,
    checked_resources: bool,
}

impl ObserveOrphan for Observation {
    fn birth_absent(&mut self, birth: &Birth) -> Result<bool, Error> {
        self.queried.push(birth.pid);
        Ok(self.live != Some(birth.pid))
    }

    fn resources_absent(&mut self, _: &Record) -> Result<bool, Reason> {
        self.checked_resources = true;
        self.resources.unwrap_or(Ok(true))
    }
}

fn prepare(fixture: &Fixture, stage: Stage) -> Lease {
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("orphan", 7)).unwrap();
    let configuration = config(&registry, &reservation);
    let mut lease = context
        .store
        .prepare(
            &reservation,
            &configuration,
            OLD_CONTROLLER,
            "a".repeat(64),
            None,
            None,
        )
        .unwrap();
    lease.stage(Stage::Starting, None).unwrap();
    if stage == Stage::Running {
        lease.stage(Stage::Running, Some(OLD_CHILD)).unwrap();
    }
    lease
}

fn recover(
    fixture: &Fixture,
    current: &Birth,
    observation: &mut impl ObserveOrphan,
) -> Vec<(Option<Owner>, Reason)> {
    let mut reasons = Vec::new();
    // SAFETY: UID query has no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    Store::recover_orphans(
        &fixture.controller,
        uid,
        current,
        observation,
        |owner, reason| reasons.push((owner.cloned(), reason)),
    )
    .unwrap();
    reasons
}

impl NativeContext<'_> {
    pub(crate) fn assert_installer_after_orphan(
        mut installer_clear: impl FnMut(&std::path::Path, &ControllerLock) -> bool,
    ) {
        let fixture = Fixture::new();
        let lease = prepare(&fixture, Stage::Running);
        assert!(!installer_clear(&fixture.directory, &fixture.controller));
        let mut absent = Observation::default();
        assert!(recover(&fixture, &CURRENT, &mut absent).is_empty());
        assert_eq!(absent.queried, [OLD_CONTROLLER.pid, OLD_CHILD.pid]);
        assert!(absent.checked_resources);
        assert!(!lease.directory.path.exists());
        assert!(installer_clear(&fixture.directory, &fixture.controller));
        assert!(recover(&fixture, &CURRENT, &mut absent).is_empty());
    }
}

#[test]
fn startup_orphan_keeps_live_producer() {
    let fixture = Fixture::new();
    let lease = prepare(&fixture, Stage::Running);
    let mut live = Observation {
        live: Some(OLD_CHILD.pid),
        ..Default::default()
    };
    let reasons = recover(&fixture, &CURRENT, &mut live);
    assert!(lease.directory.path.exists());
    assert_eq!(
        reasons,
        [(Some(lease.record.owner()), Reason::ProducerNotStopped)]
    );
    assert_eq!(live.queried, [OLD_CONTROLLER.pid, OLD_CHILD.pid]);
    assert!(!live.checked_resources);
}

#[test]
fn startup_orphan_keeps_present_resources_or_failed_observation() {
    let fixture = Fixture::new();
    let lease = prepare(&fixture, Stage::Running);
    for (result, expected) in [
        (Ok(false), Reason::RetiredResources),
        (Err(Reason::NamespaceOccupied), Reason::NamespaceOccupied),
        (Err(Reason::ObservationFailed), Reason::ObservationFailed),
    ] {
        let mut observation = Observation {
            resources: Some(result),
            ..Default::default()
        };
        let reasons = recover(&fixture, &CURRENT, &mut observation);
        assert!(lease.directory.path.exists());
        assert_eq!(reasons, [(Some(lease.record.owner()), expected)]);
        assert_eq!(observation.queried, [OLD_CONTROLLER.pid, OLD_CHILD.pid]);
        assert!(observation.checked_resources);
    }
}

#[test]
fn startup_orphan_reports_unreadable_claim_without_observing_resources() {
    let fixture = Fixture::new();
    let lease = prepare(&fixture, Stage::Running);
    let path = lease.directory.path.join("claim.json");
    fs::write(&path, b"invalid").unwrap();
    let mut observation = Observation::default();
    assert_eq!(
        recover(&fixture, &CURRENT, &mut observation),
        [(None, Reason::AdmissionCleanup)]
    );
    assert_eq!(fs::read(path).unwrap(), b"invalid");
    assert!(observation.queried.is_empty());
    assert!(!observation.checked_resources);
}

#[test]
fn startup_orphan_keeps_starting_claim_without_durable_child_birth() {
    let fixture = Fixture::new();
    let lease = prepare(&fixture, Stage::Starting);
    let mut observation = Observation::default();
    assert_eq!(
        recover(&fixture, &CURRENT, &mut observation),
        [(Some(lease.record.owner()), Reason::ProducerMissing)]
    );
    assert!(lease.directory.path.exists());
    assert_eq!(observation.queried, [OLD_CONTROLLER.pid]);
    assert!(!observation.checked_resources);
}

#[test]
fn startup_orphan_never_touches_the_current_controllers_live_generation() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("current", 7)).unwrap();
    let mut peer = context
        .prepare(&registry, &reservation, &config(&registry, &reservation))
        .unwrap();
    let client = peer.open(reservation.owner(), until(), token()).unwrap();
    let before = context.store.records().unwrap();
    assert_eq!(before[0].stage, Stage::Running);
    let mut observer = Observation::default();
    assert_eq!(
        recover(&fixture, &Birth::from(&context.identity), &mut observer),
        [(
            Some(reservation.owner().clone()),
            Reason::UnrepresentedProducer
        )]
    );
    assert!(observer.queried.is_empty());
    assert!(!observer.checked_resources);
    assert_eq!(context.store.records().unwrap(), before);
    assert_eq!(
        client
            .command("version", Message::new(), &[])
            .unwrap()
            .response
            .get_text("daemon"),
        Some("charon")
    );
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
}

#[test]
fn startup_orphan_revalidates_the_claim_after_observation_and_keeps_replacement() {
    struct Replacement(std::path::PathBuf, Vec<u8>);
    impl ObserveOrphan for Replacement {
        fn birth_absent(&mut self, _: &Birth) -> Result<bool, Error> {
            Ok(true)
        }
        fn resources_absent(&mut self, _: &Record) -> Result<bool, Reason> {
            use std::os::unix::fs::OpenOptionsExt;
            let next = self.0.with_file_name(".replacement");
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&next)
                .unwrap();
            std::io::Write::write_all(&mut file, &self.1).unwrap();
            fs::rename(next, &self.0).unwrap();
            Ok(true)
        }
    }

    let fixture = Fixture::new();
    let lease = prepare(&fixture, Stage::Running);
    let path = lease.directory.path.join("claim.json");
    let bytes = fs::read(&path).unwrap();
    let mut replacement = Replacement(path.clone(), bytes.clone());
    assert_eq!(
        recover(&fixture, &CURRENT, &mut replacement),
        [(Some(lease.record.owner()), Reason::DurableCompletion)]
    );
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert!(recover(&fixture, &CURRENT, &mut Observation::default()).is_empty());
    assert!(!lease.directory.path.exists());
}

#[test]
fn startup_orphan_durable_link_survives_stopping_and_is_used_on_recovery() {
    struct LinkObservation(record::LinkClaim);
    impl ObserveOrphan for LinkObservation {
        fn birth_absent(&mut self, _: &Birth) -> Result<bool, Error> {
            Ok(true)
        }
        fn resources_absent(&mut self, record: &Record) -> Result<bool, Reason> {
            assert_eq!(record.link.as_ref(), Some(&self.0));
            Ok(true)
        }
    }

    let fixture = Fixture::new();
    let mut lease = prepare(&fixture, Stage::Running);
    assert!(lease.record.link.is_none());
    let link = record::LinkClaim {
        name: "utun7".into(),
        index: std::num::NonZeroU16::new(7).unwrap(),
        vips: vec!["192.0.2.10".parse().unwrap()],
    };
    lease.record_link(link.clone(), until(), &token()).unwrap();
    lease.stage(Stage::Stopped, Some(OLD_CHILD)).unwrap();
    assert!(recover(&fixture, &CURRENT, &mut LinkObservation(link)).is_empty());
    assert!(!lease.directory.path.exists());
}

#[test]
fn startup_orphan_capture_records_the_utun_identity_before_configure() {
    struct Linked(Option<record::LinkClaim>);
    impl ObserveOrphan for Linked {
        fn birth_absent(&mut self, _: &Birth) -> Result<bool, Error> {
            Ok(true)
        }
        fn resources_absent(&mut self, record: &Record) -> Result<bool, Reason> {
            self.0 = record.link.clone();
            Ok(true)
        }
    }
    let link = |name: &str, index: u16, vips: &[&str]| record::LinkClaim {
        name: name.into(),
        index: std::num::NonZeroU16::new(index).unwrap(),
        vips: vips.iter().map(|vip| vip.parse().unwrap()).collect(),
    };

    let fixture = Fixture::new();
    let mut starting = prepare(&fixture, Stage::Starting);
    assert_eq!(
        starting.record_interface("utun7", 7, until(), &token()),
        Err(Error::Changed)
    );
    starting.stage(Stage::Stopped, None).unwrap();
    starting.complete().unwrap();

    let mut lease = prepare(&fixture, Stage::Running);
    for (name, index) in [("utun7", 0), ("utun7", 65_536), ("en0", 7), ("utun07", 7)] {
        assert_eq!(
            lease.record_interface(name, index, until(), &token()),
            Err(Error::Invalid),
            "{name} {index}"
        );
    }
    assert!(lease.record.link.is_none());
    lease
        .record_interface("utun7", 7, until(), &token())
        .unwrap();
    let captured = link("utun7", 7, &[]);
    assert_eq!(lease.record.link.as_ref(), Some(&captured));
    // Durable, not only in memory.
    let path = lease.directory.path.join("claim.json");
    let durable: Record = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(durable.link.as_ref(), Some(&captured));
    assert_eq!(
        lease.record_interface("utun7", 7, until(), &token()),
        Err(Error::Changed)
    );
    // Configure must name the captured interface, once.
    for other in [
        link("utun8", 7, &["192.0.2.10"]),
        link("utun7", 8, &["192.0.2.10"]),
    ] {
        assert_eq!(
            lease.record_link(other, until(), &token()),
            Err(Error::Changed)
        );
    }
    let configured = link("utun7", 7, &["192.0.2.10"]);
    lease
        .record_link(configured.clone(), until(), &token())
        .unwrap();
    assert_eq!(
        lease.record_link(configured.clone(), until(), &token()),
        Err(Error::Changed)
    );
    lease.stage(Stage::Stopped, Some(OLD_CHILD)).unwrap();
    let mut observed = Linked(None);
    assert!(recover(&fixture, &CURRENT, &mut observed).is_empty());
    assert_eq!(observed.0, Some(configured));
    assert!(!lease.directory.path.exists());
}

#[test]
fn startup_orphan_reads_a_captured_claim_without_vips() {
    let fixture = Fixture::new();
    let mut lease = prepare(&fixture, Stage::Running);
    lease
        .record_interface("utun7", 7, until(), &token())
        .unwrap();
    lease.stage(Stage::Stopped, Some(OLD_CHILD)).unwrap();
    let mut observation = Observation::default();
    assert!(recover(&fixture, &CURRENT, &mut observation).is_empty());
    assert!(observation.checked_resources);
    assert!(!lease.directory.path.exists());
}

#[test]
fn startup_orphan_seal_capture_records_the_admitted_utun_in_the_claim() {
    use crate::connection::macos::utun_observer::{InterfaceObservation, RetainedInterface};
    let retained = |name: &str, index: u32| {
        let fd: std::os::fd::OwnedFd = fs::File::open("/dev/null").unwrap().into();
        let observation = InterfaceObservation::synthetic_for_test(name, index, 7, 0x55, 0x77);
        RetainedInterface::synthetic_for_test(fd, observation)
    };
    let fixture = Fixture::new();

    // Refused write: the capture fails and the claim keeps no link.
    let starting = prepare(&fixture, Stage::Starting);
    let path = starting.directory.path.join("claim.json");
    let mut producer = child::Producer::new(fixture.context(), starting, None);
    assert_eq!(
        producer
            .seal_capture(retained("utun7", 7), until(), &token())
            .unwrap_err(),
        Error::Changed
    );
    let durable: Record = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(durable.link, None);
    drop(producer);

    let fixture = Fixture::new();
    let lease = prepare(&fixture, Stage::Running);
    let path = lease.directory.path.join("claim.json");
    let before: Record = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(before.link, None);
    // The controller stamps the current boot session when it creates the claim.
    assert_eq!(before.boot_session, Some(recovery::boot_session().unwrap()));
    let mut producer = child::Producer::new(fixture.context(), lease, None);
    let sealed = producer
        .seal_capture(retained("utun7", 7), until(), &token())
        .unwrap();
    assert_eq!((sealed.name(), sealed.index()), ("utun7", 7));
    let captured = record::LinkClaim {
        name: "utun7".into(),
        index: std::num::NonZeroU16::new(7).unwrap(),
        vips: Vec::new(),
    };
    let durable: Record = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(durable.link.as_ref(), Some(&captured));
    assert_eq!(producer.lease.record.link.as_ref(), Some(&captured));
    // A second capture for the same attempt is refused.
    assert_eq!(
        producer
            .seal_capture(retained("utun7", 7), until(), &token())
            .unwrap_err(),
        Error::Changed
    );
    drop(sealed);
    drop(producer);
}
