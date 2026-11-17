use super::*;
use crate::{connection::ssl::InterfaceName, helper::process::ManagedChild};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
    thread,
    time::{Duration, Instant},
};
struct Fixture {
    child: ManagedChild,
    owner: u32,
}
impl Fixture {
    fn new() -> Self {
        let mut command = Command::new("/bin/sleep");
        command.arg("60");
        let child = ManagedChild::spawn(&mut command).unwrap();
        let owner = Process::read(child.id()).unwrap().uid;
        Self { child, owner }
    }
    fn records(&self) -> Vec<Record> {
        vec![Record {
            key: "State:/Network/Service/fixture/PPP".into(),
            interface: InterfaceName::parse("ppp42").unwrap(),
            pid: Some(self.child.id()),
        }]
    }
    fn interfaces() -> Interfaces {
        Interfaces {
            entries: BTreeMap::from([(
                "ppp42".into(),
                Interface {
                    name: "ppp42".into(),
                    index: 42,
                    flags: (libc::IFF_UP | libc::IFF_POINTOPOINT) as u32,
                    addresses: BTreeSet::from(["10.20.0.2".parse().unwrap()]),
                },
            )]),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.stop(Duration::from_secs(1));
    }
}
#[test]
fn native_process_identity_and_exit_watch_follow_only_the_owned_child() {
    let mut fixture = Fixture::new();
    let process = Process::read(fixture.child.id()).unwrap();
    assert_eq!(process.parent, std::process::id());
    assert_eq!(process.uid, fixture.owner);
    assert!(process.running);
    assert_eq!(process.executable, Path::new("/bin/sleep"));
    let mut watch = ExitWatch::attach(&process.identity).unwrap();
    assert!(!watch.exited().unwrap());
    fixture.child.stop(Duration::from_secs(1)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while !watch.exited().unwrap() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
    assert!(watch.exited().unwrap());
    assert!(Process::read(fixture.child.id()).is_err());
}
#[test]
fn matching_parent_program_and_fresh_interface_are_all_required() {
    let fixture = Fixture::new();
    let parent = Process::read(std::process::id()).unwrap();
    let interfaces = Fixture::interfaces();
    let before = Interfaces::default();
    let records = fixture.records();
    let policy = || Policy {
        owner: fixture.owner,
        parent_program: &parent.executable,
        ppp_program: Path::new("/bin/sleep"),
    };
    let call =
        |before: &Interfaces, now: &Interfaces, record: &Record, records: &[Record], policy| {
            discover(
                (std::process::id(), fixture.child.id()),
                "State:/Network/Service/fixture/PPP",
                before,
                now,
                record,
                records,
                policy,
            )
        };
    let proof = call(&before, &interfaces, &records[0], &records, policy()).unwrap();
    assert_eq!(proof.index(), 42);
    assert_eq!(proof.ppp.pid, fixture.child.id());
    // Interface/store data are synthetic. This is not a native PPP proof.
    assert!(matches!(
        call(&interfaces, &interfaces, &records[0], &records, policy()),
        Err(OwnershipError::ForeignLink)
    ));
    assert!(matches!(
        call(
            &before,
            &interfaces,
            &records[0],
            &records,
            Policy {
                ppp_program: Path::new("/usr/sbin/pppd"),
                ..policy()
            }
        ),
        Err(OwnershipError::ForeignLink)
    ));
    assert!(matches!(
        call(
            &before,
            &interfaces,
            &records[0],
            &records,
            Policy {
                owner: fixture.owner.wrapping_add(1),
                ..policy()
            }
        ),
        Err(OwnershipError::ForeignLink)
    ));
    assert!(matches!(
        call(&before, &interfaces, &records[0], &[], policy()),
        Err(OwnershipError::NotReady)
    ));
    let mut no_pid = records[0].clone();
    no_pid.pid = None;
    assert!(call(&before, &interfaces, &no_pid, &[no_pid.clone()], policy()).is_ok());
    let mut wrong_key = no_pid.clone();
    wrong_key.key = "State:/Network/Service/other/PPP".into();
    assert!(matches!(
        call(
            &before,
            &interfaces,
            &wrong_key,
            &[wrong_key.clone()],
            policy()
        ),
        Err(OwnershipError::NotReady)
    ));
    let mut wrong_pid = no_pid.clone();
    wrong_pid.pid = Some(std::process::id());
    assert!(matches!(
        call(
            &before,
            &interfaces,
            &wrong_pid,
            &[wrong_pid.clone()],
            policy()
        ),
        Err(OwnershipError::ForeignLink)
    ));
    let duplicate = vec![records[0].clone(), wrong_key.clone()];
    assert!(matches!(
        call(&before, &interfaces, &records[0], &duplicate, policy()),
        Err(OwnershipError::ForeignLink)
    ));
    let mut down = interfaces.clone();
    down.entries.get_mut("ppp42").unwrap().flags = 0;
    assert!(matches!(
        call(&before, &down, &records[0], &records, policy()),
        Err(OwnershipError::NotReady)
    ));
}

#[test]
fn owned_ppp_exit_requires_both_original_process_watches() {
    for parent_first in [true, false] {
        let mut parent = Fixture::new();
        let mut child = Fixture::new();
        let parent_info = Process::read(parent.child.id()).unwrap();
        let child_info = Process::read(child.child.id()).unwrap();
        let watches = (
            ExitWatch::attach(&parent_info.identity).unwrap(),
            ExitWatch::attach(&child_info.identity).unwrap(),
        );
        // Association/interface are synthetic; only the two original kernel
        // process exit watches and their conjunction are exercised natively.
        let proof = OwnedPpp {
            interface: Fixture::interfaces().entries["ppp42"].clone(),
            parent: parent_info.identity,
            ppp: child_info.identity,
            watches: Mutex::new(watches),
            service_key: "fixture".into(),
            owner: parent.owner,
            parent_program: PathBuf::from("/bin/sleep"),
            ppp_program: PathBuf::from("/bin/sleep"),
            supervision: None,
        };
        assert!(!proof.processes_exited().unwrap());
        if parent_first {
            parent.child.stop(Duration::from_secs(1)).unwrap();
        } else {
            child.child.stop(Duration::from_secs(1)).unwrap();
        }
        assert!(!proof.processes_exited().unwrap());
        if parent_first {
            child.child.stop(Duration::from_secs(1)).unwrap();
        } else {
            parent.child.stop(Duration::from_secs(1)).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while !proof.processes_exited().unwrap() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        assert!(proof.processes_exited().unwrap());
    }
}

#[test]
fn current_revalidates_the_attempt_and_full_record_set() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            store::scripted(None);
            TEST_INTERFACES.with(|slot| *slot.borrow_mut() = None);
        }
    }
    let _reset = Reset;
    let fixture = Fixture::new();
    let parent = Process::read(std::process::id()).unwrap();
    let child = Process::read(fixture.child.id()).unwrap();
    let service =
        crate::helper::ppp_supervisor::ServiceId::parse("12345678-1234-4123-8123-123456789ABC")
            .unwrap();
    let mut record = fixture.records().remove(0);
    record.key = service.key();
    record.pid = None;
    let interfaces = Fixture::interfaces();
    let mut owned = discover(
        (parent.identity.pid, child.identity.pid),
        &service.key(),
        &Interfaces::default(),
        &interfaces,
        &record,
        &[record.clone()],
        Policy {
            owner: fixture.owner,
            parent_program: &parent.executable,
            ppp_program: Path::new("/bin/sleep"),
        },
    )
    .unwrap();
    owned.supervision = Some(Arc::new(Proof::fixture(&parent, &child, service).unwrap()));
    TEST_INTERFACES.with(|slot| *slot.borrow_mut() = Some(interfaces));
    let valid = vec![record.clone()];
    store::scripted(Some(vec![valid.clone(), valid.clone()]));
    assert!(owned.is_current().unwrap());
    let mut key = record.clone();
    key.key = "State:/Network/Service/other/PPP".into();
    let mut interface = record.clone();
    interface.interface = InterfaceName::parse("ppp43").unwrap();
    let mut pid = record.clone();
    pid.pid = Some(parent.identity.pid);
    let mut duplicate = record.clone();
    duplicate.key = "State:/Network/Service/other/PPP".into();
    for changed in [
        vec![key],
        vec![interface],
        vec![pid],
        vec![record.clone(), duplicate],
    ] {
        store::scripted(Some(vec![changed.clone(), changed.clone()]));
        assert!(!owned.is_current().unwrap());
        store::scripted(Some(vec![valid.clone(), changed]));
        assert!(!owned.is_current().unwrap());
    }
    owned.service_key = "State:/Network/Service/wrong/PPP".into();
    store::scripted(Some(vec![valid.clone(), valid]));
    assert!(!owned.is_current().unwrap());
}

struct FixtureDriver {
    proof: Option<Arc<Proof>>,
    exited: bool,
}
impl DiscoveryDriver for FixtureDriver {
    fn poll(&mut self) -> std::io::Result<crate::connection::ssl::Update> {
        Ok(crate::connection::ssl::Update {
            candidate: None,
            failure: None,
            exited: self.exited,
            start_error: None,
        })
    }
    fn supervised_ppp(&self) -> Option<Arc<Proof>> {
        self.proof.clone()
    }
}

#[test]
fn discovery_wrapper_revalidates_receipt_and_final_observation() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            store::scripted(None);
            TEST_INTERFACES.with(|slot| *slot.borrow_mut() = None);
            DISCOVERY_POLICY.with(|slot| *slot.borrow_mut() = None);
        }
    }
    let _reset = Reset;
    let fixture = Fixture::new();
    let parent = Process::read(std::process::id()).unwrap();
    let child = Process::read(fixture.child.id()).unwrap();
    let service =
        crate::helper::ppp_supervisor::ServiceId::parse("12345678-1234-4123-8123-123456789ABC")
            .unwrap();
    let make_proof = || Proof::fixture(&parent, &child, service.clone()).unwrap();
    let mut record = fixture.records().remove(0);
    record.key = service.key();
    record.pid = None;
    let valid = vec![record.clone()];
    let before = Interfaces::default();
    TEST_INTERFACES.with(|slot| *slot.borrow_mut() = Some(Fixture::interfaces()));
    DISCOVERY_POLICY.with(|slot| {
        *slot.borrow_mut() = Some((
            fixture.owner,
            parent.executable.clone(),
            "/bin/sleep".into(),
        ))
    });
    let receipt = Arc::new(make_proof());
    let mut driver = FixtureDriver {
        proof: Some(Arc::clone(&receipt)),
        exited: false,
    };
    store::scripted(Some(vec![valid.clone(), valid.clone()]));
    let owned = OwnedPpp::discover(&mut driver, &before).unwrap();
    assert!(Arc::ptr_eq(owned.supervision.as_ref().unwrap(), &receipt));
    let mut key = record.clone();
    key.key = "State:/Network/Service/other/PPP".into();
    let mut pid = record.clone();
    pid.pid = Some(parent.identity.pid);
    let mut interface = record.clone();
    interface.interface = InterfaceName::parse("ppp43").unwrap();
    let mut duplicate = record.clone();
    duplicate.key = "State:/Network/Service/other/PPP".into();
    for changed in [
        vec![key],
        vec![pid],
        vec![interface],
        vec![record.clone(), duplicate],
    ] {
        store::scripted(Some(vec![valid.clone(), changed]));
        assert!(matches!(
            OwnedPpp::discover(&mut driver, &before),
            Err(OwnershipError::ForeignLink)
        ));
    }
    let mut mismatched = make_proof();
    mismatched.fixture_bad_receipt();
    driver.proof = Some(Arc::new(mismatched));
    store::scripted(Some(vec![valid.clone(), valid.clone()]));
    assert!(matches!(
        OwnedPpp::discover(&mut driver, &before),
        Err(OwnershipError::ForeignLink)
    ));
    let mut mismatched_supervisor = make_proof();
    mismatched_supervisor.fixture_bad_supervisor_receipt();
    driver.proof = Some(Arc::new(mismatched_supervisor));
    store::scripted(Some(vec![valid.clone(), valid.clone()]));
    assert!(matches!(
        OwnedPpp::discover(&mut driver, &before),
        Err(OwnershipError::ForeignLink)
    ));
    let mut invalid = make_proof();
    invalid.fixture_invalid();
    driver.proof = Some(Arc::new(invalid));
    assert!(matches!(
        OwnedPpp::discover(&mut driver, &before),
        Err(OwnershipError::NotReady)
    ));
    driver.proof = None;
    assert!(matches!(
        OwnedPpp::discover(&mut driver, &before),
        Err(OwnershipError::NotReady)
    ));
    driver.proof = Some(receipt);
    driver.exited = true;
    assert!(matches!(
        OwnedPpp::discover(&mut driver, &before),
        Err(OwnershipError::NotReady)
    ));
}
