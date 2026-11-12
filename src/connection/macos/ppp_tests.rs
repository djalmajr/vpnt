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
            pid: self.child.id(),
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
    let proof = discover(std::process::id(), &before, &interfaces, &records, policy()).unwrap();
    assert_eq!(proof.index(), 42);
    assert_eq!(proof.ppp.pid, fixture.child.id());
    // Interface/store data are synthetic. This is not a native PPP proof.
    assert!(matches!(
        discover(
            std::process::id(),
            &interfaces,
            &interfaces,
            &records,
            policy()
        ),
        Err(OwnershipError::ForeignLink)
    ));
    assert!(matches!(
        discover(
            std::process::id(),
            &before,
            &interfaces,
            &records,
            Policy {
                ppp_program: Path::new("/usr/sbin/pppd"),
                ..policy()
            }
        ),
        Err(OwnershipError::ForeignLink)
    ));
    assert!(matches!(
        discover(
            std::process::id(),
            &before,
            &interfaces,
            &records,
            Policy {
                owner: fixture.owner.wrapping_add(1),
                ..policy()
            }
        ),
        Err(OwnershipError::ForeignLink)
    ));
    let other = Fixture::new();
    assert!(matches!(
        discover(
            fixture.child.id(),
            &before,
            &interfaces,
            &other.records(),
            Policy {
                parent_program: Path::new("/bin/sleep"),
                ..policy()
            }
        ),
        Err(OwnershipError::NotReady)
    ));
    assert!(matches!(
        discover(std::process::id(), &before, &interfaces, &[], policy()),
        Err(OwnershipError::NotReady)
    ));
    let duplicate = vec![records[0].clone(), records[0].clone()];
    assert!(matches!(
        discover(
            std::process::id(),
            &before,
            &interfaces,
            &duplicate,
            policy()
        ),
        Err(OwnershipError::ForeignLink)
    ));
    let mut down = interfaces.clone();
    down.entries.get_mut("ppp42").unwrap().flags = 0;
    assert!(matches!(
        discover(std::process::id(), &before, &down, &records, policy()),
        Err(OwnershipError::NotReady)
    ));
}
