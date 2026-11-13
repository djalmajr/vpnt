use super::*;
use crate::{
    helper::vici::Message,
    model::{Profile, VpnKind},
};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
mod admission;
mod binding;
mod fixture;
mod utun;
use fixture::Fixture;
#[derive(Clone, Default)]
struct Kernel(Arc<Mutex<BTreeSet<u32>>>);
impl KernelClaims for Kernel {
    fn occupied(&mut self) -> Result<BTreeSet<u32>, Error> {
        Ok(self.0.lock().unwrap().clone())
    }
}
fn owner(id: &str, generation: u64) -> Owner {
    Owner {
        uid: 502,
        profile: id.into(),
        generation,
    }
}
fn config<N: Observer>(registry: &Registry<N>, reservation: &Reservation) -> Config {
    let p = Profile {
        id: reservation.owner().profile.clone(),
        name: "Fixture".into(),
        kind: VpnKind::Ipsec,
        gateway: "vpn.example.com".into(),
        username: "fictional-user".into(),
        port: 500,
        networks: vec!["10.20.0.0/24".into()],
        certificate: String::new(),
        probe_host: "10.20.0.1".into(),
        probe_port: 8443,
        probe_method: "tcp".into(),
    };
    Config::new(
        registry,
        reservation,
        &p,
        "192.0.2.2".parse().unwrap(),
        "198.51.100.3".parse().unwrap(),
    )
    .unwrap()
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn token() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

// Mutations: skip root gate, durable pre-spawn/record binding, native peer
// identity, or finalize while native resource claims remain occupied.
#[test]
fn owned_native_child_is_bound_to_a_durable_attempt_and_completion_waits_for_absence() {
    let fixture = Fixture::new();
    assert!(matches!(
        NativeContext::new(&fixture.controller),
        Err(Error::PermissionDenied)
    ));
    assert!(!fixture.directory.join("ipsec").exists());
    let context = fixture.context();
    let kernel = Kernel::default();
    let mut registry = Registry::new(context.observer(kernel.clone()));
    let reservation = registry.reserve(owner("normal", 7)).unwrap();
    let configuration = config(&registry, &reservation);
    let mut peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    let records = context.store.records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].stage, record::Stage::Prepared);
    assert!(records[0].child.is_none());
    let opened = peer
        .open(reservation.owner(), until(), token())
        .unwrap_or_else(|error| {
            panic!(
                "peer admission: {error:?}; fixture exit/line: {:?}",
                peer.producer.lock().unwrap().status()
            )
        });
    let response = opened
        .command("version", Message::new(), &[])
        .unwrap()
        .response;
    assert_eq!(response.get_text("daemon"), Some("charon"));
    assert_eq!(response.get_text("version"), Some("6.1.0"));
    assert_eq!(
        context.store.records().unwrap()[0].stage,
        record::Stage::Running
    );
    assert_eq!(registry.release(&reservation), Err(Error::Busy));
    assert_eq!(peer.retire(&owner("other", 7)), Err(Error::Changed));
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert!(peer.producer.lock().unwrap().child_exited());
    kernel
        .0
        .lock()
        .unwrap()
        .insert(u32::from(reservation.reqid()));
    assert_eq!(registry.release(&reservation), Err(Error::Busy));
    assert_eq!(
        context.store.records().unwrap()[0].stage,
        record::Stage::Stopped
    );
    kernel.0.lock().unwrap().clear();
    registry.release(&reservation).unwrap();
    assert!(context.store.records().unwrap().is_empty());
    assert!(context.active.lock().unwrap().is_empty());
    assert!(!registry.has_reservations());
    assert!(matches!(
        peer.open(reservation.owner(), until(), token()),
        Err(Error::Changed)
    ));
}

// Mutation: UID alone admits a different server PID, or a failed/expired
// attempt can silently restart its process.
#[test]
fn foreign_peer_process_and_exited_children_are_refused_without_respawn() {
    for id in ["fork", "exit"] {
        let fixture = Fixture::new();
        let context = fixture.context();
        let mut registry = Registry::new(context.observer(Kernel::default()));
        let reservation = registry.reserve(owner(id, 1)).unwrap();
        let configuration = config(&registry, &reservation);
        let mut peer = context
            .prepare(&registry, &reservation, &configuration)
            .unwrap();
        let result = peer.open(reservation.owner(), until(), token());
        assert_eq!(
            result.err(),
            Some(if id == "fork" {
                Error::Changed
            } else {
                Error::Unavailable
            }),
            "foreign/exited producer admission: {id}"
        );
        let before = context.store.records().unwrap()[0].child.clone();
        assert!(peer.open(reservation.owner(), until(), token()).is_err());
        assert_eq!(context.store.records().unwrap()[0].child, before);
        peer.retire(reservation.owner()).unwrap();
        registry.release(&reservation).unwrap();
    }
}

// Mutations: accept replaced config/inodes/permissions, or let an admission
// failure prevent stopping the original owned Child.
#[test]
fn altered_configuration_denies_io_but_still_retires_only_the_owned_child() {
    for change in ["bytes", "inode", "mode"] {
        let fixture = Fixture::new();
        let context = fixture.context();
        let mut registry = Registry::new(context.observer(Kernel::default()));
        let reservation = registry.reserve(owner("normal", 1)).unwrap();
        let configuration = config(&registry, &reservation);
        let mut peer = context
            .prepare(&registry, &reservation, &configuration)
            .unwrap();
        peer.open(reservation.owner(), until(), token())
            .unwrap()
            .command("version", Message::new(), &[])
            .unwrap();
        let path = peer
            .producer
            .lock()
            .unwrap()
            .lease
            .directory
            .path
            .join(state::CONFIG);
        match change {
            "bytes" => fs::write(&path, b"foreign configuration").unwrap(),
            "inode" => {
                let bytes = fs::read(&path).unwrap();
                fs::remove_file(&path).unwrap();
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
        }
        assert!(peer.open(reservation.owner(), until(), token()).is_err());
        assert!(peer.retire(reservation.owner()).is_err());
        assert!(peer.producer.lock().unwrap().child_exited());
        assert!(registry.has_reservations());
    }
}

// Mutations: forget a durable claim on Drop, ignore dormant claims on restart,
// or treat cancellation as permission to start a producer.
#[test]
fn canceled_preflight_and_dropped_claims_remain_exclusive_across_context_restart() {
    let fixture = Fixture::new();
    {
        let context = fixture.context();
        let mut registry = Registry::new(context.observer(Kernel::default()));
        let reservation = registry.reserve(owner("normal", 1)).unwrap();
        let configuration = config(&registry, &reservation);
        let mut peer = context
            .prepare(&registry, &reservation, &configuration)
            .unwrap();
        assert!(matches!(
            peer.open(
                reservation.owner(),
                until(),
                Arc::new(AtomicBool::new(true))
            ),
            Err(Error::Canceled)
        ));
        assert!(context.store.records().unwrap()[0].child.is_none());
        drop(peer);
        assert_eq!(
            context.store.records().unwrap()[0].stage,
            record::Stage::Stopped
        );
    }
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("normal", 2)).unwrap();
    assert_ne!(reservation.reqid(), 0x3fff);
    let configuration = config(&registry, &reservation);
    assert!(matches!(
        context.prepare(&registry, &reservation, &configuration),
        Err(Error::Busy)
    ));
}
