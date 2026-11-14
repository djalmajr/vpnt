use super::*;
use crate::connection::{
    ipsec::{Config, Control, Error, Peer, Registry, Reservation},
    routes::{
        Backend, Coordinator, Error as RouteError, Key, Network, NextHop, Owner, Presence, Route,
    },
};
use crate::{
    helper::vici::Client,
    model::{Profile, VpnKind},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

fn owner() -> Owner {
    Owner {
        uid: 501,
        profile: "native".into(),
        generation: 1,
    }
}
fn route() -> Route {
    Route {
        key: Key {
            network: Network::host("10.0.0.1".parse().unwrap()),
            scope: 0,
        },
        interface: 7,
        next_hop: NextHop::Interface,
    }
}

#[derive(Default)]
struct Fake {
    routes: BTreeMap<Key, Route>,
    receipts: BTreeMap<u64, Key>,
    next: u64,
    pending: bool,
    detached: BTreeSet<u64>,
    removes: Arc<AtomicUsize>,
}
impl Backend for Fake {
    type Receipt = u64;
    fn authorize(&mut self, _: &Owner, _: Route) -> Result<(), RouteError> {
        Ok(())
    }
    fn existing(&mut self, key: Key) -> Result<Option<Route>, RouteError> {
        Ok(self.routes.get(&key).copied())
    }
    fn create(&mut self, route: Route) -> Result<u64, RouteError> {
        self.next += 1;
        self.routes.insert(route.key, route);
        self.receipts.insert(self.next, route.key);
        Ok(self.next)
    }
    fn receipt_state(&mut self, receipt: &u64) -> Result<Presence, RouteError> {
        let Some(key) = self.receipts.get(receipt) else {
            return Ok(Presence::Absent);
        };
        if self.detached.contains(receipt) && self.routes.contains_key(key) {
            return Err(RouteError::Busy);
        }
        Ok(if self.routes.contains_key(key) {
            Presence::Owned
        } else {
            Presence::Absent
        })
    }
    fn remove(&mut self, receipt: &u64) -> Result<(), RouteError> {
        if self.pending {
            return Err(RouteError::Busy);
        }
        self.removes.fetch_add(1, Ordering::AcqRel);
        if let Some(key) = self.receipts.get(receipt) {
            self.routes.remove(key);
        }
        Ok(())
    }
}

fn manager() -> Coordinator<Fake> {
    Coordinator::new(Fake::default()).unwrap()
}

fn detach_key(coordinator: &mut Coordinator<Fake>, key: Key) {
    let receipt = coordinator
        .backend_mut()
        .receipts
        .iter()
        .find_map(|(receipt, current)| (*current == key).then_some(*receipt))
        .expect("key has a receipt");
    coordinator.backend_mut().detached.insert(receipt);
}

#[test]
fn reservation_survives_successful_prepare_until_control_consumes_it() {
    struct Obs;
    impl crate::connection::ipsec::Observer for Obs {
        fn occupied(&mut self) -> Result<BTreeSet<u32>, Error> {
            Ok(BTreeSet::new())
        }
        fn producer_stopped(&mut self, _: &Owner) -> Result<bool, Error> {
            Ok(true)
        }
    }
    let mut registry = Registry::new(Obs);
    let reservation = registry.reserve(owner()).unwrap();
    let mut slot: Option<Reservation> = Some(reservation);
    let value = keep_for_control(&mut slot, Ok::<_, Error>(42))
        .ok()
        .unwrap();
    assert_eq!(value, 42);
    assert!(slot.is_some());
    assert!(keep_for_control(&mut slot, Err::<(), _>(Error::Unavailable)).is_err());
    assert!(slot.is_some());

    let mut missing: Option<Reservation> = None;
    assert!(keep_for_control(&mut missing, Ok::<_, Error>(())).is_err());
    assert!(missing.is_none());

    struct FakePeer;
    impl Peer for FakePeer {
        fn open(
            &mut self,
            _: &Owner,
            _: Instant,
            _: Arc<std::sync::atomic::AtomicBool>,
        ) -> Result<Client, Error> {
            Err(Error::Busy)
        }
        fn retire(&mut self, _: &Owner) -> Result<bool, Error> {
            Ok(true)
        }
    }
    let profile = Profile {
        id: "native".into(),
        name: "native".into(),
        kind: VpnKind::Ipsec,
        gateway: "10.0.0.1".into(),
        username: "user".into(),
        networks: Vec::new(),
        port: 500,
        certificate: String::new(),
        probe_host: "192.0.2.1".into(),
        probe_port: 80,
        probe_method: "tcp".into(),
    };
    let config = Config::new(
        &registry,
        slot.as_ref().unwrap(),
        &profile,
        "10.0.0.2".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
    )
    .unwrap();
    let control = Control::new(
        Arc::new(Mutex::new(registry)),
        slot.take().unwrap(),
        config,
        FakePeer,
    );
    assert!(control.is_ok());
}

#[test]
fn absent_after_acquire_releases_without_a_health_validate() {
    let mut routes = manager();
    let lease = routes.acquire(owner(), &[route()]).unwrap();
    routes.backend_mut().routes.remove(&route().key);
    let mut owned = OwnedLease::new(lease, owner());
    assert!(owned.release(&mut routes).unwrap());
    assert!(!routes.has_owner(&owner()));
}

#[test]
fn invariant_release_error_is_not_forgotten() {
    let mut first = manager();
    let lease = first.acquire(owner(), &[route()]).unwrap();
    let mut other = manager();
    let mut owned = OwnedLease::new(lease, owner());
    assert!(owned.release(&mut other).is_err());
    assert!(!other.has_owner(&owner()));
    assert!(owned.release(&mut other).is_err());
}

#[test]
fn pending_cleanup_keeps_claim_until_retry_succeeds() {
    let mut routes = manager();
    let lease = routes.acquire(owner(), &[route()]).unwrap();
    routes.backend_mut().pending = true;
    let mut owned = OwnedLease::new(lease, owner());
    assert!(!owned.release(&mut routes).unwrap());
    assert!(routes.has_owner(&owner()));
    routes.backend_mut().pending = false;
    assert!(owned.release(&mut routes).unwrap());
    assert!(!routes.has_owner(&owner()));
}

#[test]
fn detached_receipt_busy_then_absent_releases_only_own_lease() {
    let mut routes = manager();
    let own_owner = owner();
    let other_owner = Owner {
        uid: 503,
        profile: "other".into(),
        generation: 2,
    };
    let own_route = route();
    let other_route = Route {
        key: Key {
            network: Network::host("10.0.0.2".parse().unwrap()),
            scope: 0,
        },
        interface: 8,
        next_hop: NextHop::Interface,
    };
    let own_lease = routes.acquire(own_owner.clone(), &[own_route]).unwrap();
    let other_lease = routes.acquire(other_owner.clone(), &[other_route]).unwrap();
    detach_key(&mut routes, own_route.key);
    let mut owned = OwnedLease::new(own_lease, own_owner.clone());
    assert!(!owned.release(&mut routes).unwrap());
    assert!(routes.has_owner(&own_owner));
    assert!(routes.has_owner(&other_owner));
    assert_eq!(routes.backend_mut().removes.load(Ordering::Acquire), 0);
    assert_eq!(routes.backend_mut().routes.len(), 2);
    routes.backend_mut().routes.remove(&own_route.key);
    assert!(owned.release(&mut routes).unwrap());
    assert!(!routes.has_owner(&own_owner));
    assert!(routes.has_owner(&other_owner));
    routes.validate(&other_lease).unwrap();
    assert_eq!(routes.backend_mut().routes.len(), 1);
    assert!(routes.backend_mut().routes.contains_key(&other_route.key));
}
