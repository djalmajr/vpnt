//! Scope/queue tests use the same private lifecycle core as the native
//! adapter. No configured UTUN is fabricated and no RTM_ADD is attempted.
use super::*;
use crate::connection::{
    macos::routing::backend::{
        registry::{Registry, Scope, Table},
        utun_retirement::{Guard, Lifecycle, Pin, Retire, Sink},
    },
    routes::{Backend, Key, Network},
};
use std::sync::{
    Weak,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

fn owner(uid: u32) -> Owner {
    Owner {
        uid,
        profile: "fixture".into(),
        generation: 1,
    }
}
fn route(index: u16) -> Route {
    Route {
        key: Key {
            network: Network::host("10.20.0.2".parse().unwrap()),
            scope: 0,
        },
        interface: index,
        next_hop: NextHop::Interface,
    }
}

#[derive(Clone)]
struct TestPin {
    index: u16,
    absent: Arc<AtomicBool>,
    alive: Option<Arc<()>>,
}
impl TestPin {
    fn new(index: u16) -> (Self, Weak<()>) {
        let alive = Arc::new(());
        (
            Self {
                index,
                absent: Arc::new(AtomicBool::new(true)),
                alive: Some(alive.clone()),
            },
            Arc::downgrade(&alive),
        )
    }
}
impl Pin for TestPin {
    fn name(&self) -> &str {
        "utun7"
    }
    fn index(&self) -> u16 {
        self.index
    }
    fn absent(&self) -> Result<bool, Error> {
        Ok(self.absent.load(Ordering::Acquire))
    }
    fn release(&mut self) {
        self.alive = None;
    }
}

#[derive(Clone)]
struct TestPeer {
    owner: Owner,
    calls: Arc<AtomicUsize>,
}
impl TestPeer {
    fn new(owner: Owner) -> Self {
        Self {
            owner,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}
impl Retire for TestPeer {
    fn retire_peer(&self, owner: &Owner) -> Result<bool, Error> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if owner != &self.owner {
            return Err(Error::Changed);
        }
        Ok(true)
    }
}

#[derive(Clone)]
struct NoSink;
impl Sink for NoSink {
    fn gone(&self) -> Result<bool, Error> {
        Ok(true)
    }
}

struct TestScope {
    index: u16,
    guard: Guard<TestPin, TestPeer, NoSink>,
    confirmation: Result<(), Error>,
}
impl Scope for TestScope {
    fn index(&self) -> u16 {
        self.index
    }
    fn active(&self) -> Result<(), Error> {
        Ok(())
    }
    fn add(&mut self, _route: Route) -> Result<super::super::registry::Attempt, Error> {
        Ok(super::super::registry::Attempt {
            confirmation: self.confirmation,
        })
    }
    fn detach_if_stopped(&mut self) -> Result<bool, Error> {
        self.guard.detach()
    }
    fn cleanup_complete(&mut self) -> Result<bool, Error> {
        self.guard.complete()
    }
}

struct TestTable(Option<Route>);
impl Table for TestTable {
    fn exact(&mut self, _key: Key) -> Result<Option<Route>, Error> {
        Ok(self.0)
    }
}

fn scope(
    queue: &Arc<Lifecycle<TestPin, TestPeer, NoSink>>,
    index: u16,
    uid: u32,
    confirmation: Result<(), Error>,
) -> (TestScope, TestPeer, Weak<()>) {
    let (pin, alive) = TestPin::new(index);
    let peer = TestPeer::new(owner(uid));
    let guard = queue
        .open_guard(false, owner(uid), pin, peer.clone())
        .unwrap();
    (
        TestScope {
            index,
            guard,
            confirmation,
        },
        peer,
        alive,
    )
}

#[test]
fn duplicate_owner_or_index_is_rejected_before_a_guard_or_stop() {
    let mut registry = Registry::new(TestTable(None)).unwrap();
    let queue = Lifecycle::new();
    let (first, _, active) = scope(&queue, 7, 501, Ok(()));
    registry
        .register(first, owner(501), vec![route(7)])
        .unwrap();
    assert!(registry.has_owner_or_index(&owner(501), 7));
    assert!(registry.has_owner_or_index(&owner(501), 9));
    assert!(registry.has_owner_or_index(&owner(502), 7));
    assert!(!registry.has_owner_or_index(&owner(502), 9));
    let (pin, _alive) = TestPin::new(7);
    let peer = TestPeer::new(owner(501));
    // `allow-foreign-scope`: the production preconflict feeds open_guard
    // before any writer/sink allocation and before a queue entry exists.
    let error = match queue.open_guard(
        registry.has_owner_or_index(&owner(501), 7),
        owner(501),
        pin,
        peer.clone(),
    ) {
        Ok(_) => panic!("duplicate registration must not create a guard"),
        Err(error) => error,
    };
    assert_eq!(error, Error::Busy);
    assert_eq!(peer.calls(), 0, "an active producer is never stopped");
    assert!(active.upgrade().is_some(), "the active scope keeps its pin");
    assert!(!queue.has_entries().unwrap());
}

#[test]
fn draining_scope_denies_writes_before_absence() {
    let mut registry = Registry::new(TestTable(None)).unwrap();
    let queue = Lifecycle::new();
    let (first, _, _) = scope(&queue, 7, 501, Ok(()));
    let token = registry
        .register(first, owner(501), vec![route(7)])
        .unwrap();
    assert_eq!(registry.begin_cleanup(&token), Ok(true));
    assert!(matches!(registry.create(route(7)), Err(Error::Busy)));
    assert_eq!(registry.authorize(&owner(501), route(7)), Err(Error::Busy));
    assert_eq!(registry.finish_cleanup(&token), Ok(()));
    assert!(registry.is_empty());
}

#[test]
fn an_uncertain_attempt_remains_an_owned_receipt() {
    let target = route(7);
    let mut registry = Registry::new(TestTable(Some(target))).unwrap();
    let queue = Lifecycle::new();
    // `lose-attempted-receipt`: the registry must return a receipt even when
    // the typed ADD could not confirm it.
    let (first, _, _) = scope(&queue, 7, 501, Err(Error::Changed));
    registry.register(first, owner(501), vec![target]).unwrap();
    let receipt = registry.create(target).unwrap();
    assert_eq!(registry.receipt_state(&receipt), Err(Error::Busy));
    assert_eq!(registry.remove(&receipt), Err(Error::Busy));
}

#[test]
fn foreign_owner_cannot_authorize_the_scope() {
    let mut registry = Registry::new(TestTable(None)).unwrap();
    let queue = Lifecycle::new();
    let (first, _, _) = scope(&queue, 7, 501, Ok(()));
    registry
        .register(first, owner(501), vec![route(7)])
        .unwrap();
    assert_eq!(
        registry.authorize(&owner(502), route(7)),
        Err(Error::Invalid)
    );
}
