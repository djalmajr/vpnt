use super::*;
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

#[derive(Clone)]
struct TestPin {
    name: &'static str,
    index: u16,
    absent: Arc<AtomicBool>,
    alive: Option<Arc<()>>,
}
impl TestPin {
    fn new(index: u16) -> (Self, Weak<()>) {
        let alive = Arc::new(());
        (
            Self {
                name: "utun7",
                index,
                absent: Arc::new(AtomicBool::new(true)),
                alive: Some(alive.clone()),
            },
            Arc::downgrade(&alive),
        )
    }
    fn absent_flag(&self) -> Arc<AtomicBool> {
        self.absent.clone()
    }
}
impl Pin for TestPin {
    fn name(&self) -> &str {
        self.name
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
    fail: Arc<AtomicBool>,
}
impl TestPeer {
    fn new(owner: Owner) -> Self {
        Self {
            owner,
            calls: Arc::new(AtomicUsize::new(0)),
            fail: Arc::new(AtomicBool::new(false)),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
    fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::Release);
    }
}
impl Retire for TestPeer {
    fn retire_peer(&self, owner: &Owner) -> Result<bool, Error> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if owner != &self.owner {
            return Err(Error::Changed);
        }
        if self.fail.load(Ordering::Acquire) {
            return Err(Error::Busy);
        }
        Ok(true)
    }
}

#[derive(Clone)]
struct TestSink {
    gone: Arc<AtomicBool>,
}
impl Sink for TestSink {
    fn gone(&self) -> Result<bool, Error> {
        Ok(self.gone.load(Ordering::Acquire))
    }
}

#[test]
fn queue_preserves_the_last_pin_until_the_original_stop_is_confirmed() {
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let (pin, alive) = TestPin::new(7);
    let peer = TestPeer::new(owner(501));
    let guard = queue
        .open_guard(false, owner(501), pin, peer.clone())
        .unwrap();
    assert!(alive.upgrade().is_some());
    drop(guard);
    // `drop-pin-before-stop`: a Drop that releases the pin without a confirmed
    // stop loses the retained descriptor and fails here.
    assert!(alive.upgrade().is_some());
    assert_eq!(peer.calls(), 0);
    assert!(queue.has_entries().unwrap());
    assert_eq!(queue.admit(), Err(Error::Busy));
    // `forget-queue-on-failure`: a Drop that fails to enqueue leaves no entry.
    queue.reap().unwrap();
    assert_eq!(peer.calls(), 1);
    assert!(alive.upgrade().is_none());
    assert!(!queue.has_entries().unwrap());
}

#[test]
fn failed_stop_keeps_the_pin_and_reports_busy() {
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let (pin, alive) = TestPin::new(7);
    let peer = TestPeer::new(owner(501));
    peer.set_fail(true);
    let mut guard = queue
        .open_guard(false, owner(501), pin, peer.clone())
        .unwrap();
    assert_eq!(guard.detach(), Err(Error::Busy));
    assert!(alive.upgrade().is_some(), "failed stop must keep the pin");
    assert_eq!(guard.complete(), Ok(false));
    peer.set_fail(false);
    assert_eq!(guard.detach(), Ok(true));
    assert!(alive.upgrade().is_none());
    assert_eq!(guard.complete(), Ok(true));
    assert!(!queue.has_entries().unwrap());
}

#[test]
fn confirmed_stop_releases_the_pin_before_fresh_absence() {
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let (pin, alive) = TestPin::new(7);
    let absent = pin.absent_flag();
    absent.store(false, Ordering::Release);
    let peer = TestPeer::new(owner(501));
    let mut guard = queue
        .open_guard(false, owner(501), pin, peer.clone())
        .unwrap();
    assert_eq!(guard.detach(), Ok(true));
    assert!(
        alive.upgrade().is_none(),
        "confirmed stop drops the pin first"
    );
    // `ignore-implicit-route`: absence is not assumed from the released pin.
    assert_eq!(guard.complete(), Ok(false));
    absent.store(true, Ordering::Release);
    assert_eq!(guard.complete(), Ok(true));
}

#[test]
fn failed_registration_entry_is_retried_only_through_its_original_peer() {
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let (pin, alive) = TestPin::new(7);
    let absent = pin.absent_flag();
    absent.store(false, Ordering::Release);
    let peer = TestPeer::new(owner(501));
    peer.set_fail(true);
    drop(
        queue
            .open_guard(false, owner(501), pin, peer.clone())
            .unwrap(),
    );
    assert_eq!(queue.reap(), Err(Error::Busy));
    assert_eq!(peer.calls(), 1);
    assert!(alive.upgrade().is_some());
    assert!(queue.has_entries().unwrap());
    peer.set_fail(false);
    queue.reap().unwrap();
    assert_eq!(peer.calls(), 2);
    assert!(alive.upgrade().is_none());
    assert!(queue.has_entries().unwrap(), "absence still pending");
    queue.reap().unwrap();
    assert_eq!(peer.calls(), 2, "a stopped peer is never retired again");
    absent.store(true, Ordering::Release);
    queue.reap().unwrap();
    assert!(!queue.has_entries().unwrap());
}

#[test]
fn foreign_owner_cannot_stop_the_entry_pin() {
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let (pin, alive) = TestPin::new(7);
    let peer = TestPeer::new(owner(501));
    let mut guard = queue
        .open_guard(false, owner(502), pin, peer.clone())
        .unwrap();
    assert_eq!(guard.detach(), Err(Error::Busy));
    assert_eq!(peer.calls(), 1);
    assert!(alive.upgrade().is_some(), "a foreign owner keeps the pin");
}

#[test]
fn duplicate_conflict_creates_no_guard_or_stop() {
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let (pin, alive) = TestPin::new(7);
    let peer = TestPeer::new(owner(501));
    let error = match queue.open_guard(true, owner(501), pin, peer.clone()) {
        Ok(_) => panic!("duplicate registration must not create a guard"),
        Err(error) => error,
    };
    assert_eq!(error, Error::Busy);
    assert_eq!(peer.calls(), 0, "duplicate must not stop the producer");
    // The rejected registration only drops its own unconsumed clone; the
    // active producer's pin is untouched and no cleanup entry exists.
    drop(alive);
    assert!(!queue.has_entries().unwrap());
}

#[test]
fn sink_absence_is_checked_after_the_pin() {
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let (pin, _alive) = TestPin::new(7);
    let peer = TestPeer::new(owner(501));
    let sink = TestSink {
        gone: Arc::new(AtomicBool::new(false)),
    };
    let mut guard = queue.open_guard(false, owner(501), pin, peer).unwrap();
    guard.set_sink(Some(sink.clone()));
    assert_eq!(guard.detach(), Ok(true));
    assert_eq!(guard.complete(), Ok(false));
    sink.gone.store(true, Ordering::Release);
    assert_eq!(guard.complete(), Ok(true));
}
