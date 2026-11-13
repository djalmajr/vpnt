//! Work-fence cases: false/error stop and sink read errors. Private helpers
//! implement the same production traits; no production source is changed.
use super::*;
use crate::connection::macos::routing::ResourceFence;

#[test]
fn detach_alone_does_not_complete_work() {
    let (fence, work) = ResourceFence::begin(&owner(501)).unwrap();
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let mut guard = queue
        .open_guard(
            false,
            owner(501),
            TestPin::new(7).0,
            TestPeer::new(owner(501)),
        )
        .unwrap();
    guard.attach_work(work).unwrap();
    assert_eq!(guard.complete(), Ok(false));
    assert_eq!(guard.detach(), Ok(true));
    assert!(!fence.is_complete(), "detach must not complete route work");
    assert_eq!(guard.complete(), Ok(true));
    assert!(fence.is_complete());
}

#[test]
fn queued_work_waits_for_stop_absence_and_sink() {
    let (fence, work) = ResourceFence::begin(&owner(501)).unwrap();
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let (pin, _alive) = TestPin::new(7);
    let absent = pin.absent_flag();
    let error = pin.error_flag();
    absent.store(false, Ordering::Release);
    error.store(true, Ordering::Release);
    let sink = TestSink {
        gone: Arc::new(AtomicBool::new(false)),
    };
    let peer = TestPeer::new(owner(501));
    let mut guard = queue.open_guard(false, owner(501), pin, peer).unwrap();
    guard.set_sink(Some(sink.clone()));
    guard.attach_work(work).unwrap();
    drop(guard);
    assert_eq!(queue.reap(), Err(Error::Unavailable));
    error.store(false, Ordering::Release);
    queue.reap().unwrap();
    assert!(!fence.is_complete(), "interface still present");
    absent.store(true, Ordering::Release);
    queue.reap().unwrap();
    assert!(!fence.is_complete(), "sink still present");
    sink.gone.store(true, Ordering::Release);
    queue.reap().unwrap();
    assert!(fence.is_complete());
}

#[test]
fn wrong_owner_attach_refuses_without_stopping_peer() {
    let (fence, work) = ResourceFence::begin(&owner(501)).unwrap();
    let queue = Lifecycle::<TestPin, TestPeer, TestSink>::new();
    let peer = TestPeer::new(owner(501));
    let mut guard = queue
        .open_guard(false, owner(502), TestPin::new(7).0, peer.clone())
        .unwrap();
    assert_eq!(guard.attach_work(work), Err(Error::Invalid));
    assert_eq!(peer.calls(), 0);
    assert!(fence.is_complete(), "unbound rejected work completes");
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    False,
    Error,
    True,
}

#[derive(Clone)]
struct ControlledPeer {
    mode: Arc<Mutex<Mode>>,
    calls: Arc<AtomicUsize>,
}
impl ControlledPeer {
    fn new(mode: Mode) -> Self {
        Self {
            mode: Arc::new(Mutex::new(mode)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}
impl Retire for ControlledPeer {
    fn retire_peer(&self, _: &Owner) -> Result<bool, Error> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        match *self.mode.lock().unwrap() {
            Mode::False => Ok(false),
            Mode::Error => Err(Error::Unavailable),
            Mode::True => Ok(true),
        }
    }
}

#[derive(Clone)]
struct ErrorSink {
    gone: Arc<AtomicBool>,
    read_error: Arc<AtomicBool>,
}
impl ErrorSink {
    fn new(gone: bool, read_error: bool) -> Self {
        Self {
            gone: Arc::new(AtomicBool::new(gone)),
            read_error: Arc::new(AtomicBool::new(read_error)),
        }
    }
}
impl Sink for ErrorSink {
    fn gone(&self) -> Result<bool, Error> {
        if self.read_error.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        Ok(self.gone.load(Ordering::Acquire))
    }
}

// F1(a): a false stop and an error stop are distinct and both keep the bound
// work and the pin; the queued entry persists and nothing completes.
#[test]
fn false_and_error_stop_keep_bound_work_and_pin_queued() {
    for mode in [Mode::False, Mode::Error] {
        let (fence, work) = ResourceFence::begin(&owner(501)).unwrap();
        let queue = Lifecycle::<TestPin, ControlledPeer, ErrorSink>::new();
        let (pin, alive) = TestPin::new(7);
        let peer = ControlledPeer::new(mode);
        let mut guard = queue
            .open_guard(false, owner(501), pin, peer.clone())
            .unwrap();
        guard.attach_work(work).unwrap();
        assert_eq!(guard.detach(), Err(Error::Busy));
        assert_eq!(guard.complete(), Ok(false));
        assert!(alive.upgrade().is_some(), "stop kept no pin");
        assert!(!fence.is_complete(), "work completed without stop");
        drop(guard);
        assert!(queue.has_entries().unwrap());
        match mode {
            // A false stop is not an error: the entry simply stays queued.
            Mode::False => queue.reap().unwrap(),
            Mode::Error => assert_eq!(queue.reap().unwrap_err(), Error::Unavailable),
            Mode::True => unreachable!(),
        }
        assert!(!fence.is_complete(), "reap completed the work");
        assert_eq!(peer.calls(), 2, "retry used another peer");
    }
}

// F1(b): after the confirmed stop only the pin is released; a sink read error
// retains the fence and the entry in BOTH Guard.complete and queue.reap.
#[test]
fn sink_read_error_retains_bound_work_in_guard_complete_and_queue_reap() {
    let (fence, work) = ResourceFence::begin(&owner(501)).unwrap();
    let queue = Lifecycle::<TestPin, ControlledPeer, ErrorSink>::new();
    let (pin, alive) = TestPin::new(7);
    let sink = ErrorSink::new(false, true);
    let peer = ControlledPeer::new(Mode::True);
    let mut guard = queue
        .open_guard(false, owner(501), pin, peer.clone())
        .unwrap();
    guard.set_sink(Some(sink));
    guard.attach_work(work).unwrap();
    assert_eq!(guard.detach(), Ok(true));
    assert!(alive.upgrade().is_none(), "confirmed stop must release");
    assert_eq!(guard.complete(), Err(Error::Unavailable));
    assert!(!fence.is_complete(), "sink read error completed the work");
    drop(guard);
    assert!(queue.has_entries().unwrap());
    assert_eq!(queue.reap().unwrap_err(), Error::Unavailable);
    assert!(!fence.is_complete(), "queued sink read error completed");
    assert!(queue.has_entries().unwrap(), "error swallowed by the queue");
    assert_eq!(peer.calls(), 1, "a stopped peer was retired again");
}
