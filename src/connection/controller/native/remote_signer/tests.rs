use super::*;
use crate::helper::protocol::{CertificateReply, ErrorReply, SignatureReply};
use std::{
    cell::RefCell,
    thread::{self, JoinHandle},
};

const TEST_WAIT: Duration = Duration::from_secs(2);
const CANCEL_WAIT: Duration = Duration::from_millis(300);

thread_local! {
    static SENDING: RefCell<Option<mpsc::Sender<()>>> = const { RefCell::new(None) };
}

pub(super) fn sending() {
    if let Some(entered) = SENDING.with(|slot| slot.borrow_mut().take()) {
        entered.send(()).unwrap();
    }
}

struct Fixture {
    registry: RemoteSigners,
    wire: Receiver<Message>,
    context: Arc<SignContext>,
    attempt_canceled: Arc<AtomicBool>,
}

impl Fixture {
    fn new(capacity: usize, timeout: Duration) -> Self {
        let (output, wire) = mpsc::sync_channel(capacity);
        let mut registry = RemoteSigners::new(output);
        registry.timeout = timeout;
        let attempt_canceled = Arc::default();
        Self {
            registry,
            wire,
            context: Arc::new(SignContext::new(3, Arc::clone(&attempt_canceled))),
            attempt_canceled,
        }
    }

    fn signer(&self) -> Box<dyn Signer> {
        self.registry.signer("fixture", 7, self.context.clone())
    }

    fn request(&self) -> (u64, u64) {
        let Message::SignRequest {
            id,
            profile,
            generation,
            epoch,
            op,
        } = self.wire.recv_timeout(TEST_WAIT).unwrap()
        else {
            panic!("expected a signing request");
        };
        assert_eq!((profile.as_str(), generation), ("fixture", 7));
        assert!(matches!(op, SignOperation::Certificate(_)));
        (id, epoch)
    }

    fn empty(&self) {
        assert!(self.registry.requests.lock().unwrap().pending.is_empty());
    }
}

type SignResult = Result<Vec<u8>, SignError>;

struct Call {
    context: Arc<SignContext>,
    result: Receiver<SignResult>,
    worker: Option<JoinHandle<Box<dyn Signer>>>,
}

impl Call {
    fn certificate(fixture: &Fixture, mut signer: Box<dyn Signer>) -> Self {
        let (done, result) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = done.send(signer.certificate());
            signer
        });
        Self {
            context: fixture.context.clone(),
            result,
            worker: Some(worker),
        }
    }

    fn finish(mut self, expected: SignResult) -> Box<dyn Signer> {
        assert_eq!(self.result.recv_timeout(TEST_WAIT), Ok(expected));
        self.worker.take().unwrap().join().unwrap()
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.context.cancel();
            worker.join().unwrap();
        }
    }
}

fn certificate() -> SignReplyResult {
    SignReplyResult::Certificate(CertificateReply {
        certificate: serde_json::from_str(r#""MAA=""#).unwrap(),
    })
}

fn error(error: SignReplyError) -> SignReplyResult {
    SignReplyResult::Error(ErrorReply { error })
}

#[test]
fn mismatched_epoch_generation_and_profile_preserve_the_original_waiter() {
    let fixture = Fixture::new(1, TEST_WAIT);
    let call = Call::certificate(&fixture, fixture.signer());
    let (id, epoch) = fixture.request();
    for (id, profile, generation, epoch) in [
        (id + 1, "fixture", 7, epoch),
        (id, "fixture", 7, epoch + 1),
        (id, "fixture", 8, epoch),
        (id, "other", 7, epoch),
    ] {
        assert!(
            !fixture
                .registry
                .deliver(id, profile, generation, epoch, certificate()),
            "accepted mismatched tuple {id}/{profile}/{generation}/{epoch}"
        );
        assert!(matches!(call.result.try_recv(), Err(TryRecvError::Empty)));
    }
    assert!(
        fixture
            .registry
            .deliver(id, "fixture", 7, epoch, certificate())
    );
    drop(call.finish(Ok(vec![0x30, 0])));
    assert!(
        !fixture
            .registry
            .deliver(id, "fixture", 7, epoch, certificate())
    );
    fixture.empty();
}

#[test]
fn cancellation_releases_sender_even_with_a_full_wire_channel() {
    let fixture = Fixture::new(0, TEST_WAIT);
    let mut signer = fixture.signer();
    let (entered_send, entered) = mpsc::channel();
    let (done, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        SENDING.with(|slot| slot.replace(Some(entered_send)));
        done.send(signer.certificate()).unwrap();
    });
    let reached_send = entered.recv_timeout(TEST_WAIT);
    let context = fixture.context.clone();
    let cancellation = thread::spawn(move || context.cancel());
    let returned = result.recv_timeout(CANCEL_WAIT);
    // A blocking-send mutant still holds the context lock. Release that send
    // before joining either thread so even the failing test cleans up.
    drop(fixture.wire);
    cancellation.join().unwrap();
    worker.join().unwrap();
    assert_eq!(reached_send, Ok(()));
    assert_eq!(returned, Ok(Err(SignError::Unavailable)));
    assert!(fixture.registry.requests.lock().unwrap().pending.is_empty());
}

#[test]
fn cancellation_wakes_a_sent_request_and_refuses_its_late_reply() {
    for cancel_via_worker in [false, true] {
        let fixture = Fixture::new(1, TEST_WAIT);
        let call = Call::certificate(&fixture, fixture.signer());
        let (id, epoch) = fixture.request();
        if cancel_via_worker {
            fixture.attempt_canceled.store(true, Ordering::Release);
        } else {
            fixture.context.cancel();
        }
        assert!(
            !fixture
                .registry
                .deliver(id, "fixture", 7, epoch, certificate())
        );
        assert_eq!(
            call.result.recv_timeout(CANCEL_WAIT),
            Ok(Err(SignError::Unavailable)),
            "cancellation through worker flag: {cancel_via_worker}"
        );
        fixture.empty();
    }
}

#[test]
fn request_expires_without_a_reply_and_distinguishes_user_cancellation() {
    let fixture = Fixture::new(1, Duration::from_millis(120));
    let call = Call::certificate(&fixture, fixture.signer());
    let (id, epoch) = fixture.request();
    drop(call.finish(Err(SignError::Unavailable)));
    assert!(
        !fixture
            .registry
            .deliver(id, "fixture", 7, epoch, certificate())
    );
    fixture.empty();

    let fixture = Fixture::new(1, TEST_WAIT);
    let mut signer = fixture.signer();
    for (wire, expected) in [
        (SignReplyError::Canceled, SignError::Canceled),
        (SignReplyError::PinRequired, SignError::PinRequired),
        (SignReplyError::Unsupported, SignError::Unsupported),
        (SignReplyError::Unavailable, SignError::Unavailable),
    ] {
        let call = Call::certificate(&fixture, signer);
        let (id, epoch) = fixture.request();
        assert!(
            fixture
                .registry
                .deliver(id, "fixture", 7, epoch, error(wire))
        );
        signer = call.finish(Err(expected));
    }
    fixture.empty();
}

#[test]
fn each_request_reads_the_current_epoch_even_with_the_same_signer() {
    let fixture = Fixture::new(1, TEST_WAIT);
    let signer = fixture.signer();
    let first = Call::certificate(&fixture, signer);
    let (id, epoch) = fixture.request();
    assert_eq!(epoch, 3);
    assert!(
        fixture
            .registry
            .deliver(id, "fixture", 7, epoch, certificate())
    );
    let signer = first.finish(Ok(vec![0x30, 0]));

    fixture.context.set_epoch(9);
    let second = Call::certificate(&fixture, signer);
    let (next, epoch) = fixture.request();
    assert!(next > id);
    assert_eq!(epoch, 9);
    assert!(
        fixture
            .registry
            .deliver(next, "fixture", 7, epoch, certificate())
    );
    drop(second.finish(Ok(vec![0x30, 0])));
    fixture.empty();
}

#[test]
fn wrong_response_type_and_disconnected_wire_return_unavailable() {
    let fixture = Fixture::new(1, TEST_WAIT);
    let call = Call::certificate(&fixture, fixture.signer());
    let (id, epoch) = fixture.request();
    let result = SignReplyResult::Signature(SignatureReply {
        signature: serde_json::from_str(r#""MAA=""#).unwrap(),
    });
    assert!(fixture.registry.deliver(id, "fixture", 7, epoch, result));
    let mut signer = call.finish(Err(SignError::Unavailable));
    drop(fixture.wire);
    assert_eq!(signer.certificate(), Err(SignError::Unavailable));
    assert!(fixture.registry.requests.lock().unwrap().pending.is_empty());
}
