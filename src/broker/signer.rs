//! The app owns the token for an admitted OpenVPN connection generation.
use super::{Broker, Connection, Error, VpnKind, protocol};
use crate::{
    connection::ovpn::{
        pkcs11::{TokenError, TokenKey},
        session::SignError,
        signing::{Hash, Padding},
    },
    model::OvpnSettings,
    secrets::SecretStore,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use protocol::{
    CertificateReply, ErrorReply, PssHashName, SignFields, SignOperation, SignReplyError,
    SignReplyResult, SignatureReply, WireBase64,
};
use serde::{Deserialize, de::value::StringDeserializer};
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

const SIGNING_WINDOW: Duration = Duration::from_secs(60);

pub(super) trait AppSigner {
    fn certificate(&mut self) -> Result<Vec<u8>, SignError>;
    fn sign(
        &mut self,
        padding: Padding,
        data: &[u8],
        canceled: &AtomicBool,
        expires: Instant,
    ) -> Result<Option<Vec<u8>>, SignError>;
}

impl AppSigner for TokenKey {
    fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
        TokenKey::certificate(self).map_err(token_error)
    }

    fn sign(
        &mut self,
        padding: Padding,
        data: &[u8],
        canceled: &AtomicBool,
        expires: Instant,
    ) -> Result<Option<Vec<u8>>, SignError> {
        self.sign_until(padding, data, canceled, expires)
            .map_err(token_error)
    }
}

type Open = dyn Fn(&OvpnSettings, &AtomicBool, Instant) -> Result<Option<Box<dyn AppSigner>>, SignError>
    + Send
    + Sync;

pub(super) struct Signing {
    pub(super) open: Arc<Open>,
    attempts: BTreeMap<String, Attempt>,
    suspended: BTreeMap<String, Suspended>,
    replies: VecDeque<(Call, SignReplyResult)>,
}

impl Signing {
    pub(super) fn may_read(&self) -> bool {
        // Give lifecycle messages a chance to invalidate retained replies.
        // Backpressure still bounds the backlog to fewer than 64 prior
        // replies, one incoming batch and the outstanding worker results.
        self.replies.len() < 64
    }

    pub(super) fn pause_pending_for_send(&self, profile: &str) -> Option<Arc<WorkCancellation>> {
        let pending = self
            .attempts
            .get(profile)?
            .worker
            .as_ref()?
            .pending
            .as_ref()?;
        // Leave the request and token in place until the send commits the transition.
        pending
            .canceled
            .paused_for_send
            .store(true, Ordering::Release);
        pending.canceled.flag.store(true, Ordering::Release);
        Some(Arc::clone(&pending.canceled))
    }
}

impl Default for Signing {
    fn default() -> Self {
        Self {
            open: Arc::new(open_token),
            attempts: BTreeMap::new(),
            suspended: BTreeMap::new(),
            replies: VecDeque::new(),
        }
    }
}

struct Attempt {
    generation: u64,
    connect: String,
    accepted: bool,
    settings: OvpnSettings,
    worker: Option<Worker>,
}

struct Suspended {
    attempt: Attempt,
    replacement: String,
}

impl Attempt {
    fn matches_profile(&self, connection: &Connection) -> bool {
        connection.view.profile.kind == VpnKind::Ovpn
            && connection.view.profile.ovpn.as_ref() == Some(&self.settings)
    }

    fn current(&self, connection: &Connection) -> bool {
        connection.generation == self.generation
            && connection.view.state.active()
            && self.matches_profile(connection)
    }

    fn pause(&mut self, replies: &mut VecDeque<(Call, SignReplyResult)>) {
        if let Some(worker) = &mut self.worker
            && let Some(call) = worker.cancel_pending()
        {
            replies.push_back((call, failure(SignReplyError::Unavailable)));
        }
    }

    fn revoke(&mut self, profile: &str, replies: &mut VecDeque<(Call, SignReplyResult)>) {
        self.pause(replies);
        self.worker = None;
        for (call, result) in replies {
            if call.profile == profile
                && call.generation == self.generation
                && !matches!(result, SignReplyResult::Error(_))
            {
                *result = failure(SignReplyError::Unavailable);
            }
        }
    }
}

pub(super) struct Call {
    pub id: u64,
    pub profile: String,
    pub generation: u64,
    pub epoch: u64,
}

impl Call {
    fn reply(&self, result: Option<&SignReplyResult>) -> protocol::Request {
        let result = match result {
            Some(SignReplyResult::Certificate(reply)) => {
                SignReplyResult::Certificate(CertificateReply {
                    certificate: reply.certificate.clone(),
                })
            }
            Some(SignReplyResult::Signature(reply)) => SignReplyResult::Signature(SignatureReply {
                signature: reply.signature.clone(),
            }),
            Some(SignReplyResult::Error(reply)) => failure(reply.error),
            None => failure(SignReplyError::Unavailable),
        };
        protocol::Request {
            id: format!("sign-reply-{}", self.id),
            command: protocol::Command::SignReply {
                id: self.id,
                profile: self.profile.clone(),
                generation: self.generation,
                epoch: self.epoch,
                result,
            },
        }
    }
}

impl<S: SecretStore> Broker<S> {
    pub(super) fn register_signing_connect(&mut self, profile: &str) {
        let Some(c) = self.connections.get(profile) else {
            return;
        };
        let Some(pending) = &c.pending else {
            return;
        };
        if pending.previous.0.checked_add(1) != Some(c.generation)
            || c.view.profile.kind != VpnKind::Ovpn
        {
            return;
        }
        let Some(settings) = &c.view.profile.ovpn else {
            return;
        };
        if let Some(mut prior) = self.signing.suspended.remove(profile) {
            prior.attempt.revoke(profile, &mut self.signing.replies);
        }
        let previous = self.signing.attempts.insert(
            profile.into(),
            Attempt {
                generation: c.generation,
                connect: pending.id.clone(),
                accepted: false,
                settings: settings.clone(),
                worker: None,
            },
        );
        let Some(mut previous) = previous else {
            return;
        };
        if previous.generation == pending.previous.0
            && pending.previous.1.active()
            && previous.matches_profile(c)
        {
            previous.pause(&mut self.signing.replies);
            self.signing.suspended.insert(
                profile.into(),
                Suspended {
                    attempt: previous,
                    replacement: pending.id.clone(),
                },
            );
        } else {
            previous.revoke(profile, &mut self.signing.replies);
        }
    }

    pub(super) fn accept_signing_operation(&mut self, id: &str) {
        if let Some(attempt) = self
            .signing
            .attempts
            .values_mut()
            .chain(
                self.signing
                    .suspended
                    .values_mut()
                    .map(|entry| &mut entry.attempt),
            )
            .find(|attempt| attempt.connect == id)
        {
            attempt.accepted = true;
        }
    }

    pub(super) fn clear_signing(&mut self) {
        self.signing.attempts.clear();
        self.signing.suspended.clear();
        self.signing.replies.clear();
    }

    pub(super) fn revoke_suspended_signing(&mut self, profile: &str, generation: u64) {
        let suspended = &mut self.signing.suspended;
        if suspended
            .get(profile)
            .is_some_and(|prior| prior.attempt.generation == generation)
            && let Some(mut prior) = suspended.remove(profile)
        {
            prior.attempt.revoke(profile, &mut self.signing.replies);
        }
    }

    pub(super) fn reconcile_signing(&mut self) {
        let replies = &mut self.signing.replies;
        let attempts = &mut self.signing.attempts;
        attempts.retain(|profile, attempt| {
            let current = self
                .connections
                .get(profile)
                .is_some_and(|c| attempt.current(c));
            if !current {
                attempt.revoke(profile, replies);
            }
            current
        });
        let resolved = self
            .signing
            .suspended
            .iter()
            .filter(|(profile, prior)| {
                !self.connections.get(*profile).is_some_and(|c| {
                    prior.attempt.matches_profile(c)
                        && c.pending.as_ref().is_some_and(|pending| {
                            pending.id == prior.replacement && !pending.accepted
                        })
                })
            })
            .map(|(profile, _)| profile.clone())
            .collect::<Vec<_>>();
        for profile in resolved {
            let mut prior = self.signing.suspended.remove(&profile).unwrap();
            if self
                .connections
                .get(&profile)
                .is_some_and(|c| prior.attempt.current(c))
            {
                attempts.insert(profile, prior.attempt);
            } else {
                prior.attempt.revoke(&profile, replies);
            }
        }
    }

    pub(super) fn receive_sign_request(&mut self, call: Call, op: SignOperation) {
        let admitted = self.ready
            && self
                .connections
                .get(&call.profile)
                .is_some_and(|c| c.view.state.active());
        if admitted
            && let Some(attempt) = self.signing.attempts.get_mut(&call.profile)
            && attempt.accepted
            && attempt.generation == call.generation
        {
            let expires = Instant::now() + SIGNING_WINDOW;
            if attempt.worker.is_none() {
                attempt.worker =
                    Worker::start(attempt.settings.clone(), Arc::clone(&self.signing.open));
            }
            if let Some(worker) = &mut attempt.worker
                && worker.pending.is_none()
            {
                let (finish, result) = mpsc::sync_channel(1);
                let canceled = Arc::new(WorkCancellation::default());
                let work = Work {
                    op,
                    expires,
                    canceled: Arc::clone(&canceled),
                    finish,
                };
                if worker.input.try_send(work).is_ok() {
                    worker.pending = Some(PendingCall {
                        call,
                        canceled,
                        result,
                    });
                    return;
                }
            }
        }
        self.signing
            .replies
            .push_back((call, failure(SignReplyError::Unavailable)));
    }

    pub(super) fn poll_signing(&mut self) {
        for attempt in self.signing.attempts.values_mut() {
            if let Some(worker) = &mut attempt.worker
                && let Some(reply) = worker.poll()
            {
                self.signing.replies.push_back(reply);
            }
        }
    }

    pub(super) fn flush_signing(&mut self) -> Result<bool, Error> {
        while let Some((call, result)) = self.signing.replies.front() {
            let suspended = self
                .signing
                .suspended
                .get(&call.profile)
                .is_some_and(|entry| entry.attempt.generation == call.generation);
            let client = self.client.as_ref().ok_or(Error::Unavailable)?;
            match client.send(call.reply((!suspended).then_some(result))) {
                Ok(()) => {
                    self.signing.replies.pop_front();
                }
                Err(Error::Busy) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }
}

#[derive(Default)]
pub(super) struct WorkCancellation {
    flag: AtomicBool,
    paused_for_send: AtomicBool,
}

impl WorkCancellation {
    pub(super) fn resume_after_failed_send(&self) {
        self.flag.store(false, Ordering::Release);
    }
}

struct PendingCall {
    call: Call,
    canceled: Arc<WorkCancellation>,
    result: Receiver<SignReplyResult>,
}

struct Work {
    op: SignOperation,
    expires: Instant,
    canceled: Arc<WorkCancellation>,
    finish: SyncSender<SignReplyResult>,
}

struct Worker {
    input: SyncSender<Work>,
    pending: Option<PendingCall>,
}

impl Worker {
    fn start(settings: OvpnSettings, open: Arc<Open>) -> Option<Self> {
        let (input, work) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("ovpn-app-signer".into())
            .spawn(move || run(&settings, &*open, &work))
            .ok()?;
        Some(Self {
            input,
            pending: None,
        })
    }

    fn cancel_pending(&mut self) -> Option<Call> {
        let pending = self.pending.take()?;
        pending.canceled.flag.store(true, Ordering::Release);
        // Each call owns its receiver, so a discarded result cannot reach
        // another call even if rollback has already reactivated this worker.
        Some(pending.call)
    }

    fn poll(&mut self) -> Option<(Call, SignReplyResult)> {
        let result = match self.pending.as_ref()?.result.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Disconnected) => failure(SignReplyError::Unavailable),
            Err(TryRecvError::Empty) => return None,
        };
        self.pending.take().map(|pending| (pending.call, result))
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the channels releases the waiter. A provider call already
        // underway can return later, at which point the worker drops its token.
        self.cancel_pending();
    }
}

fn run(settings: &OvpnSettings, open: &Open, work: &Receiver<Work>) {
    let mut token = None;
    while let Ok(Work {
        op,
        expires,
        canceled,
        finish,
    }) = work.recv()
    {
        if canceled.flag.load(Ordering::Acquire) {
            continue;
        }
        let result = perform(
            op,
            &mut token,
            || open(settings, &canceled.flag, expires),
            &canceled,
            expires,
        );
        let _ = finish.try_send(result);
    }
}

fn perform(
    op: SignOperation,
    token: &mut Option<Result<Box<dyn AppSigner>, SignError>>,
    open: impl FnOnce() -> Result<Option<Box<dyn AppSigner>>, SignError>,
    cancellation: &WorkCancellation,
    expires: Instant,
) -> SignReplyResult {
    let canceled = &cancellation.flag;
    let sign = match op {
        SignOperation::Certificate(_) => None,
        SignOperation::Sign(fields) => {
            let (padding, data) = match fields {
                SignFields::Pkcs1(fields) => (Padding::Pkcs1, fields.data),
                SignFields::Pss(fields) => (
                    Padding::Pss(match fields.hash {
                        PssHashName::Sha256 => Hash::Sha256,
                        PssHashName::Sha384 => Hash::Sha384,
                        PssHashName::Sha512 => Hash::Sha512,
                    }),
                    fields.data,
                ),
            };
            let Ok(data) = data.decode() else {
                return failure(SignReplyError::Unavailable);
            };
            Some((padding, data))
        }
    };
    let opened = if let Some(opened) = token {
        opened
    } else {
        let result = open();
        // A canceled open may return after a failed send clears the flag.
        // Only cache a missing token when no send paused this request.
        let interrupted_open =
            matches!(result, Ok(None)) && cancellation.paused_for_send.load(Ordering::Acquire);
        if interrupted_open || (canceled.load(Ordering::Acquire) && !matches!(result, Ok(Some(_))))
        {
            return failure(SignReplyError::Unavailable);
        }
        token.insert(result.and_then(|token| token.ok_or(SignError::Unavailable)))
    };
    if canceled.load(Ordering::Acquire) {
        return failure(SignReplyError::Unavailable);
    }
    let signer = match opened {
        Ok(signer) => signer,
        Err(error) => return failure(wire_error(*error)),
    };
    match sign {
        None => signer
            .certificate()
            .and_then(encode)
            .map(|certificate| SignReplyResult::Certificate(CertificateReply { certificate })),
        Some((padding, data)) => {
            if !padding.accepts(&data) {
                return failure(SignReplyError::Unsupported);
            }
            signer
                .sign(padding, &data, canceled, expires)
                .and_then(|signature| encode(signature.ok_or(SignError::Unavailable)?))
                .map(|signature| SignReplyResult::Signature(SignatureReply { signature }))
        }
    }
    .unwrap_or_else(|error| failure(wire_error(error)))
}

fn open_token(
    settings: &OvpnSettings,
    canceled: &AtomicBool,
    expires: Instant,
) -> Result<Option<Box<dyn AppSigner>>, SignError> {
    let (pairs, remainder) = settings.certificate_id.as_bytes().as_chunks::<2>();
    if pairs.is_empty() || !remainder.is_empty() {
        return Err(SignError::Unavailable);
    }
    let id = pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or(SignError::Unavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let token = TokenKey::open_until(Path::new(&settings.module), &id, canceled, expires)
        .map_err(token_error)?;
    Ok(token.map(|token| Box::new(token) as Box<dyn AppSigner>))
}

fn token_error(error: TokenError) -> SignError {
    match error {
        TokenError::Canceled => SignError::Canceled,
        TokenError::PinRequired => SignError::PinRequired,
        _ => SignError::Unavailable,
    }
}

fn encode<const LIMIT: usize>(bytes: Vec<u8>) -> Result<WireBase64<LIMIT>, SignError> {
    // The protocol owns the encoded size limits and the strict alphabet.
    WireBase64::deserialize(StringDeserializer::<serde::de::value::Error>::new(
        STANDARD.encode(bytes),
    ))
    .map_err(|_| SignError::Unavailable)
}

fn failure(error: SignReplyError) -> SignReplyResult {
    SignReplyResult::Error(ErrorReply { error })
}

fn wire_error(error: SignError) -> SignReplyError {
    match error {
        SignError::Canceled => SignReplyError::Canceled,
        SignError::PinRequired => SignReplyError::PinRequired,
        SignError::Unsupported | SignError::Unavailable => SignReplyError::Unavailable,
    }
}
