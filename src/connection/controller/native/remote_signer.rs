use super::ovpn::OvpnSigners;
use crate::{
    connection::ovpn::{
        session::{SignError, Signer},
        signing::{Hash, Padding},
    },
    helper::protocol::{
        CertificateOperation, CertificateOperationName, Message, Pkcs1Operation, Pkcs1PaddingName,
        PssHashName, PssOperation, PssPaddingName, SignDataBytes, SignFields, SignOperation,
        SignOperationName, SignReplyError, SignReplyResult,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, de::value::StringDeserializer};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    time::{Duration, Instant},
};

// Leave the app's 60-second approval window time to return its own error.
const REPLY_TIMEOUT: Duration = Duration::from_secs(70);
const SEND_RETRY: Duration = Duration::from_millis(25);
const CANCEL_POLL: Duration = Duration::from_millis(50);

pub(super) struct SignContext {
    state: Mutex<ContextState>,
    changed: Condvar,
    attempt_canceled: Arc<AtomicBool>,
}

struct ContextState {
    epoch: u64,
    canceled: bool,
}

impl SignContext {
    pub(super) fn new(epoch: u64, attempt_canceled: Arc<AtomicBool>) -> Self {
        Self {
            state: Mutex::new(ContextState {
                epoch,
                canceled: false,
            }),
            changed: Condvar::new(),
            attempt_canceled,
        }
    }

    pub(super) fn epoch(&self) -> u64 {
        self.state.lock().unwrap().epoch
    }

    pub(super) fn set_epoch(&self, epoch: u64) {
        self.state.lock().unwrap().epoch = epoch;
        self.changed.notify_all();
    }

    pub(super) fn cancel(&self) {
        self.state.lock().unwrap().canceled = true;
        self.changed.notify_all();
    }

    fn canceled(&self, current: &ContextState) -> bool {
        current.canceled || self.attempt_canceled.load(Ordering::Acquire)
    }
}

#[derive(Default)]
struct Requests {
    last_id: u64,
    pending: BTreeMap<u64, Pending>,
}

struct Pending {
    profile: String,
    generation: u64,
    epoch: u64,
    expires: Instant,
    context: Arc<SignContext>,
    sent: Arc<AtomicBool>,
    reply: SyncSender<SignReplyResult>,
}

pub(in crate::connection::controller) struct RemoteSigners {
    output: SyncSender<Message>,
    requests: Arc<Mutex<Requests>>,
    timeout: Duration,
}

impl RemoteSigners {
    pub(in crate::connection::controller) fn new(output: SyncSender<Message>) -> Self {
        Self {
            output,
            requests: Arc::default(),
            timeout: REPLY_TIMEOUT,
        }
    }

    pub(in crate::connection::controller) fn deliver(
        &self,
        id: u64,
        profile: &str,
        generation: u64,
        epoch: u64,
        result: SignReplyResult,
    ) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let Some(call) = requests.pending.get(&id) else {
            return false;
        };
        if call.profile != profile || call.generation != generation || call.epoch != epoch {
            return false;
        }

        let context = Arc::clone(&call.context);
        // Serialize delivery with cancellation, epoch changes and the send
        // itself. All work under both locks is in-memory and nonblocking.
        let current = context.state.lock().unwrap();
        if context.canceled(&current)
            || current.epoch != call.epoch
            || Instant::now() >= call.expires
            || !call.sent.load(Ordering::Relaxed)
        {
            return false;
        }
        let call = requests.pending.remove(&id).unwrap();
        drop(requests);
        let delivered = call.reply.try_send(result).is_ok();
        context.changed.notify_all();
        delivered
    }
}

impl OvpnSigners for RemoteSigners {
    fn signer(&self, profile: &str, generation: u64, context: Arc<SignContext>) -> Box<dyn Signer> {
        Box::new(RemoteSigner {
            profile: profile.into(),
            generation,
            context,
            output: self.output.clone(),
            requests: self.requests.clone(),
            timeout: self.timeout,
            pending: None,
        })
    }
}

// A signer has at most one outstanding call because Signer takes &mut self.
// Dropping the signer also drops its registration, including on unwind.
struct Registration {
    requests: Arc<Mutex<Requests>>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.requests.lock().unwrap().pending.remove(&self.id);
    }
}

struct RemoteSigner {
    profile: String,
    generation: u64,
    context: Arc<SignContext>,
    output: SyncSender<Message>,
    requests: Arc<Mutex<Requests>>,
    timeout: Duration,
    pending: Option<Registration>,
}

impl RemoteSigner {
    fn call(&mut self, op: SignOperation) -> Result<SignReplyResult, SignError> {
        let expires = Instant::now() + self.timeout;
        let epoch = self.context.epoch();
        let sent = Arc::new(AtomicBool::new(false));
        let (reply, response) = mpsc::sync_channel(1);
        let id = {
            let mut requests = self.requests.lock().unwrap();
            let id = requests
                .last_id
                .checked_add(1)
                .ok_or(SignError::Unavailable)?;
            requests.last_id = id;
            requests.pending.insert(
                id,
                Pending {
                    profile: self.profile.clone(),
                    generation: self.generation,
                    epoch,
                    expires,
                    context: self.context.clone(),
                    sent: sent.clone(),
                    reply,
                },
            );
            id
        };
        self.pending = Some(Registration {
            requests: self.requests.clone(),
            id,
        });
        let message = Message::SignRequest {
            id,
            profile: self.profile.clone(),
            generation: self.generation,
            epoch,
            op,
        };
        let result = self
            .emit(message, epoch, expires, &sent)
            .and_then(|()| self.wait_for_reply(response, epoch, expires));
        self.pending = None;
        match result? {
            SignReplyResult::Error(reply) => Err(match reply.error {
                SignReplyError::Canceled => SignError::Canceled,
                SignReplyError::PinRequired => SignError::PinRequired,
                SignReplyError::Unsupported => SignError::Unsupported,
                SignReplyError::Unavailable => SignError::Unavailable,
            }),
            response => Ok(response),
        }
    }

    fn emit(
        &self,
        mut message: Message,
        epoch: u64,
        expires: Instant,
        sent: &AtomicBool,
    ) -> Result<(), SignError> {
        let mut current = self.context.state.lock().unwrap();
        loop {
            let remaining = expires.saturating_duration_since(Instant::now());
            if self.context.canceled(&current) || current.epoch != epoch || remaining.is_zero() {
                return Err(SignError::Unavailable);
            }
            #[cfg(test)]
            tests::sending();
            match self.output.try_send(message) {
                Ok(()) => {
                    sent.store(true, Ordering::Relaxed);
                    return Ok(());
                }
                Err(TrySendError::Disconnected(_)) => return Err(SignError::Unavailable),
                Err(TrySendError::Full(retry)) => message = retry,
            }
            current = self
                .context
                .changed
                .wait_timeout(current, remaining.min(SEND_RETRY))
                .unwrap()
                .0;
        }
    }

    fn wait_for_reply(
        &self,
        response: Receiver<SignReplyResult>,
        epoch: u64,
        expires: Instant,
    ) -> Result<SignReplyResult, SignError> {
        let mut current = self.context.state.lock().unwrap();
        loop {
            if self.context.canceled(&current) || current.epoch != epoch {
                return Err(SignError::Unavailable);
            }
            match response.try_recv() {
                Ok(reply) => return Ok(reply),
                Err(TryRecvError::Disconnected) => return Err(SignError::Unavailable),
                Err(TryRecvError::Empty) => {}
            }
            let remaining = expires.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SignError::Unavailable);
            }
            // The engine can set the attempt's atomic before cleanup gets a
            // chance to notify this condvar.
            current = self
                .context
                .changed
                .wait_timeout(current, remaining.min(CANCEL_POLL))
                .unwrap()
                .0;
        }
    }
}

#[cfg(test)]
mod tests;

impl Signer for RemoteSigner {
    fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
        match self.call(SignOperation::Certificate(CertificateOperation {
            op: CertificateOperationName::Certificate,
        }))? {
            SignReplyResult::Certificate(reply) => reply
                .certificate
                .decode()
                .map_err(|_| SignError::Unavailable),
            _ => Err(SignError::Unavailable),
        }
    }

    fn sign(&mut self, padding: Padding, data: &[u8]) -> Result<Vec<u8>, SignError> {
        if !padding.accepts(data) {
            return Err(SignError::Unsupported);
        }
        let data = SignDataBytes::deserialize(StringDeserializer::<serde::de::value::Error>::new(
            STANDARD.encode(data),
        ))
        .map_err(|_| SignError::Unsupported)?;
        let fields = match padding {
            Padding::Pkcs1 => SignFields::Pkcs1(Pkcs1Operation {
                op: SignOperationName::Sign,
                padding: Pkcs1PaddingName::Pkcs1,
                data,
            }),
            Padding::Pss(hash) => SignFields::Pss(PssOperation {
                op: SignOperationName::Sign,
                padding: PssPaddingName::Pss,
                hash: match hash {
                    Hash::Sha256 => PssHashName::Sha256,
                    Hash::Sha384 => PssHashName::Sha384,
                    Hash::Sha512 => PssHashName::Sha512,
                    Hash::Sha1 | Hash::Sha224 => return Err(SignError::Unsupported),
                },
                data,
            }),
        };
        match self.call(SignOperation::Sign(fields))? {
            SignReplyResult::Signature(reply) => {
                reply.signature.decode().map_err(|_| SignError::Unavailable)
            }
            _ => Err(SignError::Unavailable),
        }
    }
}
