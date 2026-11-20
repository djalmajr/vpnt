mod dispatch;
mod metadata;
#[cfg(target_os = "macos")]
use super::native::remote_signer::RemoteSigners;
use super::{
    worker::{self, ExitRequested, Finished, Signals},
    *,
};
#[cfg(test)]
use crate::model::VpnKind;
use crate::{
    helper::protocol::{Command, FailureNote, Message, Request, TunnelStatus, VERSION},
    model::valid_profile_id,
};
use dispatch::dispatch;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Condvar, Mutex,
        atomic::Ordering,
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, Scope, ScopedJoinHandle},
};

/// Past the cleanup budget, the watchdog waits this long before `_exit`. The
/// deadline counts from the instant the engine loop records the request,
/// within one poll (50 ms) of EOF or SIGTERM while the loop runs: request +
/// 20 s + 5 s. A loop blocked before it records the request arms nothing.
const DEADLINE_MARGIN: Duration = Duration::from_secs(5);

/// The exit request and what the watchdog does once request + budget +
/// `margin` passes while the engine has not returned. `action` receives
/// `Factory::unjournaled`.
pub(super) struct Deadline {
    exit: Arc<ExitRequested>,
    margin: Duration,
    action: Box<dyn Fn(bool) + Send + Sync>,
}
impl Deadline {
    #[cfg(test)]
    pub(super) fn new(
        exit: Arc<ExitRequested>,
        margin: Duration,
        action: impl Fn(bool) + Send + Sync + 'static,
    ) -> Self {
        Self {
            exit,
            margin,
            action: Box::new(action),
        }
    }
    /// One diagnostic line, then `_exit(DEADLINE_EXIT)`.
    fn process(exit: Arc<ExitRequested>) -> Self {
        Self {
            exit,
            margin: DEADLINE_MARGIN,
            action: Box::new(|unjournaled| {
                crate::helper::runtime::cleanup::deadline(
                    std::path::Path::new(crate::helper::paths::STATE),
                    unjournaled,
                );
                crate::helper::fd_guard::deadline_exit()
            }),
        }
    }
}
#[derive(Default)]
struct Returned {
    done: Mutex<bool>,
    wake: Condvar,
}
/// Dropped when the engine's scope body returns or unwinds, before the scope
/// joins the watchdog.
struct Finish<'a>(&'a Returned);
impl Drop for Finish<'_> {
    fn drop(&mut self) {
        *self
            .0
            .done
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;
        self.0.wake.notify_all();
    }
}
/// Started at the first exit request. Without a request it returns at once.
/// The deadline is on the monotonic clock and never moves.
fn watch(deadline: &Deadline, returned: &Returned, unjournaled: impl FnOnce() -> bool) {
    let Some(requested) = deadline.exit.at() else {
        return;
    };
    let until = requested + deadline.exit.budget() + deadline.margin;
    let mut done = returned
        .done
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    while !*done {
        let now = Instant::now();
        if now >= until {
            drop(done);
            (deadline.action)(unjournaled());
            return;
        }
        done = returned
            .wake
            .wait_timeout(done, until - now)
            .unwrap_or_else(|error| error.into_inner())
            .0;
    }
}

struct Pending {
    request: String,
    credentials: Credentials,
}
struct Worker<'scope> {
    generation: u64,
    request: String,
    signals: Signals,
    thread: ScopedJoinHandle<'scope, Finished>,
}
struct Slot<'scope> {
    profile: Profile,
    generation: u64,
    state: ConnectionState,
    failures: u32,
    cleaning: bool,
    /// Note of this generation's failed attempt; a new attempt clears it.
    failure: Option<FailureNote>,
    interval: ProbeClock,
    worker: Option<Worker<'scope>>,
    pending: Option<Pending>,
}
impl Slot<'_> {
    fn cancel(&mut self) {
        if let Some(worker) = &self.worker {
            worker.signals.canceled.store(true, Ordering::Release);
        }
    }
    /// `notes`: the peer announced `FAILURE_NOTE_PROBE_SNAPSHOT_ID`.
    fn changed(&self, notes: bool) -> Message {
        Message::Changed {
            profile_id: self.profile.id.clone(),
            generation: self.generation,
            state: self.state,
            failures: self.failures,
            cleaning: self.cleaning,
            failure: self.failure.filter(|_| notes),
        }
    }
}
fn launch<'scope, 'env: 'scope, F: Factory>(
    scope: &'scope Scope<'scope, 'env>,
    factory: &'env F,
    uid: u32,
    slot: &mut Slot<'scope>,
    timing: Timing,
    exit: &Arc<ExitRequested>,
) {
    let Some(pending) = slot.pending.take() else {
        return;
    };
    let canceled = Arc::new(AtomicBool::new(false));
    let probe = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(None));
    let signals = Signals {
        canceled: canceled.clone(),
        probe: probe.clone(),
        state: state.clone(),
        exit: exit.clone(),
    };
    let profile = slot.profile.clone();
    let generation = slot.generation;
    let interval = slot.interval.clone();
    let worker_canceled = canceled.clone();
    let thread = scope.spawn(move || {
        let attempt = factory.create(
            profile,
            uid,
            generation,
            pending.credentials,
            worker_canceled,
        );
        worker::run(attempt, signals, timing, interval)
    });
    slot.worker = Some(Worker {
        generation,
        request: pending.request,
        signals: Signals {
            canceled,
            probe,
            state,
            exit: exit.clone(),
        },
        thread,
    });
}

#[cfg(any(not(target_os = "macos"), test))]
pub(super) fn run<F: Factory>(
    factory: F,
    uid: u32,
    profiles: Vec<Profile>,
    requests: Receiver<Request>,
    output: SyncSender<Message>,
    timing: Timing,
) -> Result<(), ErrorCode> {
    run_with_exit(
        factory,
        uid,
        profiles,
        requests,
        output,
        RunOptions::new(timing),
    )
}

#[cfg(target_os = "macos")]
pub(super) fn run_native<F: Factory>(
    factory: F,
    uid: u32,
    profiles: Vec<Profile>,
    requests: Receiver<Request>,
    output: SyncSender<Message>,
    timing: Timing,
    sign_replies: Arc<RemoteSigners>,
) -> Result<(), ErrorCode> {
    run_with_exit(
        factory,
        uid,
        profiles,
        requests,
        output,
        RunOptions {
            sign_replies: Some(sign_replies),
            ..RunOptions::new(timing)
        },
    )
}

struct RunOptions {
    timing: Timing,
    deadline: Deadline,
    #[cfg(target_os = "macos")]
    sign_replies: Option<Arc<RemoteSigners>>,
}

impl RunOptions {
    fn new(timing: Timing) -> Self {
        Self {
            timing,
            deadline: Deadline::process(Arc::new(ExitRequested::new(worker::CLEANUP_BUDGET))),
            #[cfg(target_os = "macos")]
            sign_replies: None,
        }
    }
}

fn run_with_exit<F: Factory>(
    factory: F,
    uid: u32,
    profiles: Vec<Profile>,
    requests: Receiver<Request>,
    output: SyncSender<Message>,
    options: RunOptions,
) -> Result<(), ErrorCode> {
    let RunOptions {
        timing,
        deadline,
        #[cfg(target_os = "macos")]
        sign_replies,
    } = options;
    let exit = &deadline.exit;
    if uid == 0 {
        return Err(ErrorCode::UntrustedConfiguration);
    }
    let profiles = metadata::map(profiles)?;
    // The controller-wide preference; each slot starts from it and `Connect`
    // may set that generation's clock. `SetProbeInterval` updates the default
    // and every existing slot clock, so queued and live generations follow it.
    let interval = ProbeClock::new(timing.interval);
    let returned = Returned::default();
    thread::scope(|scope| {
        let _finish = Finish(&returned);
        let mut watching = false;
        let mut slots: BTreeMap<_, _> = profiles
            .into_iter()
            .map(|(id, profile)| {
                (
                    id,
                    Slot {
                        profile,
                        generation: 0,
                        state: ConnectionState::Off,
                        failures: 0,
                        cleaning: false,
                        failure: None,
                        interval: ProbeClock::new(interval.get()),
                        worker: None,
                        pending: None,
                    },
                )
            })
            .collect();
        let mut outgoing = VecDeque::new();
        let mut closing = false;
        let mut cleanup_capable = false;
        let mut failure_capable = false;
        let mut panicked = false;
        loop {
            if crate::helper::ppp_supervisor::signals::INTERRUPTED.load(Ordering::Acquire) {
                closing = true;
            }
            // Bound work per pass so pipe floods cannot starve cleanup/probes.
            for _ in 0..64 {
                if closing {
                    break;
                }
                match requests.try_recv() {
                    Ok(request) => {
                        #[cfg(target_os = "macos")]
                        let Some(request) = dispatch::dispatch_sign_reply(
                            request,
                            sign_replies.as_deref(),
                            &mut outgoing,
                        ) else {
                            continue;
                        };
                        let mut request = request;
                        if matches!(request.command, Command::Snapshot {})
                            && request.id == crate::helper::protocol::CLEANUP_PROBE_SNAPSHOT_ID
                        {
                            cleanup_capable = true;
                            request.id = crate::helper::protocol::CLEANUP_ACK_SNAPSHOT_ID.into();
                        }
                        let note_probe = matches!(request.command, Command::Snapshot {})
                            && request.id
                                == crate::helper::protocol::FAILURE_NOTE_PROBE_SNAPSHOT_ID;
                        if note_probe {
                            request.id =
                                crate::helper::protocol::FAILURE_NOTE_ACK_SNAPSHOT_ID.into();
                        }
                        let refreshed = if matches!(request.command, Command::Snapshot {}) {
                            factory.profiles().and_then(|profiles| {
                                if let Some(profiles) = profiles {
                                    metadata::refresh(&mut slots, profiles, &interval)?;
                                }
                                Ok(())
                            })
                        } else {
                            Ok(())
                        };
                        if let Err(error) = refreshed {
                            outgoing.push_back(Message::Failed {
                                id: request.id,
                                error,
                            });
                        } else {
                            // The broker turns the note on only when the ack
                            // snapshot arrives; a `Failed` keeps it off on
                            // both sides, so only a successful ack enables it.
                            if note_probe {
                                failure_capable = true;
                            }
                            dispatch(
                                request,
                                &factory,
                                &mut slots,
                                &mut outgoing,
                                &interval,
                                cleanup_capable,
                                failure_capable,
                            );
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        closing = true;
                        break;
                    }
                }
            }
            if closing {
                exit.request();
                if !watching {
                    watching = true;
                    let (deadline, returned, factory) = (&deadline, &returned, &factory);
                    scope.spawn(move || watch(deadline, returned, || factory.unjournaled()));
                }
            }
            for slot in slots.values_mut() {
                if !closing
                    && let Some(worker) = &slot.worker
                    && worker.generation == slot.generation
                    && let Some(progress) = worker
                        .signals
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .take()
                {
                    slot.state = progress.state;
                    slot.failures = progress.failures;
                    slot.cleaning = progress.cleaning;
                    slot.failure = progress.failure;
                    outgoing.push_back(slot.changed(failure_capable));
                }
                if closing {
                    slot.pending = None; // drops queued secrets before waiting
                    slot.cancel();
                }
                if slot
                    .worker
                    .as_ref()
                    .is_some_and(|worker| worker.thread.is_finished())
                {
                    let worker = slot.worker.take().unwrap();
                    let finished = match worker.thread.join() {
                        Ok(finished) => finished,
                        Err(_) => {
                            closing = true;
                            panicked = true;
                            Finished {
                                state: ConnectionState::Dropped,
                                error: Some(ErrorCode::BackendFailure),
                                step: None,
                            }
                        }
                    };
                    if slot.pending.is_none() {
                        let current = slot.generation == worker.generation;
                        slot.state = if current {
                            finished.state
                        } else {
                            ConnectionState::Off
                        };
                        slot.failures = 0;
                        slot.cleaning = false;
                        slot.failure = finished
                            .error
                            .zip(finished.step)
                            .filter(|_| current)
                            .map(|(code, step)| FailureNote { code, step });
                        if !closing {
                            outgoing.push_back(slot.changed(failure_capable));
                        }
                    }
                    if slot.generation == worker.generation
                        && let Some(error) = finished.error
                        && !closing
                    {
                        outgoing.push_back(Message::Failed {
                            id: worker.request,
                            error,
                        });
                    }
                }
                if !closing && slot.worker.is_none() && slot.pending.is_some() {
                    #[cfg(target_os = "macos")]
                    if sign_replies.is_some()
                        && slot.profile.kind == VpnKind::Ovpn
                        && let Some(pending) = &slot.pending
                        && outgoing.iter().any(
                            |message| matches!(message, Message::Accepted { id } if id == &pending.request),
                        )
                    {
                        // The app admits signing only after it sees this
                        // acknowledgement. A signer sends directly to output.
                        continue;
                    }
                    launch(scope, &factory, uid, slot, timing, exit);
                }
            }
            if outgoing.len() > 256 {
                closing = true;
                outgoing.clear();
            }
            while let Some(message) = outgoing.pop_front() {
                if let Message::Changed {
                    profile_id,
                    generation,
                    state,
                    failures,
                    cleaning,
                    ..
                } = &message
                    && !slots.get(profile_id).is_some_and(|slot| {
                        slot.generation == *generation
                            && slot.state == *state
                            && slot.failures == *failures
                            && slot.cleaning == *cleaning
                    })
                {
                    continue;
                }
                match output.try_send(message) {
                    Ok(()) => {}
                    Err(TrySendError::Full(message)) => {
                        outgoing.push_front(message);
                        break;
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        closing = true;
                        outgoing.clear();
                        break;
                    }
                }
            }
            // Never release the root lock just because the client pipe closed.
            if closing && slots.values().all(|slot| slot.worker.is_none()) && factory.idle() {
                return if panicked {
                    Err(ErrorCode::BackendFailure)
                } else {
                    Ok(())
                };
            }
            thread::sleep(timing.poll);
        }
    })
}

#[cfg(test)]
#[path = "engine/dispatch_tests.rs"]
mod dispatch_tests;
#[cfg(test)]
mod metadata_tests;
#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
