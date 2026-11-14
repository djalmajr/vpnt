mod dispatch;
mod metadata;
use super::{
    worker::{self, Finished, Signals},
    *,
};
#[cfg(test)]
use crate::model::VpnKind;
use crate::{
    helper::protocol::{Command, Message, Request, TunnelStatus, VERSION},
    model::valid_profile_id,
};
use dispatch::dispatch;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Mutex,
        atomic::Ordering,
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, Scope, ScopedJoinHandle},
};

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
    fn changed(&self) -> Message {
        Message::Changed {
            profile_id: self.profile.id.clone(),
            generation: self.generation,
            state: self.state,
            failures: self.failures,
        }
    }
}
fn launch<'scope, 'env: 'scope, F: Factory>(
    scope: &'scope Scope<'scope, 'env>,
    factory: &'env F,
    uid: u32,
    slot: &mut Slot<'scope>,
    timing: Timing,
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
        },
        thread,
    });
}

pub(super) fn run<F: Factory>(
    factory: F,
    uid: u32,
    profiles: Vec<Profile>,
    requests: Receiver<Request>,
    output: SyncSender<Message>,
    timing: Timing,
) -> Result<(), ErrorCode> {
    if uid == 0 {
        return Err(ErrorCode::UntrustedConfiguration);
    }
    let profiles = metadata::map(profiles)?;
    // The controller-wide preference; each slot starts from it and `Connect`
    // may set that generation's clock. `SetProbeInterval` updates the default
    // and every existing slot clock, so queued and live generations follow it.
    let interval = ProbeClock::new(timing.interval);
    thread::scope(|scope| {
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
                        interval: ProbeClock::new(interval.get()),
                        worker: None,
                        pending: None,
                    },
                )
            })
            .collect();
        let mut outgoing = VecDeque::new();
        let mut closing = false;
        let mut panicked = false;
        loop {
            // Bound work per pass so pipe floods cannot starve cleanup/probes.
            for _ in 0..64 {
                if closing {
                    break;
                }
                match requests.try_recv() {
                    Ok(request) => {
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
                            dispatch(request, &factory, &mut slots, &mut outgoing, &interval);
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        closing = true;
                        break;
                    }
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
                    outgoing.push_back(slot.changed());
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
                            }
                        }
                    };
                    if slot.pending.is_none() {
                        slot.state = if slot.generation == worker.generation {
                            finished.state
                        } else {
                            ConnectionState::Off
                        };
                        slot.failures = 0;
                        if !closing {
                            outgoing.push_back(slot.changed());
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
                    launch(scope, &factory, uid, slot, timing);
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
                } = &message
                    && !slots.get(profile_id).is_some_and(|slot| {
                        slot.generation == *generation
                            && slot.state == *state
                            && slot.failures == *failures
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
