use super::*;
use crate::helper::protocol::FailureNote;
use std::{
    sync::{Condvar, Mutex, atomic::Ordering},
    thread,
    time::Instant,
};

const CLEANUP_MAX_POLL: Duration = Duration::from_secs(1);
const CLEANUP_SLOW_AFTER: Duration = Duration::from_secs(30);
const CLEANUP_SLOW_MAX_POLL: Duration = Duration::from_secs(5);
pub(super) const CLEANUP_BUDGET: Duration = Duration::from_secs(20);

pub(super) struct ExitRequested {
    at: Mutex<Option<Instant>>,
    wake: Condvar,
    budget: Duration,
}
impl ExitRequested {
    pub fn new(budget: Duration) -> Self {
        Self {
            at: Mutex::new(None),
            wake: Condvar::new(),
            budget,
        }
    }
    pub fn request(&self) {
        let mut at = self.at.lock().unwrap_or_else(|error| error.into_inner());
        if at.is_none() {
            *at = Some(Instant::now());
            self.wake.notify_all();
        }
    }
    /// Monotonic instant of the first request, if any.
    pub(super) fn at(&self) -> Option<Instant> {
        *self.at.lock().unwrap_or_else(|error| error.into_inner())
    }
    pub(super) fn budget(&self) -> Duration {
        self.budget
    }
    fn wait(&self, delay: Duration, seen: Option<Instant>) {
        let at = self.at.lock().unwrap_or_else(|error| error.into_inner());
        if *at == seen {
            let _ = self.wake.wait_timeout(at, delay);
        }
    }
}

fn cleanup_delay(previous: Duration, elapsed: Duration) -> Duration {
    let cap = if elapsed >= CLEANUP_SLOW_AFTER {
        CLEANUP_SLOW_MAX_POLL
    } else {
        CLEANUP_MAX_POLL
    };
    previous.saturating_mul(2).min(cap)
}

pub(super) struct Finished {
    pub state: ConnectionState,
    pub error: Option<ErrorCode>,
    /// Where the attempt failed; `Some` exactly when `error` is.
    pub step: Option<Step>,
}
/// Latest coalesced worker status. `failures` counts consecutive actual failed
/// traffic probes, so replacing an older status in the slot never loses the
/// third failure: the engine only ever sees the newest `Progress`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Progress {
    pub state: ConnectionState,
    pub failures: u32,
    pub cleaning: bool,
    /// Carried from the first failed status on, so the transition has it.
    pub failure: Option<FailureNote>,
}
pub(super) struct Signals {
    pub canceled: Arc<AtomicBool>,
    pub probe: Arc<AtomicBool>,
    pub state: Arc<Mutex<Option<Progress>>>,
    pub exit: Arc<ExitRequested>,
}
/// The connection deadline passed: keep the step of the failure it replaces,
/// or `Tunnel` while the attempt was still waiting to become ready.
fn timeout(replaced: Option<&Failure>) -> Failure {
    Failure {
        state: ConnectionState::GatewayTimeout,
        error: ErrorCode::BackendFailure,
        step: replaced.map_or(Step::Tunnel, |failure| failure.step),
    }
}
pub(super) fn run(
    mut attempt: impl Attempt,
    signals: Signals,
    timing: Timing,
    interval: ProbeClock,
) -> Finished {
    let send = |state, failures, cleaning, failure| {
        // One coalesced status per worker. A slow pipe reader never blocks
        // traffic/cleanup or loses the latest state to a full progress queue.
        *signals
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Progress {
            state,
            failures,
            cleaning,
            failure,
        });
    };
    let canceled = || signals.canceled.load(Ordering::Acquire);
    let result = (|| {
        if canceled() {
            return Ok(());
        }
        // One connection deadline covers start and readiness; it is never
        // rebased after start or a ready poll. Traffic probes use their own budget.
        let expires = Instant::now() + timing.connect;
        let start = attempt.start(&signals.canceled, expires);
        if canceled() {
            return Ok(());
        }
        if Instant::now() >= expires {
            return Err(timeout(start.as_ref().err()));
        }
        start?;
        loop {
            if canceled() {
                return Ok(());
            }
            if Instant::now() >= expires {
                return Err(timeout(None));
            }
            let ready = attempt.ready();
            if canceled() {
                return Ok(());
            }
            if Instant::now() >= expires {
                return Err(timeout(ready.as_ref().err()));
            }
            if ready? {
                break;
            }
            thread::sleep(timing.poll);
        }
        if canceled() {
            return Ok(());
        }
        send(ConnectionState::Verifying, 0, false, None);
        let mut last_probe: Option<Instant> = None;
        let mut last_health: Option<Instant> = None;
        let mut failures = 0_u32;
        loop {
            if canceled() {
                return Ok(());
            }
            // Keep command/cancel polling responsive without revalidating the
            // native link and route leases on every poll. The first is immediate.
            if last_health.is_none_or(|last| last.elapsed() >= timing.health) {
                attempt.healthy()?;
                last_health = Some(Instant::now());
            }
            if canceled() {
                return Ok(());
            }
            // The due time is always derived from the last actual probe plus the
            // current cadence, never from a repeatedly rebased `now`. A special
            // command probe is an actual traffic probe and counts like a timer
            // probe; health checks and snapshot polls never do.
            let due = last_probe.is_none_or(|last| Instant::now() >= last + interval.get());
            if signals.probe.swap(false, Ordering::AcqRel) || due {
                // The first traffic probe verifies the new tunnel; a later
                // one checks a connection that was already verified.
                let initial = last_probe.is_none();
                let responsive =
                    attempt
                        .probe(&signals.canceled, timing.probe)
                        .map_err(|failure| Failure {
                            step: if initial { Step::Verify } else { failure.step },
                            ..failure
                        })?;
                last_probe = Some(Instant::now());
                if canceled() {
                    return Ok(());
                }
                // Revalidate leases and the owned link after the asynchronous
                // traffic test. A successful, now-stale probe proves nothing.
                attempt.healthy()?;
                last_health = Some(Instant::now());
                if canceled() {
                    return Ok(());
                }
                failures = if responsive { 0 } else { (failures + 1).min(3) };
                send(
                    if responsive {
                        ConnectionState::Connected
                    } else {
                        ConnectionState::Unresponsive
                    },
                    failures,
                    false,
                    None,
                );
            }
            thread::sleep(timing.poll);
        }
    })();
    let cleanup_state = match &result {
        Ok(()) => ConnectionState::Disconnecting,
        Err(failure) => failure.state,
    };
    let note = result.as_ref().err().map(|failure| FailureNote {
        code: failure.error,
        step: failure.step,
    });
    send(cleanup_state, 0, result.is_err(), note);
    // Cancel all outstanding network operations before releasing resources.
    signals.canceled.store(true, Ordering::Release);
    let cleanup_started = Instant::now();
    let mut cleanup_poll = timing.poll.min(CLEANUP_MAX_POLL);
    while !attempt.cleanup() {
        let requested = signals.exit.at();
        if let Some(requested) = requested {
            let deadline = cleanup_started.max(requested) + signals.exit.budget;
            if Instant::now() >= deadline {
                let reason = crate::helper::runtime::cleanup::current_reason()
                    .unwrap_or(Reason::UncertainCleanup);
                if attempt.abandon(reason).is_ok() {
                    break;
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let delay = if remaining.is_zero() {
                cleanup_poll
            } else {
                cleanup_poll.min(remaining)
            };
            signals.exit.wait(delay, requested.into());
        } else {
            signals.exit.wait(cleanup_poll, None);
        }
        cleanup_poll = cleanup_delay(cleanup_poll, cleanup_started.elapsed());
    }
    if result.is_err() {
        send(cleanup_state, 0, false, note);
    }
    match result {
        Ok(()) => Finished {
            state: ConnectionState::Off,
            error: None,
            step: None,
        },
        Err(failure) => Finished {
            state: failure.state,
            error: Some(failure.error),
            step: Some(failure.step),
        },
    }
}

#[cfg(test)]
#[path = "worker/tests.rs"]
mod tests;
