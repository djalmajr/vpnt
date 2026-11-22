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
/// Latest coalesced worker status. `failures` counts consecutive failed traffic
/// probes, including a cadence spent unable to start one on Linux. Replacing
/// an older status in the slot never loses the third failure.
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
        let mut previous_phase = None;
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
            let phase = attempt.phase();
            if phase != previous_phase
                && let Some(state) = phase
            {
                send(state, 0, false, None);
            }
            previous_phase = phase;
            thread::sleep(timing.poll);
        }
        if canceled() {
            return Ok(());
        }
        send(ConnectionState::Verifying, 0, false, None);
        let mut last_probe: Option<Instant> = None;
        let mut last_health: Option<Instant> = None;
        let mut failures = 0_u32;
        let mut traffic_verified = false;
        #[cfg(not(target_os = "linux"))]
        let mut announced_phase = None;
        // A restart seen between or during probes owes the tunnel a fresh one.
        #[cfg(not(target_os = "linux"))]
        let mut retry_probe = false;
        #[cfg(target_os = "linux")]
        let mut recovery = None;
        #[cfg(target_os = "linux")]
        let mut retry_probe = false;
        #[cfg(target_os = "linux")]
        let mut busy_since = None;
        let mut seen_epoch = attempt.restart_epoch();
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
            {
                // A periodic health check can drain a whole restart between
                // probes. Failures from before it say nothing about the
                // recovered tunnel, so the streak restarts with a fresh probe.
                let epoch = attempt.restart_epoch();
                if epoch != seen_epoch {
                    seen_epoch = epoch;
                    // Attempts that never restart keep epoch 0 and never
                    // reach this branch; an OVPN attempt does on both systems.
                    failures = 0;
                    traffic_verified = false;
                    // The busy deferral exists only on Linux.
                    #[cfg(target_os = "linux")]
                    {
                        busy_since = None;
                        retry_probe = true;
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        retry_probe = true;
                    }
                }
            }
            // The due time is always derived from the last actual probe plus the
            // current cadence, never from a repeatedly rebased `now`. A special
            // command probe is an actual traffic probe and counts like a timer
            // probe; health checks and snapshot polls never do.
            let due = last_probe.is_none_or(|last| Instant::now() >= last + interval.get());
            let requested = signals.probe.swap(false, Ordering::AcqRel);
            #[cfg(target_os = "linux")]
            let phase = attempt.phase();
            #[cfg(target_os = "linux")]
            let due = phase.is_none()
                && (due || requested || recovery.is_some() || retry_probe || busy_since.is_some());
            #[cfg(not(target_os = "linux"))]
            let phase = attempt.phase();
            // Leaving a phase probes at once, so the card does not keep the
            // phase until the next cadence and a request made during it is
            // answered by that probe.
            #[cfg(not(target_os = "linux"))]
            let due =
                phase.is_none() && (requested || due || announced_phase.is_some() || retry_probe);
            let restart_epoch = due.then(|| attempt.restart_epoch());
            let responsive = if due {
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
                #[cfg(target_os = "linux")]
                let responsive = (responsive, Instant::now(), attempt.probe_busy());
                #[cfg(not(target_os = "linux"))]
                let responsive = (responsive, Instant::now());
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
                Some(responsive)
            } else {
                None
            };
            #[cfg(target_os = "linux")]
            let responsive = {
                // The same health check can observe both the start and the end
                // of a restart. Invalidate that probe even if no phase remains.
                retry_probe = restart_epoch.is_some_and(|epoch| epoch != attempt.restart_epoch());
                seen_epoch = attempt.restart_epoch();
                let phase = if responsive.is_some() {
                    attempt.phase()
                } else {
                    phase
                };
                if retry_probe || phase.is_some() {
                    failures = 0;
                    traffic_verified = false;
                    busy_since = None;
                }
                if let Some(state) = phase
                    && recovery != phase
                {
                    send(state, 0, false, None);
                }
                recovery = phase;
                if retry_probe || recovery.is_some() {
                    thread::sleep(timing.poll);
                    continue;
                }
                responsive.and_then(|(responsive, at, busy)| {
                    if busy {
                        // Keep polling without consuming the request or the
                        // sample timestamp. A stuck job costs one failure per
                        // cadence while we continue trying to start a probe.
                        let since = busy_since.get_or_insert(at);
                        if at.duration_since(*since) < interval.get() {
                            return None;
                        }
                        *since = at;
                        return Some(false);
                    }
                    busy_since = None;
                    last_probe = Some(at);
                    Some(responsive)
                })
            };
            #[cfg(not(target_os = "linux"))]
            let responsive = {
                // Revalidation can observe an entire restart during the probe.
                // The next pass sees the new epoch and asks for another probe.
                let restarted = restart_epoch.is_some_and(|epoch| epoch != attempt.restart_epoch());
                if restart_epoch.is_some() {
                    retry_probe = false;
                }
                let phase = if responsive.is_some() {
                    attempt.phase()
                } else {
                    phase
                };
                if let Some(state) = phase {
                    failures = 0;
                    traffic_verified = false;
                    if announced_phase != phase {
                        send(state, 0, false, None);
                    }
                }
                announced_phase = phase;
                if restarted || phase.is_some() {
                    thread::sleep(timing.poll);
                    continue;
                }
                responsive.map(|(responsive, at)| {
                    last_probe = Some(at);
                    responsive
                })
            };
            if let Some(responsive) = responsive {
                if responsive {
                    traffic_verified = true;
                    failures = 0;
                } else {
                    failures = (failures + 1).min(3);
                }
                // Only a verified tunnel can tolerate one failed health probe.
                // Count it locally because Connected carries zero on the wire.
                let (state, reported_failures) =
                    if responsive || (traffic_verified && failures == 1) {
                        (ConnectionState::Connected, 0)
                    } else {
                        (ConnectionState::Unresponsive, failures)
                    };
                send(state, reported_failures, false, None);
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
