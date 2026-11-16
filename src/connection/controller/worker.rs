use super::*;
use std::{
    sync::{Mutex, atomic::Ordering},
    thread,
    time::Instant,
};

const CLEANUP_MAX_POLL: Duration = Duration::from_secs(1);
const CLEANUP_SLOW_AFTER: Duration = Duration::from_secs(30);
const CLEANUP_SLOW_MAX_POLL: Duration = Duration::from_secs(5);

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
}
/// Latest coalesced worker status. `failures` counts consecutive actual failed
/// traffic probes, so replacing an older status in the slot never loses the
/// third failure: the engine only ever sees the newest `Progress`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Progress {
    pub state: ConnectionState,
    pub failures: u32,
    pub cleaning: bool,
}
pub(super) struct Signals {
    pub canceled: Arc<AtomicBool>,
    pub probe: Arc<AtomicBool>,
    pub state: Arc<Mutex<Option<Progress>>>,
}
fn timeout() -> Failure {
    Failure {
        state: ConnectionState::GatewayTimeout,
        error: ErrorCode::BackendFailure,
    }
}
pub(super) fn run(
    mut attempt: impl Attempt,
    signals: Signals,
    timing: Timing,
    interval: ProbeClock,
) -> Finished {
    let send = |state, failures, cleaning| {
        // One coalesced status per worker. A slow pipe reader never blocks
        // traffic/cleanup or loses the latest state to a full progress queue.
        *signals
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Progress {
            state,
            failures,
            cleaning,
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
            return Err(timeout());
        }
        start?;
        loop {
            if canceled() {
                return Ok(());
            }
            if Instant::now() >= expires {
                return Err(timeout());
            }
            let ready = attempt.ready();
            if canceled() {
                return Ok(());
            }
            if Instant::now() >= expires {
                return Err(timeout());
            }
            if ready? {
                break;
            }
            thread::sleep(timing.poll);
        }
        if canceled() {
            return Ok(());
        }
        send(ConnectionState::Verifying, 0, false);
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
                let responsive = attempt.probe(&signals.canceled, timing.probe)?;
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
                );
            }
            thread::sleep(timing.poll);
        }
    })();
    let cleanup_state = match &result {
        Ok(()) => ConnectionState::Disconnecting,
        Err(failure) => failure.state,
    };
    send(cleanup_state, 0, result.is_err());
    // Cancel all outstanding network operations before releasing resources.
    signals.canceled.store(true, Ordering::Release);
    let cleanup_started = Instant::now();
    let mut cleanup_poll = timing.poll.min(CLEANUP_MAX_POLL);
    while !attempt.cleanup() {
        thread::sleep(cleanup_poll);
        cleanup_poll = cleanup_delay(cleanup_poll, cleanup_started.elapsed());
    }
    if result.is_err() {
        send(cleanup_state, 0, false);
    }
    match result {
        Ok(()) => Finished {
            state: ConnectionState::Off,
            error: None,
        },
        Err(failure) => Finished {
            state: failure.state,
            error: Some(failure.error),
        },
    }
}

#[cfg(test)]
#[path = "worker/tests.rs"]
mod tests;
