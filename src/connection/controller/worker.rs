use super::*;
use std::{
    sync::{Mutex, atomic::Ordering},
    thread,
    time::Instant,
};

pub(super) struct Finished {
    pub state: ConnectionState,
    pub error: Option<ErrorCode>,
}
pub(super) struct Signals {
    pub canceled: Arc<AtomicBool>,
    pub probe: Arc<AtomicBool>,
    pub state: Arc<Mutex<Option<ConnectionState>>>,
}
fn timeout() -> Failure {
    Failure {
        state: ConnectionState::GatewayTimeout,
        error: ErrorCode::BackendFailure,
    }
}
pub(super) fn run(mut attempt: impl Attempt, signals: Signals, timing: Timing) -> Finished {
    let send = |state| {
        // One coalesced status per worker. A slow pipe reader never blocks
        // traffic/cleanup or loses the latest state to a full progress queue.
        *signals
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(state);
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
        send(ConnectionState::Verifying);
        let mut next_probe = Instant::now();
        loop {
            if canceled() {
                return Ok(());
            }
            attempt.healthy()?;
            if signals.probe.swap(false, Ordering::AcqRel) || Instant::now() >= next_probe {
                let responsive = attempt.probe(&signals.canceled, timing.probe)?;
                if canceled() {
                    return Ok(());
                }
                // Revalidate leases and the owned link after the asynchronous
                // traffic test. A successful, now-stale probe proves nothing.
                attempt.healthy()?;
                if canceled() {
                    return Ok(());
                }
                send(if responsive {
                    ConnectionState::Connected
                } else {
                    ConnectionState::Unresponsive
                });
                next_probe = Instant::now() + timing.interval;
            }
            thread::sleep(timing.poll);
        }
    })();
    send(ConnectionState::Disconnecting);
    // Cancel all outstanding network operations before releasing resources.
    signals.canceled.store(true, Ordering::Release);
    while !attempt.cleanup() {
        thread::sleep(timing.poll);
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
