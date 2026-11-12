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
        attempt.start(&signals.canceled)?;
        let deadline = Instant::now() + timing.connect;
        loop {
            if canceled() {
                return Ok(());
            }
            if attempt.ready()? {
                break;
            }
            if Instant::now() >= deadline {
                return Err(Failure {
                    state: ConnectionState::GatewayTimeout,
                    error: ErrorCode::BackendFailure,
                });
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
