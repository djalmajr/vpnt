//! Cooperative budget for the bound producer path.
//!
//! Lock waits are cooperative and must observe the caller's deadline and
//! cancellation. Synchronous filesystem/SDK calls (`getentropy`, `create`,
//! `write`, `fsync`, `stat`, route lookups inside the egress) cannot be
//! interrupted: the budget bounds the waits and the check points around them,
//! not a syscall already in flight.
use crate::connection::ipsec::Error;
use std::{
    sync::{
        Arc, Mutex, MutexGuard, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const YIELD: Duration = Duration::from_millis(2);

pub(in crate::connection::ipsec::producer) struct Budget {
    expires: Instant,
    cancel: Arc<AtomicBool>,
}

impl Budget {
    pub(in crate::connection::ipsec::producer) fn new(
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Self {
        Self { expires, cancel }
    }

    pub(in crate::connection::ipsec::producer) fn check(&self) -> Result<(), Error> {
        check_until(self.expires, &self.cancel)
    }

    pub(in crate::connection::ipsec::producer) fn lock<'a, T>(
        &self,
        mutex: &'a Mutex<T>,
    ) -> Result<MutexGuard<'a, T>, Error> {
        lock_until(self.expires, &self.cancel, mutex)
    }
}

/// Same core as [`Budget::check`], for callers that only borrow the caller's
/// deadline/cancel (open/observe/take paths) and do not own an `Arc`.
pub(in crate::connection::ipsec::producer) fn check_until(
    expires: Instant,
    cancel: &AtomicBool,
) -> Result<(), Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    if Instant::now() >= expires {
        return Err(Error::Timeout);
    }
    Ok(())
}

/// Same core as [`Budget::lock`], borrowed for the current open/observe/take
/// budget. Never waits for its own lock and always rechecks after a yield.
pub(in crate::connection::ipsec::producer) fn lock_until<'a, T>(
    expires: Instant,
    cancel: &AtomicBool,
    mutex: &'a Mutex<T>,
) -> Result<MutexGuard<'a, T>, Error> {
    loop {
        check_until(expires, cancel)?;
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err(Error::Unavailable),
            Err(TryLockError::WouldBlock) => thread::sleep(YIELD),
        }
    }
}

/// `None` is the legacy cfg(test) wrapper: it keeps the original blocking
/// behavior. Every production entry passes `Some`.
pub(in crate::connection::ipsec::producer) fn check(budget: Option<&Budget>) -> Result<(), Error> {
    match budget {
        Some(budget) => budget.check(),
        None => Ok(()),
    }
}

pub(in crate::connection::ipsec::producer) fn lock<'a, T>(
    budget: Option<&Budget>,
    mutex: &'a Mutex<T>,
) -> Result<MutexGuard<'a, T>, Error> {
    match budget {
        Some(budget) => budget.lock(mutex),
        None => mutex.lock().map_err(|_| Error::Unavailable),
    }
}
