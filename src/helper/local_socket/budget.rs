use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(crate) struct Budget {
    expires: Instant,
    cancel: Option<Arc<AtomicBool>>,
}

impl Budget {
    pub(crate) fn new(timeout: Duration) -> io::Result<Self> {
        let expires = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        Self::until(expires, None)
    }

    pub(crate) fn until(expires: Instant, cancel: Option<Arc<AtomicBool>>) -> io::Result<Self> {
        let budget = Self { expires, cancel };
        budget.check()?;
        Ok(budget)
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        if self
            .cancel
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, Canceled));
        }
        if Instant::now() >= self.expires {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        Ok(())
    }

    pub(crate) fn poll_timeout(&self) -> io::Result<i32> {
        self.check()?;
        let remaining = self.expires.saturating_duration_since(Instant::now());
        let milliseconds = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128);
        // Cancellation has no kernel FD; bound the next observation without
        // shortening the absolute deadline or busy-polling an idle peer.
        Ok(if self.cancel.is_some() {
            milliseconds.min(25)
        } else {
            milliseconds
        } as i32)
    }
}

#[derive(Debug)]
pub(crate) struct Canceled;
impl fmt::Display for Canceled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operation canceled")
    }
}
impl std::error::Error for Canceled {}
