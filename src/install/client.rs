//! One component operation, admitted before an explicit controller handoff.
mod plan;
mod removal;
mod worker;
use crate::localization::Locale;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Install,
    Remove,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Receipt {
    Installed { helper_sha256: String },
    Removed { component_present: bool },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Untrusted,
    Unavailable,
    Incompatible,
    InvalidReply,
    Expired,
    Canceled,
    Rejected(super::Error),
}
struct State {
    prepared: AtomicBool,
    proceed: AtomicBool,
    stop: AtomicBool,
    finished: AtomicBool,
    published: AtomicBool,
    result: Mutex<Option<Result<Receipt, Error>>>,
}
pub struct Operation {
    state: Arc<State>,
}
impl Operation {
    pub fn start(kind: Kind, id: String, locale: Locale, expires: Instant) -> Result<Self, Error> {
        if unsafe { libc::getuid() == 0 || libc::getuid() != libc::geteuid() } {
            return Err(Error::Untrusted);
        }
        Self::spawn(kind, id, locale, expires, move || plan::Plan::admit(kind))
    }
    fn spawn(
        kind: Kind,
        id: String,
        locale: Locale,
        expires: Instant,
        prepare: impl FnOnce() -> Result<plan::Plan, Error> + Send + 'static,
    ) -> Result<Self, Error> {
        if id.is_empty()
            || id.len() > 64
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Error::InvalidReply);
        }
        let remaining = expires.saturating_duration_since(Instant::now());
        if remaining.is_zero() || remaining > Duration::from_secs(120) {
            return Err(Error::Expired);
        }
        let state = Arc::new(State {
            prepared: AtomicBool::new(false),
            proceed: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            published: AtomicBool::new(false),
            result: Mutex::new(None),
        });
        let task = state.clone();
        std::thread::Builder::new()
            .name("vpnt-component".into())
            .spawn(move || worker::run(kind, id, locale, expires, prepare, task))
            .map_err(|_| Error::Unavailable)?;
        Ok(Self { state })
    }
    pub fn prepared(&self) -> bool {
        self.state.prepared.load(Ordering::Acquire)
    }
    pub fn proceed(&self) {
        self.state.proceed.store(true, Ordering::Release);
    }
    pub fn poll(&mut self) -> Option<Result<Receipt, Error>> {
        self.state.result.lock().ok()?.take()
    }
    pub fn finished(&self) -> bool {
        self.state.finished.load(Ordering::Acquire)
    }
    pub fn close(&mut self) {
        self.state.stop.store(true, Ordering::Release);
    }
    #[cfg(test)]
    pub(crate) fn fixture(
        kind: Kind,
        command: std::process::Command,
        id: String,
        locale: Locale,
        expires: Instant,
    ) -> Result<Self, Error> {
        Self::spawn(kind, id, locale, expires, move || {
            Ok(plan::Plan::fixture(command))
        })
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        self.close();
    }
}
fn check(state: &State, expires: Instant) -> Result<(), Error> {
    if state.stop.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    if Instant::now() >= expires {
        return Err(Error::Expired);
    }
    Ok(())
}
fn publish(state: &State, result: Result<Receipt, Error>) {
    if !state.published.swap(true, Ordering::AcqRel)
        && let Ok(mut slot) = state.result.lock()
    {
        *slot = Some(result);
    }
}
#[cfg(test)]
pub(crate) mod tests;
