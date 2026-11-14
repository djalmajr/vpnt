//! One authenticated administrative transaction. It never shares the runtime
//! channel and never kills a helper to make an incomplete operation look done.
mod worker;
use super::{
    paths,
    protocol::{AdminRequest, ErrorCode},
    runtime::Runtime,
};
use crate::localization::Locale;
use std::{
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
pub(crate) use worker::monotonic_ns;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Untrusted,
    Unavailable,
    Incompatible,
    InvalidReply,
    Expired,
    Canceled,
    Rejected(ErrorCode),
}
struct State {
    result: Mutex<Option<Result<(), Error>>>,
    finished: AtomicBool,
    stop: AtomicBool,
}
pub struct Admin {
    state: Arc<State>,
    reported: bool,
}
impl Admin {
    pub fn start(request: AdminRequest, locale: Locale, expires: Instant) -> Result<Self, Error> {
        Runtime::verify_helper()
            .and_then(|_| Runtime::verify_askpass())
            .map_err(|_| Error::Untrusted)?;
        Self::spawn(command(), request, locale, expires)
    }
    fn spawn(
        command: Command,
        request: AdminRequest,
        locale: Locale,
        expires: Instant,
    ) -> Result<Self, Error> {
        if !std::path::Path::new(command.get_program()).is_absolute() {
            return Err(Error::Untrusted);
        }
        if Instant::now() >= expires {
            return Err(Error::Expired);
        }
        let state = Arc::new(State {
            result: Mutex::new(None),
            finished: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });
        let task = state.clone();
        std::thread::Builder::new()
            .name("vpnt-admin-client".into())
            .spawn(move || worker::run(command, request, locale, expires, task))
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            state,
            reported: false,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture(
        command: Command,
        request: AdminRequest,
        locale: Locale,
        expires: Instant,
    ) -> Result<Self, Error> {
        Self::spawn(command, request, locale, expires)
    }
    pub fn poll(&mut self) -> Option<Result<(), Error>> {
        if self.reported {
            return None;
        }
        let result = self.state.result.lock().ok()?.take();
        if result.is_some() {
            self.reported = true;
        }
        result
    }
    pub fn finished(&self) -> bool {
        self.state.finished.load(Ordering::Acquire)
    }
    pub fn close(&mut self) {
        self.state.stop.store(true, Ordering::Release);
    }
}
impl Drop for Admin {
    fn drop(&mut self) {
        self.close();
    }
}
fn command() -> Command {
    let mut command = Command::new("/usr/bin/sudo");
    command.args(["-A", "-k", "--", paths::HELPER, "admin"]);
    command
}
#[cfg(test)]
mod tests;
