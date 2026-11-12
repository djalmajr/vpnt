//! Unprivileged owner of one helper invocation. Closing the channel requests
//! cleanup; this layer never signals or kills the helper while it cleans up.
mod worker;
use super::{
    paths,
    protocol::{Message, Request},
    runtime::{Runtime, RuntimeError},
};
use std::{
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Missing,
    Untrusted,
    Unavailable,
    Incompatible,
    Busy,
}
struct State {
    fault: Mutex<Option<Error>>,
    finished: AtomicBool,
}
pub struct Client {
    requests: Option<SyncSender<Request>>,
    output: Receiver<Message>,
    stop: Arc<AtomicBool>,
    state: Arc<State>,
    failed: bool,
}
impl Client {
    pub fn runtime() -> Result<Self, Error> {
        Runtime::verify_helper().map_err(|e| {
            if e == RuntimeError::Missing {
                Error::Missing
            } else {
                Error::Untrusted
            }
        })?;
        let mut command = Command::new("/usr/bin/sudo");
        command.args(["-n", "--", paths::HELPER, "runtime"]);
        Self::spawn(command)
    }
    #[cfg(test)]
    pub(crate) fn fixture(command: Command) -> Result<Self, Error> {
        Self::spawn(command)
    }
    fn spawn(command: Command) -> Result<Self, Error> {
        if !std::path::Path::new(command.get_program()).is_absolute() {
            return Err(Error::Untrusted);
        }
        let (requests, input) = mpsc::sync_channel(32);
        let (output, receive) = mpsc::sync_channel(64);
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(State {
            fault: Mutex::new(None),
            finished: AtomicBool::new(false),
        });
        let worker_stop = stop.clone();
        let worker_state = state.clone();
        std::thread::Builder::new()
            .name("vpnt-helper-client".into())
            .spawn(move || {
                worker::run(command, input, output, worker_stop, worker_state);
            })
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            requests: Some(requests),
            output: receive,
            stop,
            state,
            failed: false,
        })
    }
    pub fn send(&self, request: Request) -> Result<(), Error> {
        if self.failed || self.stop.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        self.requests
            .as_ref()
            .ok_or(Error::Unavailable)?
            .try_send(request)
            .map_err(|e| match e {
                mpsc::TrySendError::Full(_) => Error::Busy,
                _ => Error::Unavailable,
            })
    }
    pub fn poll(&mut self) -> Result<Vec<Message>, Error> {
        if self.failed {
            return Ok(vec![]);
        }
        if let Some(error) = self
            .state
            .fault
            .lock()
            .map_err(|_| Error::Unavailable)?
            .take()
        {
            self.failed = true;
            while self.output.try_recv().is_ok() {}
            return Err(error);
        }
        Ok(self.output.try_iter().take(64).collect())
    }
    pub fn finished(&self) -> bool {
        self.state.finished.load(Ordering::Acquire)
    }
    pub fn close(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.requests = None;
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
pub(crate) mod tests;
