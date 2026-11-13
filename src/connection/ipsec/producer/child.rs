use super::*;
use crate::{
    connection::macos::utun_observer::{self, InterfaceObservation},
    helper::{process::ManagedChild, runtime::Program},
};
use std::{fs, process::Command, sync::atomic::Ordering, time::Duration};
pub(super) struct Producer<'a> {
    context: Arc<NativeContext<'a>>,
    pub lease: state::Lease,
    child: Option<ManagedChild>,
    identity: Option<Identity>,
    attempted: bool,
    retired: bool,
    pub released: bool,
    failure: Option<Error>,
    socket: Option<files::Stamp>,
}
impl<'a> Producer<'a> {
    pub fn new(context: Arc<NativeContext<'a>>, lease: state::Lease) -> Self {
        Self {
            context,
            lease,
            child: None,
            identity: None,
            attempted: false,
            retired: false,
            released: false,
            failure: None,
            socket: None,
        }
    }
    fn call(expires: Instant, cancel: &AtomicBool) -> Result<(), Error> {
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        if Instant::now() >= expires {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    fn spawn(&mut self, expires: Instant, cancel: &AtomicBool) -> Result<(), Error> {
        self.attempted = true;
        self.context.validate()?;
        self.lease.validate()?;
        for name in ["v", "pid"] {
            match fs::symlink_metadata(self.lease.directory.path.join(name)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(Error::Changed),
            }
        }
        self.lease.stage(record::Stage::Starting, None)?;
        Self::call(expires, cancel)?;
        let mut command = Command::new(self.context.runtime.program(Program::Charon));
        for group in [
            "dmn", "mgr", "ike", "chd", "job", "cfg", "knl", "net", "asn", "enc", "tnc", "imc",
            "imv", "pts", "tls", "esp", "lib",
        ] {
            command.arg(format!("--debug-{group}")).arg("-1");
        }
        self.child = Some(
            ManagedChild::spawn_charon(
                &mut command,
                &self.lease.directory.path.join(state::CONFIG),
            )
            .map_err(|_| Error::Unavailable)?,
        );
        let child = self.child.as_mut().unwrap();
        if child.poll().map_err(|_| Error::Unavailable)?.is_some() {
            return Err(Error::Unavailable);
        }
        let process = Process::read(child.id()).map_err(|_| Error::Unavailable)?;
        if !process.running
            || process.parent != self.context.identity.pid
            || process.uid != self.context.runtime.owner()
            || process.real_uid != self.context.runtime.owner()
            || process.executable != self.context.runtime.program(Program::Charon)
        {
            return Err(Error::Changed);
        }
        self.identity = Some(process.identity.clone());
        self.lease
            .stage(record::Stage::Running, Some((&process.identity).into()))?;
        Ok(())
    }
    fn current(&mut self) -> Result<(), Error> {
        self.context.validate()?;
        self.lease.validate()?;
        let child = self.child.as_mut().ok_or(Error::Unavailable)?;
        if child.poll().map_err(|_| Error::Unavailable)?.is_some() {
            return Err(Error::Unavailable);
        }
        let process = Process::read(child.id()).map_err(|_| Error::Unavailable)?;
        if Some(&process.identity) != self.identity.as_ref()
            || !process.running
            || process.parent != self.context.identity.pid
            || process.uid != self.context.runtime.owner()
            || process.real_uid != self.context.runtime.owner()
            || process.executable != self.context.runtime.program(Program::Charon)
        {
            return Err(Error::Changed);
        }
        Ok(())
    }
    /// Observe the original child's utun control socket. Read-only and bounded:
    /// this never spawns, reopens or reaps another producer.
    pub(super) fn observe_interface(
        &mut self,
        owner: &Owner,
        expires: Instant,
        cancel: &AtomicBool,
    ) -> Result<InterfaceObservation, Error> {
        if self.lease.record.owner() != *owner || self.retired || self.released || !self.attempted {
            return Err(Error::Changed);
        }
        self.current()?;
        let identity = self.identity.as_ref().ok_or(Error::Changed)?.clone();
        let executable = self.context.runtime.program(Program::Charon);
        let expected = utun_observer::Expected {
            identity,
            parent: self.context.identity.pid,
            uid: self.context.runtime.owner(),
            executable: &executable,
        };
        let child = self.child.as_mut().ok_or(Error::Changed)?;
        utun_observer::observe(self.context.controller, child, &expected, expires, cancel)
            .map_err(map_observe)
    }
    pub fn open(
        &mut self,
        owner: &Owner,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<Client, Error> {
        if self.lease.record.owner() != *owner || self.retired || self.released {
            return Err(Error::Changed);
        }
        Self::call(expires, &cancel)?;
        if let Some(e) = self.failure {
            return Err(e);
        }
        if !self.attempted
            && let Err(e) = self.spawn(expires, &cancel)
        {
            self.failure = Some(e);
            return Err(e);
        }
        loop {
            Self::call(expires, &cancel)?;
            self.current()?;
            let path = self.lease.directory.path.join("v");
            match socket::stamp(&path, self.context.runtime.owner()) {
                Err(Error::Unavailable) => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => return Err(e),
                Ok(stamp) => {
                    if self.socket.is_some_and(|previous| previous != stamp) {
                        return Err(Error::Changed);
                    }
                    let client = socket::connect(
                        &path,
                        self.context.runtime.owner(),
                        self.identity.as_ref().unwrap().pid,
                        expires,
                        cancel.clone(),
                    )?;
                    if socket::stamp(&path, self.context.runtime.owner())? != stamp {
                        return Err(Error::Changed);
                    }
                    self.current()?;
                    Self::call(expires, &cancel)?;
                    self.socket = Some(stamp);
                    return Ok(client);
                }
            }
        }
    }
    pub fn stopped(&self) -> bool {
        self.retired && self.lease.record.stage == record::Stage::Stopped
    }
    #[cfg(test)]
    pub(super) fn child_exited(&mut self) -> bool {
        self.child
            .as_mut()
            .is_none_or(|c| c.poll().unwrap().is_some())
    }
    #[cfg(test)]
    pub(super) fn status(&mut self) -> Option<std::process::ExitStatus> {
        self.child.as_mut().and_then(|c| c.poll().unwrap())
    }
    pub fn retire(&mut self) -> Result<bool, Error> {
        if self.released {
            return Ok(true);
        }
        self.retired = true;
        // Stop only our unreaped Child, even when runtime/config admission changed.
        if let Some(child) = self.child.as_mut() {
            child
                .stop(Duration::from_secs(3))
                .map_err(|_| Error::Unavailable)?;
        }
        self.context.validate()?;
        if self.lease.record.stage != record::Stage::Stopped {
            self.lease.stage(
                record::Stage::Stopped,
                self.identity.as_ref().map(Into::into),
            )?;
        }
        Ok(true)
    }
}
impl Drop for Producer<'_> {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}

pub(super) fn observe_active<'a>(
    context: &NativeContext<'a>,
    owner: &Owner,
    expires: Instant,
    cancel: &AtomicBool,
) -> Result<InterfaceObservation, Error> {
    loop {
        utun_observer::check(expires, cancel).map_err(map_check)?;
        let live: Vec<SharedProducer<'a>> = context
            .active
            .lock()
            .map_err(|_| Error::Unavailable)?
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        let mut matching: Option<SharedProducer<'a>> = None;
        let mut busy = false;
        for producer in live {
            let matches = match producer.try_lock() {
                Ok(guard) => {
                    let matches = guard.lease.record.owner() == *owner;
                    drop(guard);
                    matches
                }
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::Unavailable),
                Err(std::sync::TryLockError::WouldBlock) => {
                    busy = true;
                    false
                }
            };
            if matches {
                if matching.is_some() {
                    return Err(Error::Changed);
                }
                matching = Some(producer);
            }
        }
        if busy {
            utun_observer::check(expires, cancel).map_err(map_check)?;
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }
        let Some(producer) = matching else {
            return Err(Error::Unavailable);
        };
        loop {
            utun_observer::check(expires, cancel).map_err(map_check)?;
            match producer.try_lock() {
                Ok(mut producer) => return producer.observe_interface(owner, expires, cancel),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::Unavailable),
                Err(std::sync::TryLockError::WouldBlock) => {
                    utun_observer::check(expires, cancel).map_err(map_check)?;
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }
}

fn map_check(error: utun_observer::Error) -> Error {
    match error {
        utun_observer::Error::Canceled => Error::Canceled,
        utun_observer::Error::Timeout => Error::Timeout,
        _ => Error::Unavailable,
    }
}

fn map_observe(error: utun_observer::Error) -> Error {
    match error {
        utun_observer::Error::NotFound => Error::Unavailable,
        utun_observer::Error::Ambiguous | utun_observer::Error::Changed => Error::Changed,
        utun_observer::Error::Canceled => Error::Canceled,
        utun_observer::Error::Timeout => Error::Timeout,
        utun_observer::Error::Unavailable => Error::Unavailable,
        utun_observer::Error::Exhausted => Error::Exhausted,
        utun_observer::Error::Permission => Error::PermissionDenied,
        utun_observer::Error::Invalid => Error::Invalid,
    }
}
