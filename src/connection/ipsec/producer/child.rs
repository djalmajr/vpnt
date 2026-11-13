use super::bound::{map_budget, map_check, map_handoff, map_observe};
use super::*;
use crate::{
    connection::macos::utun_observer::{self, InterfaceObservation},
    helper::{charon_channel, local_socket::Budget, process::ManagedChild, runtime::Program},
};
use std::{fs, process::Command, sync::atomic::Ordering, time::Duration};

pub(super) mod interface;
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
    binding: Option<bound::Binding>,
    /// Unadmitted descriptor from the child's single handoff. Private: it
    /// carries no type, route or cleanup authority until it is admitted.
    descriptor: Option<charon_channel::Descriptor>,
    /// Test-only pause immediately before the Starting stage write.
    #[cfg(test)]
    stage_pause: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}
impl<'a> Producer<'a> {
    pub fn new(
        context: Arc<NativeContext<'a>>,
        lease: state::Lease,
        binding: Option<bound::Binding>,
    ) -> Self {
        Self {
            context,
            lease,
            binding,
            child: None,
            identity: None,
            attempted: false,
            retired: false,
            released: false,
            failure: None,
            socket: None,
            descriptor: None,
            #[cfg(test)]
            stage_pause: None,
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
    fn spawn(&mut self, expires: Instant, cancel: &Arc<AtomicBool>) -> Result<(), Error> {
        if let Some(binding) = self.binding.as_ref() {
            binding.validate(expires, cancel)?;
        }
        // Bounded, read-only revalidation before the attempt is marked: a
        // caller deadline/cancel while the lease io is held leaves the attempt
        // open and retryable. Once `attempted` is set, failures latch.
        self.lease.validate_bounded(expires, cancel)?;
        self.attempted = true;
        self.context.validate()?;
        for name in ["v", "pid"] {
            match fs::symlink_metadata(self.lease.directory.path.join(name)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(Error::Changed),
            }
        }
        #[cfg(test)]
        if let Some((ready, release)) = self.stage_pause.take() {
            let _ = ready.send(());
            let _ = release.recv_timeout(Duration::from_secs(2));
        }
        self.lease
            .stage_bounded(record::Stage::Starting, None, expires, cancel)?;
        Self::call(expires, cancel)?;
        let mut command = Command::new(self.context.runtime.program(Program::Charon));
        for group in [
            "dmn", "mgr", "ike", "chd", "job", "cfg", "knl", "net", "asn", "enc", "tnc", "imc",
            "imv", "pts", "tls", "esp", "lib",
        ] {
            command.arg(format!("--debug-{group}")).arg("-1");
        }
        let configuration = self.lease.directory.path.join(state::CONFIG);
        let (child, receiver) =
            charon_channel::spawn(command, &configuration).map_err(|_| Error::Unavailable)?;
        // The exact original handle is stored before anything else can fail, so
        // every later error keeps its own RAII cleanup.
        self.child = Some(child);
        let child = self.child.as_mut().expect("stored above");
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
        self.lease.stage_bounded(
            record::Stage::Running,
            Some((&process.identity).into()),
            expires,
            cancel,
        )?;
        // The durable birth is recorded before the handoff, so a canceled or
        // failed reception still leaves the exact original child owned and
        // reapable; the attempt itself is terminal either way.
        let mut receiver = receiver;
        let budget = Budget::until(expires, Some(cancel.clone())).map_err(map_budget)?;
        let child = self.child.as_mut().expect("stored above");
        let descriptor = receiver.receive(child, &budget).map_err(map_handoff)?;
        self.descriptor = Some(descriptor);
        Ok(())
    }
    fn current(&mut self, expires: Instant, cancel: &AtomicBool) -> Result<(), Error> {
        self.context.validate()?;
        self.lease.validate_bounded(expires, cancel)?;
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
        self.current(expires, cancel)?;
        self.observe_child(expires, cancel)
    }
    fn observe_child(
        &mut self,
        expires: Instant,
        cancel: &AtomicBool,
    ) -> Result<InterfaceObservation, Error> {
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
            // A pre-attempt binding/cancel/timeout error leaves the attempt
            // open. Once `attempted` is set (starting/handoff included), the
            // receiver is consumed and every failure stays latched.
            if self.attempted {
                self.failure = Some(e);
            }
            return Err(e);
        }
        loop {
            Self::call(expires, &cancel)?;
            self.current(expires, &cancel)?;
            if let Some(binding) = self.binding.as_ref()
                && let Err(error) = binding.validate(expires, &cancel)
            {
                self.failure = Some(error);
                return Err(error);
            }
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
                    self.current(expires, &cancel)?;
                    if let Some(binding) = self.binding.as_ref()
                        && let Err(error) = binding.validate(expires, &cancel)
                    {
                        self.failure = Some(error);
                        return Err(error);
                    }
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
    pub(super) fn pause_before_stage(
        &mut self,
        ready: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.stage_pause = Some((ready, release));
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
        // Stop succeeded: release the pin before re-checking admission, so a
        // changed context cannot keep it. A failed stop keeps the pin.
        self.descriptor = None;
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
