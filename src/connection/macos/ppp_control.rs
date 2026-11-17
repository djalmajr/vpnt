//! Host end of one inherited PPP capability. All permissions are conditional
//! on native identity/ancestry and retained exit watches. No PID signaling.
use super::process::{ExitWatch, Identity, Process};
use crate::helper::{local_socket::peer_uid, ppp_supervisor::ServiceId};
use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub(crate) struct Policy {
    pub owner: u32,
    pub client: PathBuf,
    pub supervisor: PathBuf,
    pub ppp: PathBuf,
}
struct Observed {
    identity: Identity,
    program: PathBuf,
    owner: u32,
    parent: u32,
    watch: Mutex<ExitWatch>,
}
impl Observed {
    fn capture(pid: u32, before: &Path, after: &Path, owner: u32, parent: u32) -> io::Result<Self> {
        let value = Process::read(pid)?;
        if !value.running
            || value.uid != owner
            || value.real_uid != owner
            || value.executable != before
            || (parent != 0 && value.parent != parent)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let watch = ExitWatch::attach(&value.identity)?;
        let again = Process::read(pid)?;
        if again.identity != value.identity
            || again.executable != value.executable
            || again.parent != value.parent
            || again.uid != owner
            || again.real_uid != owner
            || !again.running
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Self {
            identity: value.identity,
            program: after.into(),
            owner,
            parent: value.parent,
            watch: Mutex::new(watch),
        })
    }
    fn current(&self) -> io::Result<bool> {
        if self.exited()? {
            return Ok(false);
        }
        Ok(Process::read(self.identity.pid).is_ok_and(|value| {
            value.identity == self.identity
                && value.running
                && value.uid == self.owner
                && value.real_uid == self.owner
                && value.executable == self.program
                && value.parent == self.parent
        }))
    }
    fn exited(&self) -> io::Result<bool> {
        self.watch
            .lock()
            .map_err(|_| io::Error::from(io::ErrorKind::Other))?
            .exited()
    }
}
pub(crate) struct ChildIdentity {
    identity: Identity,
    service: ServiceId,
}
impl std::ops::Deref for ChildIdentity {
    type Target = Identity;
    fn deref(&self) -> &Identity {
        &self.identity
    }
}
impl ChildIdentity {
    #[cfg(test)]
    pub(super) fn fixture(identity: Identity, service: ServiceId) -> Self {
        Self { identity, service }
    }
    pub fn service(&self) -> &ServiceId {
        &self.service
    }
}
pub(crate) struct Proof {
    client: Arc<Observed>,
    supervisor: Arc<Observed>,
    child: Arc<Observed>,
    child_identity: ChildIdentity,
    #[cfg(test)]
    supervisor_receipt: Option<Identity>,
}
impl Proof {
    #[cfg(test)]
    pub(super) fn fixture(
        parent: &Process,
        child: &Process,
        service: ServiceId,
    ) -> io::Result<Self> {
        fn observed(process: &Process) -> io::Result<Arc<Observed>> {
            Ok(Arc::new(Observed {
                identity: process.identity.clone(),
                program: process.executable.clone(),
                owner: process.uid,
                parent: process.parent,
                watch: Mutex::new(ExitWatch::attach(&process.identity)?),
            }))
        }
        let supervisor = observed(parent)?;
        Ok(Self {
            client: Arc::clone(&supervisor),
            supervisor,
            child: observed(child)?,
            child_identity: ChildIdentity {
                identity: child.identity.clone(),
                service,
            },
            supervisor_receipt: None,
        })
    }
    #[cfg(test)]
    pub(super) fn fixture_bad_supervisor_receipt(&mut self) {
        let mut identity = self.supervisor.identity.clone();
        identity.start.0 = identity.start.0.wrapping_add(1);
        self.supervisor_receipt = Some(identity);
    }
    #[cfg(test)]
    pub(super) fn fixture_bad_receipt(&mut self) {
        self.child_identity.identity.start.0 = self.child_identity.identity.start.0.wrapping_add(1);
    }
    #[cfg(test)]
    pub(super) fn fixture_invalid(&mut self) {
        Arc::get_mut(&mut self.child).unwrap().program = "/invalid-fixture".into();
    }
    pub fn supervisor(&self) -> &Identity {
        #[cfg(test)]
        if let Some(receipt) = &self.supervisor_receipt {
            return receipt;
        }
        &self.supervisor.identity
    }
    pub fn child(&self) -> &ChildIdentity {
        &self.child_identity
    }
    pub fn current(&self) -> io::Result<bool> {
        Ok(self.client.current()? && self.supervisor.current()? && self.child.current()?)
    }
    pub fn exited(&self) -> io::Result<bool> {
        Ok(self.client.exited()? && self.supervisor.exited()? && self.child.exited()?)
    }
}
pub(crate) struct Control {
    socket: UnixStream,
    client_pid: u32,
    policy: Policy,
    canceled: Arc<AtomicBool>,
    service: ServiceId,
    client: Option<Arc<Observed>>,
    supervisor: Option<Arc<Observed>>,
    proof: Option<Arc<Proof>>,
    bytes: [u8; 8],
    used: usize,
    closed: bool,
    eof: bool,
    failed: bool,
    finished: bool,
}
impl Control {
    pub fn new(
        socket: UnixStream,
        client_pid: u32,
        policy: Policy,
        canceled: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        if peer_uid(&socket)? != policy.owner {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            client_pid,
            policy,
            canceled,
            service: ServiceId::random()?,
            client: None,
            supervisor: None,
            proof: None,
            bytes: [0; 8],
            used: 0,
            closed: false,
            eof: false,
            failed: false,
            finished: false,
        })
    }
    pub fn cancel(&mut self) {
        self.closed = true;
        // Keep the read side open for final receipts and EOF. Only admission
        // closes here; a complete ACK may already have authorized exec.
        let _ = self.socket.shutdown(Shutdown::Write);
    }
    pub fn poll(&mut self) -> io::Result<()> {
        if self.canceled.load(Ordering::Acquire) {
            self.cancel();
        }
        for _ in 0..8 {
            if self.eof {
                break;
            }
            match self.socket.read(&mut self.bytes[self.used..]) {
                Ok(0) => {
                    self.eof = true;
                    if self.used != 0 {
                        self.failed = true;
                    }
                    self.cancel();
                    break;
                }
                Ok(count) => self.used += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.failed = true;
                    self.cancel();
                    return Err(error);
                }
            }
            if self.used == 8 {
                let frame = self.bytes;
                self.used = 0;
                if self.message(frame).is_err() {
                    self.failed = true;
                    self.cancel();
                }
            }
        }
        Ok(())
    }
    fn message(&mut self, bytes: [u8; 8]) -> io::Result<()> {
        let pid = u32::from_be_bytes(bytes[4..].try_into().unwrap());
        match &bytes[..4] {
            b"VPS1" if self.supervisor.is_none() && !self.finished => {
                if self.closed {
                    return Ok(());
                }
                let client = Arc::new(Observed::capture(
                    self.client_pid,
                    &self.policy.client,
                    &self.policy.client,
                    self.policy.owner,
                    0,
                )?);
                let supervisor = Arc::new(Observed::capture(
                    pid,
                    &self.policy.supervisor,
                    &self.policy.supervisor,
                    self.policy.owner,
                    self.client_pid,
                )?);
                if !client.current()? {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                self.client = Some(client);
                self.supervisor = Some(supervisor);
                self.permit(*b"VPA1", pid)
            }
            b"VPB1" if self.supervisor.is_some() && self.proof.is_none() && !self.finished => {
                if self.closed {
                    return Ok(());
                }
                let client = self.client.as_ref().unwrap();
                let supervisor = self.supervisor.as_ref().unwrap();
                let child = Arc::new(Observed::capture(
                    pid,
                    &self.policy.supervisor,
                    &self.policy.ppp,
                    self.policy.owner,
                    supervisor.identity.pid,
                )?);
                if !client.current()? || !supervisor.current()? {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                // Retain the attempted grant BEFORE writing: partial/error
                // after send never means that the child could not execute.
                self.proof = Some(Arc::new(Proof {
                    client: client.clone(),
                    supervisor: supervisor.clone(),
                    #[cfg(test)]
                    supervisor_receipt: None,
                    child_identity: ChildIdentity {
                        identity: child.identity.clone(),
                        service: self.service.clone(),
                    },
                    child,
                }));
                self.permit(*b"VPC1", pid)
            }
            b"VPF1" if !self.finished => {
                if let Some(proof) = &self.proof {
                    if pid != proof.child.identity.pid {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                } else if !self.closed && pid != 0 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.finished = true;
                self.cancel();
                Ok(())
            }
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }
    fn permit(&mut self, magic: [u8; 4], pid: u32) -> io::Result<()> {
        if self.closed || self.canceled.load(Ordering::Acquire) {
            self.cancel();
            return Err(io::ErrorKind::Interrupted.into());
        }
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&magic);
        bytes[4..].copy_from_slice(&pid.to_be_bytes());
        self.socket.write_all(&bytes)?;
        if magic == *b"VPA1" {
            self.socket.write_all(self.service.as_str().as_bytes())?;
        }
        Ok(())
    }
    pub fn proof(&self) -> Option<Arc<Proof>> {
        self.proof.clone()
    }
    /// Snapshot of already captured identities; never re-observe a PID here.
    pub(crate) fn recorded(&self) -> (&ServiceId, Vec<(&Identity, &Path)>) {
        let mut identities = Vec::new();
        if let Some(client) = &self.client {
            identities.push((&client.identity, client.program.as_path()));
        }
        if let Some(supervisor) = &self.supervisor {
            identities.push((&supervisor.identity, supervisor.program.as_path()));
        }
        if let Some(proof) = &self.proof {
            identities.push((&proof.child.identity, proof.child.program.as_path()));
        }
        (&self.service, identities)
    }
    pub fn may_have_run(&self) -> bool {
        self.proof.is_some()
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
    pub fn complete(&mut self, client_exited: bool) -> io::Result<bool> {
        self.poll()?;
        if !client_exited || !self.eof {
            return Ok(false);
        }
        // No granted exec + closed inherited endpoint means none of its
        // holders can later obtain permission. Otherwise every original
        // process must have exited, even if the final receipt was lost.
        self.proof.as_ref().map_or(Ok(true), |proof| proof.exited())
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod recorded_tests {
    use super::*;
    #[test]
    fn recorded_returns_only_previously_captured_identities() {
        let (server, _peer) = UnixStream::pair().unwrap();
        let process = Process::read(std::process::id()).unwrap();
        let mut control = Control::new(
            server,
            process.identity.pid,
            Policy {
                owner: process.uid,
                client: process.executable.clone(),
                supervisor: process.executable.clone(),
                ppp: process.executable.clone(),
            },
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let service = control.service.clone();
        let (before_service, before) = control.recorded();
        assert_eq!(before_service, &service);
        assert!(before.is_empty());
        let observed = || {
            Arc::new(Observed {
                identity: process.identity.clone(),
                program: process.executable.clone(),
                owner: process.uid,
                parent: process.parent,
                watch: Mutex::new(ExitWatch::attach(&process.identity).unwrap()),
            })
        };
        control.client = Some(observed());
        control.supervisor = Some(observed());
        let (_, partial) = control.recorded();
        assert_eq!(partial.len(), 2);
        assert_eq!(partial[0].0, &process.identity);
        assert_eq!(partial[1].0, &process.identity);
        control.proof = Some(Arc::new(
            Proof::fixture(&process, &process, service).unwrap(),
        ));
        let (_, complete) = control.recorded();
        assert_eq!(complete.len(), 3);
        assert_eq!(complete[2].0, &process.identity);
        assert_eq!(complete[2].1, process.executable.as_path());
    }
}
