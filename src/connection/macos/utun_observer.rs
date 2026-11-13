//! Bounded, read-only observation of the owned child's utun control socket.
//!
//! The observation is a sample: it borrows the validated controller lock and the
//! original unreaped child, never scans other processes, and grants no route,
//! cleanup or ownership authority. Callers must refresh it around later route
//! mutations instead of treating it as an atomic lease.
use super::{
    process::{Identity, Process},
    utun_socket,
};
use crate::helper::{controller_lock::ControllerLock, process::ManagedChild};
use std::{
    fmt,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

mod native;
use native::Live;

const FD_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    NotFound,
    Ambiguous,
    Changed,
    Canceled,
    Timeout,
    Unavailable,
    Exhausted,
    Permission,
    Invalid,
}

/// Identity and fixed runtime facts the producer must match.
pub(crate) struct Expected<'a> {
    pub(crate) identity: Identity,
    pub(crate) parent: u32,
    pub(crate) uid: u32,
    pub(crate) executable: &'a Path,
}

/// A utun control socket observed for the admitted child at sample time.
///
/// Fields are private; the public surface is the interface name/index and
/// equality for later revalidation. No serialization and no authority.
#[derive(Clone, Eq, PartialEq)]
pub struct InterfaceObservation {
    name: String,
    index: u32,
    fd: i32,
    unit: u32,
    pid: u32,
    socket: u64,
    pcb: u64,
}

impl InterfaceObservation {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

impl fmt::Debug for InterfaceObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InterfaceObservation")
            .field("name", &self.name)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

pub(crate) fn check(expires: Instant, cancel: &AtomicBool) -> Result<(), Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    if Instant::now() >= expires {
        return Err(Error::Timeout);
    }
    Ok(())
}

/// Private seam over the kernel queries; production uses [`Live`] and tests use
/// scripted inventories through the same collection/selection code.
trait Source {
    fn pid(&self) -> u32;
    fn hint(&mut self) -> Result<usize, Error>;
    fn list(&mut self, capacity: usize) -> Result<Vec<(i32, u32)>, Error>;
    fn socket(&mut self, fd: i32) -> Result<utun_socket::Observation, utun_socket::Error>;
    fn index_of(&mut self, name: &str) -> u32;
    fn name_of(&mut self, index: u32) -> Option<String>;
}

struct Sample {
    entries: Vec<(i32, u32)>,
    fd: i32,
    unit: u32,
    name: String,
    index: u32,
    socket: u64,
    pcb: u64,
    pid: u32,
}

impl From<Sample> for InterfaceObservation {
    fn from(sample: Sample) -> Self {
        Self {
            name: sample.name,
            index: sample.index,
            fd: sample.fd,
            unit: sample.unit,
            pid: sample.pid,
            socket: sample.socket,
            pcb: sample.pcb,
        }
    }
}

fn same(first: &Sample, second: &Sample) -> bool {
    first.entries == second.entries
        && first.fd == second.fd
        && first.unit == second.unit
        && first.name == second.name
        && first.index == second.index
        && first.socket == second.socket
        && first.pcb == second.pcb
        && first.pid == second.pid
}

fn collect_pair<S: Source>(
    source: &mut S,
    expires: Instant,
    cancel: &AtomicBool,
    mut between: impl FnMut() -> Result<(), Error>,
) -> Result<InterfaceObservation, Error> {
    check(expires, cancel)?;
    let first = collect(source, expires, cancel)?;
    check(expires, cancel)?;
    between()?;
    let second = collect(source, expires, cancel)?;
    check(expires, cancel)?;
    if !same(&first, &second) {
        return Err(Error::Changed);
    }
    Ok(first.into())
}

fn collect<S: Source>(
    source: &mut S,
    expires: Instant,
    cancel: &AtomicBool,
) -> Result<Sample, Error> {
    let entries = inventory(source, expires, cancel)?;
    let mut found: Option<(i32, utun_socket::Observation)> = None;
    for &(fd, kind) in &entries {
        if kind != libc::PROX_FDTYPE_SOCKET as u32 {
            continue;
        }
        check(expires, cancel)?;
        match source.socket(fd) {
            Ok(observation) => {
                if found.is_some() {
                    return Err(Error::Ambiguous);
                }
                found = Some((fd, observation));
            }
            Err(utun_socket::Error::NotUtun) => {}
            Err(utun_socket::Error::Permission) => return Err(Error::Permission),
            Err(utun_socket::Error::Changed) => return Err(Error::Changed),
            Err(utun_socket::Error::Unavailable) | Err(utun_socket::Error::Abi) => {
                return Err(Error::Unavailable);
            }
        }
        check(expires, cancel)?;
    }
    let (fd, observation) = found.ok_or(Error::NotFound)?;
    if observation.unit == 0 {
        return Err(Error::Invalid);
    }
    let name = format!("utun{}", observation.unit - 1);
    if name.len() >= libc::IF_NAMESIZE {
        return Err(Error::Invalid);
    }
    check(expires, cancel)?;
    let index = source.index_of(&name);
    if index == 0 {
        return Err(Error::Changed);
    }
    if source.name_of(index).as_deref() != Some(name.as_str()) {
        return Err(Error::Changed);
    }
    check(expires, cancel)?;
    Ok(Sample {
        entries,
        fd,
        unit: observation.unit,
        name,
        index,
        socket: observation.socket,
        pcb: observation.pcb,
        pid: source.pid(),
    })
}

fn inventory<S: Source>(
    source: &mut S,
    expires: Instant,
    cancel: &AtomicBool,
) -> Result<Vec<(i32, u32)>, Error> {
    check(expires, cancel)?;
    let hint = source.hint()?;
    check(expires, cancel)?;
    let mut capacity = hint.saturating_add(16).clamp(32, FD_LIMIT);
    loop {
        check(expires, cancel)?;
        let mut entries = source.list(capacity)?;
        check(expires, cancel)?;
        if entries.len() == capacity {
            if capacity == FD_LIMIT {
                return Err(Error::Exhausted);
            }
            capacity = (capacity * 2).min(FD_LIMIT);
            continue;
        }
        let mut again = source.list(capacity)?;
        check(expires, cancel)?;
        entries.sort_unstable();
        again.sort_unstable();
        if entries != again {
            return Err(Error::Changed);
        }
        if entries.iter().any(|(fd, _)| *fd < 0) {
            return Err(Error::Invalid);
        }
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::Invalid);
        }
        return Ok(entries);
    }
}

fn validate(
    controller: &ControllerLock,
    child: &mut ManagedChild,
    expected: &Expected<'_>,
) -> Result<(), Error> {
    controller.validate().map_err(|_| Error::Changed)?;
    if child.poll().map_err(|_| Error::Unavailable)?.is_some() {
        return Err(Error::Changed);
    }
    if child.id() != expected.identity.pid {
        return Err(Error::Changed);
    }
    let process = Process::read(expected.identity.pid).map_err(|_| Error::Changed)?;
    if process.identity != expected.identity
        || !process.running
        || process.parent != expected.parent
        || process.uid != expected.uid
        || process.real_uid != expected.uid
        || process.executable.as_path() != expected.executable
    {
        return Err(Error::Changed);
    }
    Ok(())
}

pub(crate) fn observe(
    controller: &ControllerLock,
    child: &mut ManagedChild,
    expected: &Expected<'_>,
    expires: Instant,
    cancel: &AtomicBool,
) -> Result<InterfaceObservation, Error> {
    let pid = expected.identity.pid;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(Error::Changed);
    }
    check(expires, cancel)?;
    validate(controller, child, expected)?;
    let mut source = Live::new(pid);
    let observation = collect_pair(&mut source, expires, cancel, || {
        validate(controller, child, expected)
    })?;
    check(expires, cancel)?;
    validate(controller, child, expected)?;
    Ok(observation)
}

#[cfg(test)]
mod tests;
