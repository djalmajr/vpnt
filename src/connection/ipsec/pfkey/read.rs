//! Read-only protocol observations. Neither a countdown terminator nor an
//! echoed empty reply grants ownership or permission to release a VPN claim.
use super::{Entry, Error, Kind};
use crate::helper::{controller_lock::ControllerLock, local_socket::Budget};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};
mod batch;
mod socket;
use socket::Transport;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolEnd {
    EmptyReply,
    Countdown { first: u32 },
}
#[derive(Debug, Eq, PartialEq)]
pub struct Collection {
    pub kind: Kind,
    pub entries: Vec<Entry>,
    pub end: ProtocolEnd,
}
static NEXT: AtomicU32 = AtomicU32::new(1);
pub struct Reader<'a> {
    controller: &'a ControllerLock,
    pid: u32,
}
impl<'a> Reader<'a> {
    pub fn new(controller: &'a ControllerLock) -> Result<Self, Error> {
        let reader = Self {
            controller,
            pid: std::process::id(),
        };
        reader.validate()?;
        Ok(reader)
    }
    fn validate(&self) -> Result<(), Error> {
        // SAFETY: UID queries have no memory preconditions. No kernel socket
        // is created before admitting the fixed cooperating root controller.
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(Error::PermissionDenied);
        }
        if self.pid != std::process::id()
            || self.controller.directory() != std::path::Path::new(crate::helper::paths::STATE)
        {
            return Err(Error::Changed);
        }
        self.controller.validate().map_err(|_| Error::Changed)
    }
    pub fn collect(
        &self,
        kind: Kind,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<Collection, Error> {
        self.validate()?;
        let budget = Budget::until(expires, Some(cancel)).map_err(socket::map)?;
        let sequence = next_sequence(&NEXT)?;
        let channel = socket::Kernel::open(&budget)?;
        let result = collect_transport(&channel, kind, self.pid, sequence, &budget)?;
        self.validate()?;
        budget.check().map_err(socket::map)?;
        Ok(result)
    }
}
fn next_sequence(counter: &AtomicU32) -> Result<u32, Error> {
    let mut value = counter.load(Ordering::Relaxed);
    loop {
        if value == 0 {
            return Err(Error::Exhausted);
        }
        let next = value.checked_add(1).ok_or(Error::Exhausted)?;
        match counter.compare_exchange_weak(value, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(value),
            Err(current) => value = current,
        }
    }
}
fn kind_byte(kind: Kind) -> u8 {
    match kind {
        Kind::Sad => 10,
        Kind::Spd => 18,
    }
}
fn request(kind: Kind, pid: u32, sequence: u32) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[0] = 2;
    bytes[1] = kind_byte(kind);
    bytes[4..6].copy_from_slice(&2u16.to_ne_bytes());
    bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
    bytes[12..16].copy_from_slice(&pid.to_ne_bytes());
    bytes
}
fn collect_transport(
    io: &impl Transport,
    kind: Kind,
    pid: u32,
    sequence: u32,
    budget: &Budget,
) -> Result<Collection, Error> {
    budget.check().map_err(socket::map)?;
    io.send(&request(kind, pid, sequence), budget)?;
    let mut batch = batch::Batch::new(kind, pid, sequence);
    let mut buffer = Zeroizing::new(vec![0u8; 524_280]);
    loop {
        budget.check().map_err(socket::map)?;
        if batch.finished() && !io.pending(budget)? {
            budget.check().map_err(socket::map)?;
            return batch.finish();
        }
        let length = io.receive(&mut buffer, budget)?;
        let raw = buffer.get_mut(..length).ok_or(Error::Invalid)?;
        let result = batch.push(raw);
        raw.zeroize();
        result?;
    }
}

#[cfg(test)]
mod tests;
