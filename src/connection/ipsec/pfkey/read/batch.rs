use super::super::{decode, wire};
use super::{Collection, Entry, Error, Kind, ProtocolEnd, kind_byte};

pub(super) struct Batch {
    kind: Kind,
    pid: u32,
    nonce: u32,
    count: usize,
    bytes: usize,
    first: Option<u32>,
    next: Option<u32>,
    entries: Vec<Entry>,
    end: Option<ProtocolEnd>,
}
impl Batch {
    pub fn new(kind: Kind, pid: u32, nonce: u32) -> Self {
        Self {
            kind,
            pid,
            nonce,
            count: 0,
            bytes: 0,
            first: None,
            next: None,
            entries: vec![],
            end: None,
        }
    }
    pub fn finished(&self) -> bool {
        self.end.is_some()
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.count = self.count.checked_add(1).ok_or(Error::Exhausted)?;
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(Error::Exhausted)?;
        if self.count > 4096 || self.bytes > 16 * 1024 * 1024 {
            return Err(Error::Exhausted);
        }
        wire::check_datagram(bytes)?;
        if wire::u32_at(bytes, 12)? != self.pid || bytes[1] != kind_byte(self.kind) {
            return Ok(());
        }
        if self.finished() {
            return Err(Error::Changed);
        }
        let packet = decode(bytes)?;
        if let Entry::KernelError(errno) = packet.entry {
            if packet.sequence != self.nonce || !self.entries.is_empty() {
                return Err(Error::Changed);
            }
            if i32::from(errno) == libc::ENOENT {
                self.end = Some(ProtocolEnd::EmptyReply);
                return Ok(());
            }
            return Err(if [libc::EACCES, libc::EPERM].contains(&i32::from(errno)) {
                Error::PermissionDenied
            } else {
                Error::Unavailable
            });
        }
        if packet.sequence >= 4096 {
            return Err(Error::Exhausted);
        }
        if self.next.is_some_and(|next| packet.sequence != next) {
            return Err(Error::Changed);
        }
        let first = *self.first.get_or_insert(packet.sequence);
        if packet.sequence == 0 {
            self.end = Some(ProtocolEnd::Countdown { first });
        } else {
            self.next = Some(packet.sequence - 1);
        }
        self.entries.push(packet.entry);
        Ok(())
    }
    pub fn finish(self) -> Result<Collection, Error> {
        Ok(Collection {
            kind: self.kind,
            entries: self.entries,
            end: self.end.ok_or(Error::Changed)?,
        })
    }
}
