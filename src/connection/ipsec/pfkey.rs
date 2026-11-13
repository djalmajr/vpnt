//! Sanitized Darwin PF_KEY metadata. A decoded packet is not a complete dump,
//! ownership receipt, traffic proof or permission to delete/release resources.
use super::Error;
use crate::connection::routes::{Address, Network};
use std::collections::BTreeSet;
mod address;
mod entry;
pub mod read;
mod wire;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Sad,
    Spd,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub kind: Kind,
    pub sequence: u32,
    pub pid: u32,
    pub entry: Entry,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Entry {
    Sa(Sa),
    Policy(Policy),
    KernelError(u8),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub address: Address,
    pub port: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selector {
    pub start: Endpoint,
    pub end: Option<Endpoint>,
    pub prefix: u8,
    pub protocol: u8,
}
impl Selector {
    pub fn network(&self) -> Result<Network, Error> {
        Network::new(self.start.address.ip, self.prefix).map_err(|_| Error::Invalid)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lifetime {
    pub allocations: u32,
    pub bytes: u64,
    pub added: u64,
    pub used: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sa {
    pub protocol: u8,
    pub spi: u32,
    pub state: u8,
    pub flags: u32,
    pub reqid: u32,
    pub mode: u8,
    pub replay_sequence: u32,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub natt_port: Option<u16>,
    pub lifetime: Option<Lifetime>,
    pub extra_extensions: BTreeSet<u16>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub id: u32,
    pub kind: u16,
    pub direction: u8,
    pub source: Selector,
    pub destination: Selector,
    pub requests: Vec<Request>,
    pub extra_extensions: BTreeSet<u16>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub protocol: u16,
    pub mode: u8,
    pub level: u8,
    pub reqid: u16,
    pub endpoints: Option<(Endpoint, Endpoint)>,
}

/// The caller owns and must clear its raw receive buffer. No key, identity or
/// unknown extension payload is retained or exposed by the returned metadata.
pub fn decode(bytes: &[u8]) -> Result<Packet, Error> {
    let h = wire::Header::parse(bytes)?;
    let entry = if h.errno != 0 {
        if bytes.len() != 16 {
            return Err(Error::Invalid);
        }
        Entry::KernelError(h.errno)
    } else {
        let extensions = wire::Extensions::parse(&bytes[16..])?;
        match h.kind {
            Kind::Sad => Entry::Sa(entry::sa(h.satype, &extensions)?),
            Kind::Spd => Entry::Policy(entry::policy(&extensions)?),
        }
    };
    Ok(Packet {
        kind: h.kind,
        sequence: h.sequence,
        pid: h.pid,
        entry,
    })
}

#[cfg(test)]
mod tests;
