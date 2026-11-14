//! A new, FD-owned UTUN for blackhole routes, never an existing interface.
//! Both packet directions are disabled before assigning a private host address.
mod native;
// Crate-private reuse of the existing SDK-exact alias encoder and ioctl codes;
// the encoder bytes and OwnedSink behaviour are unchanged.
use super::{Interfaces, routing::Snapshot};
use crate::{
    connection::routes::{Error, Network},
    helper::controller_lock::ControllerLock,
};
pub(crate) use native::{ALIAS4, ALIAS6, alias};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, OwnedFd, RawFd},
};

const DROP_BOTH: u32 = 3; // UTUN_FLAGS_NO_OUTPUT | UTUN_FLAGS_NO_INPUT

#[derive(Clone, Debug)]
pub(super) struct RetiredSink {
    pub name: String,
    pub index: u16,
    pub source: Option<IpAddr>,
}
impl RetiredSink {
    pub fn gone(&self, interfaces: &Interfaces, table: &Snapshot) -> bool {
        !interfaces
            .entries
            .values()
            .any(|entry| entry.index == u32::from(self.index) || entry.name == self.name)
            && !table
                .records
                .iter()
                .any(|record| record.interface == self.index)
            && self
                .source
                .is_none_or(|source| address_unused(source, interfaces, table))
    }
}
pub(super) struct CreateError {
    pub error: Error,
    pub retired: Option<RetiredSink>,
}
pub(super) struct OwnedSink<'a> {
    socket: SinkSocket,
    controller: &'a ControllerLock,
}
impl<'a> OwnedSink<'a> {
    pub fn create(ipv4: bool, controller: &'a ControllerLock) -> Result<Self, CreateError> {
        require_root().map_err(|error| CreateError {
            error,
            retired: None,
        })?;
        let socket = create_using(ipv4, &native::Native, || {
            controller.validate().map_err(|_| Error::Unavailable)
        })?;
        Ok(Self { socket, controller })
    }
    pub fn index(&self) -> u16 {
        self.socket.identity.index
    }
    pub fn source(&self, ipv4: bool) -> Option<IpAddr> {
        self.socket
            .identity
            .source
            .filter(|source| source.is_ipv4() == ipv4)
    }
    pub fn controller(&self) -> &ControllerLock {
        self.controller
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.controller.validate().map_err(|_| Error::Unavailable)?;
        self.socket.validate(&native::Native)
    }
    pub fn identity(&self) -> RetiredSink {
        self.socket.identity.clone()
    }
    pub fn retire(self) -> RetiredSink {
        let identity = self.identity();
        drop(self); // closing our control FD asks XNU to detach this UTUN only
        identity
    }
}
fn require_root() -> Result<(), Error> {
    // SAFETY: UID queries have no memory preconditions. No socket on denial.
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        return Err(Error::Unavailable);
    }
    Ok(())
}
trait Api {
    fn open(&self) -> io::Result<OwnedFd>;
    fn connect(&self, fd: RawFd) -> io::Result<()>;
    fn name(&self, fd: RawFd) -> io::Result<String>;
    fn set_flags(&self, fd: RawFd, flags: u32) -> io::Result<()>;
    fn flags(&self, fd: RawFd) -> io::Result<u32>;
    fn assign(&self, name: &str, source: IpAddr) -> io::Result<()>;
    fn interfaces(&self) -> io::Result<Interfaces>;
    fn table(&self) -> Result<Snapshot, Error>;
    fn random(&self) -> [u8; 16];
}
struct SinkSocket {
    fd: OwnedFd,
    identity: RetiredSink,
}
impl SinkSocket {
    fn validate(&self, api: &impl Api) -> Result<(), Error> {
        if api
            .name(self.fd.as_raw_fd())
            .map_err(|_| Error::Unavailable)?
            != self.identity.name
            || api
                .flags(self.fd.as_raw_fd())
                .map_err(|_| Error::Unavailable)?
                != DROP_BOTH
        {
            return Err(Error::Changed);
        }
        let interfaces = api.interfaces().map_err(|_| Error::Unavailable)?;
        let source = self.identity.source.ok_or(Error::Invalid)?;
        let Some(interface) = interfaces.entries.get(&self.identity.name) else {
            return Err(Error::Changed);
        };
        if interface.index != u32::from(self.identity.index)
            || !interface.usable_ppp()
            || !interface.addresses.contains(&source)
            || interfaces
                .entries
                .values()
                .any(|entry| entry.index != interface.index && entry.addresses.contains(&source))
        {
            return Err(Error::Changed);
        }
        Ok(())
    }
}
fn create_using(
    ipv4: bool,
    api: &impl Api,
    mut current: impl FnMut() -> Result<(), Error>,
) -> Result<SinkSocket, CreateError> {
    let mut retired = None;
    let result = (|| {
        current()?;
        let before = api.interfaces().map_err(|_| Error::Unavailable)?;
        let fd = api.open().map_err(|_| Error::Unavailable)?;
        // SAFETY: set integer flags on our new, still-owned descriptor.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(Error::Unavailable);
        }
        api.connect(fd.as_raw_fd())
            .map_err(|_| Error::Unavailable)?;
        let name = api.name(fd.as_raw_fd()).map_err(|_| Error::Unavailable)?;
        let unit = name.strip_prefix("utun").ok_or(Error::Invalid)?;
        if unit
            .parse::<u32>()
            .ok()
            .is_none_or(|n| n.to_string() != unit)
            || name.len() >= libc::IFNAMSIZ
        {
            return Err(Error::Invalid);
        }
        let interfaces = api.interfaces().map_err(|_| Error::Unavailable)?;
        let interface = interfaces.entries.get(&name).ok_or(Error::Changed)?;
        let index = u16::try_from(interface.index).map_err(|_| Error::Invalid)?;
        if !interface.usable_ppp()
            || before
                .entries
                .values()
                .any(|entry| entry.name == name || entry.index == interface.index)
        {
            return Err(Error::Changed);
        }
        retired = Some(RetiredSink {
            name: name.clone(),
            index,
            source: None,
        });
        api.set_flags(fd.as_raw_fd(), DROP_BOTH)
            .map_err(|_| Error::Unavailable)?;
        if api.flags(fd.as_raw_fd()).map_err(|_| Error::Unavailable)? != DROP_BOTH {
            return Err(Error::Changed);
        }
        let table = api.table()?;
        let source = (0..32)
            .find_map(|_| {
                let mut bytes = api.random();
                let source = if ipv4 {
                    IpAddr::V4(Ipv4Addr::new(169, 254, 1 + bytes[0] % 254, bytes[1]))
                } else {
                    bytes[0] = 0xfd;
                    IpAddr::V6(Ipv6Addr::from(bytes))
                };
                address_unused(source, &interfaces, &table).then_some(source)
            })
            .ok_or(Error::Conflict)?;
        // Save intent before the syscall: even an error may follow partial work.
        retired.as_mut().unwrap().source = Some(source);
        current()?;
        api.assign(&name, source).map_err(|_| Error::Unavailable)?;
        let socket = SinkSocket {
            fd,
            identity: retired.clone().unwrap(),
        };
        socket.validate(api)?;
        current()?;
        Ok(socket)
    })();
    result.map_err(|error| CreateError { error, retired })
}
fn address_unused(source: IpAddr, interfaces: &Interfaces, table: &Snapshot) -> bool {
    !interfaces
        .entries
        .values()
        .any(|entry| entry.addresses.contains(&source))
        && !table
            .records
            .iter()
            .any(|record| record.key.network == Network::host(source))
}

#[cfg(test)]
#[path = "sink/tests.rs"]
mod tests;
