//! Hold the specific PPP ifnet alive with our own PF_PPP client reference.
//! Closing this owned socket only detaches this client. We never issue
//! NEWUNIT, DETACH, interface destruction or operations on a discovered PID.
use super::{Interfaces, interfaces::Interface, ppp::OwnedPpp};
use crate::helper::controller_lock::ControllerLock;
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

// Apple ppp/Family/{if_ppp.h,ppp_domain.h}; not installed in the public SDK.
// Darwin _IOW/_IOR encode direction, sizeof(int), group and command number.
pub(super) const ATTACH: libc::c_ulong = 0x8004_743d;
pub(super) const GET_UNIT: libc::c_ulong = 0x4004_7456;
const CONTROL: libc::c_int = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachError {
    PermissionDenied,
    Invalid,
    Changed,
    Unavailable,
}

#[must_use = "retain the attachment through route creation and tunnel shutdown"]
pub struct PppAttachment<'a> {
    socket: Attachment,
    interface: Interface,
    controller: &'a ControllerLock,
}
impl<'a> PppAttachment<'a> {
    pub fn retain(ppp: &OwnedPpp, controller: &'a ControllerLock) -> Result<Self, AttachError> {
        require_root()?;
        let socket = attach_using(&ppp.interface, &Native, || {
            controller.validate().map_err(|_| AttachError::Changed)?;
            ppp.is_current().map_err(|_| AttachError::Unavailable)
        })?;
        Ok(Self {
            socket,
            interface: ppp.interface.clone(),
            controller,
        })
    }
    pub fn index(&self) -> u16 {
        // attach_using rejects indices outside the native routing ABI.
        self.interface.index as u16
    }
    pub fn name(&self) -> &str {
        &self.interface.name
    }
    /// This proves the retained ifnet, not that pppd or the tunnel is alive.
    /// OwnedPpp/probes remain required to classify an active connection.
    pub fn validate(&self) -> Result<(), AttachError> {
        self.controller
            .validate()
            .map_err(|_| AttachError::Changed)?;
        self.socket.verify(&Native)?;
        let interfaces = Interfaces::read().map_err(|_| AttachError::Unavailable)?;
        if !interfaces
            .entries
            .get(self.name())
            .is_some_and(|now| now.index == self.interface.index)
        {
            return Err(AttachError::Changed);
        }
        Ok(())
    }
    pub(super) fn source(&self, ipv4: bool) -> Option<std::net::IpAddr> {
        self.interface
            .addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == ipv4)
    }
    pub(super) fn controller(&self) -> &ControllerLock {
        self.controller
    }
}

fn require_root() -> Result<(), AttachError> {
    // SAFETY: UID queries have no memory preconditions.
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        return Err(AttachError::PermissionDenied);
    }
    Ok(())
}

trait Api {
    fn socket(&self) -> io::Result<OwnedFd>;
    fn ioctl(&self, fd: RawFd, request: libc::c_ulong, value: &mut libc::c_int) -> io::Result<()>;
}
struct Native;
impl Api for Native {
    fn socket(&self) -> io::Result<OwnedFd> {
        // SAFETY: socket has no memory arguments and returns a new owned FD.
        let fd = unsafe { libc::socket(libc::PF_PPP, libc::SOCK_RAW, CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: transfer the new descriptor into exactly one owner.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    fn ioctl(&self, fd: RawFd, request: libc::c_ulong, value: &mut libc::c_int) -> io::Result<()> {
        // SAFETY: the only two internal requests use a live, correctly sized
        // int as input/output. The caller keeps its FD alive across the call.
        if unsafe { libc::ioctl(fd, request, value) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
struct Attachment {
    fd: OwnedFd,
    unit: libc::c_int,
}
impl Attachment {
    fn verify(&self, api: &impl Api) -> Result<(), AttachError> {
        let mut unit = -1;
        api.ioctl(self.fd.as_raw_fd(), GET_UNIT, &mut unit)
            .map_err(|_| AttachError::Unavailable)?;
        if unit != self.unit {
            return Err(AttachError::Changed);
        }
        Ok(())
    }
}
fn attach_using(
    interface: &Interface,
    api: &impl Api,
    mut current: impl FnMut() -> Result<bool, AttachError>,
) -> Result<Attachment, AttachError> {
    let text = interface
        .name
        .strip_prefix("ppp")
        .ok_or(AttachError::Invalid)?;
    let unit: u16 = text.parse().map_err(|_| AttachError::Invalid)?;
    if unit == u16::MAX
        || unit.to_string() != text
        || !interface.usable_ppp()
        || interface.index > u16::MAX as u32
        || interface.addresses.is_empty()
    {
        return Err(AttachError::Invalid);
    }
    if !current()? {
        return Err(AttachError::Changed);
    }
    let fd = api.socket().map_err(|_| AttachError::Unavailable)?;
    // SAFETY: fd remains live; these fcntl operations take integer flags.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(AttachError::Unavailable);
    }
    let mut requested = libc::c_int::from(unit);
    api.ioctl(fd.as_raw_fd(), ATTACH, &mut requested)
        .map_err(|_| AttachError::Unavailable)?;
    let socket = Attachment {
        fd,
        unit: libc::c_int::from(unit),
    };
    socket.verify(api)?;
    if !current()? {
        return Err(AttachError::Changed);
    }
    Ok(socket)
}

#[cfg(test)]
#[path = "ppp_attachment_tests.rs"]
mod tests;
