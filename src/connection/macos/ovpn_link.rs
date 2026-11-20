//! Observed OpenVPN utun identity and the local operations it authorizes.
//! The snapshots do not prove who owns the kernel control descriptor.
use super::{Api, LinkAliases, Target, check, preflight};
use crate::{
    connection::{
        ipsec::Error,
        macos::{Interfaces, resolve, sink, tcp},
    },
    helper::fd_guard,
    model::Profile,
};
use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

// Darwin <sys/sockio.h>: _IOW('i', 52, struct ifreq).
const SET_MTU: libc::c_ulong =
    0x8000_6934 | ((mem::size_of::<libc::ifreq>() as libc::c_ulong) << 16);

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct OvpnUtun {
    name: String,
    index: u32,
}

impl OvpnUtun {
    pub(crate) fn prove(name: &str, before: &Interfaces, current: &Interfaces) -> Option<Self> {
        if !name.starts_with("utun") || before.index(name).is_some() {
            return None;
        }
        let index = current.index(name).filter(|&index| index != 0)?;
        Some(Self {
            name: name.into(),
            index,
        })
    }

    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    pub(crate) fn matches(&self, snapshot: &Interfaces) -> bool {
        snapshot.index(&self.name) == Some(self.index)
    }

    pub(crate) fn current(&self) -> io::Result<bool> {
        Interfaces::read().map(|snapshot| self.matches(&snapshot))
    }

    pub(crate) fn absent(&self, snapshot: &Interfaces) -> bool {
        snapshot.index(&self.name).is_none() && self.index_missing(snapshot)
    }

    fn index_missing(&self, snapshot: &Interfaces) -> bool {
        !snapshot
            .entries
            .values()
            .any(|interface| interface.index == self.index)
    }

    pub(crate) fn index_absent(&self) -> io::Result<bool> {
        Interfaces::read().map(|snapshot| self.index_missing(&snapshot))
    }

    pub(crate) fn address_current(&self, address: Ipv4Addr) -> bool {
        Interfaces::read().is_ok_and(|snapshot| {
            preflight::verify(&snapshot, &self.target(), &[address.into()]).is_ok()
        })
    }

    fn target(&self) -> Target {
        Target {
            name: self.name.clone(),
            index: self.index,
        }
    }

    pub(crate) fn assign_address(
        &self,
        address: Ipv4Addr,
        prefix: u8,
        expires: Instant,
        cancel: &AtomicBool,
    ) -> Result<(), Error> {
        check(expires, cancel)?;
        let snapshot = Interfaces::read().map_err(|_| Error::Unavailable)?;
        if !self.matches(&snapshot) {
            return Err(Error::Changed);
        }
        if snapshot
            .entries
            .values()
            .any(|interface| interface.addresses.contains(&address.into()))
        {
            return Err(Error::Busy);
        }
        // A new OpenVPN utun may still be down before its first address.
        if !self.current().map_err(|_| Error::Unavailable)? {
            return Err(Error::Changed);
        }
        check(expires, cancel)?;
        LinkAliases(Some(prefix))
            .assign(&self.name, address.into())
            .map_err(|_| Error::Unavailable)?;
        check(expires, cancel)?;
        if !self.address_current(address) {
            return Err(Error::Changed);
        }
        Ok(())
    }

    pub(crate) fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        let fd = root_dgram()?;
        let mut request = mtu_request(&self.name, mtu)?;
        if !self.current()? {
            return Err(io::ErrorKind::NotFound.into());
        }
        // SAFETY: Darwin's SIOCSIFMTU reads a complete ifreq on a live socket.
        if unsafe { libc::ioctl(fd.as_raw_fd(), SET_MTU, &mut request) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Use the same scoped resolver and bound TCP sockets as the native
    /// probes. The configured IPv4 address must still be on this exact utun.
    pub(crate) fn probe(
        &self,
        address: Ipv4Addr,
        profile: &Profile,
        canceled: &AtomicBool,
        timeout: Duration,
    ) -> io::Result<bool> {
        let expires = Instant::now() + timeout.min(Duration::from_secs(30));
        let check = || {
            if canceled.load(Ordering::Acquire) || Instant::now() >= expires {
                Ok(false)
            } else if !self.address_current(address) {
                Err(io::Error::from(io::ErrorKind::NotFound))
            } else {
                Ok(true)
            }
        };
        if !check()? {
            return Ok(false);
        }
        let remaining = expires.saturating_duration_since(Instant::now());
        let dns_until = (Instant::now() + (remaining / 2).min(Duration::from_secs(2))).min(expires);
        let Ok(targets) = resolve::resolve(&profile.probe_host, self.index, 1, dns_until, canceled)
        else {
            check()?;
            return Ok(false);
        };
        let local = Interfaces::read()?;
        for target in targets {
            let IpAddr::V4(ip) = target else { continue };
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || local
                    .entries
                    .values()
                    .any(|interface| interface.addresses.contains(&target))
            {
                continue;
            }
            if !check()? {
                return Ok(false);
            }
            let until = (Instant::now() + Duration::from_secs(1)).min(expires);
            if let Ok(_socket) = tcp::connect(
                self.index,
                address.into(),
                SocketAddr::new(target, profile.probe_port),
                until,
                canceled,
            ) {
                return check();
            }
        }
        check()?;
        Ok(false)
    }
}

pub(super) fn assign_ipv4_alias(name: &str, address: IpAddr, prefix: u8) -> io::Result<()> {
    let fd = root_dgram()?;
    let mut bytes = ipv4_alias(name, address, prefix)?;
    // SAFETY: bytes are a live Darwin ifaliasreq for the AF_INET socket.
    if unsafe { libc::ioctl(fd.as_raw_fd(), sink::ALIAS4, bytes.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ipv4_alias(name: &str, address: IpAddr, prefix: u8) -> io::Result<Vec<u8>> {
    if !address.is_ipv4() || !(1..=32).contains(&prefix) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = sink::alias(name, address)?;
    let mask = u32::MAX << (32 - prefix);
    bytes[52..56].copy_from_slice(&mask.to_be_bytes());
    Ok(bytes)
}

fn mtu_request(name: &str, mtu: u16) -> io::Result<libc::ifreq> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || !name.is_ascii()
        || name.as_bytes().contains(&0)
        || !(576..=9000).contains(&mtu)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: ifreq is an ABI struct of arrays and a C union, all zeroable.
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_mtu = i32::from(mtu);
    Ok(request)
}

fn root_dgram() -> io::Result<OwnedFd> {
    // SAFETY: UID queries have no memory preconditions.
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let _guard = fd_guard::spawn();
    // SAFETY: socket returns a fresh descriptor without accepting any pointers.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor is fresh and has a single owner.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: fcntl sets one flag on the live owned descriptor.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(test)]
pub(crate) fn fixture_interfaces(entries: &[(&str, u32)]) -> Interfaces {
    use crate::connection::macos::interfaces::Interface;
    Interfaces {
        entries: entries
            .iter()
            .map(|&(name, index)| {
                (
                    name.into(),
                    Interface {
                        name: name.into(),
                        index,
                        flags: 0,
                        addresses: Default::default(),
                    },
                )
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_request_matches_darwin_ifreq_layout() {
        let request = mtu_request("utun42", 1420).unwrap();
        assert_eq!(mem::size_of::<libc::ifreq>(), 32);
        assert_eq!(mem::offset_of!(libc::ifreq, ifr_ifru), 16);
        assert_eq!(SET_MTU, 0x8020_6934);
        assert_eq!(&request.ifr_name[..7], &[117, 116, 117, 110, 52, 50, 0]);
        // SAFETY: mtu_request initialized the MTU variant.
        assert_eq!(unsafe { request.ifr_ifru.ifru_mtu }, 1420);
        for invalid in ["", "utun\0", "utun1234567890123", "utuné"] {
            assert!(mtu_request(invalid, 1500).is_err());
        }
        assert!(mtu_request("utun42", 575).is_err());
    }

    #[test]
    fn alias_uses_the_negotiated_netmask() {
        let address = "192.0.2.2".parse().unwrap();
        let bytes = ipv4_alias("utun42", address, 25).unwrap();
        assert_eq!(&bytes[20..24], &[192, 0, 2, 2]);
        assert_eq!(&bytes[52..56], &[255, 255, 255, 128]);
        assert!(ipv4_alias("utun42", address, 0).is_err());
    }
}
