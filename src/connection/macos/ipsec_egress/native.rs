//! Native source for the IPsec egress selector. Read-only: no route write,
//! no packet and no IPsec BYPASS policy.
use super::super::{
    interfaces::{Interfaces, address},
    resolve,
    routing::{Reader, Record},
};
use super::{Source, resolve_error};
use crate::{
    connection::routes::{Address, Error},
    helper::fd_guard,
};
use std::{
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const IP_BOUND_IF: libc::c_int = 25;
const IPV6_BOUND_IF: libc::c_int = 125;

pub(super) struct Native;

impl Source for Native {
    fn resolve(
        &mut self,
        host: &str,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Vec<IpAddr>, Error> {
        resolve::gateway(host, deadline, cancel).map_err(resolve_error)
    }

    fn interfaces(&mut self, deadline: Instant, cancel: &AtomicBool) -> Result<Interfaces, Error> {
        check(deadline, cancel)?;
        // getifaddrs is synchronous and cannot be interrupted; the check after
        // the call is the honest bound, not a promise against a stuck syscall.
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        check(deadline, cancel)?;
        Ok(interfaces)
    }

    fn route(
        &mut self,
        address: Address,
        scope: u16,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<Record, Error> {
        let deadline = Instant::now() + timeout;
        check(deadline, cancel)?;
        let mut reader = {
            let _guard = fd_guard::spawn();
            Reader::open()?
        };
        check(deadline, cancel)?;
        // Reader::lookup rejects a timeout above 2 s; use the balance left
        // after opening the route socket, not the caller's initial timeout.
        let budget = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(Error::TimedOut)?
            .min(Duration::from_secs(2));
        let result = reader.lookup(address, scope, budget, cancel);
        check(deadline, cancel)?;
        result
    }

    fn source(
        &mut self,
        remote: IpAddr,
        port: u16,
        index: u16,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<IpAddr, Error> {
        let deadline = Instant::now() + timeout;
        source_for(remote, port, index, deadline, cancel)
    }
}

fn check(deadline: Instant, cancel: &AtomicBool) -> Result<(), Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    if Instant::now() >= deadline {
        return Err(Error::TimedOut);
    }
    Ok(())
}

fn source_for(
    remote: IpAddr,
    port: u16,
    index: u16,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<IpAddr, Error> {
    if index == 0 {
        return Err(Error::Invalid);
    }
    check(deadline, cancel)?;
    let family = if remote.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd: OwnedFd = {
        let _guard = fd_guard::spawn();
        // SAFETY: socket has no memory arguments and returns a new descriptor.
        let raw = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
        if raw < 0 {
            return Err(Error::Unavailable);
        }
        // SAFETY: transfer the new descriptor into exactly one owner.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        fd_guard::mark_cloexec(fd.as_raw_fd()).map_err(|_| Error::Unavailable)?;
        fd
    };
    // The spawn guard is released before any connection wait.
    let value: libc::c_uint = index.into();
    let (level, option) = if remote.is_ipv4() {
        (libc::IPPROTO_IP, IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
    };
    // SAFETY: integer option with matching length on our live descriptor.
    let bound = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_uint).cast(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if bound != 0 {
        return Err(Error::Unavailable);
    }
    check(deadline, cancel)?;
    let (storage, length) = sockaddr(remote, port);
    let pointer = &storage as *const libc::sockaddr_storage as *const libc::sockaddr;
    // SAFETY: storage/length describe a live sockaddr of the matching family.
    if unsafe { libc::connect(fd.as_raw_fd(), pointer, length) } != 0 {
        return Err(Error::Unavailable);
    }
    check(deadline, cancel)?;
    let mut local: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut local_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: writable storage with its exact capacity.
    if unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            &mut local as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut local_length,
        )
    } != 0
    {
        return Err(Error::Unavailable);
    }
    check(deadline, cancel)?;
    // SAFETY: kernel-filled sockaddr within the storage capacity.
    let pointer = &local as *const libc::sockaddr_storage as *const libc::sockaddr;
    let local = unsafe { address(pointer) }.ok_or(Error::Invalid)?;
    if local.is_ipv4() != remote.is_ipv4() {
        return Err(Error::Invalid);
    }
    Ok(local)
}

fn sockaddr(remote: IpAddr, port: u16) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match remote {
        IpAddr::V4(ip) => {
            // SAFETY: storage is large enough for sockaddr_in and zeroed.
            let target = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            target.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            target.sin_family = libc::AF_INET as u8;
            target.sin_port = port.to_be();
            target.sin_addr.s_addr = u32::from(ip).to_be();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        IpAddr::V6(ip) => {
            // SAFETY: storage is large enough for sockaddr_in6 and zeroed.
            let target = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            target.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            target.sin6_family = libc::AF_INET6 as u8;
            target.sin6_port = port.to_be();
            target.sin6_addr.s6_addr = ip.octets();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    #[test]
    fn native_selector_uses_loopback_and_preserves_family() {
        let name = CString::new("lo0").unwrap();
        // SAFETY: live NUL-terminated interface name.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert!(index > 0, "lo0 is required; no fallback to en0");
        let index = u16::try_from(index).unwrap();
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(2);
        let v4 = source_for("127.0.0.1".parse().unwrap(), 9, index, deadline, &cancel)
            .expect("v4 source");
        assert_eq!(v4, "127.0.0.1".parse::<IpAddr>().unwrap());
        let v6 =
            source_for("::1".parse().unwrap(), 9, index, deadline, &cancel).expect("v6 source");
        assert_eq!(v6, "::1".parse::<IpAddr>().unwrap());
        cancel.store(true, Ordering::Release);
        assert_eq!(
            source_for("127.0.0.1".parse().unwrap(), 9, index, deadline, &cancel),
            Err(Error::Canceled)
        );
    }
}
