//! No fallback to an unbound socket: both the interface and source address are
//! mandatory. The caller separately proves that these belong to its tunnel.
use super::interfaces::address;
use std::{
    io, mem,
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Canceled,
    TimedOut,
    Failed,
    Invalid,
}

pub(super) fn wait(
    fd: libc::c_int,
    events: libc::c_short,
    deadline: Instant,
    canceled: &AtomicBool,
) -> Result<(), Error> {
    wait_ready(
        &mut [libc::pollfd {
            fd,
            events,
            revents: 0,
        }],
        deadline,
        canceled,
    )
}

pub(super) fn wait_ready(
    descriptors: &mut [libc::pollfd],
    deadline: Instant,
    canceled: &AtomicBool,
) -> Result<(), Error> {
    if descriptors.is_empty() || descriptors.len() > 2 {
        return Err(Error::Invalid);
    }
    loop {
        if canceled.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::TimedOut)?;
        if remaining.is_zero() {
            return Err(Error::TimedOut);
        }
        let millis = remaining.as_millis().saturating_add(1).min(25) as i32;
        // SAFETY: all descriptor entries are initialized and a finite timeout
        // is supplied. poll writes only their revents fields.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                millis,
            )
        };
        if result < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(Error::Failed);
            }
        } else if result > 0 {
            return Ok(());
        }
    }
}

enum Address {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}
impl Address {
    fn new(value: SocketAddr, index: u32) -> Self {
        match value {
            SocketAddr::V4(value) => {
                // SAFETY: sockaddr_in consists of plain integer fields/arrays.
                let mut address: libc::sockaddr_in = unsafe { mem::zeroed() };
                address.sin_len = mem::size_of_val(&address) as u8;
                address.sin_family = libc::AF_INET as u8;
                address.sin_port = value.port().to_be();
                address.sin_addr.s_addr = u32::from_ne_bytes(value.ip().octets());
                Self::V4(address)
            }
            SocketAddr::V6(value) => {
                // SAFETY: sockaddr_in6 consists of plain integer fields/arrays.
                let mut address: libc::sockaddr_in6 = unsafe { mem::zeroed() };
                address.sin6_len = mem::size_of_val(&address) as u8;
                address.sin6_family = libc::AF_INET6 as u8;
                address.sin6_port = value.port().to_be();
                address.sin6_addr.s6_addr = value.ip().octets();
                if value.ip().is_unicast_link_local() {
                    address.sin6_scope_id = index;
                }
                Self::V6(address)
            }
        }
    }
    fn raw(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            Self::V4(value) => (
                (value as *const libc::sockaddr_in).cast(),
                mem::size_of_val(value) as libc::socklen_t,
            ),
            Self::V6(value) => (
                (value as *const libc::sockaddr_in6).cast(),
                mem::size_of_val(value) as libc::socklen_t,
            ),
        }
    }
}

pub(super) fn connect(
    index: u32,
    source: IpAddr,
    target: SocketAddr,
    deadline: Instant,
    canceled: &AtomicBool,
) -> Result<OwnedFd, Error> {
    if index == 0
        || source.is_ipv4() != target.is_ipv4()
        || target.port() == 0
        || target.port() == 22
    {
        return Err(Error::Invalid);
    }
    if canceled.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    if deadline <= Instant::now() {
        return Err(Error::TimedOut);
    }
    let family = if target.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket has no memory arguments and yields a new owned descriptor.
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(Error::Failed);
    }
    // SAFETY: fd was freshly created and is transferred into one owner.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let raw = fd.as_raw_fd();
    // SAFETY: fcntl operates on the live owned descriptor with integer flags.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(raw, libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(Error::Failed);
    }
    let (level, option) = if target.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    };
    // SAFETY: index is a correctly sized interface-index socket option value.
    if unsafe {
        libc::setsockopt(
            raw,
            level,
            option,
            (&index as *const u32).cast(),
            mem::size_of_val(&index) as libc::socklen_t,
        )
    } != 0
    {
        return Err(Error::Failed);
    }
    let source_address = Address::new(SocketAddr::new(source, 0), index);
    let (pointer, length) = source_address.raw();
    // SAFETY: pointer and length refer to the live native source sockaddr.
    if unsafe { libc::bind(raw, pointer, length) } != 0 {
        return Err(Error::Failed);
    }
    let target_address = Address::new(target, index);
    let (pointer, length) = target_address.raw();
    // SAFETY: pointer and length refer to the live native target sockaddr.
    if unsafe { libc::connect(raw, pointer, length) } != 0 {
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(Error::Failed);
        }
        wait(raw, libc::POLLOUT, deadline, canceled)?;
        let mut result: libc::c_int = 0;
        let mut length = mem::size_of_val(&result) as libc::socklen_t;
        // SAFETY: SO_ERROR writes one native integer into the supplied buffer.
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut result as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
            || result != 0
            || length as usize != mem::size_of_val(&result)
        {
            return Err(Error::Failed);
        }
    }
    if canceled.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    let mut bound = 0u32;
    let mut length = mem::size_of_val(&bound) as libc::socklen_t;
    // SAFETY: the option is read into a correctly sized native index buffer.
    if unsafe {
        libc::getsockopt(
            raw,
            level,
            option,
            (&mut bound as *mut u32).cast(),
            &mut length,
        )
    } != 0
        || bound != index
        || length as usize != mem::size_of_val(&bound)
    {
        return Err(Error::Failed);
    }
    // SAFETY: sockaddr_storage is an all-integer native storage buffer.
    let mut local: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut length = mem::size_of_val(&local) as libc::socklen_t;
    // SAFETY: getsockname writes within the storage size; address() checks its
    // native family/length before reading the corresponding sockaddr fields.
    if unsafe {
        libc::getsockname(
            raw,
            (&mut local as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } != 0
        || unsafe { address((&local as *const libc::sockaddr_storage).cast()) } != Some(source)
    {
        return Err(Error::Failed);
    }
    if canceled.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    if deadline <= Instant::now() {
        return Err(Error::TimedOut);
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CString, net::TcpListener, time::Duration};
    #[test]
    fn kernel_wait_honors_a_deadline_and_an_in_flight_cancellation() {
        use std::{os::unix::net::UnixStream, thread};
        let (read, _write) = UnixStream::pair().unwrap();
        let canceled = AtomicBool::new(false);
        let start = Instant::now();
        assert_eq!(
            wait(
                read.as_raw_fd(),
                libc::POLLIN,
                start + Duration::from_millis(30),
                &canceled
            ),
            Err(Error::TimedOut)
        );
        assert!(start.elapsed() < Duration::from_millis(250));
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(20));
                canceled.store(true, Ordering::Release);
            });
            let start = Instant::now();
            assert_eq!(
                wait(
                    read.as_raw_fd(),
                    libc::POLLIN,
                    start + Duration::from_secs(2),
                    &canceled
                ),
                Err(Error::Canceled)
            );
            assert!(start.elapsed() < Duration::from_millis(250));
        });
    }
    #[test]
    fn actual_loopback_connection_is_rejected_when_interface_or_source_is_invalid() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap();
        let name = CString::new("lo0").unwrap();
        // SAFETY: name is a live NUL-terminated native interface name.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(index, 0);
        let canceled = AtomicBool::new(false);
        let source = "127.0.0.1".parse().unwrap();
        let connection = connect(
            index,
            source,
            target,
            Instant::now() + Duration::from_secs(1),
            &canceled,
        )
        .unwrap();
        listener.accept().unwrap();
        drop(connection);
        assert!(
            connect(
                u32::MAX,
                source,
                target,
                Instant::now() + Duration::from_millis(100),
                &canceled
            )
            .is_err()
        );
        let interfaces = super::super::Interfaces::read().unwrap();
        let unavailable = ["192.0.2.200", "198.51.100.200", "203.0.113.200"]
            .into_iter()
            .map(|value| value.parse::<IpAddr>().unwrap())
            .find(|value| {
                !interfaces
                    .entries
                    .values()
                    .any(|interface| interface.addresses.contains(value))
            })
            .unwrap();
        assert!(
            connect(
                index,
                unavailable,
                target,
                Instant::now() + Duration::from_millis(100),
                &canceled
            )
            .is_err()
        );
        canceled.store(true, Ordering::Release);
        assert!(matches!(
            connect(
                index,
                source,
                target,
                Instant::now() + Duration::from_secs(1),
                &canceled
            ),
            Err(Error::Canceled)
        ));
    }
}
