use super::{Budget, Error};
use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};
pub(super) trait Transport {
    fn send(&self, request: &[u8; 16], budget: &Budget) -> Result<(), Error>;
    fn receive(&self, bytes: &mut [u8], budget: &Budget) -> Result<usize, Error>;
    fn pending(&self, budget: &Budget) -> Result<bool, Error>;
}
pub(super) struct Kernel {
    pub(super) fd: OwnedFd,
}
impl Kernel {
    pub fn open(budget: &Budget) -> Result<Self, Error> {
        budget.check().map_err(map)?;
        // SAFETY: no pointers; this returns a new descriptor owned below.
        let raw = unsafe { libc::socket(libc::PF_KEY, libc::SOCK_RAW, 2) };
        if raw < 0 {
            return Err(Error::Unavailable);
        }
        // SAFETY: exactly one owner for the freshly-created descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        configure(fd.as_raw_fd())?;
        let size: libc::c_int = 4 * 1024 * 1024;
        // Per-socket only; no sysctl/global network configuration changes.
        // SAFETY: size is a live integer of the advertised length.
        if unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&size as *const libc::c_int).cast(),
                mem::size_of_val(&size) as _,
            )
        } != 0
        {
            return Err(Error::Unavailable);
        }
        budget.check().map_err(map)?;
        Ok(Self { fd })
    }
}
impl Transport for Kernel {
    fn send(&self, request: &[u8; 16], budget: &Budget) -> Result<(), Error> {
        send(self.fd.as_raw_fd(), request, budget)
    }
    fn receive(&self, bytes: &mut [u8], budget: &Budget) -> Result<usize, Error> {
        let received = receive(self.fd.as_raw_fd(), bytes, budget)?;
        if !received.kernel_source() {
            return Err(Error::Changed);
        }
        Ok(received.length)
    }
    fn pending(&self, budget: &Budget) -> Result<bool, Error> {
        pending(self.fd.as_raw_fd(), budget)
    }
}
pub(super) fn configure(fd: RawFd) -> Result<(), Error> {
    // SAFETY: callers retain a live owned FD; only integer flags are passed.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}
fn healthy(fd: RawFd) -> Result<(), Error> {
    let mut error: libc::c_int = 0;
    let mut length = mem::size_of_val(&error) as libc::socklen_t;
    // SAFETY: live descriptor, correctly-sized integer and length outputs.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut error as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
        || length as usize != mem::size_of_val(&error)
        || error != 0
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}
pub(super) fn wait(fd: RawFd, events: libc::c_short, budget: &Budget) -> Result<(), Error> {
    loop {
        let timeout = budget.poll_timeout().map_err(map)?;
        let mut p = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: initialized pollfd output remains live during this call.
        let n = unsafe { libc::poll(&mut p, 1, timeout) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Unavailable);
        }
        budget.check().map_err(map)?;
        if n > 0 {
            healthy(fd)?;
            if p.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
                return Err(Error::Unavailable);
            }
            return Ok(());
        }
    }
}
pub(super) fn pending(fd: RawFd, budget: &Budget) -> Result<bool, Error> {
    budget.check().map_err(map)?;
    healthy(fd)?;
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live descriptor, initialized output and zero timeout.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    if n < 0 || p.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
        return Err(Error::Unavailable);
    }
    budget.check().map_err(map)?;
    Ok(n > 0)
}
pub(super) fn send(fd: RawFd, request: &[u8; 16], budget: &Budget) -> Result<(), Error> {
    wait(fd, libc::POLLOUT, budget)?;
    // SAFETY: request is a complete fixed-size read-only query. Never replay
    // an uncertain send, including EINTR; dropping this socket isolates it.
    let n = unsafe {
        libc::send(
            fd,
            request.as_ptr().cast(),
            request.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if n != request.len() as isize {
        return Err(Error::Unavailable);
    }
    budget.check().map_err(map)
}
pub(super) struct Received {
    pub length: usize,
    pub source: libc::sockaddr_storage,
    pub source_length: libc::socklen_t,
}
impl Received {
    pub fn kernel_source(&self) -> bool {
        self.source_length == 2
            && self.source.ss_len == 2
            && i32::from(self.source.ss_family) == libc::PF_KEY
    }
}
pub(super) fn receive(fd: RawFd, bytes: &mut [u8], budget: &Budget) -> Result<Received, Error> {
    loop {
        wait(fd, libc::POLLIN, budget)?;
        // SAFETY: plain C output structs have valid all-zero representations.
        let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        message.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
        message.msg_namelen = mem::size_of_val(&source) as _;
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        // SAFETY: message points to live initialized outputs and our writable
        // buffer; no ancillary buffer or descriptor transfer is accepted.
        let n = unsafe { libc::recvmsg(fd, &mut message, 0) };
        if n < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(Error::Unavailable);
        }
        budget.check().map_err(map)?;
        if n == 0 {
            return Err(Error::Unavailable);
        }
        if n as usize > bytes.len() || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err(Error::Invalid);
        }
        return Ok(Received {
            length: n as usize,
            source,
            source_length: message.msg_namelen,
        });
    }
}
pub(super) fn map(error: io::Error) -> Error {
    match crate::helper::vici::Error::from(error) {
        crate::helper::vici::Error::Canceled => Error::Canceled,
        crate::helper::vici::Error::Timeout => Error::Timeout,
        _ => Error::Unavailable,
    }
}
