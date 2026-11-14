//! Peer authentication and bounded nonblocking I/O for private local channels.
use std::{
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    time::Duration,
};
#[path = "local_socket/budget.rs"]
mod budget;
pub(crate) use budget::{Budget, Canceled};

pub(crate) fn connect_deadline(path: &Path, budget: &Budget) -> io::Result<UnixStream> {
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
    budget.check()?;
    let path = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is a C struct whose all-zero representation is valid.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.is_empty() || path.len() >= address.sun_path.len() || path.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(path) {
        *target = *byte as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        address.sun_len = length as u8;
    }
    // SAFETY: socket has no memory preconditions and returns a new owned FD.
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: transfer the newly created descriptor into exactly one owner.
    let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
    // SAFETY: descriptor is owned and valid; F_SETFD accepts integer flag bits.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    stream.set_nonblocking(true)?;
    // SAFETY: pointer refers to a complete sockaddr_un and length includes the
    // initialized path plus terminator within that struct.
    let result = unsafe {
        libc::connect(
            descriptor,
            (&address as *const libc::sockaddr_un).cast(),
            length as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let pending = TimedStream {
            stream,
            budget: budget.clone(),
            received: 0,
            limit: 1,
        };
        pending.wait(libc::POLLOUT)?;
        if let Some(error) = pending.stream.take_error()? {
            return Err(error);
        }
        return Ok(pending.stream);
    }
    budget.check()?;
    Ok(stream)
}

pub(crate) struct TimedStream {
    stream: UnixStream,
    budget: Budget,
    received: usize,
    limit: usize,
}

impl TimedStream {
    pub(crate) fn new(stream: UnixStream, timeout: Duration, limit: usize) -> io::Result<Self> {
        Self::with_budget(stream, Budget::new(timeout)?, limit)
    }
    pub(crate) fn with_budget(
        stream: UnixStream,
        budget: Budget,
        limit: usize,
    ) -> io::Result<Self> {
        if limit == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        budget.check()?;
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            budget,
            received: 0,
            limit,
        })
    }
    pub(crate) fn shutdown_write(&self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Write)
    }

    fn wait(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let milliseconds = self.budget.poll_timeout()?;
            let mut descriptor = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: poll receives one live descriptor and a valid output struct.
            let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            } else if result > 0 {
                self.budget.check()?;
                // HUP is readable: drain buffered data before returning EOF.
                // In particular, Darwin rejects setting SO_RCVTIMEO after the
                // peer closes even when a complete reply remains buffered.
                return Ok(());
            }
        }
    }
}
impl Read for TimedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let available = self.limit.saturating_sub(self.received);
        if available == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let length = bytes.len().min(available);
        loop {
            self.wait(libc::POLLIN)?;
            match self.stream.read(&mut bytes[..length]) {
                Ok(read) => {
                    self.received += read;
                    return Ok(read);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
}
impl Write for TimedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.wait(libc::POLLOUT)?;
            match self.stream.write(bytes) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.budget.check()?;
        self.stream.flush()
    }
}

pub(crate) fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let mut uid = 0;
        let mut gid = 0;
        // SAFETY: the stream owns a live descriptor; output pointers are valid.
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(uid)
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: ucred is a plain C struct and all-zero bits are valid.
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: descriptor is live, the buffer and length have matching sizes.
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of::<libc::ucred>()
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(credentials.uid)
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "linux"
    )))]
    {
        let _ = stream;
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}
