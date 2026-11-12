//! One command per peer-authenticated connection, with a total I/O deadline.
use super::{Error, Message, Packet, read_packet, valid_name, write_packet};
use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    time::{Duration, Instant},
};
const MAX_EVENTS: usize = 256;
const MAX_RECEIVED: usize = 4 * 1024 * 1024;

pub struct CommandResult {
    pub response: Message,
    pub events: Vec<(String, Message)>,
}

pub struct Client {
    stream: UnixStream,
    timeout: Duration,
}

impl Client {
    /// The driver supplies a socket inside its admitted root-owned directory.
    /// This check also rejects a different user impersonating a charon peer.
    pub fn connect(path: &Path, owner: u32, timeout: Duration) -> Result<Self, Error> {
        if !path.is_absolute() {
            return Err(Error::InvalidMessage);
        }
        Self::from_stream(connect_deadline(path, timeout)?, owner, timeout)
    }
    pub fn from_stream(stream: UnixStream, owner: u32, timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err(Error::Timeout);
        }
        if peer_uid(&stream)? != owner {
            return Err(Error::UntrustedPeer);
        }
        stream.set_nonblocking(true)?;
        Ok(Self { stream, timeout })
    }
    pub fn command(
        self,
        name: &str,
        message: Message,
        events: &[&str],
    ) -> Result<CommandResult, Error> {
        if !valid_name(name) || events.iter().any(|name| !valid_name(name)) {
            return Err(Error::InvalidMessage);
        }
        let registered: BTreeSet<_> = events.iter().copied().collect();
        if registered.len() != events.len() || registered.len() > 16 {
            return Err(Error::Limit);
        }
        let mut stream = DeadlineStream {
            stream: self.stream,
            deadline: Instant::now()
                .checked_add(self.timeout)
                .ok_or(Error::Timeout)?,
            received: 0,
        };
        let mut received = Vec::new();
        // Do not expect confirmations before events from subscriptions that
        // have already been confirmed: charon can emit at any time.
        let mut confirmed = BTreeSet::new();
        for event in events {
            write_packet(&mut stream, &Packet::Register((*event).into()))?;
            loop {
                match read_packet(&mut stream)? {
                    Packet::Confirm => {
                        confirmed.insert(*event);
                        break;
                    }
                    Packet::UnknownEvent => return Err(Error::UnknownEvent),
                    Packet::Event(name, message) if confirmed.contains(name.as_str()) => {
                        push_event(&mut received, name, message)?
                    }
                    _ => return Err(Error::UnexpectedPacket),
                }
            }
        }
        write_packet(&mut stream, &Packet::Request(name.into(), message))?;
        loop {
            match read_packet(&mut stream)? {
                Packet::Response(response) => {
                    return Ok(CommandResult {
                        response,
                        events: received,
                    });
                }
                Packet::UnknownCommand => return Err(Error::UnknownCommand),
                Packet::Event(name, message) if registered.contains(name.as_str()) => {
                    push_event(&mut received, name, message)?
                }
                _ => return Err(Error::UnexpectedPacket),
            }
        }
        // Dropping this connection removes its subscriptions at charon. A new
        // connection is mandatory for any subsequent command, including cancel.
    }
}

fn connect_deadline(path: &Path, timeout: Duration) -> Result<UnixStream, Error> {
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
    let deadline = Instant::now().checked_add(timeout).ok_or(Error::Timeout)?;
    if timeout.is_zero() {
        return Err(Error::Timeout);
    }
    let path = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is a C struct whose all-zero representation is valid.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.is_empty() || path.len() >= address.sun_path.len() || path.contains(&0) {
        return Err(Error::InvalidMessage);
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
        return Err(Error::Io);
    }
    // SAFETY: transfer the newly created descriptor into exactly one owner.
    let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
    // SAFETY: descriptor is owned and valid; F_SETFD accepts integer flag bits.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(Error::Io);
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
            return Err(error.into());
        }
        let pending = DeadlineStream {
            stream,
            deadline,
            received: 0,
        };
        pending.wait(libc::POLLOUT)?;
        if let Some(error) = pending.stream.take_error()? {
            return Err(error.into());
        }
        return Ok(pending.stream);
    }
    Ok(stream)
}

fn push_event(
    events: &mut Vec<(String, Message)>,
    name: String,
    message: Message,
) -> Result<(), Error> {
    if events.len() >= MAX_EVENTS {
        return Err(Error::Limit);
    }
    events.push((name, message));
    Ok(())
}

struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
    received: usize,
}

impl DeadlineStream {
    fn wait(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
            let milliseconds = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
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
                // HUP is readable: drain buffered data before returning EOF.
                // In particular, Darwin rejects setting SO_RCVTIMEO after the
                // peer closes even when a complete reply remains buffered.
                return Ok(());
            }
        }
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let available = MAX_RECEIVED.saturating_sub(self.received);
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
impl Write for DeadlineStream {
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
        self.stream.flush()
    }
}

fn peer_uid(stream: &UnixStream) -> Result<u32, Error> {
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
            return Err(Error::UntrustedPeer);
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
            return Err(Error::UntrustedPeer);
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
        Err(Error::UntrustedPeer)
    }
}
