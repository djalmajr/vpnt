use super::{Address, Error, Record, codec};
use crate::connection::macos::tcp;
use std::{
    io,
    mem::{offset_of, size_of},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
    time::{Duration, Instant},
};
static NEXT_QUERY: AtomicI32 = AtomicI32::new(1);
const MAX_TABLE: usize = 8 * 1024 * 1024;
#[derive(Debug)]
pub struct Snapshot {
    pub records: Vec<Record>,
}
impl Snapshot {
    /// Exact destination/mask/scope, never a longest-prefix approximation.
    /// Multiple entries with the same key are uncertain, not an arbitrary hit.
    pub fn exact(&self, key: super::Key) -> Result<Option<&Record>, Error> {
        let mut records = self.records.iter().filter(|record| record.key == key);
        let first = records.next();
        if records.next().is_some() {
            return Err(Error::Conflict);
        }
        Ok(first)
    }
    pub fn read() -> Result<Self, Error> {
        for _ in 0..3 {
            let mut mib = [
                libc::CTL_NET,
                libc::PF_ROUTE,
                0,
                libc::AF_UNSPEC,
                libc::NET_RT_DUMP2,
                0,
            ];
            let mut length = 0;
            // SAFETY: MIB/length are correctly sized; null output asks only for size.
            if unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    ptr::null_mut(),
                    &mut length,
                    ptr::null_mut(),
                    0,
                )
            } != 0
            {
                return Err(Error::Unavailable);
            }
            if length > MAX_TABLE {
                return Err(Error::Limit);
            }
            if length == 0 {
                return Ok(Self {
                    records: Vec::new(),
                });
            }
            let mut bytes = vec![0u8; length];
            // SAFETY: bytes owns the advertised writable buffer. Kernel reports
            // the actual length, which is checked before parsing any records.
            if unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    bytes.as_mut_ptr().cast(),
                    &mut length,
                    ptr::null_mut(),
                    0,
                )
            } != 0
            {
                if io::Error::last_os_error().raw_os_error() == Some(libc::ENOMEM) {
                    continue;
                }
                return Err(Error::Unavailable);
            }
            if length > bytes.len() {
                return Err(Error::Invalid);
            }
            bytes.truncate(length);
            return Self::parse(&bytes);
        }
        Err(Error::Unavailable)
    }
    pub(super) fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        let mut records = Vec::new();
        while !bytes.is_empty() {
            let frame = codec::frame(bytes)?;
            if frame[3] != libc::RTM_GET2 as u8 {
                return Err(Error::Invalid);
            }
            if records.len() >= 65_536 {
                return Err(Error::Limit);
            }
            records.push(codec::record(frame, codec::DUMP)?);
            bytes = &bytes[frame.len()..];
        }
        Ok(Self { records })
    }
}
pub struct Reader {
    pub(super) fd: OwnedFd,
}
impl Reader {
    pub fn open() -> Result<Self, Error> {
        // SAFETY: socket has no memory arguments and returns a new descriptor.
        let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if fd < 0 {
            return Err(Error::Unavailable);
        }
        // SAFETY: transfer this new descriptor into exactly one owner.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: fcntl is called only with valid integer flags on our descriptor.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0
        {
            return Err(Error::Unavailable);
        }
        Ok(Self { fd })
    }
    /// Fixed RTM_GET only. No raw-message/write API or mutating command exists.
    pub fn lookup(
        &mut self,
        address: Address,
        scope: u16,
        timeout: Duration,
        canceled: &AtomicBool,
    ) -> Result<Record, Error> {
        if canceled.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        if timeout.is_zero() || timeout > Duration::from_secs(2) {
            return Err(Error::Invalid);
        }
        let mut sequence = NEXT_QUERY.load(Ordering::Relaxed);
        loop {
            let next = sequence.checked_add(1).ok_or(Error::Limit)?;
            match NEXT_QUERY.compare_exchange_weak(
                sequence,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => sequence = current,
            }
        }
        let pid = i32::try_from(std::process::id()).map_err(|_| Error::Invalid)?;
        let packet = codec::query(address, scope, pid, sequence)?;
        let deadline = Instant::now() + timeout;
        tcp::wait(self.fd.as_raw_fd(), libc::POLLOUT, deadline, canceled).map_err(wait_error)?;
        // SAFETY: packet is a live byte buffer containing only a fixed GET query.
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != packet.len() as isize {
            return Err(Error::Unavailable);
        }
        let mut bytes = vec![0u8; 65_536];
        for _ in 0..4096 {
            tcp::wait(self.fd.as_raw_fd(), libc::POLLIN, deadline, canceled).map_err(wait_error)?;
            // SAFETY: recv writes at most bytes.len() bytes to our live buffer.
            // The u16 message length fits in this capacity; no message can be
            // silently accepted after truncation.
            let length = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                )
            };
            if length < 0 {
                if matches!(
                    io::Error::last_os_error().kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(Error::Unavailable);
            }
            let frame = codec::frame(&bytes[..length as usize])?;
            if frame.len() != length as usize {
                return Err(Error::Invalid);
            }
            if frame[3] != libc::RTM_GET as u8 {
                continue;
            }
            if frame.len() < size_of::<libc::rt_msghdr>() {
                return Err(Error::Invalid);
            }
            if codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_pid))? != pid
                || codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_seq))? != sequence
            {
                continue;
            }
            let errno = codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_errno))?;
            if errno != 0 {
                return Err(if errno == libc::ESRCH {
                    Error::Changed
                } else {
                    Error::Unavailable
                });
            }
            if canceled.load(Ordering::Acquire) {
                return Err(Error::Canceled);
            }
            if Instant::now() >= deadline {
                return Err(Error::TimedOut);
            }
            let record = codec::record(frame, codec::CLASSIC)?;
            if !record.key.network.contains(address.ip) {
                return Err(Error::Invalid);
            }
            return Ok(record);
        }
        Err(Error::Limit)
    }
}
fn wait_error(error: tcp::Error) -> Error {
    match error {
        tcp::Error::Canceled => Error::Canceled,
        tcp::Error::TimedOut => Error::TimedOut,
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
