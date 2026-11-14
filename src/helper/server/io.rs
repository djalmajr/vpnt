use super::interrupted;
use std::{
    io::{self, BufRead, Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) const DEADLINE: Duration = Duration::from_secs(5);
const POLL_MS: i32 = 20;

pub(super) struct Input {
    stream: UnixStream,
    buffer: zeroize::Zeroizing<[u8; 8192]>,
    head: usize,
    tail: usize,
    stop: Arc<AtomicBool>,
    deadline: Option<Instant>,
}
impl Input {
    pub fn new(stream: UnixStream, stop: Arc<AtomicBool>) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            stop,
            deadline: None,
            buffer: zeroize::Zeroizing::new([0; 8192]),
            head: 0,
            tail: 0,
        })
    }
    pub fn begin(&mut self, buffered: bool) {
        self.deadline = (buffered || self.head < self.tail).then(|| Instant::now() + DEADLINE);
    }
}
impl BufRead for Input {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.head < self.tail {
            return Ok(&self.buffer[self.head..self.tail]);
        }
        loop {
            if self.stop.load(Ordering::Acquire) || interrupted() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            wait(&self.stream, libc::POLLIN, self.deadline)?;
            match self.stream.read(&mut self.buffer[..]) {
                Ok(count) => {
                    if count > 0 && self.deadline.is_none() {
                        self.deadline = Some(Instant::now() + DEADLINE);
                    }
                    self.head = 0;
                    self.tail = count;
                    return Ok(&self.buffer[..count]);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
    }
    fn consume(&mut self, amount: usize) {
        use zeroize::Zeroize;
        let end = self.head + amount.min(self.tail - self.head);
        self.buffer[self.head..end].zeroize();
        self.head = end;
    }
}
impl Read for Input {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let available = self.fill_buf()?;
        let count = bytes.len().min(available.len());
        bytes[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}
pub(super) struct Output<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}
impl<'a> Output<'a> {
    pub fn new(stream: &'a mut UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            deadline: Instant::now() + DEADLINE,
        })
    }
}
impl Write for Output<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            wait(self.stream, libc::POLLOUT, Some(self.deadline))?;
            match self.stream.write(bytes) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn wait(stream: &UnixStream, events: i16, deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|d| Instant::now() >= d) {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let mut item = libc::pollfd {
        fd: stream.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: one live socket and matching output struct; short polling lets
    // EOF, cancellation and process signals reach the controller promptly.
    let result = unsafe { libc::poll(&mut item, 1, POLL_MS) };
    if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consumed_secret_bytes_are_erased_without_corrupting_the_next_buffered_frame() {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(b"fictional-secret\nnext-frame\n").unwrap();
        let mut input = Input::new(a, Arc::new(AtomicBool::new(false))).unwrap();
        let mut first = String::new();
        input.read_line(&mut first).unwrap();
        assert_eq!(first, "fictional-secret\n");
        assert!(input.buffer[..first.len()].iter().all(|byte| *byte == 0));
        let mut second = String::new();
        input.read_line(&mut second).unwrap();
        assert_eq!(second, "next-frame\n");
    }
}
