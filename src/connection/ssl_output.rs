//! Drain untrusted client output into bounded typed observations. Raw output is
//! never retained in the driver, logs, snapshots or an error value.
use super::ssl::{InterfaceName, SslFailure};
use std::{
    io::{self, Read},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, Default)]
pub(super) struct Observation {
    pub candidate: Option<InterfaceName>,
    pub failure: Option<SslFailure>,
}

#[derive(Default)]
pub(super) struct Output {
    observed: Arc<Mutex<Observation>>,
    canceled: Arc<AtomicBool>,
    done: Arc<AtomicUsize>,
    workers: Vec<JoinHandle<()>>,
}

impl Output {
    pub fn attach(&mut self, pipe: impl Read + AsRawFd + Send + 'static) -> io::Result<()> {
        let fd = pipe.as_raw_fd();
        // SAFETY: pipe owns a live descriptor and fcntl takes integer flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let (observed, canceled, done) = (
            Arc::clone(&self.observed),
            Arc::clone(&self.canceled),
            Arc::clone(&self.done),
        );
        self.workers.push(
            thread::Builder::new()
                .name("vpnt-ssl-output".into())
                .spawn(move || {
                    drain(pipe, &observed, &canceled);
                    done.fetch_add(1, Ordering::Release);
                })?,
        );
        Ok(())
    }
    pub fn snapshot(&self) -> Observation {
        self.observed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
    pub fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_millis(100);
        while self.done.load(Ordering::Acquire) < self.workers.len() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        self.canceled.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        self.finish();
    }
}

fn drain(mut pipe: impl Read + AsRawFd, observed: &Mutex<Observation>, canceled: &AtomicBool) {
    let mut line = Zeroizing::new(Vec::with_capacity(4096));
    let mut chunk = Zeroizing::new([0; 4096]);
    let mut discarded = false;
    while !canceled.load(Ordering::Acquire) {
        let mut poll = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live descriptor and one correctly sized poll output.
        let result = unsafe { libc::poll(&mut poll, 1, 50) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if result == 0 {
            continue;
        }
        let length = match pipe.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        for byte in &chunk[..length] {
            if *byte == b'\n' {
                if !discarded {
                    parse(
                        &line,
                        &mut observed.lock().unwrap_or_else(|error| error.into_inner()),
                    );
                }
                line.zeroize();
                discarded = false;
            } else if !discarded {
                if line.len() == 4096 {
                    line.zeroize();
                    discarded = true;
                } else {
                    line.push(*byte);
                }
            }
        }
        chunk.zeroize();
    }
    // Incomplete/oversized lines are not candidates. Zeroizing also clears a
    // partial credential-bearing line when cancellation interrupts the reader.
}

fn parse(line: &[u8], observed: &mut Observation) {
    if line==b"ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc." {
        observed.failure=Some(SslFailure::CredentialsRejected);
    } else if (line==b"ERROR:  connect: Connection timed out" || line==b"ERROR:  connect: Operation timed out") && observed.failure.is_none() {
        observed.failure=Some(SslFailure::GatewayTimeout);
    } else if let Some(value)=line.strip_prefix(b"INFO:   Interface ").and_then(|value|value.strip_suffix(b" is UP."))
        && let Ok(name)=std::str::from_utf8(value)
        && let Some(name)=InterfaceName::parse(name)
    {
        observed.candidate=Some(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_bounded_messages_become_typed_observations() {
        let mut observed = Observation::default();
        for line in [
            b"INFO:   Tunnel is up and running.".as_slice(),
            b"INFO:   Interface en0 is UP.",
            b"INFO:   Interface ppp1;touch is UP.",
            b"password: fictional",
        ] {
            parse(line, &mut observed);
        }
        assert!(observed.candidate.is_none());
        assert!(observed.failure.is_none());
        parse(b"INFO:   Interface ppp12 is UP.", &mut observed);
        assert_eq!(observed.candidate.as_ref().unwrap().as_str(), "ppp12");
        assert!(!format!("{observed:?}").contains("fictional"));
    }
}
