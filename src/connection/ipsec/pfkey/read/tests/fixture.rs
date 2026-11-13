use super::super::{Budget, Error, socket};
use socket::Transport;
use std::{
    fs, io,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixDatagram,
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::Sender,
    },
    time::{Duration, Instant},
};
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) struct Fixture(PathBuf);
impl Fixture {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vpnt-pfkey-reader-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let result = Command::new("/usr/bin/xcrun")
            .args(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ipsec/pfkey_peer.c"),
            )
            .arg("-o")
            .arg(fixture.0.join("peer"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "peer compile: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        fixture
    }
    pub fn peer(&self, mode: &str) -> Peer {
        let (channel, remote) = UnixDatagram::pair().unwrap();
        socket::configure(channel.as_raw_fd()).unwrap();
        let fd: OwnedFd = remote.into();
        let child = Command::new(self.0.join("peer"))
            .arg(mode)
            .env_clear()
            .stdin(Stdio::from(fd))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Peer {
            channel,
            child: Some(child),
            ready: None,
            expire_after_ready: false,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub(super) struct Peer {
    channel: UnixDatagram,
    child: Option<Child>,
    pub ready: Option<Sender<()>>,
    pub expire_after_ready: bool,
}
impl Peer {
    pub fn finish(mut self) {
        assert!(
            self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            "peer alive until release"
        );
        self.channel.send(b"release").unwrap();
        let output = self.child.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "peer exit: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = self.channel.send(b"release");
            let _ = child.wait();
        }
    }
}
impl Transport for Peer {
    fn send(&self, query: &[u8; 16], budget: &Budget) -> Result<(), Error> {
        socket::send(self.channel.as_raw_fd(), query, budget)?;
        // key_output builds/enqueues its replies before send returns. This
        // independent peer signals the same boundary instead of racing poll(0).
        let fd = self
            .child
            .as_ref()
            .unwrap()
            .stdout
            .as_ref()
            .unwrap()
            .as_raw_fd();
        // The child's exec and startup are fixture overhead, not collector
        // time, so wait for the readiness byte under a fixture-owned ceiling
        // instead of spending the collector's absolute budget on the exec.
        let ready_by = Instant::now() + Duration::from_secs(5);
        loop {
            let mut p = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: live pipe descriptor and initialized output.
            let n = unsafe { libc::poll(&mut p, 1, 25) };
            if n < 0 {
                return Err(socket::map(io::Error::last_os_error()));
            }
            if n == 0 {
                assert!(
                    Instant::now() < ready_by,
                    "fixture peer did not signal readiness within 5 s"
                );
                continue;
            }
            let mut byte = [0u8; 1];
            // SAFETY: the pipe is readable and the byte output is live.
            if unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) } != 1 || byte != *b"R" {
                return Err(Error::Unavailable);
            }
            if let Some(sender) = &self.ready {
                sender.send(()).unwrap();
            }
            // A fixed original Budget is intentionally retained while
            // processing consumes time; this is not a per-message timeout.
            if self.expire_after_ready {
                std::thread::sleep(Duration::from_millis(160));
            }
            return Ok(());
        }
    }
    fn receive(&self, bytes: &mut [u8], budget: &Budget) -> Result<usize, Error> {
        // The expired-send fixture proves the collector re-checks the one
        // absolute Budget after processing; a re-based deadline would resume
        // IO here and must fail instead of silently waiting again.
        assert!(
            !self.expire_after_ready,
            "receive resumed after the send exhausted the absolute deadline"
        );
        let received = socket::receive(self.channel.as_raw_fd(), bytes, budget)?;
        // Fixture-only unnamed AF_UNIX channel; production requires AF_KEY.
        assert!(
            !received.kernel_source(),
            "fixture cannot impersonate AF_KEY"
        );
        Ok(received.length)
    }
    fn pending(&self, budget: &Budget) -> Result<bool, Error> {
        socket::pending(self.channel.as_raw_fd(), budget)
    }
}
