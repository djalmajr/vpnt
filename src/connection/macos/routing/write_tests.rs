use super::*;
use std::{
    fs,
    os::unix::{net::UnixDatagram, process::CommandExt},
    path::PathBuf,
    process::{Child, Command},
    sync::Arc,
    thread,
};

struct Fixture {
    directory: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!("route-add-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let output = Command::new("/usr/bin/cc")
            .arg(format!(
                "-DVPNT_ATTACH={}",
                crate::connection::macos::ppp_attachment::ATTACH
            ))
            .arg(format!(
                "-DVPNT_GET_UNIT={}",
                crate::connection::macos::ppp_attachment::GET_UNIT
            ))
            .arg(root.join("tests/fixtures/route_add.c"))
            .arg("-o")
            .arg(directory.join("consumer"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "C ABI consumer must compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self { directory }
    }
    fn consumer(&self, mode: &str) -> Consumer {
        let (client, server) = UnixDatagram::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let raw = server.as_raw_fd();
        let mut command = Command::new(self.directory.join("consumer"));
        command.arg(mode);
        // SAFETY: the child only duplicates a still-live owned FD and clears
        // CLOEXEC on target 3. Both operations are async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                if raw != 3 && libc::dup2(raw, 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        drop(server);
        let consumer = Consumer {
            fd: client.into(),
            child,
        };
        let mut ready = [0; 5];
        // SAFETY: the owned socket and five-byte output buffer remain live.
        // Wait for exec/startup before measuring the actual exchange deadline.
        assert_eq!(
            unsafe {
                libc::recv(
                    consumer.fd.as_raw_fd(),
                    ready.as_mut_ptr().cast(),
                    ready.len(),
                    0,
                )
            },
            5
        );
        assert_eq!(&ready, b"READY");
        // SAFETY: this changes flags on our own still-live socket only.
        assert_eq!(
            unsafe { libc::fcntl(consumer.fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        consumer
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
struct Consumer {
    fd: OwnedFd,
    child: Child,
}
impl Consumer {
    fn finish(&mut self) {
        assert!(self.child.wait().unwrap().success());
    }
}
impl Drop for Consumer {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
fn plan(mode: &str) -> (Route, Address) {
    let (network, source) = match mode {
        "v6" => ("2001:db8:42::/64", "2001:db8::2"),
        "v6link" => ("2001:db8:42::/64", "fe80::2"),
        "blackhole" => ("::/1", "2001:db8::2"),
        "host" => ("198.51.100.2/32", "10.20.0.2"),
        _ => ("10.40.0.0/16", "10.20.0.2"),
    };
    (
        Route {
            key: Key {
                network: network.parse().unwrap(),
                scope: 0,
            },
            interface: 234,
            next_hop: if mode == "blackhole" {
                NextHop::Blackhole
            } else {
                NextHop::Interface
            },
        },
        Address {
            ip: source.parse().unwrap(),
            zone: if mode == "v6link" { 234 } else { 0 },
        },
    )
}
#[test]
fn add_consumer_uses_sdk_abi_and_retains_unconfirmed_attempts() {
    let fixture = Fixture::new();
    for (mode, expected) in [
        ("ok", Ok(())),
        ("v6", Ok(())),
        ("v6link", Ok(())),
        ("blackhole", Ok(())),
        ("host", Ok(())),
        ("foreign", Ok(())),
        ("exists", Err(Error::Conflict)),
        ("changed", Err(Error::Changed)),
        ("truncated", Err(Error::Invalid)),
        ("lost", Err(Error::Unavailable)),
        ("silent", Err(Error::TimedOut)),
    ] {
        let mut consumer = fixture.consumer(mode);
        let (route, source) = plan(mode);
        let receipt = exchange(
            &consumer.fd,
            route,
            source,
            Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(receipt.route(), route);
        assert_eq!(receipt.confirmation(), expected, "mode {mode}");
        consumer.finish();
    }
}
#[test]
fn cancellation_after_dispatch_keeps_a_receipt_and_precancel_sends_nothing() {
    let (client, server) = UnixDatagram::pair().unwrap();
    client.set_nonblocking(true).unwrap();
    let fd: OwnedFd = client.into();
    let (route, source) = plan("ok");
    let cancel = Arc::new(AtomicBool::new(false));
    let notify = cancel.clone();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let worker = thread::spawn(move || {
        assert!(server.recv(&mut [0; 1024]).unwrap() > 0);
        notify.store(true, Ordering::Release);
    });
    let receipt = exchange(&fd, route, source, Duration::from_secs(1), &cancel).unwrap();
    worker.join().unwrap();
    assert_eq!(receipt.confirmation(), Err(Error::Canceled));
    let (client, server) = UnixDatagram::pair().unwrap();
    client.set_nonblocking(true).unwrap();
    server.set_nonblocking(true).unwrap();
    let fd: OwnedFd = client.into();
    assert!(matches!(
        exchange(
            &fd,
            route,
            source,
            Duration::from_secs(1),
            &AtomicBool::new(true)
        ),
        Err(Error::Canceled)
    ));
    assert_eq!(
        server.recv(&mut [0; 1024]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
