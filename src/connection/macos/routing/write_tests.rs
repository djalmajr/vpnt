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

struct ScopedFixture(PathBuf);

impl ScopedFixture {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            ".vpnt-scoped-writer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let fixture = Self(directory);
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(fixture.0.join(".controller.lock"))
            .unwrap();
        fixture
    }

    fn lock(&self) -> ControllerLock {
        // SAFETY: geteuid has no memory preconditions.
        ControllerLock::fixture(&self.0, unsafe { libc::geteuid() }).unwrap()
    }
}

impl Drop for ScopedFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove scoped writer fixture");
    }
}

fn datagrams() -> (OwnedFd, UnixDatagram) {
    let (client, peer) = UnixDatagram::pair().unwrap();
    client.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    (client.into(), peer)
}

fn receive(peer: &UnixDatagram, opcode: i32) -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    let length = peer.recv(&mut bytes).unwrap();
    bytes.truncate(length);
    assert!(length >= size_of::<libc::rt_msghdr>());
    assert_eq!(bytes[3], opcode as u8);
    bytes
}

fn set_errno(bytes: &mut [u8], errno: i32) {
    let offset = offset_of!(libc::rt_msghdr, rtm_errno);
    bytes[offset..offset + size_of::<i32>()].copy_from_slice(&errno.to_ne_bytes());
}

fn reply_id(bytes: &[u8]) -> (i32, i32) {
    (
        codec::signed(bytes, offset_of!(libc::rt_msghdr, rtm_pid)).unwrap(),
        codec::signed(bytes, offset_of!(libc::rt_msghdr, rtm_seq)).unwrap(),
    )
}

fn scoped_route() -> TransportDefault {
    TransportDefault::from_egress(
        7,
        NextHop::Gateway(Address::unscoped("192.0.2.1".parse().unwrap())),
    )
    .unwrap()
}

#[test]
fn scoped_get_ignores_a_queued_reader_reply() {
    // Neither allocator has history in this child. Separate counters would
    // assign the same ID to the first GET on each socket.
    const CHILD: &str = "VPNT_SCOPED_GET_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let (_, module) = module_path!().split_once("::").unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("{module}::scoped_get_ignores_a_queued_reader_reply"),
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let fixture = ScopedFixture::new();
    let controller = fixture.lock();
    let (fd, write_peer) = datagrams();
    let mut writer = AddWriter {
        fd,
        controller: &controller,
    };
    let (fd, read_peer) = datagrams();
    let mut reader = Reader { fd };
    let canceled = AtomicBool::new(false);
    let route = scoped_route();

    thread::scope(|scope| {
        let peer = scope.spawn(move || {
            let mut query = receive(&read_peer, libc::RTM_GET);
            set_errno(&mut query, libc::ESRCH);
            // Queue the broadcast on the writer before letting the reader return.
            write_peer.send(&query).unwrap();
            read_peer.send(&query).unwrap();
            let get = receive(&write_peer, libc::RTM_GET);
            let (pid, seq) = reply_id(&get);
            let mut response =
                add_codec::scoped_default(add_codec::DefaultRequest::Add, route, pid, seq).unwrap();
            response[3] = libc::RTM_GET as u8;
            write_peer.send(&response).unwrap();
        });
        assert_eq!(
            reader.lookup(
                Address::unscoped("198.51.100.40".parse().unwrap()),
                0,
                Duration::from_secs(2),
                &canceled
            ),
            Err(Error::Changed)
        );
        let result = writer.get_transport_default(route);
        peer.join().unwrap();
        assert!(route.matches_static(&result.unwrap().expect("exact reply must win")));
    });
}

#[test]
fn scoped_writer_uses_exact_get_and_reports_unowned_add_and_uncertain_delete() {
    let fixture = ScopedFixture::new();
    let controller = fixture.lock();
    let (fd, peer) = datagrams();
    let mut writer = AddWriter {
        fd,
        controller: &controller,
    };
    let route = scoped_route();

    thread::scope(|scope| {
        let (finished, wait_for_delete) = std::sync::mpsc::channel();
        let peer = scope.spawn(move || {
            let mut add = receive(&peer, libc::RTM_ADD);
            set_errno(&mut add, libc::EEXIST);
            peer.send(&add).unwrap();

            let mut get = receive(&peer, libc::RTM_GET);
            let address_size = size_of::<libc::sockaddr_in>();
            let mask_offset = size_of::<libc::rt_msghdr>() + address_size;
            assert_eq!(
                codec::signed(&get, offset_of!(libc::rt_msghdr, rtm_addrs)).unwrap(),
                libc::RTA_DST | libc::RTA_NETMASK
            );
            assert_eq!(
                u16::from_ne_bytes(
                    get[offset_of!(libc::rt_msghdr, rtm_index)..][..2]
                        .try_into()
                        .unwrap()
                ),
                route.route().key.scope
            );
            assert_eq!(get.len(), mask_offset + address_size);
            assert_eq!(
                &get[mask_offset..],
                &[
                    address_size as u8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0
                ]
            );
            set_errno(&mut get, libc::ESRCH);
            peer.send(&get).unwrap();

            let delete = receive(&peer, libc::RTM_DELETE);
            assert_eq!(
                &delete[size_of::<libc::rt_msghdr>()..],
                &add[size_of::<libc::rt_msghdr>()..]
            );
            // Hold the peer open and let the writer's ACK deadline expire.
            wait_for_delete
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
        });
        assert_eq!(
            writer.add_transport_default(route, &AtomicBool::new(false)),
            Err(Error::Conflict)
        );
        assert_eq!(writer.get_transport_default(route), Ok(None));
        let deleted = writer.delete_transport_default(route);
        finished.send(()).unwrap();
        peer.join().unwrap();
        assert_eq!(deleted, Ok(Err(Error::TimedOut)));
    });
}
