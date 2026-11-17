//! Typed retained-UTUN ADD path for the future Driver.
use super::*;
use crate::connection::macos::vip::{ConfiguredUtun, Family};

/// Private seam: the ADD core only needs the opaque pin's controller,
/// validity, index and exact family VIP. Implemented by `ConfiguredUtun` in
/// production; a test-only implementation may use a private UDS fd.
pub(super) trait Source {
    fn controller(&self) -> &ControllerLock;
    fn validate(&self) -> Result<(), Error>;
    fn index(&self) -> u32;
    fn vip(&self, family: Family) -> Option<std::net::IpAddr>;
}

impl Source for ConfiguredUtun<'_> {
    fn controller(&self) -> &ControllerLock {
        ConfiguredUtun::controller(self)
    }
    fn validate(&self) -> Result<(), Error> {
        ConfiguredUtun::validate(self).map_err(|_| Error::Changed)
    }
    fn index(&self) -> u32 {
        ConfiguredUtun::index(self)
    }
    fn vip(&self, family: Family) -> Option<std::net::IpAddr> {
        ConfiguredUtun::vip(self, family)
    }
}

impl<'a> AddWriter<'a> {
    /// Crate-private typed method: index/VIP/source come only from the opaque
    /// configured UTUN, never IPC or a caller string. No DELETE/CHANGE exists.
    pub(crate) fn add_utun(
        &mut self,
        link: &ConfiguredUtun<'_>,
        network: Network,
        timeout: Duration,
        canceled: &AtomicBool,
    ) -> Result<AddReceipt, Error> {
        self.add_retained(link, network, timeout, canceled)
    }

    /// The single ADD implementation shared by the opaque adapter and the
    /// private test source. Every preflight failure returns before any byte is
    /// sent; every post-dispatch failure stays in the returned receipt.
    fn add_retained<S: Source>(
        &mut self,
        source: &S,
        network: Network,
        timeout: Duration,
        canceled: &AtomicBool,
    ) -> Result<AddReceipt, Error> {
        if !std::ptr::eq(self.controller, source.controller()) {
            return Err(Error::Invalid);
        }
        source.validate()?;
        let index = u16::try_from(source.index())
            .ok()
            .filter(|index| *index > 0)
            .ok_or(Error::Invalid)?;
        let family = if network.address().is_ipv4() {
            Family::V4
        } else {
            Family::V6
        };
        let vip = source.vip(family).ok_or(Error::Invalid)?;
        if vip.is_unspecified()
            || vip.is_multicast()
            || matches!(vip, std::net::IpAddr::V6(value) if value.is_unicast_link_local())
        {
            return Err(Error::Invalid);
        }
        let route = Route {
            key: Key { network, scope: 0 },
            interface: index,
            next_hop: NextHop::Interface,
        };
        let mut receipt = exchange(&self.fd, route, Address::unscoped(vip), timeout, canceled)?;
        if source.validate().is_err() {
            receipt.confirmation = Err(Error::Changed);
        }
        Ok(receipt)
    }
}

/// Test-only fixture and fake source. Compiled only under `cfg(test)`; the
/// public/crate `add_utun` still accepts only the opaque `ConfiguredUtun`.
#[cfg(test)]
mod support {
    use super::*;
    use crate::helper::controller_lock::ControllerLock;
    use std::{
        fs, io,
        net::{IpAddr, Ipv4Addr},
        os::{
            fd::{AsRawFd, OwnedFd},
            unix::{
                fs::{DirBuilderExt, PermissionsExt},
                net::UnixDatagram,
                process::CommandExt,
            },
        },
        path::PathBuf,
        process::{Child, Command},
        sync::atomic::AtomicUsize,
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    pub(super) const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 20, 0, 2));

    pub(super) struct Fixture {
        directory: PathBuf,
        pub(super) controller: ControllerLock,
    }
    impl Fixture {
        pub(super) fn new() -> Self {
            let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
                ".vpnt-writer-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            fs::write(directory.join(".controller.lock"), b"").unwrap();
            fs::set_permissions(
                directory.join(".controller.lock"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            // SAFETY: UID query has no memory preconditions.
            let uid = unsafe { libc::geteuid() };
            let controller = ControllerLock::fixture(&directory, uid).unwrap();
            let output = Command::new("/usr/bin/cc")
                .arg(format!(
                    "-DVPNT_ATTACH={}",
                    crate::connection::macos::ppp_attachment::ATTACH
                ))
                .arg(format!(
                    "-DVPNT_GET_UNIT={}",
                    crate::connection::macos::ppp_attachment::GET_UNIT
                ))
                .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/route_add.c"))
                .arg("-o")
                .arg(directory.join("consumer"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "C ABI consumer must compile: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Self {
                directory,
                controller,
            }
        }
        pub(super) fn writer(&self, fd: OwnedFd) -> AddWriter<'_> {
            AddWriter {
                fd,
                controller: &self.controller,
            }
        }
        pub(super) fn consumer(&self, mode: &str) -> (OwnedFd, Consumer) {
            let (client, server) = UnixDatagram::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let raw = server.as_raw_fd();
            let mut command = Command::new(self.directory.join("consumer"));
            command.arg(mode);
            // SAFETY: the child only duplicates a live FD and clears CLOEXEC on 3.
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
            let fd: OwnedFd = client.into();
            let mut ready = [0; 5];
            // SAFETY: the owned socket and five-byte buffer remain live.
            assert_eq!(
                unsafe { libc::recv(fd.as_raw_fd(), ready.as_mut_ptr().cast(), ready.len(), 0,) },
                5
            );
            assert_eq!(&ready, b"READY");
            assert_eq!(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
                0
            );
            (fd, Consumer { child })
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    pub(super) struct Consumer {
        child: Child,
    }
    impl Consumer {
        pub(super) fn finish(&mut self) {
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

    pub(super) fn v6() -> IpAddr {
        "2001:db8::2".parse().unwrap()
    }
    pub(super) fn quiet() -> (OwnedFd, UnixDatagram) {
        let (client, server) = UnixDatagram::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        (client.into(), server)
    }
    pub(super) fn no_bytes(server: &UnixDatagram) {
        assert_eq!(
            server.recv(&mut [0; 1024]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    pub(super) fn expect_error(result: Result<AddReceipt, Error>, expected: Error) {
        match result {
            Err(error) => assert_eq!(error, expected),
            Ok(receipt) => {
                panic!(
                    "expected {expected:?}, got Ok({})",
                    receipt.route().interface
                )
            }
        }
    }
}

#[cfg(test)]
#[path = "retained/tests.rs"]
mod tests;
