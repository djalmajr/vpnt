use super::*;
use crate::connection::{
    macos::{interfaces::Interface, routing::Record},
    routes::Key,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::{Command, Stdio},
};

struct Fixture {
    fd: RefCell<Option<OwnedFd>>,
    peer: RefCell<UnixStream>,
    interfaces: RefCell<Interfaces>,
    records: RefCell<Vec<Record>>,
    calls: RefCell<Vec<&'static str>>,
    flags: Cell<u32>,
    bound: Cell<bool>,
    connected: Cell<bool>,
    failure: &'static str,
    name: String,
    index: u32,
    randoms: Cell<usize>,
}
impl Fixture {
    fn new(failure: &'static str) -> Self {
        let (fd, peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        Self {
            fd: RefCell::new(Some(fd.into())),
            peer: RefCell::new(peer),
            interfaces: RefCell::new(Interfaces::default()),
            records: RefCell::new(vec![]),
            calls: RefCell::new(vec![]),
            flags: Cell::new(0),
            bound: Cell::new(false),
            connected: Cell::new(false),
            failure,
            name: "utun42".into(),
            index: 234,
            randoms: Cell::new(0),
        }
    }
    fn closed(&self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match self.peer.borrow_mut().read(&mut [0]) {
                Ok(0) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => panic!("unexpected close result: {result:?}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "own control FD must close"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    fn interface(&self) -> Interface {
        Interface {
            name: self.name.clone(),
            index: self.index,
            flags: (libc::IFF_UP | libc::IFF_POINTOPOINT) as u32,
            addresses: BTreeSet::new(),
        }
    }
    fn record(source: IpAddr, index: u16) -> Record {
        Record {
            key: Key {
                network: Network::host(source),
                scope: 99,
            },
            interface: index,
            flags: libc::RTF_LOCAL,
            gateway: None,
            source: None,
        }
    }
}
impl Api for Fixture {
    fn open(&self) -> io::Result<OwnedFd> {
        self.calls.borrow_mut().push("open");
        Ok(self.fd.borrow_mut().take().unwrap())
    }
    fn bind(&self, _: RawFd) -> io::Result<()> {
        self.calls.borrow_mut().push("bind");
        self.bound.set(true);
        Ok(())
    }
    fn connect(&self, _: RawFd) -> io::Result<()> {
        self.calls.borrow_mut().push("connect-new-unit");
        if self.failure == "connect" {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if !self.bound.get() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        self.connected.set(true);
        self.interfaces
            .borrow_mut()
            .entries
            .insert(self.name.clone(), self.interface());
        Ok(())
    }
    fn name(&self, _: RawFd) -> io::Result<String> {
        if self.failure == "name-race" && self.calls.borrow().contains(&"assign-only-own-interface")
        {
            return Ok("utun43".into());
        }
        Ok(self.name.clone())
    }
    fn set_flags(&self, _: RawFd, flags: u32) -> io::Result<()> {
        assert_eq!(flags, 3);
        self.calls.borrow_mut().push("disable-both-directions");
        if !self.bound.get() || self.connected.get() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        self.flags.set(flags);
        Ok(())
    }
    fn flags(&self, _: RawFd) -> io::Result<u32> {
        self.calls.borrow_mut().push("read-flags");
        Ok(
            if self.failure == "flags"
                || (self.failure == "flags-race"
                    && self.calls.borrow().contains(&"assign-only-own-interface"))
            {
                1
            } else {
                self.flags.get()
            },
        )
    }
    fn assign(&self, name: &str, source: IpAddr) -> io::Result<()> {
        assert_eq!(
            self.flags.get(),
            3,
            "no address before both packet directions are disabled"
        );
        assert_eq!(name, self.name);
        self.calls.borrow_mut().push("assign-only-own-interface");
        self.interfaces
            .borrow_mut()
            .entries
            .get_mut(name)
            .unwrap()
            .addresses
            .insert(source);
        if self.failure == "alias-partial" {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if self.failure == "source-collision" {
            let mut other = self.interface();
            other.name = "utun9".into();
            other.index = 99;
            other.addresses.insert(source);
            self.interfaces
                .borrow_mut()
                .entries
                .insert(other.name.clone(), other);
        }
        if self.failure == "index-race" {
            self.interfaces
                .borrow_mut()
                .entries
                .get_mut(name)
                .unwrap()
                .index += 1;
        }
        Ok(())
    }
    fn interfaces(&self) -> io::Result<Interfaces> {
        Ok(self.interfaces.borrow().clone())
    }
    fn table(&self) -> Result<Snapshot, Error> {
        Ok(Snapshot {
            records: self.records.borrow().clone(),
        })
    }
    fn random(&self) -> [u8; 16] {
        let n = self.randoms.get();
        self.randoms.set(n + 1);
        [n as u8; 16]
    }
}

#[test]
fn sink_fixture_enforces_kernel_flag_phase() {
    let fixture = Fixture::new("");
    let fd = fixture.open().unwrap();
    assert_eq!(
        fixture
            .set_flags(fd.as_raw_fd(), DROP_BOTH)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EINVAL)
    );
    fixture.bind(fd.as_raw_fd()).unwrap();
    fixture.set_flags(fd.as_raw_fd(), DROP_BOTH).unwrap();
    fixture.connect(fd.as_raw_fd()).unwrap();
    assert_eq!(
        fixture
            .set_flags(fd.as_raw_fd(), DROP_BOTH)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EINVAL)
    );
    drop(fd);
    fixture.closed();
}
#[test]
fn transport_refusal_precedes_sink_creation_and_alias_assignment() {
    use crate::connection::{
        macos::{
            ipsec_egress::ipsec_transport_default,
            routing::{TransportDefault, TunnelPlan},
        },
        routes::{NextHop, Route},
    };

    for ipv4 in [true, false] {
        let on_link = Route {
            key: Key {
                network: "0.0.0.0/0".parse().unwrap(),
                scope: 0,
            },
            interface: 7,
            next_hop: NextHop::Interface,
        };
        for ipsec in [false, true] {
            let decide = || {
                if ipsec {
                    ipsec_transport_default(Route {
                        key: Key {
                            network: Network::host("192.0.2.9".parse().unwrap()),
                            scope: 0,
                        },
                        ..on_link
                    })
                } else {
                    TransportDefault::for_plan(
                        on_link.interface,
                        on_link.next_hop,
                        Some(on_link.key),
                    )
                }
            };
            let fixture = Fixture::new("");
            let result = TunnelPlan::prepare(&[], (ipv4, !ipv4), decide, |plan| {
                let sink = create_using(plan.sink_ipv4().unwrap(), &fixture, || Ok(()))
                    .map_err(|failure| failure.error)?;
                plan.bind(3, Some(sink.identity.index))
            });
            assert_eq!(result, Err(Error::Conflict));
            assert_eq!(
                (
                    fixture
                        .calls
                        .borrow()
                        .iter()
                        .filter(|&&call| call == "connect-new-unit")
                        .count(),
                    fixture
                        .calls
                        .borrow()
                        .iter()
                        .filter(|&&call| call == "assign-only-own-interface")
                        .count()
                ),
                (0, 0),
            );
            assert!(fixture.calls.borrow().is_empty());
        }

        let fixture = Fixture::new("");
        let scoped = TransportDefault::from_egress(
            7,
            NextHop::Gateway(crate::connection::routes::Address::unscoped(
                "192.0.2.1".parse().unwrap(),
            )),
        )
        .unwrap();
        let (routes, default) = TunnelPlan::prepare(
            &[],
            (ipv4, !ipv4),
            || Ok(Some(scoped)),
            |plan| {
                let sink = create_using(plan.sink_ipv4().unwrap(), &fixture, || Ok(()))
                    .map_err(|failure| failure.error)?;
                plan.bind(3, Some(sink.identity.index))
            },
        )
        .unwrap();
        assert_eq!(default, Some(scoped));
        assert_eq!(routes[0], scoped.route());
        assert_eq!(
            routes.iter().filter(|route| route.interface == 234).count(),
            2
        );
        assert_eq!(
            fixture
                .calls
                .borrow()
                .iter()
                .filter(|&&call| call == "assign-only-own-interface")
                .count(),
            1,
        );
        fixture.closed();
    }
}

#[test]
fn sink_disables_packets_before_alias_and_retains_only_its_control_descriptor() {
    for ipv4 in [true, false] {
        let fixture = Fixture::new("");
        let mut checks = 0;
        let socket = create_using(ipv4, &fixture, || {
            checks += 1;
            Ok(())
        })
        .ok()
        .unwrap();
        assert_eq!(checks, 3);
        assert_eq!(socket.identity.index, 234);
        let source = socket.identity.source.unwrap();
        assert_eq!(source.is_ipv4(), ipv4);
        assert!(match source {
            IpAddr::V4(ip) => ip.is_link_local(),
            IpAddr::V6(ip) => ip.octets()[0] == 0xfd,
        });
        assert_eq!(
            *fixture.calls.borrow(),
            [
                "open",
                "bind",
                "disable-both-directions",
                "read-flags",
                "connect-new-unit",
                "assign-only-own-interface",
                "read-flags"
            ]
        );
        // SAFETY: fd belongs to the live socket throughout the query.
        assert!(
            unsafe { libc::fcntl(socket.fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0
        );
        socket.validate(&fixture).unwrap();
        assert_eq!(
            fixture.peer.borrow_mut().read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(socket);
        fixture.closed();
    }
}
#[test]
fn sink_failures_close_only_owned_fd_and_keep_partial_alias_retirement() {
    for failure in [
        "connect",
        "flags",
        "alias-partial",
        "source-collision",
        "index-race",
        "name-race",
        "flags-race",
        "postflight",
    ] {
        let fixture = Fixture::new(failure);
        let mut checks = 0;
        let error = create_using(false, &fixture, || {
            checks += 1;
            if failure == "postflight" && checks == 3 {
                Err(Error::Canceled)
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
        fixture.closed();
        if failure == "connect" || failure == "flags" {
            assert!(error.retired.is_none());
        } else {
            let retired = error.retired.unwrap();
            assert_eq!(retired.index, 234);
            assert!(retired.source.is_some());
            assert!(!retired.gone(&fixture.interfaces.borrow(), &Snapshot { records: vec![] }));
        }
        assert!(
            !fixture
                .calls
                .borrow()
                .iter()
                .any(|call| call.contains("delete"))
        );
    }
}
#[test]
fn sink_refuses_preexisting_names_indices_and_noncanonical_units_before_alias() {
    // This check exercises the production UID boundary without any socket.
    assert!(unsafe { libc::getuid() != 0 && libc::geteuid() != 0 });
    assert_eq!(require_root(), Err(Error::Unavailable));
    for case in 0..5 {
        let mut fixture = Fixture::new("");
        match case {
            0 => {
                let mut prior = fixture.interface();
                prior.flags = 0;
                fixture
                    .interfaces
                    .borrow_mut()
                    .entries
                    .insert(prior.name.clone(), prior);
            }
            1 => {
                let mut prior = fixture.interface();
                prior.name = "en9".into();
                fixture
                    .interfaces
                    .borrow_mut()
                    .entries
                    .insert(prior.name.clone(), prior);
            }
            2 => fixture.name = "utun042".into(),
            3 => fixture.index = 65_536,
            4 => fixture.name = "ppp42".into(),
            _ => unreachable!(),
        }
        assert!(create_using(false, &fixture, || Ok(())).is_err());
        fixture.closed();
        assert!(
            !fixture
                .calls
                .borrow()
                .contains(&"assign-only-own-interface")
        );
    }
    let fixture = Fixture::new("");
    assert!(create_using(false, &fixture, || Err(Error::Canceled)).is_err());
    assert!(fixture.calls.borrow().is_empty());
}
#[test]
fn sink_skips_addresses_and_host_routes_in_any_scope_and_waits_for_implicit_cleanup() {
    let fixture = Fixture::new("");
    fixture
        .records
        .borrow_mut()
        .push(Fixture::record("169.254.1.0".parse().unwrap(), 9));
    let socket = create_using(true, &fixture, || Ok(())).ok().unwrap();
    assert_eq!(fixture.randoms.get(), 2);
    assert_eq!(
        socket.identity.source.unwrap(),
        "169.254.2.1".parse::<IpAddr>().unwrap()
    );
    let retired = socket.identity.clone();
    drop(socket);
    fixture.closed();
    let empty = Snapshot { records: vec![] };
    assert!(!retired.gone(&fixture.interfaces.borrow(), &empty));
    fixture.interfaces.borrow_mut().entries.clear();
    assert!(retired.gone(&fixture.interfaces.borrow(), &empty));
    let mut table = Snapshot {
        records: vec![Fixture::record(retired.source.unwrap(), 1)],
    };
    assert!(
        !retired.gone(&fixture.interfaces.borrow(), &table),
        "local route may remain on lo0"
    );
    table.records[0].key.network = "192.0.2.0/24".parse().unwrap();
    table.records[0].interface = retired.index;
    assert!(
        !retired.gone(&fixture.interfaces.borrow(), &table),
        "an unplanned route still uses the old index"
    );
    let mut other = fixture.interface();
    other.name = "utun99".into();
    other.index = 99;
    other.addresses.insert(retired.source.unwrap());
    fixture
        .interfaces
        .borrow_mut()
        .entries
        .insert(other.name.clone(), other);
    assert!(!retired.gone(&fixture.interfaces.borrow(), &empty));
}
#[test]
fn sink_address_allocation_is_bounded_and_excludes_existing_interface_addresses() {
    let fixture = Fixture::new("");
    let mut other = fixture.interface();
    other.name = "utun9".into();
    other.index = 9;
    for n in 0u8..32 {
        other
            .addresses
            .insert(IpAddr::V4(Ipv4Addr::new(169, 254, 1 + n, n)));
    }
    fixture
        .interfaces
        .borrow_mut()
        .entries
        .insert(other.name.clone(), other);
    let failure = create_using(true, &fixture, || Ok(())).err().unwrap();
    assert_eq!(failure.error, Error::Conflict);
    assert_eq!(fixture.randoms.get(), 32);
    assert!(failure.retired.unwrap().source.is_none());
    assert!(
        !fixture
            .calls
            .borrow()
            .contains(&"assign-only-own-interface")
    );
    fixture.closed();
}
#[test]
fn sink_native_requests_match_independent_sdk_consumer_without_privileged_calls() {
    let directory = std::env::current_dir()
        .unwrap()
        .join(format!("output/fixtures/sink-abi-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let output = Command::new("/usr/bin/cc")
        .args(["-Wall", "-Wextra", "-Werror"])
        .arg(format!("-DVPNT_ALIAS4={}", native::ALIAS4))
        .arg(format!("-DVPNT_ALIAS6={}", native::ALIAS6))
        .arg(format!("-DVPNT_DROP_BOTH={DROP_BOTH}"))
        .arg("tests/fixtures/sink_abi.c")
        .arg("-o")
        .arg(directory.join("consumer"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut child = Command::new(directory.join("consumer"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let control = native::control(1234);
    // SAFETY: sockaddr_ctl has no padding (checked by the C consumer) and all
    // its scalar/array fields were initialized. Reading its byte view is valid.
    input
        .write_all(unsafe {
            std::slice::from_raw_parts(
                (&control as *const libc::sockaddr_ctl).cast(),
                std::mem::size_of_val(&control),
            )
        })
        .unwrap();
    input
        .write_all(&native::alias("utun42", "169.254.42.8".parse().unwrap()).unwrap())
        .unwrap();
    input
        .write_all(&native::alias("utun42", "fd12:3456:789a::1".parse().unwrap()).unwrap())
        .unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"sink ABI ok\n");
    fs::remove_dir_all(directory).unwrap();
}
