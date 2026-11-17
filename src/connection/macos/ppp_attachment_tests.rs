use super::*;
use std::{cell::RefCell, collections::BTreeSet, io::Read, os::unix::net::UnixStream};

struct Fixture {
    fd: RefCell<Option<OwnedFd>>,
    peer: RefCell<UnixStream>,
    calls: RefCell<Vec<libc::c_ulong>>,
    wrong_unit: bool,
    fail_attach: bool,
}
impl Fixture {
    fn new() -> Self {
        let (owned, peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        Self {
            fd: RefCell::new(Some(owned.into())),
            peer: RefCell::new(peer),
            calls: RefCell::new(vec![]),
            wrong_unit: false,
            fail_attach: false,
        }
    }
    fn interface() -> Interface {
        Interface {
            name: "ppp42".into(),
            index: 234,
            flags: (libc::IFF_UP | libc::IFF_POINTOPOINT) as u32,
            addresses: BTreeSet::from(["10.20.0.2".parse().unwrap()]),
        }
    }
    fn assert_closed(&self) {
        // A concurrently forked fixture may briefly retain CLOEXEC descriptors
        // until exec. Require eventual EOF, not an instantaneous close event.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match self.peer.borrow_mut().read(&mut [0]) {
                Ok(0) => return,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => panic!("unexpected close observation: {result:?}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "owned descriptor must close"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}
impl Api for Fixture {
    fn socket(&self) -> io::Result<OwnedFd> {
        Ok(self.fd.borrow_mut().take().expect("one socket only"))
    }
    fn ioctl(&self, _: RawFd, request: libc::c_ulong, value: &mut libc::c_int) -> io::Result<()> {
        self.calls.borrow_mut().push(request);
        match request {
            ATTACH => {
                assert_eq!(*value, 42);
                if self.fail_attach {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
            }
            GET_UNIT => {
                assert_eq!(*value, -1);
                *value = if self.wrong_unit { 43 } else { 42 };
            }
            _ => panic!("no other PPP operation may be issued"),
        }
        Ok(())
    }
}

#[test]
fn attachment_retains_only_its_owned_descriptor_and_never_destroys_by_name() {
    let fixture = Fixture::new();
    let mut validations = 0;
    let socket = attach_using(&Fixture::interface(), &fixture, || {
        validations += 1;
        Ok(true)
    })
    .unwrap();
    assert_eq!(validations, 2);
    assert_eq!(*fixture.calls.borrow(), [ATTACH, GET_UNIT]);
    assert_eq!(
        fixture.peer.borrow_mut().read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    // SAFETY: socket owns this live descriptor.
    assert!(unsafe { libc::fcntl(socket.fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0);
    drop(socket);
    fixture.assert_closed();
    assert_eq!(*fixture.calls.borrow(), [ATTACH, GET_UNIT]);
}
#[test]
fn a_raced_or_mismatched_attachment_closes_the_reference_before_returning() {
    for case in 0..3 {
        let mut fixture = Fixture::new();
        fixture.wrong_unit = case == 0;
        fixture.fail_attach = case == 1;
        let mut checks = 0;
        assert!(
            attach_using(&Fixture::interface(), &fixture, || {
                checks += 1;
                Ok(case != 2 || checks == 1)
            })
            .is_err()
        );
        fixture.assert_closed();
    }
    let fixture = Fixture::new();
    assert!(matches!(
        attach_using(&Fixture::interface(), &fixture, || Ok(false)),
        Err(AttachError::Changed)
    ));
    assert!(fixture.fd.borrow().is_some());
    assert!(fixture.calls.borrow().is_empty());
}
#[test]
fn malformed_unit_names_and_a_nonroot_caller_cannot_attach() {
    for name in ["en0", "ppp", "ppp-1", "ppp042", "ppp65535", "ppp65536"] {
        let fixture = Fixture::new();
        let mut interface = Fixture::interface();
        interface.name = name.into();
        assert!(matches!(
            attach_using(&interface, &fixture, || Ok(true)),
            Err(AttachError::Invalid)
        ));
        assert!(fixture.calls.borrow().is_empty());
        assert!(fixture.fd.borrow().is_some());
    }
    // This boundary test never opens a PPP control socket.
    assert!(unsafe { libc::getuid() != 0 && libc::geteuid() != 0 });
    assert_eq!(require_root(), Err(AttachError::PermissionDenied));
}
