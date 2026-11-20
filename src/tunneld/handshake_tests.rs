use super::*;

#[test]
fn decodes_named_final_confirmation() {
    assert!(matches!(
        decode_frame(br#"{"phase":"writer_confirm"}"#).unwrap(),
        Frame::WriterConfirm {}
    ));
}

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

const GENERATION: &str = "0123456789abcdef0123456789abcdef";
const INVOCATION: &str = "fedcba9876543210fedcba9876543210";
const ATTEMPT: Attempt<'static> = Attempt {
    generation: GENERATION,
    backend: Backend::Ipsec,
};

fn ids() -> Credentials {
    // SAFETY: these syscalls take no pointers.
    unsafe {
        Credentials {
            uid: libc::geteuid(),
            gid: libc::getegid(),
        }
    }
}

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("vpnt-handshake-{}", &challenge().unwrap()[..16]));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn publish(&self, expected: Credentials, timeout: Duration) -> io::Result<Writer> {
        Writer::publish_as(&self.0, OsStr::new("control"), ATTEMPT, expected, timeout)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only this test's fixture");
    }
}

struct TestChild(Child);

impl Drop for TestChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn child(fixture: &Fixture, mode: &str, private_pid: bool, expected_pid: u32) -> TestChild {
    child_with(fixture, mode, private_pid, expected_pid, &[])
}

fn child_with(
    fixture: &Fixture,
    mode: &str,
    private_pid: bool,
    expected_pid: u32,
    extra_env: &[(&str, &str)],
) -> TestChild {
    let executable = std::env::current_exe().unwrap();
    let mut command = if private_pid {
        let mut command = Command::new("/usr/bin/unshare");
        command.args([
            "--map-current-user",
            "--pid",
            "--kill-child",
            "--",
            executable.to_str().unwrap(),
        ]);
        command
    } else {
        Command::new(executable)
    };
    if mode == "no-read" {
        command.stdin(Stdio::piped());
    }
    TestChild(
        command
            .env_clear()
            .envs(extra_env.iter().copied())
            .env("HOME", &fixture.0)
            .env("USERPROFILE", &fixture.0)
            .env("XDG_CONFIG_HOME", &fixture.0)
            .env("TMPDIR", &fixture.0)
            .env("PATH", &fixture.0)
            .env("VPN_HANDSHAKE_FIXTURE", &fixture.0)
            .env("VPN_HANDSHAKE_MODE", mode)
            .env("VPN_HANDSHAKE_WRITER_PID", expected_pid.to_string())
            .args([
                "--exact",
                "tunneld::handshake::tests::instance_fixture",
                "--nocapture",
            ])
            .spawn()
            .unwrap(),
    )
}

#[test]
fn instance_fixture() {
    let Some(root) = std::env::var_os("VPN_HANDSHAKE_FIXTURE") else {
        return;
    };
    let root = PathBuf::from(root);
    let mode = std::env::var("VPN_HANDSHAKE_MODE").unwrap();
    if mode == "datagrams" {
        check_datagrams();
        return;
    }
    if mode == "dead" {
        check_dead_peer();
        return;
    }
    if mode == "phases" {
        check_phases();
        return;
    }
    if mode == "decoy" {
        run_decoy_writer(&root);
        return;
    }
    if mode == "fd-copy" {
        check_fd_copy(&root);
        return;
    }
    if mode == "replay" {
        replay_instance(&root);
        return;
    }
    let socket_path = root.join("control");
    if mode == "no-read" {
        let transport = connect_fixture(&socket_path);
        transport
            .send(b"ready", Instant::now() + PHASE_TIMEOUT)
            .unwrap();
        let mut signal = [0];
        assert_eq!(io::stdin().lock().read(&mut signal).unwrap(), 0);
        return;
    }
    let record_path = root.join(GENERATION);
    let expected_pid = std::env::var("VPN_HANDSHAKE_WRITER_PID")
        .unwrap()
        .parse::<libc::pid_t>()
        .unwrap();
    let before = fd_count();
    protect_supervisor().unwrap();
    // SAFETY: PR_GET_DUMPABLE takes only zeroed integer arguments.
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    let result = connect_as(
        &socket_path,
        &record_path,
        ATTEMPT,
        INVOCATION,
        ids(),
        PHASE_TIMEOUT,
    );
    if mode == "success" {
        let mut channel = result.unwrap();
        let transport = channel.transport.as_ref().unwrap();
        for fd in [transport.socket.as_fd(), transport.peer.fd.as_fd()] {
            // SAFETY: F_GETFD reads flags for the borrowed descriptor.
            assert_eq!(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) },
                libc::FD_CLOEXEC
            );
        }
        assert_eq!(
            peer_credential(transport.socket.as_fd()).unwrap().pid,
            expected_pid
        );
        assert_eq!(channel.invocation(), INVOCATION);
        assert_eq!(channel.receive().unwrap(), b"writer");
        channel.send(b"instance").unwrap();
        assert_eq!(channel.receive().unwrap(), b"received");
    } else {
        assert!(
            result.is_err(),
            "unexpected authenticated channel for {mode}"
        );
    }
    assert_eq!(fd_count(), before);
}

fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
}

struct FakeAttestor {
    main_pid: libc::pid_t,
    name: String,
    invocation: String,
}

impl FakeAttestor {
    fn expected(main_pid: u32) -> Self {
        Self {
            main_pid: main_pid.try_into().unwrap(),
            name: ATTEMPT.unit_name(),
            invocation: INVOCATION.to_owned(),
        }
    }
}

impl UnitAttestor for FakeAttestor {
    fn attest(&self, pidfd: BorrowedFd<'_>) -> io::Result<UnitIdentity> {
        live(pidfd)?;
        Ok(UnitIdentity {
            name: self.name.clone(),
            invocation: self.invocation.clone(),
            main_pid: self.main_pid,
        })
    }
}

#[test]
fn real_process_completes_handshake() {
    let fixture = Fixture::new();
    let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    let mut instance = child(&fixture, "success", false, std::process::id());
    let mut channel = writer
        .authenticate(&FakeAttestor::expected(instance.0.id()))
        .unwrap();
    assert_eq!(channel.invocation(), INVOCATION);
    channel.send(b"writer").unwrap();
    assert_eq!(channel.receive().unwrap(), b"instance");
    channel.send(b"received").unwrap();
    assert!(instance.0.wait().unwrap().success());
    assert_eq!(
        channel.receive().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert!(!fixture.0.join("control").exists());
}

#[test]
fn private_pid_namespace_observes_writer_pid_zero() {
    let fixture = Fixture::new();
    let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    let mut instance = child(&fixture, "success", true, 0);
    struct NoHostPid;
    impl UnitAttestor for NoHostPid {
        fn attest(&self, fd: BorrowedFd<'_>) -> io::Result<UnitIdentity> {
            // In the fixture only, procfs fdinfo provides the host-visible PID
            // attached to the borrowed pidfd. Production attests through systemd.
            let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?;
            let pid = info
                .lines()
                .find_map(|line| line.strip_prefix("Pid:")?.trim().parse().ok())
                .ok_or_else(|| invalid("missing pidfd Pid in fdinfo"))?;
            FakeAttestor::expected(pid).attest(fd)
        }
    }
    let mut channel = writer.authenticate(&NoHostPid).unwrap();
    channel.send(b"writer").unwrap();
    assert_eq!(channel.receive().unwrap(), b"instance");
    channel.send(b"received").unwrap();
    assert!(instance.0.wait().unwrap().success());
}

#[test]
fn rejects_wrong_expected_gid_before_attestation() {
    let fixture = Fixture::new();
    let expected = ids();
    let writer = fixture
        .publish(
            Credentials {
                gid: expected.gid.wrapping_add(1),
                ..expected
            },
            PHASE_TIMEOUT,
        )
        .unwrap();
    let mut instance = child(&fixture, "reject", false, std::process::id());
    let result = writer.authenticate(&FakeAttestor::expected(instance.0.id()));
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
    assert!(instance.0.wait().unwrap().success());
}

#[test]
fn rejects_wrong_unit_identity() {
    for mismatch in ["name", "invocation", "main_pid"] {
        let fixture = Fixture::new();
        let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
        let mut instance = child(&fixture, "reject", false, std::process::id());
        let mut attestor = FakeAttestor::expected(instance.0.id());
        match mismatch {
            "name" => attestor.name.push_str(".invalid"),
            "invocation" => attestor.invocation = GENERATION.to_owned(),
            "main_pid" => attestor.main_pid = 0,
            _ => unreachable!(),
        }
        let result = writer.authenticate(&attestor);
        assert!(
            matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied && error.to_string().contains("unit attestation")),
            "{mismatch}"
        );
        assert!(instance.0.wait().unwrap().success());
    }
}

#[test]
fn rejects_record_scope_and_reuse() {
    let fixture = Fixture::new();
    drop(fixture.publish(ids(), PHASE_TIMEOUT).unwrap());
    let result = Writer::publish_as(
        &fixture.0,
        OsStr::new("other-socket"),
        ATTEMPT,
        ids(),
        PHASE_TIMEOUT,
    );
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::AlreadyExists));

    for (generation, backend) in [
        (INVOCATION, Backend::Ipsec),
        (GENERATION, Backend::Fortinet),
    ] {
        let result = connect_as(
            &fixture.0.join("control"),
            &fixture.0.join(GENERATION),
            Attempt {
                generation,
                backend,
            },
            INVOCATION,
            ids(),
            PHASE_TIMEOUT,
        );
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
    }

    let record = fixture.0.join(GENERATION);
    fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        matches!(open_record(&record, ids().uid), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn rejects_malformed_frame_shapes() {
    for malformed in [
        r#"["writer_confirm"]"#,
        r#"{"phase":"writer_confirm","phase":"writer_confirm"}"#,
        r#"{"phase":"writer_confirm","extra":0}"#,
        r#"{"phase":"writer_challenge","challenge_i":"a","challenge_i":"b","challenge_w":"c"}"#,
        r#"{"phase":"writer_confirm"} {}"#,
        r#"{"phase":"unknown"}"#,
    ] {
        assert!(decode_frame(malformed.as_bytes()).is_err(), "{malformed}");
    }
}

fn pair() -> (OwnedFd, Transport) {
    let mut pair = [-1; 2];
    // SAFETY: the kernel writes two newly owned descriptors on success.
    unsafe {
        syscall_result(libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            pair.as_mut_ptr(),
        ))
        .unwrap();
    }
    let [sender, receiver] = pair.map(|raw| new_fd(raw).unwrap());
    for option in [libc::SO_PASSCRED, libc::SO_PASSPIDFD] {
        let enabled: libc::c_int = 1;
        // SAFETY: setsockopt reads the supplied integer.
        unsafe {
            syscall_result(libc::setsockopt(
                receiver.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                ptr::from_ref(&enabled).cast(),
                size_of::<libc::c_int>() as _,
            ))
            .unwrap();
        }
    }
    let peer = Peer::new(receiver.as_fd(), ids()).unwrap();
    (
        sender,
        Transport {
            socket: receiver,
            peer,
        },
    )
}

fn send_fixture_datagram(socket: BorrowedFd<'_>, bytes: &[u8], rights: Option<BorrowedFd<'_>>) {
    let mut vector = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0_usize; 4];
    // SAFETY: the inputs are readable through sendmsg, which receives no FDs.
    unsafe {
        let mut message: libc::msghdr = zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        if let Some(rights) = rights {
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = libc::CMSG_SPACE(size_of::<RawFd>() as _) as _;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as _;
            libc::CMSG_DATA(header)
                .cast::<RawFd>()
                .write_unaligned(rights.as_raw_fd());
        }
        let sent = libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL);
        assert_eq!(sent, bytes.len() as isize, "{}", io::Error::last_os_error());
    }
}

fn check_datagrams() {
    let start = fd_count();
    {
        let (sender, transport) = pair();
        let before = fd_count();
        let deadline = Instant::now() + PHASE_TIMEOUT;
        send_fixture_datagram(sender.as_fd(), b"valid", None);
        assert_eq!(transport.receive(deadline).unwrap().0, b"valid");
        assert_eq!(fd_count(), before);

        send_fixture_datagram(
            sender.as_fd(),
            b"unexpected ancillary",
            Some(sender.as_fd()),
        );
        let error = transport.receive(deadline).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("exactly one kernel credential and pidfd")
        );
        assert_eq!(fd_count(), before);

        send_fixture_datagram(sender.as_fd(), &[b'a'; MAX_FRAME + 1], None);
        let error = transport.receive(deadline).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("truncated"));
        assert_eq!(fd_count(), before);
    }
    assert_eq!(fd_count(), start);
}

#[test]
fn rejects_extra_ancillary_and_truncation_without_leaks() {
    let fixture = Fixture::new();
    let mut isolated = child(&fixture, "datagrams", false, std::process::id());
    assert!(isolated.0.wait().unwrap().success());
}

fn check_dead_peer() {
    let before = fd_count();
    {
        let fixture = Fixture::new();
        let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
        let mut instance = child(&fixture, "reject", false, std::process::id());

        let attestor = FakeAttestor::expected(instance.0.id());
        let finish_instance = AttestorFn::new(|fd: BorrowedFd<'_>| {
            let unit = attestor.attest(fd)?;
            instance.0.kill()?;
            instance.0.wait()?;
            Ok(unit)
        });
        let error = writer.authenticate(&finish_instance).err().unwrap();
        assert!(
            error.to_string().contains("pidfd is no longer live"),
            "{error}"
        );
    }
    assert_eq!(fd_count(), before);
}

struct AttestorFn<F>(std::sync::Mutex<F>);

impl<F> AttestorFn<F> {
    fn new(function: F) -> Self {
        Self(std::sync::Mutex::new(function))
    }
}

impl<F> UnitAttestor for AttestorFn<F>
where
    F: FnMut(BorrowedFd<'_>) -> io::Result<UnitIdentity>,
{
    fn attest(&self, fd: BorrowedFd<'_>) -> io::Result<UnitIdentity> {
        (self.0.lock().unwrap())(fd)
    }
}

#[test]
fn rejects_peer_that_exits_during_attestation() {
    let fixture = Fixture::new();
    let mut isolated = child(&fixture, "dead", false, std::process::id());
    assert!(isolated.0.wait().unwrap().success());
}

const FIXTURE_TIMEOUT: Duration = Duration::from_millis(250);

fn connect_fixture(path: &Path) -> Transport {
    let addr = address(path).unwrap();
    let socket = socket().unwrap();
    // SAFETY: connect reads the initialized Unix socket address.
    unsafe {
        syscall_result(libc::connect(
            socket.as_raw_fd(),
            ptr::from_ref(&addr).cast(),
            size_of::<libc::sockaddr_un>() as _,
        ))
        .unwrap();
    }
    let peer = Peer::new(socket.as_fd(), ids()).unwrap();
    Transport { socket, peer }
}

fn accept_fixture(writer: &Writer) -> Transport {
    accept_on(writer.listener.as_fd())
}

fn accept_on(listener: BorrowedFd<'_>) -> Transport {
    wait_ready(listener, libc::POLLIN, Instant::now() + PHASE_TIMEOUT).unwrap();
    // SAFETY: no peer address requested and accept4 transfers a new FD.
    let socket = new_fd(unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            ptr::null_mut(),
            ptr::null_mut(),
            libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        )
    })
    .unwrap();
    let peer = Peer::new(socket.as_fd(), ids()).unwrap();
    Transport { socket, peer }
}

fn fixture_hello() -> Frame {
    Frame::InstanceHello {
        version: VERSION,
        generation: GENERATION.to_owned(),
        backend: Backend::Ipsec,
        challenge_i: challenge().unwrap(),
    }
}

fn check_phases() {
    let before = fd_count();
    for expire in [true, false] {
        for phase in [1, 3] {
            let fixture = Fixture::new();
            let writer = fixture.publish(ids(), FIXTURE_TIMEOUT).unwrap();
            let client = connect_fixture(&fixture.0.join("control"));
            let deadline = Instant::now() + PHASE_TIMEOUT;
            if phase == 3 {
                client.write_frame(&fixture_hello(), deadline).unwrap();
            }
            let rejected = std::thread::scope(|scope| {
                let handshake = scope
                    .spawn(|| writer.authenticate(&FakeAttestor::expected(std::process::id())));
                if phase == 3 {
                    assert!(matches!(
                        client.read_frame(deadline).unwrap().0,
                        Frame::WriterChallenge { .. }
                    ));
                }
                if !expire {
                    drop(client);
                }
                handshake.join().unwrap().err().unwrap()
            });
            let expected = if expire {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::UnexpectedEof
            };
            assert_eq!(rejected.kind(), expected, "phase {phase}: {rejected}");
        }
        for phase in [2, 4] {
            let fixture = Fixture::new();
            let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
            let socket_path = fixture.0.join("control");
            let record_path = fixture.0.join(GENERATION);
            let rejected = std::thread::scope(|scope| {
                let handshake = scope.spawn(|| {
                    connect_as(
                        &socket_path,
                        &record_path,
                        ATTEMPT,
                        INVOCATION,
                        ids(),
                        FIXTURE_TIMEOUT,
                    )
                });
                let server = accept_fixture(&writer);
                let deadline = Instant::now() + PHASE_TIMEOUT;
                let (Frame::InstanceHello { challenge_i, .. }, _) =
                    server.read_frame(deadline).unwrap()
                else {
                    panic!("fixture expected instance_hello");
                };
                if phase == 4 {
                    server
                        .write_frame(
                            &Frame::WriterChallenge {
                                challenge_i,
                                challenge_w: challenge().unwrap(),
                            },
                            deadline,
                        )
                        .unwrap();
                    assert!(matches!(
                        server.read_frame(deadline).unwrap().0,
                        Frame::InstanceConfirm { .. }
                    ));
                }
                if !expire {
                    drop(server);
                }
                handshake.join().unwrap().err().unwrap()
            });
            let expected = if expire {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::UnexpectedEof
            };
            assert_eq!(rejected.kind(), expected, "phase {phase}: {rejected}");
        }
    }
    assert_eq!(fd_count(), before);
}

#[test]
fn expires_and_closes_at_every_phase_without_early_authentication() {
    let fixture = Fixture::new();
    let mut isolated = child(&fixture, "phases", false, std::process::id());
    assert!(isolated.0.wait().unwrap().success());
}

#[test]
fn rejects_out_of_order_phase() {
    let fixture = Fixture::new();
    let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    let client = connect_fixture(&fixture.0.join("control"));
    client
        .write_frame(&Frame::WriterConfirm {}, Instant::now() + PHASE_TIMEOUT)
        .unwrap();
    let failure = writer
        .authenticate(&FakeAttestor::expected(std::process::id()))
        .err()
        .unwrap();
    assert!(failure.to_string().contains("expected instance_hello"));
}

#[test]
fn rejects_mismatched_confirm_fields() {
    for mismatch in ["generation", "invocation", "challenge", "challenge_i"] {
        let fixture = Fixture::new();
        let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
        let client = connect_fixture(&fixture.0.join("control"));
        let deadline = Instant::now() + PHASE_TIMEOUT;
        client.write_frame(&fixture_hello(), deadline).unwrap();
        std::thread::scope(|scope| {
            let handshake = scope.spawn(|| {
                writer
                    .authenticate(&FakeAttestor::expected(std::process::id()))
                    .err()
                    .unwrap()
            });
            let (
                Frame::WriterChallenge {
                    challenge_i,
                    challenge_w,
                },
                _,
            ) = client.read_frame(deadline).unwrap()
            else {
                panic!("fixture expected writer_challenge");
            };
            let challenge_i = if mismatch == "challenge_i" {
                challenge().unwrap()
            } else {
                challenge_i
            };
            let (generation, invocation) = match mismatch {
                "generation" => (INVOCATION, INVOCATION),
                "invocation" => (GENERATION, GENERATION),
                _ => (GENERATION, INVOCATION),
            };
            client
                .write_frame(
                    &Frame::InstanceConfirm {
                        challenge_i,
                        challenge_w: if mismatch == "challenge" {
                            challenge().unwrap()
                        } else {
                            challenge_w
                        },
                        version: VERSION,
                        generation: generation.to_owned(),
                        backend: Backend::Ipsec,
                        invocation: invocation.to_owned(),
                    },
                    deadline,
                )
                .unwrap();
            let error = handshake.join().unwrap();
            let expected = match mismatch {
                "generation" => "handshake version, generation or backend mismatch",
                "invocation" => "unit attestation does not match the instance",
                _ => "instance confirmation challenge mismatch",
            };
            assert_eq!(error.to_string(), expected);
        });
    }
}

#[test]
fn rejects_divergent_writer_pidfs_record() {
    let fixture = Fixture::new();
    let _writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    let path = fixture.0.join(GENERATION);
    let mut record = open_record(&path, ids().uid).unwrap();
    record.writer_pidfs.ino ^= 1;
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    let error = connect_as(
        &fixture.0.join("control"),
        &path,
        ATTEMPT,
        INVOCATION,
        ids(),
        PHASE_TIMEOUT,
    )
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("writer does not match its pidfs record")
    );
}

#[test]
fn handshake_send_respects_phase_deadline_when_peer_does_not_read() {
    let fixture = Fixture::new();
    let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    let mut instance = child(&fixture, "no-read", false, std::process::id());
    let transport = accept_fixture(&writer);
    let (message, sender) = transport.receive(Instant::now() + PHASE_TIMEOUT).unwrap();
    assert_eq!(message, b"ready");
    assert_eq!(sender, instance.0.id() as libc::pid_t);

    let capacity = (2 * MAX_FRAME) as libc::c_int;
    // SAFETY: setsockopt reads the supplied integer.
    unsafe {
        syscall_result(libc::setsockopt(
            transport.socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            ptr::from_ref(&capacity).cast(),
            size_of::<libc::c_int>() as _,
        ))
        .unwrap();
    }
    let fill = [0_u8; MAX_FRAME];
    let full = (0..1024).any(|_| {
        // SAFETY: send reads the supplied buffer. DONTWAIT makes the fill
        // bounded even if the test socket settings change.
        let count = unsafe {
            libc::send(
                transport.socket.as_raw_fd(),
                fill.as_ptr().cast(),
                fill.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        match count {
            -1 => {
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                true
            }
            count => {
                assert_eq!(count as usize, fill.len());
                false
            }
        }
    });
    assert!(full, "fixture failed to fill the connected socket queue");

    let frame = Frame::WriterChallenge {
        challenge_i: challenge().unwrap(),
        challenge_w: challenge().unwrap(),
    };
    let start = Instant::now();
    let deadline = start + PHASE_TIMEOUT;
    let error = transport.write_frame(&frame, deadline).unwrap_err();
    let elapsed = start.elapsed();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(elapsed >= PHASE_TIMEOUT, "{elapsed:?}");
    assert!(
        elapsed < PHASE_TIMEOUT + Duration::from_secs(2),
        "{elapsed:?}"
    );

    // EOF on the fixture's stdin lets it close the socket and exit.
    drop(instance.0.stdin.take().expect("fixture stdin pipe"));
    assert!(instance.0.wait().unwrap().success());
}

#[test]
fn writer_rejects_a_client_outside_the_attested_instance() {
    let fixture = Fixture::new();
    let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    // SAFETY: pidfd_open takes a PID and flags and returns a newly owned FD.
    let expected =
        new_fd(unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as RawFd).unwrap();
    let expected_identity = pidfs(expected.as_fd()).unwrap();
    let mut other = child(&fixture, "reject", false, std::process::id());
    let attestor = AttestorFn::new(|fd: BorrowedFd<'_>| {
        if pidfs(fd)? != expected_identity {
            return Err(denied(
                "fixture manager did not attest the connecting process",
            ));
        }
        FakeAttestor::expected(std::process::id()).attest(fd)
    });

    let error = writer.authenticate(&attestor).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        error.to_string(),
        "fixture manager did not attest the connecting process"
    );
    assert!(other.0.wait().unwrap().success());
}

// A protocol-compliant writer that never checks who connects. The instance
// side alone must decide whether this server is the one in the record.
fn serve_compliant_writer(listener: BorrowedFd<'_>) -> io::Result<()> {
    let server = accept_on(listener);
    let deadline = Instant::now() + PHASE_TIMEOUT;
    let (Frame::InstanceHello { challenge_i, .. }, _) = server.read_frame(deadline)? else {
        return Err(invalid("fixture expected instance_hello"));
    };
    server.write_frame(
        &Frame::WriterChallenge {
            challenge_i,
            challenge_w: challenge()?,
        },
        deadline,
    )?;
    if !matches!(
        server.read_frame(deadline)?.0,
        Frame::InstanceConfirm { .. }
    ) {
        return Err(invalid("fixture expected instance_confirm"));
    }
    server.write_frame(&Frame::WriterConfirm {}, deadline)
}

// A second identity of the same user serving the socket path. It must receive
// no frame at all: the instance refuses before it speaks.
fn run_decoy_writer(root: &Path) {
    let addr = address(&root.join("control")).unwrap();
    let listener = socket().unwrap();
    // SAFETY: bind and listen read the initialized address and the socket FD.
    unsafe {
        syscall_result(libc::bind(
            listener.as_raw_fd(),
            ptr::from_ref(&addr).cast(),
            size_of::<libc::sockaddr_un>() as _,
        ))
        .unwrap();
        syscall_result(libc::listen(listener.as_raw_fd(), 1)).unwrap();
    }
    fs::write(root.join("decoy-ready"), b"").unwrap();
    let error = serve_compliant_writer(listener.as_fd()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{error}");
}

#[test]
fn instance_rejects_a_second_identity_serving_the_socket_path() {
    let connect = |fixture: &Fixture| {
        connect_as(
            &fixture.0.join("control"),
            &fixture.0.join(GENERATION),
            ATTEMPT,
            INVOCATION,
            ids(),
            PHASE_TIMEOUT,
        )
    };

    // Control: the same compliant server, run by the process the record names,
    // completes the handshake, so only the pidfs identity differs below.
    let fixture = Fixture::new();
    let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| serve_compliant_writer(writer.listener.as_fd()));
        assert!(connect(&fixture).is_ok());
        server.join().unwrap().unwrap();
    });
    drop(writer);

    // Attack: the record names this process, but another process of the same
    // user (same UID and GID) owns the socket path and speaks the protocol.
    let fixture = Fixture::new();
    drop(fixture.publish(ids(), PHASE_TIMEOUT).unwrap());
    let mut decoy = child(&fixture, "decoy", false, std::process::id());
    let ready = fixture.0.join("decoy-ready");
    let start = Instant::now();
    while !ready.exists() {
        assert!(start.elapsed() < PHASE_TIMEOUT, "decoy did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    let error = connect(&fixture).err().expect("authenticated a decoy");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        error.to_string(),
        "connected writer does not match its pidfs record"
    );
    assert!(decoy.0.wait().unwrap().success());
}

// The connected supervisor hands a copy of its FD to a forked child, which
// sends the next frame. The kernel stamps that frame with the child's pidfd.
fn check_fd_copy(root: &Path) {
    let transport = connect_fixture(&root.join("control"));
    let deadline = Instant::now() + PHASE_TIMEOUT;
    transport.write_frame(&fixture_hello(), deadline).unwrap();
    let (
        Frame::WriterChallenge {
            challenge_i,
            challenge_w,
        },
        _,
    ) = transport.read_frame(deadline).unwrap()
    else {
        panic!("fixture expected writer_challenge");
    };
    let confirm = serde_json::to_vec(&Frame::InstanceConfirm {
        challenge_i,
        challenge_w,
        version: VERSION,
        generation: GENERATION.to_owned(),
        backend: Backend::Ipsec,
        invocation: INVOCATION.to_owned(),
    })
    .unwrap();
    let raw = transport.socket.as_raw_fd();
    // SAFETY: the forked child only calls async-signal-safe send and _exit
    // on data prepared before the fork.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "{}", io::Error::last_os_error());
    if pid == 0 {
        // SAFETY: see above.
        unsafe {
            let sent = libc::send(
                raw,
                confirm.as_ptr().cast(),
                confirm.len(),
                libc::MSG_NOSIGNAL,
            );
            libc::_exit(if sent == confirm.len() as isize { 0 } else { 1 });
        }
    }
    let mut status = 0;
    // SAFETY: waitpid writes the status of our own child.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    // The writer refused the copy, so no writer_confirm ever arrives.
    assert!(transport.read_frame(deadline).is_err());
}

#[test]
fn writer_rejects_a_frame_from_a_copy_of_the_connected_fd() {
    let fixture = Fixture::new();
    let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    let mut instance = child(&fixture, "fd-copy", false, std::process::id());
    let error = writer
        .authenticate(&FakeAttestor::expected(instance.0.id()))
        .err()
        .expect("authenticated a forked copy of the connected fd");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "frame pidfd differs from connected peer");
    assert!(instance.0.wait().unwrap().success());
}

fn replay_instance(root: &Path) {
    let transport = connect_fixture(&root.join("control"));
    let deadline = Instant::now() + PHASE_TIMEOUT;
    match std::env::var("VPN_HANDSHAKE_REPLAY_HELLO") {
        Ok(hello) => transport.send(hello.as_bytes(), deadline).unwrap(),
        Err(_) => transport.write_frame(&fixture_hello(), deadline).unwrap(),
    }
    assert!(matches!(
        transport.read_frame(deadline).unwrap().0,
        Frame::WriterChallenge { .. }
    ));
    let confirm = std::env::var("VPN_HANDSHAKE_REPLAY_CONFIRM").unwrap();
    transport.send(confirm.as_bytes(), deadline).unwrap();
    assert!(transport.read_frame(deadline).is_err());
}

#[test]
fn writer_rejects_replayed_instance_frames_in_a_new_session() {
    // Session A is valid: capture the exact bytes the writer accepted.
    let fixture = Fixture::new();
    let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    let client = connect_fixture(&fixture.0.join("control"));
    let deadline = Instant::now() + PHASE_TIMEOUT;
    let hello = serde_json::to_vec(&fixture_hello()).unwrap();
    client.send(&hello, deadline).unwrap();
    let confirm = std::thread::scope(|scope| {
        let handshake =
            scope.spawn(|| writer.authenticate(&FakeAttestor::expected(std::process::id())));
        let (
            Frame::WriterChallenge {
                challenge_i,
                challenge_w,
            },
            _,
        ) = client.read_frame(deadline).unwrap()
        else {
            panic!("fixture expected writer_challenge");
        };
        let confirm = serde_json::to_vec(&Frame::InstanceConfirm {
            challenge_i,
            challenge_w,
            version: VERSION,
            generation: GENERATION.to_owned(),
            backend: Backend::Ipsec,
            invocation: INVOCATION.to_owned(),
        })
        .unwrap();
        client.send(&confirm, deadline).unwrap();
        assert!(
            handshake.join().unwrap().is_ok(),
            "captured bytes are valid"
        );
        confirm
    });

    // Session B is a new writer and a real process that resends session A's
    // bytes: first with a fresh hello, then with the replayed hello as well,
    // so the instance challenge matches and only the writer's is new.
    let hello = String::from_utf8(hello).unwrap();
    let confirm = String::from_utf8(confirm).unwrap();
    for replay_hello in [false, true] {
        let fixture = Fixture::new();
        let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
        let mut env = vec![("VPN_HANDSHAKE_REPLAY_CONFIRM", confirm.as_str())];
        if replay_hello {
            env.push(("VPN_HANDSHAKE_REPLAY_HELLO", hello.as_str()));
        }
        let mut instance = child_with(&fixture, "replay", false, std::process::id(), &env);
        let error = writer
            .authenticate(&FakeAttestor::expected(instance.0.id()))
            .err()
            .expect("authenticated a replayed instance_confirm");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "instance confirmation challenge mismatch",
            "replay_hello={replay_hello}"
        );
        assert!(instance.0.wait().unwrap().success());
    }
}

#[test]
fn writer_returns_no_channel_when_writer_confirm_cannot_be_delivered() {
    let fixture = Fixture::new();
    let writer = fixture.publish(ids(), PHASE_TIMEOUT).unwrap();
    let client = connect_fixture(&fixture.0.join("control"));
    let deadline = Instant::now() + PHASE_TIMEOUT;
    client.write_frame(&fixture_hello(), deadline).unwrap();
    // The attestor holds the writer between instance_confirm and writer_confirm
    // until the instance is gone, so the order is deterministic, not a race.
    let (gone, wait_gone) = std::sync::mpsc::channel::<()>();
    let attestor = AttestorFn::new(move |fd: BorrowedFd<'_>| {
        wait_gone
            .recv()
            .expect("fixture signals the closed instance");
        FakeAttestor::expected(std::process::id()).attest(fd)
    });
    let error = std::thread::scope(|scope| {
        let handshake = scope.spawn(|| writer.authenticate(&attestor));
        let (
            Frame::WriterChallenge {
                challenge_i,
                challenge_w,
            },
            _,
        ) = client.read_frame(deadline).unwrap()
        else {
            panic!("fixture expected writer_challenge");
        };
        client
            .write_frame(
                &Frame::InstanceConfirm {
                    challenge_i,
                    challenge_w,
                    version: VERSION,
                    generation: GENERATION.to_owned(),
                    backend: Backend::Ipsec,
                    invocation: INVOCATION.to_owned(),
                },
                deadline,
            )
            .unwrap();
        // The instance disappears after a valid confirmation and before it
        // can read writer_confirm.
        // shutdown, not only close: a concurrent test's fork-before-exec child
        // can briefly hold a copy of this descriptor open.
        // SAFETY: shutdown takes the client's socket FD and an integer.
        unsafe {
            syscall_result(libc::shutdown(client.socket.as_raw_fd(), libc::SHUT_RDWR)).unwrap();
        }
        drop(client);
        gone.send(()).unwrap();
        handshake.join().unwrap().err().expect("returned a channel")
    });
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
        ),
        "{error}"
    );
}
