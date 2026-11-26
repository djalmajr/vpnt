use super::*;
use crate::tunneld::{
    admin::{PolicyFixture, acquire_eventually},
    policy::Entry,
    protocol::{CidrV4, Credentials, ProbeBinding, decode_response},
};
use std::{
    io::{Read, Write},
    net::Shutdown,
    sync::atomic::{AtomicUsize, Ordering},
};

const HELLO: &[u8] = b"{\"op\":\"hello\",\"version\":1}\n";

fn connection(server: &Arc<Server>, uid: u32) -> (UnixStream, Option<thread::JoinHandle<()>>) {
    let (client, stream) = UnixStream::pair().unwrap();
    let worker = server.dispatch(stream, |_| Ok(uid));
    (client, worker)
}

fn receive(stream: &UnixStream) -> Response {
    read_control(
        &mut timed(stream, Instant::now() + FRAME_TIMEOUT).unwrap(),
        decode_response,
    )
    .unwrap()
}

fn expect_close(stream: &UnixStream) {
    let mut io = timed(stream, Instant::now() + FRAME_TIMEOUT).unwrap();
    assert_eq!(io.read(&mut [0]).unwrap(), 0);
}

fn session() -> (UnixStream, thread::JoinHandle<()>) {
    let (mut client, worker) = connection(&Arc::default(), 1000);
    client.write_all(HELLO).unwrap();
    assert!(matches!(
        receive(&client),
        Response::Version { version: VERSION }
    ));
    (client, worker.unwrap())
}

fn expect_error(client: &UnixStream, expected: ErrorCode) {
    assert!(matches!(receive(client), Response::Error { code } if code == expected));
    expect_close(client);
}

#[test]
fn uid_zero_is_closed_without_a_reply() {
    let server = Arc::default();
    let (root, worker) = connection(&server, 0);
    assert!(worker.is_none());
    expect_close(&root);
    let (mut user, worker) = connection(&server, 1000);
    user.write_all(HELLO).unwrap();
    assert!(matches!(
        receive(&user),
        Response::Version { version: VERSION }
    ));
    drop(user);
    worker.unwrap().join().unwrap();
}

#[test]
fn busy_at_per_uid_and_global_limit_and_slots_are_reused() {
    let server = Arc::default();
    let exercise = |uids: &[u32], overflow_uid| {
        let held: Vec<_> = uids
            .iter()
            .map(|&uid| {
                let (mut client, worker) = connection(&server, uid);
                client.write_all(HELLO).unwrap();
                assert!(matches!(
                    receive(&client),
                    Response::Version { version: VERSION }
                ));
                (client, worker.unwrap())
            })
            .collect();

        let (mut busy, worker) = connection(&server, overflow_uid);
        busy.write_all(HELLO).unwrap();
        expect_error(&busy, ErrorCode::Busy);
        worker.unwrap().join().unwrap();

        for (client, worker) in held {
            drop(client);
            worker.join().unwrap();
        }
        let (mut reused, worker) = connection(&server, overflow_uid);
        reused.write_all(HELLO).unwrap();
        assert!(matches!(
            receive(&reused),
            Response::Version { version: VERSION }
        ));
        drop(reused);
        worker.unwrap().join().unwrap();
    };
    exercise(&[1000, 1000], 1000);
    exercise(&[1000, 1000, 1001, 1001, 1002, 1002, 1003, 1003], 1004);
}

#[test]
fn unsupported_hello_version_closes_with_typed_error() {
    let (mut client, worker) = connection(&Arc::default(), 1000);
    client
        .write_all(b"{\"op\":\"hello\",\"version\":3}\n")
        .unwrap();
    expect_error(&client, ErrorCode::UnsupportedVersion);
    worker.unwrap().join().unwrap();
}

#[test]
fn valid_preparations_are_denied_before_any_prepared_response() {
    for frame in [
        concat!(
            r#"{"op":"prepare_ipsec","endpoint":{"host":"vpn.example","port":500},"#,
            r#""username":"alice","networks":[{"network":"10.20.0.0","prefix":16}]}"#,
            "\n",
        ),
        concat!(
            r#"{"op":"prepare_fortinet","endpoint":{"host":"vpn.example","port":443},"#,
            r#""username":"alice","certificate_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#,
            "\n",
        ),
    ] {
        assert!(matches!(
            decode_request(frame.as_bytes()),
            Ok(Request::PrepareIpsec(_) | Request::PrepareFortinet(_))
        ));
        let (mut client, worker) = session();
        client.write_all(frame.as_bytes()).unwrap();
        expect_error(&client, ErrorCode::PermissionDenied);
        worker.join().unwrap();
    }
}

#[test]
fn rejects_wrong_phase_and_malformed_control_frames() {
    for frame in [b"{\"op\":\"status\"}\n".as_slice(), b"{broken}\n"] {
        let (mut client, worker) = connection(&Arc::default(), 1000);
        client.write_all(frame).unwrap();
        expect_error(&client, ErrorCode::BadRequest);
        worker.unwrap().join().unwrap();

        let (mut client, worker) = session();
        client.write_all(frame).unwrap();
        expect_error(&client, ErrorCode::BadRequest);
        worker.join().unwrap();
    }
}

#[test]
fn partial_frames_expire_in_both_phases_without_blocking_other_connections() {
    let expected_timeout = Duration::from_secs(5);
    let server = Arc::default();
    let start = Instant::now();
    let (mut partial_hello, hello_worker) = connection(&server, 1000);
    partial_hello.write_all(b"{").unwrap();
    let (mut partial_prepare, prepare_worker) = connection(&server, 1000);
    partial_prepare.write_all(HELLO).unwrap();
    assert!(matches!(
        receive(&partial_prepare),
        Response::Version { version: VERSION }
    ));
    partial_prepare.write_all(b"{").unwrap();

    let (mut control, worker) = connection(&server, 1001);
    control.write_all(HELLO).unwrap();
    assert!(matches!(
        receive(&control),
        Response::Version { version: VERSION }
    ));
    drop(control);
    worker.unwrap().join().unwrap();

    // A second byte shortly before expiry must not reset either frame's budget.
    thread::sleep(expected_timeout - Duration::from_secs(1));
    partial_hello.write_all(b"\"").unwrap();
    partial_prepare.write_all(b"\"").unwrap();
    expect_close(&partial_hello);
    expect_close(&partial_prepare);
    let elapsed = start.elapsed();
    assert!(
        (expected_timeout..expected_timeout + Duration::from_secs(2)).contains(&elapsed),
        "partial frames closed after {elapsed:?}",
    );
    hello_worker.unwrap().join().unwrap();
    prepare_worker.unwrap().join().unwrap();
}

#[test]
fn eof_closes_silently_in_both_phases() {
    let (client, worker) = connection(&Arc::default(), 1000);
    client.shutdown(Shutdown::Write).unwrap();
    expect_close(&client);
    worker.unwrap().join().unwrap();

    let (client, worker) = session();
    client.shutdown(Shutdown::Write).unwrap();
    expect_close(&client);
    worker.join().unwrap();
}

#[test]
fn a_slow_busy_hello_does_not_block_the_listener_or_grow_the_rejection_path() {
    let server = Arc::default();
    let (first, first_worker) = connection(&server, 1000);
    let (second, second_worker) = connection(&server, 1000);
    let (mut pending_busy, busy_worker) = connection(&server, 1000);
    let (extra, extra_worker) = connection(&server, 1000);
    assert!(extra_worker.is_none());
    expect_close(&extra);

    let (mut other_uid, other_worker) = connection(&server, 1001);
    other_uid.write_all(HELLO).unwrap();
    assert!(matches!(
        receive(&other_uid),
        Response::Version { version: VERSION }
    ));
    pending_busy.write_all(HELLO).unwrap();
    expect_error(&pending_busy, ErrorCode::Busy);

    for (stream, worker) in [
        (first, first_worker),
        (second, second_worker),
        (other_uid, other_worker),
        (pending_busy, busy_worker),
    ] {
        drop(stream);
        worker.unwrap().join().unwrap();
    }
}

#[test]
fn cleanup_queries_are_v2_only_and_fail_closed_for_invalid_or_absent_ids() {
    let server = Arc::default();
    for (version, generation, expected_error) in [
        (1, "0123456789abcdef0123456789abcdef", true),
        (2, "../not-a-generation", true),
        (2, "0123456789abcdef0123456789abcdef", false),
    ] {
        let (mut client, worker) = connection(&server, 1000);
        writeln!(client, r#"{{"op":"hello","version":{version}}}"#).unwrap();
        assert!(
            matches!(receive(&client), Response::Version {version: actual} if actual == version)
        );
        writeln!(
            client,
            r#"{{"op":"cleanup_status","generation":"{generation}"}}"#
        )
        .unwrap();
        if expected_error {
            expect_error(&client, ErrorCode::BadRequest);
        } else {
            assert!(matches!(
                receive(&client),
                Response::CleanupStatus {
                    state: CleanupState::Unknown
                }
            ));
            expect_close(&client);
        }
        worker.unwrap().join().unwrap();
    }
}

#[test]
fn admitted_v2_stop_acknowledges_before_publishing_cleanup_receipt() {
    struct FakeLaunch {
        stops: AtomicUsize,
        finish: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    struct FakeSession<'a> {
        launcher: &'a FakeLaunch,
        binding: ProbeBinding,
    }

    impl Launch for FakeLaunch {
        fn launch<'a>(
            &'a self,
            _: &Prepare,
            _: &Entry,
            _: Credentials,
            _: File,
            _: &Arc<SetupCancellation>,
        ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
            panic!("expected the v2 launch");
        }

        fn launch_v2<'a>(
            &'a self,
            _: &Prepare,
            _: &Entry,
            _: Credentials,
            _: File,
            _: &Arc<SetupCancellation>,
            record: &mut Reservation<'_>,
        ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
            record.arm().expect("arm the fixture cleanup receipt");
            Ok(Box::new(FakeSession {
                launcher: self,
                binding: ProbeBinding::new(
                    record.generation().clone(),
                    7,
                    "10.99.0.2".parse().unwrap(),
                    vec![CidrV4::new("10.20.0.0".parse().unwrap(), 16).unwrap()],
                )
                .unwrap(),
            }))
        }
    }

    impl Running for FakeSession<'_> {
        fn state(&self) -> State {
            State::NetworkReady
        }

        fn probe_binding(&self, _: Instant) -> io::Result<ProbeBinding> {
            Ok(self.binding.clone())
        }

        fn stop(&mut self) -> State {
            self.launcher.stops.fetch_add(1, Ordering::SeqCst);
            self.launcher
                .finish
                .lock()
                .unwrap()
                .recv_timeout(FRAME_TIMEOUT)
                .unwrap();
            State::Stopped
        }
    }

    let policy = PolicyFixture::new();
    policy.install();
    let directory = policy.store.open().unwrap();
    drop(acquire_eventually(|| directory.lock_shared()).unwrap());
    let store = Store::open(policy.path().parent().unwrap()).unwrap();
    let (finish, resume) = std::sync::mpsc::channel();
    let launcher = FakeLaunch {
        stops: AtomicUsize::new(0),
        finish: Mutex::new(resume),
    };

    thread::scope(|scope| {
        let serve_pair = || {
            let (mut client, stream) = UnixStream::pair().unwrap();
            let worker = scope
                .spawn(|| serve_cleanup_fixture(stream, 1000, &policy.store, &launcher, &store));
            write_control(
                &mut client,
                &Request::Hello {
                    version: CLEANUP_VERSION,
                },
            )
            .unwrap();
            assert!(matches!(
                receive(&client),
                Response::Version {
                    version: CLEANUP_VERSION
                }
            ));
            (client, worker)
        };
        let (mut client, worker) = serve_pair();
        writeln!(client, r#"{{"op":"prepare_ipsec","endpoint":{{"host":"vpn.example","port":500}},"username":"fixture","networks":[{{"network":"10.20.0.0","prefix":16}}]}}"#).unwrap();
        let Response::Prepared {
            generation: Some(generation),
        } = receive(&client)
        else {
            panic!("expected a v2 generation");
        };
        Credentials::ipsec("fixture-password", "fixture-psk")
            .unwrap()
            .write(&mut client)
            .unwrap();
        let ready_by = Instant::now() + FRAME_TIMEOUT;
        loop {
            write_control(&mut client, &Request::Status {}).unwrap();
            match receive(&client) {
                Response::NetworkReady { binding } => {
                    assert_eq!(binding.generation(), &generation);
                    break;
                }
                Response::Status {
                    state: State::Starting,
                } if Instant::now() < ready_by => {
                    thread::yield_now();
                }
                response => panic!("expected an active dialogue: {response:?}"),
            }
        }
        write_control(&mut client, &Request::Stop {}).unwrap();
        assert!(matches!(
            receive(&client),
            Response::Status {
                state: State::Stopping
            }
        ));
        expect_close(&client);

        let query = |expected| {
            let (mut query, worker) = serve_pair();
            write_control(
                &mut query,
                &Request::CleanupStatus {
                    generation: generation.clone(),
                },
            )
            .unwrap();
            let response = receive(&query);
            assert!(
                matches!(response, Response::CleanupStatus { state } if state == expected),
                "expected cleanup {expected:?}, got {response:?}"
            );
            expect_close(&query);
            worker.join().unwrap().unwrap();
        };
        query(CleanupState::Pending);
        finish.send(()).unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(launcher.stops.load(Ordering::SeqCst), 1);
        query(CleanupState::Stopped);
    });
}
