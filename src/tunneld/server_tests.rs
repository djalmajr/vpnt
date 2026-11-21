use super::*;
use crate::tunneld::protocol::decode_response;
use std::{
    io::{Read, Write},
    net::Shutdown,
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
        .write_all(b"{\"op\":\"hello\",\"version\":2}\n")
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
