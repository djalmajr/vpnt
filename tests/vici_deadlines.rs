#![cfg(unix)]
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use vpnt::helper::vici::{self, Client, Message};
#[path = "vici_deadlines/peer.rs"]
mod peer;

fn uid() -> u32 {
    // SAFETY: geteuid has no memory preconditions.
    unsafe { libc::geteuid() }
}

// Mutation: restarting the deadline in command() sends a request after expiry.
#[test]
fn a_client_cannot_restart_its_budget_or_send_a_request_after_expiry() {
    let (stream, mut server) = UnixStream::pair().unwrap();
    // SAFETY: geteuid has no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    let client = Client::from_stream(stream, uid, Duration::from_millis(30)).unwrap();
    server.write_all(b"\0\0\0\x01\x01").unwrap();
    thread::sleep(Duration::from_millis(60));
    let result = client.command("version", Message::new(), &[]);
    let mut request = Vec::new();
    // The server's preloaded response may be discarded at socket close.
    let _ = server.read_to_end(&mut request);
    assert!(
        matches!(result, Err(vici::Error::Timeout)),
        "expired client sent a command"
    );
    assert!(request.is_empty(), "expired request reached the peer");
}

// Mutations: omit cancellation or poll for the whole deadline.
#[test]
fn cancellation_interrupts_response_header_subscription_and_blocked_write_before_peer_exit() {
    for mode in ["request", "fragment", "subscription", "write"] {
        let (mut peer, stream) = peer::Peer::new(mode);
        if mode == "write" {
            use std::os::fd::AsRawFd;
            let size = 4096_i32;
            // SAFETY: live descriptor, matching integer buffer and length.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        (&size as *const i32).cast(),
                        std::mem::size_of_val(&size) as _,
                    )
                },
                0
            );
        }
        let cancel = Arc::new(AtomicBool::new(false));
        // Longer than the 3.5 s readiness limit plus the result guard's margin:
        // the mutant must fail the readiness assertion, not a test timeout.
        let expires = Instant::now() + Duration::from_secs(15);
        let client = Client::from_stream_until(stream, uid(), expires, cancel.clone()).unwrap();
        let mut message = Message::new();
        if mode == "write" {
            for key in ["a", "b", "c", "d", "e", "f", "g", "h"] {
                message.value(key, &vec![b'x'; 60000]);
            }
        }
        let mut operation = peer::Operation::new(move || {
            client.command(
                "version",
                message,
                if mode == "subscription" {
                    &["list-sa"]
                } else {
                    &[]
                },
            )
        });
        assert_eq!(peer.line(), "waiting");
        if let Err(reason) = operation.wait_until_blocked(mode) {
            // Release both sides before unwinding without letting cleanup
            // replace the synchronization diagnosis.
            cancel.store(true, Ordering::Release);
            let result = operation.receive("cleanup");
            let received = match &result {
                Ok(Ok(_)) => "ok",
                Ok(Err(_)) => "error",
                Err(_) => "timeout",
            };
            let finish = peer.try_finish();
            let join = operation.try_join();
            panic!("{reason}; cleanup: receive={received}, finish={finish:?}, join={join:?}");
        }
        let cancel_at = Instant::now();
        cancel.store(true, Ordering::Release);
        let result = operation.receive(mode);
        let finished = operation
            .finished_at()
            .expect("operation did not record its return instant");
        let alive = peer.alive();
        let before_deadline = Instant::now() < expires;
        peer.finish();
        operation.join();
        let elapsed = finished.saturating_duration_since(cancel_at);
        assert!(
            elapsed <= Duration::from_millis(3500),
            "cancel took {elapsed:?} after store: {mode}"
        );
        assert!(
            matches!(result, Ok(Err(vici::Error::Canceled))),
            "cancel did not finish promptly: {mode}"
        );
        assert!(
            alive && before_deadline,
            "cancel was replaced by peer exit or timeout: {mode}"
        );
        if mode == "write" {
            let counts = peer.line();
            let (received, length) = counts
                .strip_prefix("body:")
                .unwrap()
                .split_once('/')
                .unwrap();
            assert!(
                received.parse::<usize>().unwrap() < length.parse::<usize>().unwrap(),
                "canceled write sent the full body"
            );
        }
    }
}

// Mutations: ignore a canceled/expired admission or remove peer UID validation.
#[test]
fn preflight_denies_canceled_expired_and_foreign_peers_without_sending_bytes() {
    for (canceled, expired, foreign, expected) in [
        (true, false, false, vici::Error::Canceled),
        (false, true, false, vici::Error::Timeout),
        (false, false, true, vici::Error::UntrustedPeer),
    ] {
        let (stream, mut server) = UnixStream::pair().unwrap();
        let expires = Instant::now()
            + if expired {
                Duration::ZERO
            } else {
                Duration::from_secs(15)
            };
        let result = Client::from_stream_until(
            stream,
            uid() + u32::from(foreign),
            expires,
            Arc::new(AtomicBool::new(canceled)),
        );
        let observed = result.err();
        let mut bytes = Vec::new();
        let _ = server.read_to_end(&mut bytes);
        assert_eq!(observed, Some(expected));
        assert!(bytes.is_empty());
    }
    // An OS abort is not an operator cancellation; only our private marker is.
    assert_eq!(
        vici::Error::from(std::io::Error::from(std::io::ErrorKind::ConnectionAborted)),
        vici::Error::Io
    );
}

// Mutations: replace the caller's absolute deadline, or report timeout as cancel.
#[test]
fn an_independent_peer_cannot_extend_the_callers_deadline_and_a_reply_still_succeeds() {
    for mode in ["request", "reply"] {
        let (mut peer, stream) = peer::Peer::new(mode);
        // Both arms need room for a 3 s setup pause before the request is
        // sent. The readiness limit is the 3.5 s measured from `expires` to
        // the worker's recorded return, not the length of the setup.
        let expires = Instant::now()
            + if mode == "reply" {
                Duration::from_secs(15)
            } else {
                Duration::from_secs(4)
            };
        let client =
            Client::from_stream_until(stream, uid(), expires, Arc::new(AtomicBool::new(false)))
                .unwrap();
        let mut operation =
            peer::Operation::new(move || client.command("version", Message::new(), &[]));
        assert_eq!(peer.line(), "waiting");
        let result = operation.receive(mode);
        let finished = operation
            .finished_at()
            .expect("operation did not record its return instant");
        let alive = peer.alive();
        peer.finish();
        operation.join();
        assert!(alive, "peer exited before the consumer result");
        if mode == "reply" {
            assert!(
                finished < expires,
                "reply arrived after the caller deadline"
            );
            assert!(matches!(result, Ok(Ok(_))));
        } else {
            let elapsed = finished.saturating_duration_since(expires);
            assert!(
                elapsed <= Duration::from_millis(3500),
                "timeout took {elapsed:?} after expires"
            );
            assert!(
                matches!(result, Ok(Err(vici::Error::Timeout))),
                "caller deadline was extended"
            );
        }
    }
}

// Mutations: drop cancellation/deadline during connect, admit another UID, or
// reset the budget between opening the real listener and sending the command.
#[test]
fn path_connection_keeps_the_callers_budget_and_rejects_unadmitted_peers() {
    use std::os::unix::net::UnixListener;
    let directory = peer::SocketDirectory::new();
    let path = directory.0.join("vici.sock");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    for (canceled, expired, foreign, expected) in [
        (true, false, false, vici::Error::Canceled),
        (false, true, false, vici::Error::Timeout),
        (false, false, true, vici::Error::UntrustedPeer),
    ] {
        let expires = Instant::now()
            + if expired {
                Duration::ZERO
            } else {
                Duration::from_secs(15)
            };
        let result = Client::connect_until(
            &path,
            uid() + u32::from(foreign),
            expires,
            Arc::new(AtomicBool::new(canceled)),
        );
        assert_eq!(result.err(), Some(expected));
        if foreign {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            let _ = stream.read_to_end(&mut bytes);
            assert!(bytes.is_empty());
        } else {
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let client = Client::connect_until(
        &path,
        uid(),
        Instant::now() + Duration::from_secs(15),
        cancel.clone(),
    )
    .unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    cancel.store(true, Ordering::Release);
    assert!(matches!(
        client.command("version", Message::new(), &[]),
        Err(vici::Error::Canceled)
    ));
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    assert!(bytes.is_empty());

    // The budget given to the public `Client::connect` is the one under test:
    // it must reach the later command. Four seconds tolerate a 3 s setup pause;
    // after it has actually expired, the command must still reject without
    // sending the preloaded reply request.
    // The budget starts inside `connect`, so anchor the wait at its return:
    // that instant is never earlier than the budget's own start.
    let connect_budget = Duration::from_secs(4);
    let client = Client::connect(&path, uid(), connect_budget).unwrap();
    let connected_at = Instant::now();
    let (mut stream, _) = listener.accept().unwrap();
    stream.write_all(b"\0\0\0\x01\x01").unwrap();
    let expired_at = connected_at + connect_budget + Duration::from_millis(50);
    while Instant::now() < expired_at {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        client.command("version", Message::new(), &[]),
        Err(vici::Error::Timeout)
    ));
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    assert!(bytes.is_empty());
    assert!(matches!(
        Client::connect_until(
            std::path::Path::new("relative.sock"),
            uid(),
            Instant::now() + Duration::from_secs(15),
            Arc::new(AtomicBool::new(false))
        ),
        Err(vici::Error::InvalidMessage)
    ));
}
