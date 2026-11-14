//! Actual Producer -> C bind/listen barrier -> authenticated VICI.
use super::*;
use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::{atomic::Ordering, mpsc},
    thread,
};

fn bound(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let expires = Instant::now() + Duration::from_secs(3);
    loop {
        match listener.accept() {
            Ok((mut gate, _)) => {
                gate.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut byte = [0];
                gate.read_exact(&mut byte).unwrap();
                assert_eq!(byte, *b"B", "C has bound before listening");
                return gate;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < expires,
                    "fixture did not reach bind barrier"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("barrier accept: {error}"),
        }
    }
}

// Mutation: propagate the first connection-refused instead of retrying startup.
#[test]
fn bound_socket_waits_for_listen_then_reaches_real_vici() {
    let fixture = Fixture::new();
    let listener =
        UnixListener::bind(fixture.directory.join("startup.sock")).unwrap_or_else(|error| {
            panic!(
                "startup control bind in {}: {error}",
                fixture.directory.display()
            )
        });
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("startup-listen", 70)).unwrap();
    let configuration = config(&registry, &reservation);
    let mut peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    let (send, receive) = mpsc::channel();
    thread::scope(|scope| {
        let owner = reservation.owner();
        let peer = &mut peer;
        scope.spawn(move || {
            let result = peer.open(owner, until(), token()).map(|client| {
                let reply = client
                    .command("version", Message::new(), &[])
                    .unwrap()
                    .response;
                assert_eq!(reply.get_text("daemon"), Some("charon"));
                assert_eq!(reply.get_text("version"), Some("6.1.0"));
            });
            send.send(result).unwrap();
        });
        let mut gate = bound(&listener);
        // Readiness is a real C barrier. The observation interval discriminates
        // an immediate failed open; it does not create the bind/listen window.
        assert_eq!(
            receive.recv_timeout(Duration::from_millis(150)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "Producer.open must remain pending while C is bound but not listening"
        );
        gate.write_all(b"L").unwrap();
        assert_eq!(
            receive.recv_timeout(Duration::from_secs(3)).unwrap(),
            Ok(())
        );
    });
    peer.retire(reservation.owner()).unwrap();
    registry.release(&reservation).unwrap();
}

#[test]
fn bound_socket_deadline_and_cancel_keep_the_original_budget() {
    for mode in ["deadline", "cancel"] {
        let fixture = Fixture::new();
        let listener =
            UnixListener::bind(fixture.directory.join("startup.sock")).unwrap_or_else(|error| {
                panic!(
                    "startup control bind in {}: {error}",
                    fixture.directory.display()
                )
            });
        let context = fixture.context();
        let mut registry = Registry::new(context.observer(Kernel::default()));
        let reservation = registry.reserve(owner("startup-budget", 71)).unwrap();
        let configuration = config(&registry, &reservation);
        let mut peer = context
            .prepare(&registry, &reservation, &configuration)
            .unwrap();
        let cancel = token();
        // Both budgets include spawn/handoff and are never renewed. Cancellation
        // uses the ordinary fixture budget so the deadline does not win first.
        let expires = if mode == "deadline" {
            Instant::now() + Duration::from_millis(900)
        } else {
            until()
        };
        let (send, receive) = mpsc::channel();
        thread::scope(|scope| {
            let peer = &mut peer;
            let owner = reservation.owner();
            let flag = cancel.clone();
            scope.spawn(move || {
                send.send(peer.open(owner, expires, flag).map(|_| ()))
                    .unwrap();
            });
            let _gate = bound(&listener);
            let expected = if mode == "cancel" {
                assert_eq!(
                    receive.recv_timeout(Duration::from_millis(100)),
                    Err(mpsc::RecvTimeoutError::Timeout),
                    "{mode}: must wait at the bound socket"
                );
                cancel.store(true, Ordering::Release);
                Error::Canceled
            } else {
                Error::Timeout
            };
            assert_eq!(
                receive.recv_timeout(Duration::from_secs(2)).unwrap(),
                Err(expected),
                "{mode}"
            );
            assert!(
                Instant::now() < expires + Duration::from_millis(500),
                "deadline was rebased"
            );
            // Dropping the gate releases the C wait by EOF; it never listened.
        });
        peer.retire(reservation.owner()).unwrap();
        registry.release(&reservation).unwrap();
    }
}
