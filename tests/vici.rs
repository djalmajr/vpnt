#![cfg(unix)]
use std::{io::Cursor, os::unix::net::UnixStream, thread, time::Duration};
use vpnt::helper::vici::{self, Client, Message, Packet};

#[test]
fn version_request_uses_the_documented_binary_frame() {
    let mut output = Vec::new();
    vici::write_packet(
        &mut output,
        &Packet::Request("version".into(), Message::new()),
    )
    .unwrap();
    assert_eq!(output, b"\0\0\0\x09\0\x07version");
    let decoded = vici::read_packet(&mut Cursor::new(output)).unwrap();
    assert!(matches!(decoded,Packet::Request(name,_) if name=="version"));
}

#[test]
fn nested_sections_lists_and_binary_values_round_trip_without_debug_disclosure() {
    let mut child = Message::new();
    child.value("secret", b"fictional-secret\0\xff");
    child.list("networks", [b"10.20.0.0/24".as_slice(), b"::/0"]);
    let mut message = Message::new();
    message.section("vpnt-a", child);
    let mut output = Vec::new();
    vici::write_packet(&mut output, &Packet::Response(message)).unwrap();
    let Packet::Response(decoded) = vici::read_packet(&mut Cursor::new(output)).unwrap() else {
        panic!("wrong packet");
    };
    assert!(
        decoded
            .get_section("vpnt-a")
            .unwrap()
            .get_value("secret")
            .unwrap()
            == b"fictional-secret\0\xff"
    );
    assert_eq!(
        decoded
            .get_section("vpnt-a")
            .unwrap()
            .get_list("networks")
            .unwrap()
            .len(),
        2
    );
    assert!(!format!("{decoded:?}").contains("fictional-secret"));
}

#[test]
fn duplicate_keys_unbalanced_lists_and_oversized_frames_are_rejected() {
    let bodies: Vec<Vec<u8>> = vec![
        vec![1, 3, 1, b'a', 0, 1, b'x', 3, 1, b'a', 0, 1, b'y'],
        vec![1, 4, 1, b'a', 3, 1, b'b', 0, 1, b'x'],
        vec![1, 1, 1, b'a'],
        vec![1, 6],
        vec![5, 1],
    ];
    for body in bodies {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend(body);
        assert!(vici::read_packet(&mut Cursor::new(frame)).is_err());
    }
    assert!(vici::read_packet(&mut Cursor::new([0xff; 4])).is_err());
}

#[test]
fn client_handles_streamed_events_before_the_command_response_and_checks_peer_uid() {
    let (client, mut server) = UnixStream::pair().unwrap();
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    let worker = thread::spawn(move || {
        assert!(
            matches!(vici::read_packet(&mut server).unwrap(),Packet::Register(name) if name=="control-log")
        );
        vici::write_packet(&mut server, &Packet::Confirm).unwrap();
        assert!(
            matches!(vici::read_packet(&mut server).unwrap(),Packet::Request(name,_) if name=="initiate")
        );
        let mut event = Message::new();
        event.value("msg", b"fixture event");
        vici::write_packet(&mut server, &Packet::Event("control-log".into(), event)).unwrap();
        let mut reply = Message::new();
        reply.value("success", b"yes");
        vici::write_packet(&mut server, &Packet::Response(reply)).unwrap();
    });
    let result = Client::from_stream(client, uid, Duration::from_secs(1))
        .unwrap()
        .command("initiate", Message::new(), &["control-log"])
        .unwrap();
    assert_eq!(result.response.get_text("success"), Some("yes"));
    assert_eq!(result.events.len(), 1);
    worker.join().unwrap();
    let (client, _server) = UnixStream::pair().unwrap();
    assert!(Client::from_stream(client, uid.wrapping_add(1), Duration::from_secs(1)).is_err());
}

#[test]
fn malformed_or_excessive_output_is_rejected_before_any_bytes_are_written() {
    for key in ["", "bad name", "bad\0name", "não-ascii"] {
        let mut message = Message::new();
        message.value(key, b"fixture");
        let mut output = Vec::new();
        assert!(vici::write_packet(&mut output, &Packet::Response(message)).is_err());
        assert!(output.is_empty());
    }
    let mut duplicate = Message::new();
    duplicate.value("same", b"first").value("same", b"second");
    let mut large = Message::new();
    large.value("blob", &vec![0; 65536]);
    let mut deep = Message::new();
    for _ in 0..33 {
        let mut parent = Message::new();
        parent.section("s", deep);
        deep = parent;
    }
    for message in [duplicate, large, deep] {
        let mut output = Vec::new();
        assert!(vici::write_packet(&mut output, &Packet::Response(message)).is_err());
        assert!(output.is_empty());
    }
}

#[test]
fn decoder_rejects_every_truncation_and_bounds_nesting_and_element_count() {
    let mut child = Message::new();
    child.value("v", b"binary\0\xff");
    let mut message = Message::new();
    message.section("s", child).list("l", [b"item".as_slice()]);
    let mut frame = Vec::new();
    vici::write_packet(&mut frame, &Packet::Event("test".into(), message)).unwrap();
    for length in 0..frame.len() {
        assert!(vici::read_packet(&mut Cursor::new(&frame[..length])).is_err());
    }
    let deep: Vec<_> = std::iter::once(1)
        .chain([1, 1, b's'].repeat(33))
        .chain(vec![2; 33])
        .collect();
    let mut many = vec![1, 4, 1, b'l'];
    for _ in 0..16384 {
        many.extend([5, 0, 0]);
    }
    many.push(6);
    for body in [deep, many] {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend(body);
        assert_eq!(
            vici::read_packet(&mut Cursor::new(frame)).unwrap_err(),
            vici::Error::Limit
        );
    }
}

#[test]
fn client_drains_buffered_replies_and_honors_a_total_deadline_for_fragmented_frames() {
    use std::{io::Write, time::Instant};
    // SAFETY: geteuid has no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        vici::read_packet(&mut server).unwrap();
        // A peer may close with a complete response still in the receive buffer.
        server.write_all(b"\0\0\0\x01\x01").unwrap();
    });
    Client::from_stream(client, uid, Duration::from_secs(1))
        .unwrap()
        .command("version", Message::new(), &[])
        .unwrap();
    worker.join().unwrap();

    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        vici::read_packet(&mut server).unwrap();
        for byte in b"\0\0\0\x01\x01" {
            if server.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
    });
    let start = Instant::now();
    let result = Client::from_stream(client, uid, Duration::from_millis(45))
        .unwrap()
        .command("version", Message::new(), &[]);
    assert!(matches!(result, Err(vici::Error::Timeout)));
    assert!(start.elapsed() < Duration::from_secs(1));
    worker.join().unwrap();
}

#[test]
fn subscriptions_allow_interleaved_confirmed_events_and_reject_unrequested_events() {
    // SAFETY: geteuid has no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        vici::read_packet(&mut server).unwrap();
        vici::write_packet(&mut server, &Packet::Confirm).unwrap();
        vici::read_packet(&mut server).unwrap();
        vici::write_packet(&mut server, &Packet::Event("first".into(), Message::new())).unwrap();
        vici::write_packet(&mut server, &Packet::Confirm).unwrap();
        vici::read_packet(&mut server).unwrap();
        vici::write_packet(&mut server, &Packet::Response(Message::new())).unwrap();
    });
    let result = Client::from_stream(client, uid, Duration::from_secs(1))
        .unwrap()
        .command("version", Message::new(), &["first", "second"])
        .unwrap();
    assert_eq!(result.events.len(), 1);
    worker.join().unwrap();
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        vici::read_packet(&mut server).unwrap();
        vici::write_packet(
            &mut server,
            &Packet::Event("unrequested".into(), Message::new()),
        )
        .unwrap();
    });
    assert!(matches!(
        Client::from_stream(client, uid, Duration::from_secs(1))
            .unwrap()
            .command("version", Message::new(), &[]),
        Err(vici::Error::UnexpectedPacket)
    ));
    worker.join().unwrap();
}

#[test]
fn client_connects_only_to_the_expected_user_on_a_real_unix_listener() {
    use std::{fs, os::unix::net::UnixListener};
    let directory = std::env::current_dir().unwrap().join("output/fixtures");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("vici-{}.sock", std::process::id()));
    let server = UnixListener::bind(&path).unwrap();
    // SAFETY: geteuid has no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    let worker = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        assert!(
            matches!(vici::read_packet(&mut stream).unwrap(),Packet::Request(name,_) if name=="version")
        );
        vici::write_packet(&mut stream, &Packet::Response(Message::new())).unwrap();
    });
    Client::connect(&path, uid, Duration::from_secs(1))
        .unwrap()
        .command("version", Message::new(), &[])
        .unwrap();
    worker.join().unwrap();
    fs::remove_file(path).unwrap();
    assert!(Client::connect(std::path::Path::new("/"), uid, Duration::ZERO).is_err());
}
