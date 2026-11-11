use std::io::{BufReader, Cursor};
use vpnt::helper::protocol::{self, Command, MAX_REQUEST_BYTES, Message, ProtocolError};

#[test]
fn runtime_cannot_edit_profiles_or_accept_arbitrary_paths_and_commands() {
    for body in [
        r#"{"id":"r-1","command":{"type":"save_profile","profile":{}}}"#,
        r#"{"id":"r-1","command":{"type":"shell","program":"/bin/sh"}}"#,
        r#"{"id":"r-1","command":{"type":"snapshot","path":"/etc/passwd"}}"#,
        r#"{"id":"r-1","command":{"type":"probe","id":"../other-user","generation":1}}"#,
        r#"{"id":"r-1","command":{"type":"disconnect","id":"a","generation":0}}"#,
        r#"{"id":"r-1","command":{"type":"snapshot"}} {}"#,
    ] {
        assert!(protocol::parse_request(body.as_bytes()).is_err());
    }
    let request =
        protocol::parse_request(br#"{"id":"r-1","command":{"type":"snapshot"}}"#).unwrap();
    assert!(matches!(request.command, Command::Snapshot {}));
}

#[test]
fn framed_input_is_bounded_and_requires_a_complete_document() {
    let wire = b"{\"id\":\"r-1\",\"command\":{\"type\":\"snapshot\"}}\n{\"id\":\"r-2\",\"command\":{\"type\":\"snapshot\"}}\n";
    let mut reader = BufReader::with_capacity(1, Cursor::new(wire));
    assert_eq!(
        protocol::read_request(&mut reader).unwrap().unwrap().id,
        "r-1"
    );
    assert_eq!(
        protocol::read_request(&mut reader).unwrap().unwrap().id,
        "r-2"
    );
    assert!(protocol::read_request(&mut reader).unwrap().is_none());
    for invalid in [
        b"{}".to_vec(),
        b"\n".to_vec(),
        vec![b' '; MAX_REQUEST_BYTES + 1],
        b"\xff\n".to_vec(),
    ] {
        assert!(protocol::read_request(&mut BufReader::new(Cursor::new(invalid))).is_err());
    }
    let request = protocol::Request {
        id: "r-3".into(),
        command: Command::Connect {
            id: "a".into(),
            generation: 1,
            credentials: vpnt::secrets::Credentials {
                password: "fictício-✓".into(),
                psk: "chave-fictícia".into(),
            },
        },
    };
    let mut wire = Vec::new();
    protocol::write_request(&mut wire, &request).unwrap();
    let decoded = protocol::read_request(&mut BufReader::with_capacity(1, Cursor::new(wire)))
        .unwrap()
        .unwrap();
    let Command::Connect { credentials, .. } = decoded.command else {
        panic!("wrong command");
    };
    assert!(credentials.password.expose() == "fictício-✓");
    assert!(credentials.psk.expose() == "chave-fictícia");
}

#[test]
fn administration_rejects_runtime_secrets_and_multiple_documents_before_any_mutation() {
    for invalid in [
        b"{\"id\":\"r-1\",\"command\":{\"type\":\"connect\",\"id\":\"a\",\"generation\":1,\"credentials\":{\"password\":\"fake\",\"psk\":\"fake\"}}}\n".as_slice(),
        b"{\"id\":\"r-1\",\"command\":{\"type\":\"remove_profile\",\"id\":\"a\"}}\n{\"id\":\"r-2\",\"command\":{\"type\":\"remove_profile\",\"id\":\"b\"}}\n".as_slice(),
    ] {
        assert!(protocol::read_admin_request(&mut BufReader::new(Cursor::new(invalid))).is_err());
    }
    assert!(
        protocol::read_admin_request(&mut BufReader::new(Cursor::new(
            b"{\"id\":\"r-1\",\"command\":{\"type\":\"remove_profile\",\"id\":\"a\"}}\n"
        )))
        .is_ok()
    );
}

#[test]
fn helper_replies_are_typed_and_incompatible_versions_are_reported() {
    let unsupported = b"{\"type\":\"snapshot\",\"id\":\"r-1\",\"protocol_version\":999,\"version\":\"0.1.0\",\"profiles\":[],\"connections\":[]}\n";
    assert!(matches!(
        protocol::read_message(&mut BufReader::new(Cursor::new(unsupported))),
        Err(ProtocolError::UnsupportedVersion)
    ));
    let injected = b"{\"type\":\"accepted\",\"id\":\"r-1\",\"password\":\"fake\"}\n";
    assert!(protocol::read_message(&mut BufReader::new(Cursor::new(injected))).is_err());
    let mut wire = Vec::new();
    protocol::write_message(&mut wire, &Message::Accepted { id: "r-1".into() }).unwrap();
    let decoded = protocol::read_message(&mut BufReader::new(Cursor::new(wire)))
        .unwrap()
        .unwrap();
    assert!(matches!(decoded, Message::Accepted { id } if id == "r-1"));
}
