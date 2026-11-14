use std::io::{BufReader, Cursor};
use vpnt::helper::protocol::{self, Command, MAX_REQUEST_BYTES, Message, ProtocolError};
use vpnt::preferences::ProbeInterval;

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
fn pipe_shape_validation_does_not_apply_ssl_limits_to_an_unknown_profile_type() {
    let bytes=serde_json::to_vec(&serde_json::json!({"id":"request-1","command":{"type":"connect","id":"profile-1","generation":1,"interval":10,"credentials":{"password":"p".repeat(257),"psk":"fictional"}}})).unwrap();
    let request = protocol::parse_request(&bytes).unwrap();
    let Command::Connect { credentials, .. } = request.command else {
        panic!("wrong operation");
    };
    assert!(credentials.validate(vpnt::model::VpnKind::Ipsec).is_ok());
    assert!(credentials.validate(vpnt::model::VpnKind::Ssl).is_err());
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
            interval: ProbeInterval::TEN,
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

#[test]
fn administrative_readiness_requires_the_current_protocol_before_any_document() {
    for version in [1, 2, 999] {
        let frame = format!(
            "{{\"type\":\"admin_ready\",\"protocol_version\":{version},\"version\":\"0.1.0\"}}\n"
        );
        assert!(matches!(
            protocol::read_message(&mut BufReader::new(frame.as_bytes())),
            Err(ProtocolError::UnsupportedVersion)
        ));
    }
    let mut bytes = Vec::new();
    protocol::write_message(
        &mut bytes,
        &Message::AdminReady {
            protocol_version: protocol::VERSION,
            version: env!("CARGO_PKG_VERSION").into(),
        },
    )
    .unwrap();
    assert!(matches!(
        protocol::read_message(&mut BufReader::new(bytes.as_slice())),
        Ok(Some(Message::AdminReady {
            protocol_version: 3,
            ..
        }))
    ));
}

fn read_wire(frame: &str) -> Result<Option<Message>, ProtocolError> {
    protocol::read_message(&mut BufReader::new(Cursor::new(frame.as_bytes().to_vec())))
}
fn profile(id: &str) -> serde_json::Value {
    serde_json::json!({"id":id,"name":id,"kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})
}

#[test]
fn a_protocol_two_helper_is_incompatible_before_any_operation_or_secret() {
    let old = b"{\"type\":\"snapshot\",\"id\":\"r-1\",\"protocol_version\":2,\"version\":\"0.1.0\",\"profiles\":[],\"connections\":[]}\n";
    assert!(matches!(
        read_wire(std::str::from_utf8(old).unwrap()),
        Err(ProtocolError::UnsupportedVersion)
    ));
    // Same for the administrative readiness document, which precedes any
    // document a caller could execute.
    assert!(matches!(
        read_wire("{\"type\":\"admin_ready\",\"protocol_version\":2,\"version\":\"0.1.0\"}\n"),
        Err(ProtocolError::UnsupportedVersion)
    ));
}

#[test]
fn consecutive_failure_metadata_must_match_the_reported_state() {
    for (state, failures) in [("unresponsive", 1), ("unresponsive", 3)] {
        let frame = format!(
            "{{\"type\":\"changed\",\"profile_id\":\"one\",\"generation\":1,\"state\":\"{state}\",\"failures\":{failures}}}\n"
        );
        assert!(
            read_wire(&frame).unwrap().is_some(),
            "coherent progress must decode"
        );
    }
    for (state, failures) in [
        ("unresponsive", 0),
        ("unresponsive", 4),
        ("connected", 1),
        ("off", 2),
        ("connecting", 1),
    ] {
        let frame = format!(
            "{{\"type\":\"changed\",\"profile_id\":\"one\",\"generation\":1,\"state\":\"{state}\",\"failures\":{failures}}}\n"
        );
        assert!(
            matches!(read_wire(&frame), Err(ProtocolError::InvalidRequest)),
            "incoherent {state}/{failures} must be rejected"
        );
    }
    // No serde default: an old helper that omits the counter is not accepted
    // as a zero-failure status.
    assert!(matches!(
        read_wire(
            "{\"type\":\"changed\",\"profile_id\":\"one\",\"generation\":1,\"state\":\"connected\"}\n"
        ),
        Err(ProtocolError::InvalidRequest)
    ));
    let snapshot = |state: &str, failures: u32| {
        serde_json::json!({
            "type": "snapshot",
            "id": "snapshot-1",
            "protocol_version": protocol::VERSION,
            "version": "0.1.0",
            "profiles": [profile("one")],
            "connections": [{"id": "one", "generation": 1, "state": state, "failures": failures}],
        })
        .to_string()
            + "\n"
    };
    assert!(read_wire(&snapshot("unresponsive", 3)).unwrap().is_some());
    assert!(matches!(
        read_wire(&snapshot("unresponsive", 0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        read_wire(&snapshot("connected", 1)),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn the_wire_interval_is_a_closed_typed_set_and_required_on_connect() {
    let connect = |interval: &str| {
        format!(
            "{{\"id\":\"r-1\",\"command\":{{\"type\":\"connect\",\"id\":\"one\",\"generation\":1,\"interval\":{interval},\"credentials\":{{\"password\":\"fictional\",\"psk\":\"\"}}}}}}\n"
        )
    };
    for seconds in ["10", "30", "60"] {
        assert!(
            protocol::parse_request(connect(seconds).as_bytes()).is_ok(),
            "supported interval {seconds} must decode"
        );
    }
    for invalid in ["0", "5", "15", "61", "\"10\"", "10.5", "null", "{}"] {
        assert!(
            protocol::parse_request(connect(invalid).as_bytes()).is_err(),
            "unsupported interval {invalid} must be rejected"
        );
    }
    // No silent fallback when an old caller omits the field.
    assert!(
        protocol::parse_request(
            br#"{"id":"r-1","command":{"type":"connect","id":"one","generation":1,"credentials":{"password":"fictional","psk":""}}}"#
        )
        .is_err()
    );
    let request = protocol::parse_request(connect("30").as_bytes()).unwrap();
    let Command::Connect { interval, .. } = request.command else {
        panic!("wrong operation");
    };
    assert_eq!(interval, ProbeInterval::THIRTY);

    let set = |interval: &str| {
        format!(
            "{{\"id\":\"r-1\",\"command\":{{\"type\":\"set_probe_interval\",\"interval\":{interval}}}}}\n"
        )
    };
    for invalid in ["0", "15", "100", "-10"] {
        assert!(
            protocol::parse_request(set(invalid).as_bytes()).is_err(),
            "unsupported cadence {invalid} must be rejected"
        );
    }
    let request = protocol::parse_request(set("60").as_bytes()).unwrap();
    let Command::SetProbeInterval { interval } = request.command else {
        panic!("wrong operation");
    };
    assert_eq!(interval, ProbeInterval::SIXTY);
}

#[test]
fn a_genuine_protocol_two_snapshot_is_classified_by_version_not_by_its_old_shape() {
    // Protocol 2's TunnelStatus had no `failures` field. Typed decoding under
    // the current schema fails on that missing field, so the version must be
    // read from the raw frame before the shape is rejected.
    let snapshot = |version: serde_json::Value| {
        serde_json::json!({
            "type": "snapshot",
            "id": "snapshot-1",
            "protocol_version": version,
            "version": "0.1.0",
            "profiles": [profile("one")],
            "connections": [{"id": "one", "generation": 1, "state": "off"}],
        })
        .to_string()
            + "\n"
    };
    assert!(matches!(
        read_wire(&snapshot(serde_json::json!(2))),
        Err(ProtocolError::UnsupportedVersion)
    ));
    // The same body at the current version is a missing required field, not a
    // version skew, and is not accepted through the version probe.
    assert!(matches!(
        read_wire(&snapshot(serde_json::json!(3))),
        Err(ProtocolError::InvalidRequest)
    ));
    // A non-numeric version is malformed even when it names a different
    // version; the probe only reads integers.
    assert!(matches!(
        read_wire(&snapshot(serde_json::json!("2"))),
        Err(ProtocolError::InvalidRequest)
    ));
    // An unknown field on a current-version snapshot stays rejected.
    let unknown = serde_json::json!({
        "type": "snapshot",
        "id": "snapshot-1",
        "protocol_version": protocol::VERSION,
        "version": "0.1.0",
        "profiles": [profile("one")],
        "connections": [{"id": "one", "generation": 1, "state": "off", "failures": 0}],
        "foreign": true,
    })
    .to_string()
        + "\n";
    assert!(matches!(
        read_wire(&unknown),
        Err(ProtocolError::InvalidRequest)
    ));
    // Duplicate classifier fields remain malformed even if the last value
    // would otherwise look like an older helper.
    let duplicate = snapshot(serde_json::json!(3))
        .trim_end()
        .strip_suffix('}')
        .unwrap()
        .to_owned()
        + ",\"protocol_version\":2}\n";
    assert!(matches!(
        read_wire(&duplicate),
        Err(ProtocolError::InvalidRequest)
    ));
    for (wire, skew) in [
        (r#"{"type":"admin_ready","protocol_version":2}"#, true),
        (r#"{"type":"admin_ready","protocol_version":3}"#, false),
        (
            r#"{"type":"admin_ready","protocol_version":3,"protocol_version":2}"#,
            false,
        ),
    ] {
        let error = read_wire(&(wire.to_owned() + "\n")).unwrap_err();
        assert_eq!(
            matches!(error, ProtocolError::UnsupportedVersion),
            skew,
            "{wire}"
        );
    }
}
