use super::*;
use std::{
    io::Write,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

const HELLO: &[u8] = b"{\"op\":\"hello\",\"version\":1}\n";
const STATUS: &[u8] = b"{\"op\":\"status\"}\n";
const STOP: &[u8] = b"{\"op\":\"stop\"}\n";
const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

fn ipsec(host: &str, port: u32, username: &str, networks: serde_json::Value) -> Vec<u8> {
    let mut json = serde_json::to_vec(&serde_json::json!({
        "op": "prepare_ipsec", "endpoint": {"host": host, "port": port},
        "username": username, "networks": networks,
    }))
    .unwrap();
    json.push(b'\n');
    json
}

fn fortinet(username: &str, pin: &str) -> Vec<u8> {
    let mut json = serde_json::to_vec(&serde_json::json!({
        "op": "prepare_fortinet", "endpoint": {"host": "vpn.example", "port": 443},
        "username": username, "certificate_sha256": pin,
    }))
    .unwrap();
    json.push(b'\n');
    json
}

fn networks(cidr: &[(&str, u8)]) -> serde_json::Value {
    serde_json::Value::Array(
        cidr.iter()
            .map(|(network, prefix)| serde_json::json!({"network": network, "prefix": prefix}))
            .collect(),
    )
}

#[test]
fn validates_host_port_and_user_limits() {
    let routes = networks(&[("10.8.0.0", 16)]);
    for host in ["vpn-1.example", "192.0.2.1", "a", &"a".repeat(63)] {
        assert!(
            decode_request(&ipsec(host, 65535, &"é".repeat(100), routes.clone())).is_ok(),
            "{host}"
        );
    }
    for host in [
        "",
        "1.2.3.004",
        "127.1",
        "0.1.2.3",
        "127.0.0.1",
        "169.254.0.1",
        "224.0.0.1",
        "240.1.2.3",
        "255.255.255.255",
        "a.",
        "-foo",
        "bar-",
        "A",
        "a..b",
        "a_b",
        "a:443",
        "https://a",
        "a\n",
        "a\0",
        "é",
        &"a".repeat(64),
    ] {
        assert_eq!(
            decode_request(&ipsec(host, 500, "user", routes.clone())).unwrap_err(),
            ErrorCode::BadRequest,
            "{host:?}"
        );
    }
    let max_host = [63, 63, 63, 61].map(|length| "a".repeat(length)).join(".");
    assert!(decode_request(&ipsec(&max_host, 1, "user", routes.clone())).is_ok());
    assert!(decode_request(&ipsec(&(max_host + "a"), 1, "user", routes.clone())).is_err());
    for port in [0, 65536] {
        assert!(decode_request(&ipsec("vpn.example", port, "user", routes.clone())).is_err());
    }
    for username in [
        "",
        "line\n",
        "cr\r",
        "user\0",
        "user\u{0085}",
        &"é".repeat(101),
    ] {
        assert!(decode_request(&ipsec("vpn.example", 500, username, routes.clone())).is_err());
    }
    assert!(decode_request(&fortinet(&"é".repeat(32), PIN)).is_ok());
    assert!(decode_request(&fortinet(&"é".repeat(33), PIN)).is_err());
}

#[test]
fn validates_canonical_non_overlapping_routes_and_pin() {
    assert!(
        decode_request(&ipsec(
            "vpn.example",
            500,
            "u",
            networks(&[("10.0.0.0", 8), ("192.0.2.1", 32)])
        ))
        .is_ok()
    );
    for routes in [
        vec![],
        vec![("10.1.0.0", 8)],
        vec![("10.0.0.0", 7)],
        vec![("10.0.0.0", 33)],
        vec![("10.0.0.0", 8), ("10.0.0.0", 8)],
        vec![("10.1.0.0", 16), ("10.0.0.0", 8)],
        vec![("0.0.0.0", 8)],
        vec![("127.0.0.0", 8)],
        vec![("169.0.0.0", 8)],
        vec![("169.254.0.0", 16)],
        vec![("224.0.0.0", 8)],
        vec![("240.0.0.0", 8)],
        vec![("255.255.255.255", 32)],
        vec![("192.000.2.1", 32)],
    ] {
        assert!(
            decode_request(&ipsec("vpn.example", 500, "u", networks(&routes))).is_err(),
            "{routes:?}"
        );
    }
    let many: Vec<_> = (1..=65).map(|n| format!("192.0.2.{n}")).collect();
    let routes: Vec<_> = many.iter().map(|n| (n.as_str(), 32)).collect();
    assert!(decode_request(&ipsec("vpn.example", 500, "u", networks(&routes[..64]))).is_ok());
    assert!(decode_request(&ipsec("vpn.example", 500, "u", networks(&routes))).is_err());

    let Request::PrepareFortinet(prepared) = decode_request(&fortinet("u", PIN)).unwrap() else {
        panic!("expected Fortinet preparation");
    };
    assert_eq!(&prepared.certificate_sha256()[..4], &[1, 35, 69, 103]);
    for invalid in [
        "",
        &PIN[..63],
        &format!("{PIN}a"),
        &PIN.to_uppercase(),
        &PIN.replace('f', "g"),
    ] {
        assert!(decode_request(&fortinet("u", invalid)).is_err());
    }
}

#[test]
fn json_frames_are_closed_and_bounded() {
    assert!(matches!(
        decode_request(HELLO),
        Ok(Request::Hello { version: VERSION })
    ));
    assert_eq!(
        decode_request(b"{\"op\":\"hello\",\"version\":2}\n").unwrap_err(),
        ErrorCode::UnsupportedVersion
    );
    for line in [
        b"{\n".as_slice(), &HELLO[..HELLO.len() - 1],
        b"{\"op\":\"hello\",\"version\":1,\"version\":1}\n",
        b"{\"op\":\"hello\",\"op\":\"hello\",\"version\":1}\n",
        b"{\"op\":\"status\",\"extra\":true}\n", b"{\"op\":\"stop\",\"extra\":true}\n",
        b"{\"op\":\"restart\"}\n", b"{\"op\":\"hello\",\"version\":\"1\"}\n",
        b"{\"op\":\"status\"}\n{\"op\":\"stop\"}\n", b"\xff\n",
        b"{\"op\":\"prepare_ipsec\",\"endpoint\":{\"host\":\"example\",\"port\":1,\"port\":1},\"username\":\"u\",\"networks\":[{\"network\":\"10.0.0.0\",\"prefix\":8}]}\n",
        b"{\"op\":\"prepare_ipsec\",\"endpoint\":{\"host\":\"example\",\"port\":1},\"username\":\"u\",\"networks\":[{\"network\":\"10.0.0.0\",\"prefix\":8,\"extra\":1}]}\n",
    ] {
        assert_eq!(decode_request(line).unwrap_err(), ErrorCode::BadRequest, "{line:?}");
    }
    let mut line = STATUS[..STATUS.len() - 1].to_vec();
    line.resize(MAX_LINE - 1, b' ');
    line.push(b'\n');
    assert!(matches!(decode_request(&line), Ok(Request::Status {})));
    line.insert(line.len() - 1, b' ');
    assert!(decode_request(&line).is_err());
    for line in [
        b"{\"op\":\"prepared\",\"text\":\"no\"}\n".as_slice(),
        b"{\"op\":\"status\",\"state\":\"unknown\"}\n",
        b"{\"op\":\"error\",\"code\":\"unknown\"}\n",
        b"{\"op\":\"version\",\"version\":1,\"version\":1}\n",
    ] {
        assert!(decode_response(line).is_err(), "{line:?}");
    }
    assert!(matches!(
        decode_response(b"{\"op\":\"error\",\"code\":\"busy\"}\n"),
        Ok(Response::Error {
            code: ErrorCode::Busy
        })
    ));
}

fn assert_named_object<T: serde::de::DeserializeOwned>(
    fields: &str,
    sequence: &str,
    duplicate: &str,
) {
    assert!(serde_json::from_str::<T>(&format!("{{{fields}}}")).is_ok());
    for invalid in [
        sequence.to_owned(),
        format!("{{{fields},{duplicate}}}"),
        format!(r#"{{{fields},"extra":1}}"#),
    ] {
        assert!(serde_json::from_str::<T>(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn endpoint_requires_named_fields() {
    assert_named_object::<Endpoint>(
        r#""host":"vpn.example","port":443"#,
        r#"["vpn.example",443]"#,
        r#""port":443"#,
    );
}

#[test]
fn cidr_requires_named_fields() {
    assert_named_object::<CidrV4>(
        r#""network":"10.0.0.0","prefix":8"#,
        r#"["10.0.0.0",8]"#,
        r#""prefix":8"#,
    );
}

#[test]
fn ipsec_preparation_requires_named_fields() {
    let endpoint = r#"{"host":"vpn.example","port":500}"#;
    let routes = r#"[{"network":"10.0.0.0","prefix":8}]"#;
    assert_named_object::<IpsecRequest>(
        &format!(r#""endpoint":{endpoint},"username":"u","networks":{routes}"#),
        &format!(r#"[{endpoint},"u",{routes}]"#),
        r#""username":"u""#,
    );
}

#[test]
fn fortinet_preparation_requires_named_fields() {
    let endpoint = r#"{"host":"vpn.example","port":443}"#;
    assert_named_object::<FortinetRequest>(
        &format!(r#""endpoint":{endpoint},"username":"u","certificate_sha256":"{PIN}""#),
        &format!(r#"[{endpoint},"u","{PIN}"]"#),
        r#""username":"u""#,
    );
}

#[test]
fn request_rejects_sequences_in_nested_objects() {
    let routes = networks(&[("10.0.0.0", 8), ("192.0.2.1", 32)]);
    let request = ipsec("vpn.example", 500, "u", routes.clone());
    assert!(decode_request(&request).is_ok());
    for index in 0..2 {
        let mut routes = routes.clone();
        routes[index] = serde_json::json!([routes[index]["network"], routes[index]["prefix"]]);
        let request = ipsec("vpn.example", 500, "u", routes);
        assert_eq!(decode_request(&request).unwrap_err(), ErrorCode::BadRequest);
    }
    for request in [request, fortinet("u", PIN)] {
        assert!(decode_request(&request).is_ok());
        let mut request: serde_json::Value = serde_json::from_slice(&request).unwrap();
        request["endpoint"] = serde_json::json!(["vpn.example", request["endpoint"]["port"]]);
        assert_eq!(
            decode_request(format!("{request}\n").as_bytes()).unwrap_err(),
            ErrorCode::BadRequest
        );
    }
}

#[test]
fn control_requests_require_named_fields() {
    assert_named_object::<Request>(
        r#""op":"hello","version":1"#,
        r#"["hello",1]"#,
        r#""version":1"#,
    );
    assert!(decode_request(STATUS).is_ok());
    assert!(decode_request(b"[\"status\"]\n").is_err());
}

#[test]
fn control_responses_require_named_fields() {
    assert_named_object::<Response>(
        r#""op":"version","version":1"#,
        r#"["version",1]"#,
        r#""version":1"#,
    );
    assert!(decode_response(b"{\"op\":\"prepared\"}\n").is_ok());
    assert!(decode_response(b"[\"prepared\"]\n").is_err());
}

fn begin(request: &[u8]) -> (UnixStream, ServerDecoder) {
    let (mut writer, reader) = UnixStream::pair().unwrap();
    let mut decoder = ServerDecoder::new(reader);
    writer.write_all(&[HELLO, request].concat()).unwrap();
    decoder.hello(deadline()).unwrap();
    decoder.prepare(deadline()).unwrap();
    (writer, decoder)
}

#[test]
fn rejects_frames_outside_the_current_phase() {
    let (mut writer, reader) = UnixStream::pair().unwrap();
    let mut decoder = ServerDecoder::new(reader);
    writer.write_all(STATUS).unwrap();
    assert!(matches!(
        decoder.hello(deadline()),
        Err(FrameError::Protocol(ErrorCode::BadRequest))
    ));

    let request = fortinet("u", PIN);
    let (mut writer, mut decoder) = begin(&request);
    writer.write_all(b"\0\x01p").unwrap();
    assert!(decoder.credentials(deadline()).is_err());

    let (mut writer, mut decoder) = begin(&request);
    writer.write_all(b"\0\x01p").unwrap();
    assert!(matches!(
        decoder.prepared(deadline()),
        Err(FrameError::Protocol(ErrorCode::BadRequest))
    ));
    assert!(decoder.credentials(deadline()).is_err());

    let (mut writer, mut decoder) = begin(&request);
    writer.write_all(&request).unwrap();
    assert!(matches!(
        decoder.prepared(deadline()),
        Err(FrameError::Protocol(ErrorCode::BadRequest))
    ));

    let (mut writer, mut decoder) = begin(&request);
    decoder.prepared(deadline()).unwrap();
    writer
        .write_all(&[b"\0\x01p".as_slice(), &request].concat())
        .unwrap();
    let _credentials = decoder.credentials(deadline()).unwrap();
    assert!(decoder.command(deadline()).is_err());
}

#[test]
fn rejects_malformed_credentials() {
    let request = fortinet("u", PIN);
    for frame in [
        b"".as_slice(),
        b"\0",
        b"\0\x02p",
        b"\0\0",
        b"\x01\x01",
        b"\0\x01\r",
        b"\0\x01\n",
        b"\0\x01\0",
        b"\0\x01\xff",
        STATUS,
    ] {
        let (mut writer, mut decoder) = begin(&request);
        decoder.prepared(deadline()).unwrap();
        writer.write_all(frame).unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(decoder.credentials(deadline()).is_err(), "{frame:?}");
    }
    let request_ipsec = ipsec("vpn.example", 500, "u", networks(&[("10.0.0.0", 8)]));
    for frame in [b"\0\x01p".as_slice(), b"\0\x01p\x10\x01", b"\x10\x01"] {
        let (mut writer, mut decoder) = begin(&request_ipsec);
        decoder.prepared(deadline()).unwrap();
        writer.write_all(frame).unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(decoder.credentials(deadline()).is_err(), "{frame:?}");
    }
}

#[test]
fn rejects_followup_bytes_at_command_for_both_write_patterns() {
    let request = fortinet("u", PIN);
    let frame = b"\0\x01p";
    for extra in [b"!".as_slice(), b"\0\x01q"] {
        let invalid_command = [extra, STATUS].concat();
        for coalesced in [false, true] {
            let (mut writer, mut decoder) = begin(&request);
            decoder.prepared(deadline()).unwrap();
            if coalesced {
                writer
                    .write_all(&[frame, &invalid_command[..]].concat())
                    .unwrap();
            } else {
                for byte in frame {
                    writer.write_all(&[*byte]).unwrap();
                }
            }
            let credentials = decoder.credentials(deadline()).unwrap();
            assert_eq!(credentials.password(), "p");
            assert_eq!(credentials.psk(), None);
            if !coalesced {
                for byte in &invalid_command {
                    writer.write_all(&[*byte]).unwrap();
                }
            }
            assert_eq!(
                decoder.command(deadline()).unwrap_err(),
                FrameError::Protocol(ErrorCode::BadRequest)
            );
        }
    }
}

#[test]
fn handles_coalesced_and_byte_fragmented_frames() {
    for request in [
        fortinet("u", PIN),
        ipsec("vpn.example", 500, "u", networks(&[("10.0.0.0", 8)])),
    ] {
        let (mut writer, mut decoder) = begin(&request);
        decoder.prepared(deadline()).unwrap();
        let is_ipsec = matches!(decode_request(&request), Ok(Request::PrepareIpsec(_)));
        let mut wire = b"\0\x01p".to_vec();
        if is_ipsec {
            wire.extend_from_slice(b"\0\x01q");
        }
        wire.extend_from_slice(STATUS);
        wire.extend_from_slice(STOP);
        std::thread::scope(|scope| {
            let sender = scope.spawn(move || {
                if is_ipsec {
                    for byte in wire {
                        writer.write_all(&[byte]).unwrap();
                    }
                } else {
                    writer.write_all(&wire).unwrap();
                }
            });
            let credentials = decoder.credentials(deadline()).unwrap();
            assert_eq!(credentials.password(), "p");
            assert_eq!(credentials.psk(), is_ipsec.then_some("q"));
            let debug = format!("{credentials:?}");
            assert_eq!(debug, "Credentials([redacted])");
            assert_eq!(decoder.command(deadline()).unwrap(), Command::Status);
            assert_eq!(decoder.command(deadline()).unwrap(), Command::Stop);
            sender.join().unwrap();
        });
    }
}

#[test]
fn deadline_expires_after_partial_read() {
    for credential in [false, true] {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let mut decoder = ServerDecoder::new(reader);
        if credential {
            writer
                .write_all(&[HELLO, &fortinet("u", PIN)].concat())
                .unwrap();
            decoder.hello(deadline()).unwrap();
            decoder.prepare(deadline()).unwrap();
            decoder.prepared(deadline()).unwrap();
        }
        writer
            .write_all(if credential { b"\0\x04p" } else { b"{\"op\":" })
            .unwrap();
        let expires = Instant::now() + Duration::from_millis(30);
        let error = if credential {
            decoder.credentials(expires).unwrap_err()
        } else {
            decoder.hello(expires).unwrap_err()
        };
        assert!(
            matches!(error, FrameError::Io(std::io::ErrorKind::TimedOut)),
            "{error:?}"
        );
        assert!(Instant::now() >= expires);
    }
}

#[test]
fn accepts_credential_limits_and_reports_partial_write() {
    for (credentials, backend) in [
        (
            Credentials::ipsec(&"é".repeat(2048), &"s".repeat(4096)).unwrap(),
            Backend::Ipsec,
        ),
        (
            Credentials::fortinet(&"é".repeat(128)).unwrap(),
            Backend::Fortinet,
        ),
    ] {
        let mut writer = Zeroizing::new(Vec::new());
        credentials.write(&mut *writer).unwrap();
        let decoded = Credentials::read(&mut writer.as_slice(), backend).unwrap();
        assert_eq!(decoded.password(), credentials.password());
        assert_eq!(decoded.psk(), credentials.psk());

        // A bounded writer accepts the header and part of the password,
        // then returns WriteZero. No subsequent field can be sent.
        let mut space = Zeroizing::new([0; 3]);
        let mut remaining = space.as_mut_slice();
        assert_eq!(
            credentials.write(&mut remaining),
            Err(FrameError::Io(io::ErrorKind::WriteZero))
        );
        assert_eq!(space[2], 0xc3);
    }
    assert!(Credentials::ipsec(&"p".repeat(4097), "s").is_err());
    assert!(Credentials::ipsec("p", &"s".repeat(4097)).is_err());
    assert!(Credentials::fortinet(&"p".repeat(257)).is_err());
    for value in ["", "\r", "\n", "\0"] {
        assert!(Credentials::ipsec(value, "s").is_err());
        assert!(Credentials::ipsec("p", value).is_err());
        assert!(Credentials::fortinet(value).is_err());
    }
}
