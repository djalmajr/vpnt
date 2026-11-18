use super::*;
use std::io::Cursor;

#[test]
fn pk_sign_keeps_the_whole_algorithm_after_the_first_comma() {
    // Mutation captured: splitting at the last comma drops hashalg and saltlen.
    let event = parse(b">PK_SIGN:AAEC,RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest\r\n");
    assert_eq!(
        event,
        Event::Sign {
            data: vec![0, 1, 2],
            algorithm: Some("RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest".into()),
        }
    );
}

#[test]
fn pk_sign_from_an_old_client_protocol_has_no_algorithm() {
    assert_eq!(
        parse(b">PK_SIGN:AAEC\n"),
        Event::Sign {
            data: vec![0, 1, 2],
            algorithm: None
        }
    );
}

#[test]
fn pk_sign_without_decodable_data_is_malformed() {
    // Mutation captured: accepting empty data would ask the token to sign nothing.
    assert_eq!(
        parse(b">PK_SIGN:,RSA_PKCS1_PADDING\n"),
        Event::UnreadableSign
    );
    assert_eq!(
        parse(b">PK_SIGN:%%%,RSA_PKCS1_PADDING\n"),
        Event::UnreadableSign
    );
}

#[test]
fn exiting_after_a_refused_authorization_reports_auth_failure() {
    // The line a real server sent when it refused the profile.
    let Event::State(state) = parse(b">STATE:1794850171,EXITING,auth-failure,,,,,\r\n") else {
        panic!("expected a state");
    };
    assert_eq!(state.phase, Phase::Exiting);
    assert_eq!(state.reason, Some(Reason::AuthFailure));
}

#[test]
fn connected_carries_the_tunnel_address_and_no_failure_reason() {
    // Mutation captured: deriving a reason for every phase would read
    // "SUCCESS" as a failure.
    let Event::State(state) =
        parse(b">STATE:1794850320,CONNECTED,SUCCESS,10.8.0.6,198.51.100.7,1195,,\n")
    else {
        panic!("expected a state");
    };
    assert_eq!(state.phase, Phase::Connected);
    assert_eq!(state.reason, None);
    assert_eq!(state.tunnel_ipv4, Some(Ipv4Addr::new(10, 8, 0, 6)));
}

#[test]
fn reconnecting_after_a_ping_timeout_reports_ping_restart() {
    let Event::State(state) = parse(b">STATE:1794850400,RECONNECTING,ping-restart,,,,,\n") else {
        panic!("expected a state");
    };
    assert_eq!(
        (state.phase, state.reason),
        (Phase::Reconnecting, Some(Reason::PingRestart))
    );
}

#[test]
fn state_without_a_numeric_timestamp_is_malformed() {
    assert_eq!(
        parse(b">STATE:soon,CONNECTED,SUCCESS,,,,,\n"),
        Event::Malformed
    );
}

#[test]
fn hold_certificate_and_fatal_requests_are_recognized() {
    assert_eq!(parse(b">HOLD:Waiting for hold release:0\n"), Event::Hold);
    assert_eq!(parse(b">NEED-CERTIFICATE:vpnt\n"), Event::NeedCertificate);
    assert_eq!(parse(b">FATAL:cannot open tun\n"), Event::Fatal);
}

#[test]
fn replies_and_informational_lines_are_ignored() {
    for line in [
        &b">INFO:OpenVPN Management Interface Version 5\n"[..],
        b">LOG:1794850171,I,Initialization Sequence Completed\n",
        b"SUCCESS: real-time state notification set to ON\n",
        b"ERROR: unknown command\n",
        b"END\n",
    ] {
        assert_eq!(parse(line), Event::Ignored);
    }
}

#[test]
fn non_utf8_lines_are_malformed() {
    assert_eq!(parse(b">HOLD:\xff\n"), Event::Malformed);
}

#[test]
fn read_line_refuses_a_line_longer_than_the_bound() {
    // Mutation captured: dropping the length check accepts the oversized line
    // (the take() bound itself is exercised by the session test).
    let mut reader = Cursor::new(vec![b'a'; MAX_LINE + 10]);
    let error = read_line(&mut reader, &mut Vec::new()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn read_line_accepts_a_line_at_the_bound_and_then_reports_end_of_stream() {
    let mut bytes = vec![b'a'; MAX_LINE - 1];
    bytes.push(b'\n');
    let mut reader = Cursor::new(bytes);
    let mut line = Vec::new();
    assert!(read_line(&mut reader, &mut line).unwrap());
    assert_eq!(line.len(), MAX_LINE);
    assert!(!read_line(&mut reader, &mut line).unwrap());
}

#[test]
fn signature_is_base64_in_64_column_lines_closed_by_end() {
    // Mutation captured: without the END line openvpn keeps waiting.
    let command = signature(&[7; 100]);
    let lines: Vec<&str> = command.lines().collect();
    assert_eq!(lines.first(), Some(&"pk-sig"));
    assert_eq!(lines.last(), Some(&"END"));
    assert_eq!(
        lines[1..lines.len() - 1]
            .iter()
            .map(|line| line.len())
            .collect::<Vec<_>>(),
        [64, 64, 8]
    );
    assert_eq!(
        STANDARD.decode(lines[1..lines.len() - 1].concat()).unwrap(),
        [7; 100]
    );
}

#[test]
fn certificate_is_a_pem_block_inside_the_certificate_command() {
    let command = certificate(&[1, 2, 3]);
    assert_eq!(
        command,
        "certificate\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\nEND\n"
    );
}

#[test]
fn updown_events() {
    assert_eq!(parse(b">UPDOWN:UP\n"), Event::Up);
    assert_eq!(parse(b">UPDOWN:DOWN\n"), Event::Down);
    assert_eq!(
        parse(b">UPDOWN:ENV,dev=vpnt0\n"),
        Event::Env {
            key: "dev".into(),
            value: "vpnt0".into()
        }
    );
    assert_eq!(parse(b">UPDOWN:ENV,END\n"), Event::EnvEnd);
    assert_eq!(parse(b">UPDOWN:ENV,=x\n"), Event::Malformed);
    assert_eq!(parse(b">UPDOWN:ENV,broken\n"), Event::Malformed);
}
