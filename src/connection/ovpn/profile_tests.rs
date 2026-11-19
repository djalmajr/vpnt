use super::*;

const MINIMAL: &str = "remote vpn.example.test\n<ca>\nFAKE-CA\n</ca>\n";

fn append(line: &str) -> String {
    format!("{MINIMAL}{line}\n")
}

#[test]
fn remote_cert_tls_requires_exact_server_role() {
    for value in ["client", "", "server extra", "SERVER"] {
        assert_eq!(
            inspect(append(&format!("remote-cert-tls {value}")).as_bytes()).unwrap_err(),
            ImportError::Forbidden("remote-cert-tls".into())
        );
    }
    assert!(inspect(append("remote-cert-tls server").as_bytes()).is_ok());
    assert!(inspect(MINIMAL.as_bytes()).is_ok());
}

#[test]
fn control_channel_timers_are_accepted() {
    // Provider profiles tune TLS retransmission and key transition windows.
    for line in ["tls-timeout 2", "tran-window 3600", "hand-window 60"] {
        let inspected = inspect(append(line).as_bytes()).unwrap();
        assert!(
            inspected.normalized.ends_with(&format!("{line}\n")),
            "{line}"
        );
    }
}

#[test]
fn provider_shape_normalizes_and_extracts_metadata() {
    let input = concat!(
        "  # Name: Rede de teste \r\n",
        "# Description: synthetic\r# Servers: synthetic\r\n",
        "# Date: 2026-11-18\r\n# Signature: placeholder\r\n\r\n",
        "client\r\nremote \"vpn.example.test\" 1195 udp  \r\n",
        "--remote 192.0.2.1 443 tcp-client\r\n",
        "<ca>\r\nFAKE-CA\r\n</ca>\r\n",
        "<tls-crypt>\r\nFAKE-TLS-CRYPT\r\n</tls-crypt>"
    );
    let inspected = inspect(input.as_bytes()).unwrap();
    assert_eq!(inspected.name.as_deref(), Some("Rede de teste"));
    assert_eq!(
        inspected.remotes,
        [
            Remote {
                host: "vpn.example.test".into(),
                port: 1195,
                proto: Some(Proto::Udp)
            },
            Remote {
                host: "192.0.2.1".into(),
                port: 443,
                proto: Some(Proto::Tcp)
            },
        ]
    );
    assert_eq!(
        inspected.normalized,
        concat!(
            "  # Name: Rede de teste\n",
            "# Description: synthetic\n# Servers: synthetic\n",
            "# Date: 2026-11-18\n# Signature: placeholder\n\n",
            "client\nremote \"vpn.example.test\" 1195 udp\n",
            "--remote 192.0.2.1 443 tcp-client\n",
            "<ca>\nFAKE-CA\n</ca>\n",
            "<tls-crypt>\nFAKE-TLS-CRYPT\n</tls-crypt>\n"
        )
    );
    assert_eq!(inspect(MINIMAL.as_bytes()).unwrap().remotes[0].port, 1194);
}

#[test]
fn forbidden_directives_include_only_their_names() {
    for (line, expected) in [
        ("up /bin/sh secret-marker", "up"),
        ("down /bin/sh", "down"),
        ("script-security 2", "script-security"),
        ("plugin some-module", "plugin"),
        ("log some-file", "log"),
        ("cd some-directory", "cd"),
        ("config some-file", "config"),
        ("management 127.0.0.1 5555", "management"),
        ("management-client", "management-client"),
        ("tls-version-max 1.2", "tls-version-max"),
        ("ca some-file", "ca"),
        ("cert some-file", "cert"),
        ("tls-auth some-file", "tls-auth"),
        ("tls-crypt some-file", "tls-crypt"),
        ("tls-crypt-v2 some-file", "tls-crypt-v2"),
        ("extra-certs some-file", "extra-certs"),
        ("pkcs11-providers some-file", "pkcs11-providers"),
        ("<key>", "key"),
        ("<connection>", "connection"),
        ("setenv opt up some-file", "setenv opt"),
        ("--setenv \"opt\" up some-file", "setenv opt"),
        ("unknown-directive some-value", "unknown-directive"),
        ("--up /bin/sh", "up"),
        ("ignore-unknown-option up\nup /bin/sh", "up"),
    ] {
        assert_eq!(
            inspect(append(line).as_bytes()).unwrap_err(),
            ImportError::Forbidden(expected.into()),
            "{line}"
        );
    }
    assert!(inspect(append("ignore-unknown-option up").as_bytes()).is_ok());
}

#[test]
fn malformed_block_boundaries_and_directive_quoting_are_rejected() {
    for line in [
        "<tls-crypt>\nFAKE",
        "<tls-auth>\n<ca>\n</ca>\n</tls-auth>",
        "<ca>\n</tls-crypt>",
        "<ca>\n</ca> trailing",
        "</ca>",
        "setenv 4name value",
        "setenv bad-name value",
        "setenv",
        "setenv TEST \"unterminated",
        "setenv TEST 'unterminated",
        "verify-x509-name foo\\",
    ] {
        assert_eq!(
            inspect(append(line).as_bytes()).unwrap_err(),
            ImportError::Malformed,
            "{line}"
        );
    }
    assert!(inspect(append("setenv _Test2 \"quoted value\" # comment").as_bytes()).is_ok());
}

#[test]
fn input_size_encoding_and_line_boundaries() {
    assert_eq!(
        inspect(&vec![b' '; 256 * 1024 + 1]).unwrap_err(),
        ImportError::TooLarge
    );
    assert_eq!(inspect(b"\xff").unwrap_err(), ImportError::NotUtf8);
    assert_eq!(
        inspect(append("# comment\0").as_bytes()).unwrap_err(),
        ImportError::Malformed
    );
    let comment = format!("#{}", "x".repeat(253));
    assert!(inspect(append(&comment).as_bytes()).is_ok());
    assert_eq!(
        inspect(append(&(comment + "x")).as_bytes()).unwrap_err(),
        ImportError::Malformed
    );
}

#[test]
fn required_remote_and_ca_and_remote_validation() {
    assert_eq!(
        inspect(b"<ca>\nFAKE\n</ca>\n").unwrap_err(),
        ImportError::NoRemote
    );
    assert_eq!(
        inspect(b"remote vpn.example.test\n").unwrap_err(),
        ImportError::MissingBlock("ca")
    );
    for line in [
        "remote",
        "remote vpn.example.test 0",
        "remote vpn.example.test 65536",
        "remote vpn.example.test +1",
        "remote bad_name",
        "remote \"two words\"",
        "remote 2001:db8::1",
        "remote vpn.example.test 443 bad",
        "remote vpn.example.test 443 udp extra",
    ] {
        assert_eq!(
            inspect(append(line).as_bytes()).unwrap_err(),
            ImportError::Malformed,
            "{line}"
        );
    }
}

#[test]
fn first_name_in_header_and_only_valid_names() {
    let input = |header: &str| format!("{header}\n{MINIMAL}");
    let result = |header: &str| inspect(input(header).as_bytes()).unwrap().name;
    assert_eq!(
        result("; a comment\n# Name: First\n# Name: Second").as_deref(),
        Some("First")
    );
    assert_eq!(result("# Name: invalid\tname\n# Name: Second"), None);
    assert_eq!(
        result(&format!("# Name: {}", "é".repeat(120)))
            .unwrap()
            .chars()
            .count(),
        120
    );
    assert_eq!(result(&format!("# Name: {}", "x".repeat(121))), None);
    assert_eq!(
        inspect(append("# Name: late").as_bytes()).unwrap().name,
        None
    );
}

#[test]
fn diagnostics_do_not_include_profile_data() {
    let fixture = append("<tls-crypt>\nFAKE-TLS-SECRET-MARKER\n</tls-crypt>");
    let inspected = inspect(fixture.as_bytes()).unwrap();
    assert!(!format!("{inspected:?}").contains("FAKE-TLS-SECRET-MARKER"));
    let invalid = format!("{fixture}up DO-NOT-LOG-ARGUMENT\n");
    let error = inspect(invalid.as_bytes()).unwrap_err();
    for diagnostic in [format!("{error}"), format!("{error:?}")] {
        assert!(!diagnostic.contains("DO-NOT-LOG-ARGUMENT"));
        assert!(!diagnostic.contains("FAKE-TLS-SECRET-MARKER"));
    }
}

#[test]
fn control_characters_are_refused_even_in_comments() {
    for control in [0x00u8, 0x01, 0x1b, 0x7f] {
        let mut content = b"remote vpn.example.test 1194\n# note ".to_vec();
        content.push(control);
        content.extend_from_slice(b"\n<ca>\nx\n</ca>\n");
        assert!(
            matches!(inspect(&content), Err(ImportError::Malformed)),
            "control 0x{control:02x} was accepted"
        );
    }
    let tabs = b"remote vpn.example.test 1194\r\n#\tnote\r\n<ca>\nx\n</ca>\n";
    assert!(inspect(tabs).is_ok());
}

#[test]
fn accepted_profiles_escape_to_at_most_twice_their_size_in_json() {
    let mut content = "remote vpn.example.test 1194\n<ca>\nx\n</ca>\n".to_owned();
    while content.len() + 200 <= MAX_PROFILE_BYTES {
        content.push_str(&format!("#{}\n", "\"\\é".repeat(49)));
    }
    let inspected = inspect(content.as_bytes()).unwrap();
    let escaped = serde_json::to_string(&inspected.normalized).unwrap();
    assert!(escaped.len() <= 2 * inspected.normalized.len() + 2);
}
