use vpnt::bridge::{Command, parse_request, trusted_origin};

// Mutation captured: prefix matching grants an attacker the privileged application bridge.
#[test]
fn only_the_embedded_document_can_send_native_commands() {
    assert!(trusted_origin("vpnt://localhost/index.html"));
    for origin in [
        "https://localhost/index.html",
        "vpnt://localhost.attacker/index.html",
        "vpnt://localhost/index.html/extra",
        "file:///index.html",
    ] {
        assert!(!trusted_origin(origin), "{origin}");
    }
}

// Mutation captured: permissive JSON parsing accepts extra privileged fields or a second document.
#[test]
fn malformed_or_ambiguous_requests_are_rejected_before_dispatch() {
    for body in [
        r#"{"id":"a","command":{"type":"get_snapshot"},"extra":true}"#,
        r#"{"id":"a","command":{"type":"get_snapshot","path":"/etc/passwd"}}"#,
        r#"{"id":"a","command":{"type":"shell","program":"sh"}}"#,
        r#"{"id":"a","command":{"type":"get_snapshot"}} {}"#,
    ] {
        assert!(parse_request(body).is_err(), "{body}");
    }
    assert!(parse_request(&" ".repeat(65537)).is_err());
    let request = parse_request(r#"{"id":"a","command":{"type":"get_snapshot"}}"#).unwrap();
    assert!(matches!(request.command, Command::GetSnapshot {}));
}

#[test]
fn authorization_locale_is_typed_and_uses_the_shared_catalogs() {
    use vpnt::localization::Locale;
    for (code, locale, confirm) in [
        ("pt-BR", Locale::PtBr, "Autorizar"),
        ("en-US", Locale::EnUs, "Authorize"),
    ] {
        let body = format!(r#"{{"id":"a","command":{{"type":"get_snapshot"}},"locale":"{code}"}}"#);
        let request = parse_request(&body).unwrap();
        assert_eq!(request.locale, Some(locale));
        assert_eq!(request.locale.unwrap().native().auth_confirm, confirm);
    }
    for code in ["pt-br", "en", "en-US\n", "/tmp/catalog.json"] {
        let body = serde_json::json!({"id":"a","command":{"type":"get_snapshot"},"locale":code});
        assert!(parse_request(&body.to_string()).is_err());
    }
}
