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

// Mutation captured: the bridge forwards a preferences document it never
// validated (unknown field, missing field or an interval outside the domain).
#[test]
fn preferences_are_validated_at_the_real_bridge_boundary() {
    use vpnt::localization::Locale;
    use vpnt::preferences::{Preferences, ProbeInterval};

    let body = r#"{"id":"a","command":{"type":"set_preferences","preferences":{"interval":30,"notify":false,"reconnect":true,"startup":false}},"locale":"pt-BR"}"#;
    let request = parse_request(body).unwrap();
    assert_eq!(request.locale, Some(Locale::PtBr));
    match request.command {
        Command::SetPreferences { preferences } => assert_eq!(
            preferences,
            Preferences {
                interval: ProbeInterval::THIRTY,
                notify: false,
                reconnect: true,
                startup: false,
            }
        ),
        _ => panic!("set_preferences must decode as its own command"),
    }

    for body in [
        r#"{"id":"a","command":{"type":"set_preferences","preferences":{"interval":45,"notify":true,"reconnect":false,"startup":false}}}"#,
        r#"{"id":"a","command":{"type":"set_preferences","preferences":{"interval":"30","notify":true,"reconnect":false,"startup":false}}}"#,
        r#"{"id":"a","command":{"type":"set_preferences","preferences":{"interval":30,"notify":true,"reconnect":false}}}"#,
        r#"{"id":"a","command":{"type":"set_preferences","preferences":{"interval":30,"notify":true,"reconnect":false,"startup":false,"theme":"dark"}}}"#,
        r#"{"id":"a","command":{"type":"set_preferences","preferences":{"interval":30,"notify":true,"reconnect":false,"startup":false},"path":"/x"}}"#,
        r#"{"id":"a","command":{"type":"set_preferences"}}"#,
        // the bridge admits the documented object, not the positional value form
        r#"{"id":"a","command":{"type":"set_preferences","preferences":[10,true,false,false]}}"#,
    ] {
        assert!(parse_request(body).is_err(), "{body}");
    }
}

// Mutations: echo a choice the demo app never stored, rewrite demo/connection
// data while echoing, or let a normal app accept the demo intake.
#[test]
fn demo_choices_are_echoed_without_changing_demo_or_connection_data() {
    use vpnt::app::App;
    use vpnt::preferences::{Preferences, ProbeInterval};

    let mut demo = App::demo();
    let before = serde_json::to_value(demo.snapshot()).unwrap();
    let chosen = Preferences {
        interval: ProbeInterval::SIXTY,
        notify: false,
        reconnect: true,
        startup: true,
    };
    let echoed = demo
        .dispatch(Command::SetPreferences {
            preferences: chosen,
        })
        .unwrap();
    assert_eq!(echoed.preferences, chosen);
    let after = serde_json::to_value(demo.snapshot()).unwrap();
    assert_eq!(after["preferences"], serde_json::to_value(chosen).unwrap());
    for key in ["version", "demo", "helper", "vpns"] {
        assert_eq!(after[key], before[key], "{key} must not change");
    }
    assert!(after["demo"].as_bool().unwrap());

    let mut normal = App::new();
    assert!(
        normal
            .dispatch(Command::SetPreferences {
                preferences: chosen
            })
            .is_err()
    );
    assert_eq!(normal.snapshot().preferences, Preferences::default());
}
