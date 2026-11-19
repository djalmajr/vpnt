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

#[test]
fn a_new_ovpn_profile_without_configuration_is_rejected_by_app() {
    use vpnt::app::App;

    let body = concat!(
        r#"{"id":"new-ovpn","command":{"type":"save_profile","profile":{"id":"one","name":"Example","kind":"ovpn","gateway":"vpn.example.test","username":"","networks":[],"port":1194,"certificate":"","probeHost":"192.0.2.1","probePort":443,"probeMethod":"tcp","#,
        r#""ovpn":{"certificateId":"01ab","module":"/opt/test/token.so"}}}}"#
    );
    for mut app in [App::new(), App::demo()] {
        let before = app.snapshot().vpns.len();
        let command = parse_request(body).unwrap().command;
        let result = app.dispatch(command);
        assert_eq!(result.unwrap_err(), "invalid_profile");
        assert_eq!(app.snapshot().vpns.len(), before);
    }
}

#[test]
fn ovpn_bridge_parser_checks_the_three_command_shapes_and_limit() {
    let profile = ovpn_profile();
    let valid = [
        serde_json::json!({"type":"inspect_ovpn", "content":"synthetic"}),
        serde_json::json!({"type":"list_certificates", "module":"/opt/test/token.so"}),
        serde_json::json!({"type":"save_profile", "profile":profile, "ovpn_config":"synthetic"}),
    ];
    for mut command in valid {
        let request = parse_request(&wire(command.clone())).unwrap();
        match request.command {
            Command::InspectOvpn { content } => assert_eq!(content, "synthetic"),
            Command::ListCertificates { module } => assert_eq!(module, "/opt/test/token.so"),
            Command::SaveProfile {
                ovpn_config,
                profile,
            } => {
                assert_eq!(ovpn_config.as_deref(), Some("synthetic"));
                assert_eq!(profile.kind, vpnt::model::VpnKind::Ovpn);
            }
            _ => panic!("wrong typed command"),
        }
        command["extra"] = serde_json::json!(true);
        assert!(parse_request(&wire(command)).is_err());
    }
    for malformed in [
        serde_json::json!({"type":"inspect_ovpn"}),
        serde_json::json!({"type":"list_certificates", "module":false}),
        serde_json::json!({"type":"save_profile", "profile":profile, "ovpn_config":17}),
    ] {
        assert!(parse_request(&wire(malformed)).is_err());
    }
    let mut body = wire(serde_json::json!({"type":"inspect_ovpn", "content":""}));
    body.push_str(&" ".repeat(128 * 1024 - body.len()));
    assert!(parse_request(&body).is_ok());
    body.push(' ');
    assert!(parse_request(&body).is_err());
}

#[cfg(unix)]
const SYNTHETIC_OVPN: &str = "# Name: Imported\r\nremote first.example.test 8443 udp\r\nremote second.example.test 1194\r\n<ca>\r\nFAKE-CERT\r\n</ca>\r\n";

fn ovpn_profile() -> serde_json::Value {
    serde_json::json!({
        "id":"one", "name":"Example", "kind":"ovpn", "gateway":"first.example.test",
        "username":"", "networks":[], "port":8443, "certificate":"",
        "probeHost":"192.0.2.1", "probePort":443, "probeMethod":"tcp",
        "ovpn":{"certificateId":"01ab","module":"/opt/test/token.so"}
    })
}

fn wire(command: serde_json::Value) -> String {
    serde_json::json!({"id":"ovpn-fixture","command":command}).to_string()
}

#[cfg(unix)]
#[test]
fn inspection_returns_first_remote_and_never_returns_profile_content() {
    let inspect = |content: &str| {
        let request = parse_request(&wire(
            serde_json::json!({"type":"inspect_ovpn","content":content}),
        ))
        .unwrap();
        let reply = vpnt::bridge::ovpn::reply(&request.id, &request.command).unwrap();
        serde_json::to_value(reply).unwrap()
    };
    assert_eq!(
        inspect(SYNTHETIC_OVPN),
        serde_json::json!({
            "id":"ovpn-fixture", "ovpn":{"name":"Imported", "gateway":"first.example.test","port":8443}
        })
    );
    assert_eq!(
        inspect("remote first.example.test\n<ca>\nFAKE\n</ca>\n")["ovpn"]["name"],
        serde_json::Value::Null
    );
    for (content, detail) in [
        ("up FAKE-DO-NOT-ECHO", "up"),
        ("remote first.example.test\n", "missing_ca"),
        ("<ca>\nFAKE\n</ca>\n", "no_remote"),
        ("remote invalid.example.test 0\n", "malformed"),
    ] {
        assert_eq!(
            inspect(content),
            serde_json::json!({
                "id":"ovpn-fixture", "error":"invalid_ovpn", "detail":detail,
            })
        );
    }
    assert!(vpnt::bridge::ovpn::reply("control", &Command::GetSnapshot {}).is_none());
}

#[cfg(unix)]
#[test]
fn demo_validates_ovpn_config_keeps_only_metadata_and_allows_edit_without_file() {
    use vpnt::{app::App, session::ConnectionState};
    let mut demo = App::demo();
    let mut linux = App::new();
    let mut profile = ovpn_profile();
    let create = |profile: &serde_json::Value, content| {
        parse_request(&wire(serde_json::json!({
            "type":"save_profile", "profile":profile, "ovpn_config":content
        })))
        .unwrap()
        .command
    };
    for app in [&mut demo, &mut linux] {
        let before = app.snapshot().vpns.len();
        assert_eq!(
            app.dispatch(create(&profile, "up FAKE-DO-NOT-ECHO"))
                .unwrap_err(),
            "invalid_ovpn"
        );
        assert_eq!(app.snapshot().vpns.len(), before);
    }
    let snapshot = demo.dispatch(create(&profile, SYNTHETIC_OVPN)).unwrap();
    let vpn = snapshot
        .vpns
        .iter()
        .find(|vpn| vpn.profile.id == "one")
        .unwrap();
    assert_eq!(vpn.state, ConnectionState::Off);
    assert!(!vpn.has_password && !vpn.has_psk);
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains("FAKE-CERT")
    );
    profile["name"] = serde_json::json!("Edited");
    let edit = parse_request(&wire(
        serde_json::json!({"type":"save_profile", "profile":profile}),
    ))
    .unwrap();
    let snapshot = demo.dispatch(edit.command).unwrap();
    assert!(snapshot.vpns.iter().any(|vpn| vpn.profile.name == "Edited"));
    profile["kind"] = serde_json::json!("ssl");
    profile.as_object_mut().unwrap().remove("ovpn");
    assert_eq!(
        demo.dispatch(create(&profile, SYNTHETIC_OVPN)).unwrap_err(),
        "invalid_profile"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn certificate_listing_validates_paths_and_reports_missing_module() {
    use std::{
        path::Path,
        time::{Duration, Instant},
    };

    let list = |module: &str| {
        let request = parse_request(&wire(
            serde_json::json!({"type":"list_certificates", "module":module}),
        ))
        .unwrap();
        let reply = vpnt::bridge::ovpn::reply(&request.id, &request.command).unwrap();
        serde_json::to_value(reply).unwrap()
    };
    for module in [
        "relative/token.so",
        "/path/../token.so",
        "/path/token.dll",
        "/path/token.so.1",
        "/path/token\n.so",
        &format!("/{}.so", "x".repeat(4093)),
    ] {
        assert_eq!(
            list(module),
            serde_json::json!({"id":"ovpn-fixture", "error":"invalid_module"}),
            "{module:?}"
        );
    }
    let missing_module = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml/absent.so");
    assert!(!missing_module.exists());
    let start = Instant::now();
    assert_eq!(
        list(missing_module.to_str().unwrap()),
        serde_json::json!({"id":"ovpn-fixture", "error":"token_unavailable"})
    );
    assert!(start.elapsed() < Duration::from_secs(30));
}
