use std::time::Duration;
use vpnt::preferences::{Preferences, ProbeInterval};

fn body(interval: &str, notify: &str, reconnect: &str, startup: &str) -> String {
    format!(
        r#"{{"interval":{interval},"notify":{notify},"reconnect":{reconnect},"startup":{startup}}}"#
    )
}

fn supported(interval: &str) -> String {
    body(interval, "true", "false", "false")
}

// Mutation captured: a default that drifts from the UI catalog (notify off,
// reconnect on, or a 30-second interval) changes what an untouched app sends.
#[test]
fn defaults_match_the_existing_ui_catalog() {
    let preferences = Preferences::default();
    assert_eq!(preferences.interval, ProbeInterval::TEN);
    assert_eq!(preferences.interval.seconds(), 10);
    assert!(preferences.notify);
    assert!(!preferences.reconnect);
    assert!(!preferences.startup);
    assert_eq!(
        serde_json::to_string(&preferences).unwrap(),
        r#"{"interval":10,"notify":true,"reconnect":false,"startup":false}"#
    );
}

// Mutation captured: serializing the enum name or a converted value instead of
// whole seconds breaks every consumer that reads an integer.
#[test]
fn intervals_serialize_as_whole_seconds_and_expose_duration() {
    for (interval, seconds) in [
        (ProbeInterval::TEN, 10),
        (ProbeInterval::THIRTY, 30),
        (ProbeInterval::SIXTY, 60),
    ] {
        assert_eq!(interval.seconds(), seconds);
        assert_eq!(interval.duration(), Duration::from_secs(seconds.into()));
        assert_eq!(
            serde_json::to_string(&interval).unwrap(),
            seconds.to_string()
        );
        assert_eq!(
            serde_json::from_str::<ProbeInterval>(&seconds.to_string()).unwrap(),
            interval
        );
    }
    let parsed: Preferences = serde_json::from_str(&supported("30")).unwrap();
    assert_eq!(parsed.interval, ProbeInterval::THIRTY);
    assert_eq!(parsed.interval.duration(), Duration::from_secs(30));
    assert_eq!(serde_json::to_string(&parsed).unwrap(), supported("30"));
}

// Mutation captured: a second whitelist (in `from_seconds`, in the decoder or
// in a future caller) that accepts a value the other side refuses. The Rust
// domain and the JSON domain are compared for every representable value.
#[test]
fn the_wire_domain_is_exactly_the_rust_domain() {
    let mut accepted = Vec::new();
    for seconds in 0..=u16::MAX {
        let decoded = serde_json::from_str::<Preferences>(&supported(&seconds.to_string()));
        match (ProbeInterval::from_seconds(seconds), decoded) {
            (Some(expected), Ok(parsed)) => {
                assert_eq!(parsed.interval, expected, "{seconds} decoded differently");
                accepted.push(seconds);
            }
            (None, Err(_)) => {}
            (rust, json) => panic!("{seconds}: rust={rust:?} json_accepted={}", json.is_ok()),
        }
    }
    assert_eq!(accepted, [10, 30, 60]);
}

// Mutation captured: accepting any integer (or silently clamping) instead of
// refusing intervals outside the product domain.
#[test]
fn unsupported_or_malformed_intervals_are_rejected() {
    for interval in [
        "-10",
        "0",
        "1",
        "9",
        "11",
        "29",
        "31",
        "45",
        "59",
        "61",
        "120",
        "65535",
        "65536",
        "99999999999999999999",
    ] {
        assert!(
            serde_json::from_str::<Preferences>(&supported(interval)).is_err(),
            "{interval} must not decode as an interval"
        );
    }
    for interval in [
        "10.0", "10.5", "1e1", "\"10\"", "\"ten\"", "null", "true", "[]", "{}",
    ] {
        assert!(
            serde_json::from_str::<Preferences>(&supported(interval)).is_err(),
            "{interval} must not decode as an interval"
        );
        assert!(
            serde_json::from_str::<ProbeInterval>(interval).is_err(),
            "{interval} must not decode as a bare interval"
        );
    }
}

// Mutation captured: dropping `deny_unknown_fields`, which lets UI-only or
// future fields ride into the native contract unnoticed.
#[test]
fn unknown_preference_fields_are_rejected() {
    for extra in [
        r#","theme":"dark""#,
        r#","locale":"pt-BR""#,
        r#","intervalSeconds":10"#,
        r#","path":"/etc/passwd""#,
        r#","notify":true"#,
    ] {
        let body =
            format!(r#"{{"interval":10,"notify":true,"reconnect":false,"startup":false{extra}}}"#);
        assert!(
            serde_json::from_str::<Preferences>(&body).is_err(),
            "{extra} must not be admitted"
        );
    }
    assert!(
        serde_json::from_str::<ProbeInterval>(r#"{"seconds":10}"#).is_err(),
        "an object must not decode as an interval"
    );
}

// Mutation captured: making the booleans optional or coercing non-booleans,
// which would let a partial or mistyped document enable an effect.
#[test]
fn every_boolean_is_required_and_typed() {
    for document in [
        r#"{"interval":10,"reconnect":false,"startup":false}"#,
        r#"{"interval":10,"notify":true,"startup":false}"#,
        r#"{"interval":10,"notify":true,"reconnect":false}"#,
        r#"{"interval":10}"#,
        r#"{"notify":true,"reconnect":false,"startup":false}"#,
    ] {
        assert!(
            serde_json::from_str::<Preferences>(document).is_err(),
            "missing field must not decode: {document}"
        );
    }
    for (notify, reconnect, startup) in [
        ("\"true\"", "false", "false"),
        ("1", "false", "false"),
        ("null", "false", "false"),
        ("true", "\"false\"", "false"),
        ("true", "0", "false"),
        ("true", "false", "\"false\""),
        ("true", "false", "1"),
        ("true", "false", "[]"),
        ("true", "false", "{}"),
    ] {
        let document = body("10", notify, reconnect, startup);
        assert!(
            serde_json::from_str::<Preferences>(&document).is_err(),
            "non-boolean must not decode: {document}"
        );
    }
}

// Mutation captured: an unchecked constructor or a conversion that reports
// seconds the value does not hold.
#[test]
fn construction_is_checked_and_reports_its_own_value() {
    assert_eq!(ProbeInterval::TEN.seconds(), 10);
    assert_eq!(ProbeInterval::THIRTY.seconds(), 30);
    assert_eq!(ProbeInterval::SIXTY.seconds(), 60);
    assert_eq!(ProbeInterval::from_seconds(30), Some(ProbeInterval::THIRTY));
    assert_eq!(ProbeInterval::from_seconds(0), None);
    assert_eq!(ProbeInterval::from_seconds(45), None);
    assert_eq!(ProbeInterval::from_seconds(u16::MAX), None);
}
