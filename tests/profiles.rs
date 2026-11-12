use vpnt::model::Profile;

#[test]
fn malformed_networks_cannot_expand_the_root_configuration_or_inject_client_options() {
    let mut profile: Profile = serde_json::from_value(serde_json::json!({
        "id":"a","name":"Example","kind":"ipsec","gateway":"vpn.example.com",
        "username":"fictional","networks":[],"port":443,"certificate":"",
        "probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"
    }))
    .unwrap();
    for invalid in [
        "10.20.0.0/33".to_string(),
        "10.20.0.0/+24".into(),
        "10.20.0.0/024".into(),
        format!("10.20.0.0/{}24", "0".repeat(60_000)),
        "10.20.0.0/24\n--updown=/tmp/script".into(),
    ] {
        profile.networks = vec![invalid];
        assert_eq!(profile.validate(), Err("invalid_network"));
    }
    profile.networks = vec![
        "10.20.0.0/24".into(),
        "::/0".into(),
        "2001:db8::/128".into(),
    ];
    assert!(profile.validate().is_ok());
}

#[test]
fn ssl_profile_rejects_native_username_truncation_and_invalid_fingerprints() {
    let mut profile: Profile = serde_json::from_value(serde_json::json!({
        "id":"a","name":"Example","kind":"ssl","gateway":"vpn.example.com",
        "username":"user","networks":[],"port":443,"certificate":"",
        "probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"
    }))
    .unwrap();
    for username in ["a".repeat(65), "é".repeat(33)] {
        profile.username = username;
        assert!(profile.validate().is_err());
    }
    profile.username = "é".repeat(32);
    assert!(profile.validate().is_ok());
    for certificate in ["0".repeat(63), "g".repeat(64), "../file".into()] {
        profile.certificate = certificate;
        assert!(profile.validate().is_err());
    }
    profile.certificate = "A1".repeat(32);
    assert!(profile.validate().is_ok());
}
