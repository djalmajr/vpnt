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
