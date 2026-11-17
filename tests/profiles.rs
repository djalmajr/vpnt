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

#[test]
fn dns_domains_round_trip_validation_and_ipsec_rejection() {
    let old = serde_json::json!({"id":"a","name":"Example","kind":"ssl","gateway":"vpn.example.com", "username":"user","networks":[],"port":443,"certificate":"", "probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"});
    let profile: Profile = serde_json::from_value(old.clone()).unwrap();
    assert!(profile.dns_domains.is_empty());
    assert_eq!(serde_json::to_value(&profile).unwrap(), old);
    let mut value = old.clone();
    value["dnsDomains"] = serde_json::json!(["CORP.Example.Com", "other.example"]);
    let profile: Profile = serde_json::from_value(value).unwrap();
    assert_eq!(profile.dns_domains, ["corp.example.com", "other.example"]);
    profile.validate().unwrap();
    let saved = serde_json::to_value(&profile).unwrap();
    assert_eq!(
        saved["dnsDomains"],
        serde_json::json!(["corp.example.com", "other.example"])
    );
    assert_eq!(serde_json::from_value::<Profile>(saved).unwrap(), profile);
    let mut bad = profile.clone();
    for domains in [
        vec!["".into()],
        vec!["single".into()],
        vec!["a..b".into()],
        vec!["a.b.".into()],
        vec!["-a.b".into()],
        vec!["a-.b".into()],
        vec!["a_b.example".into()],
        vec!["é.example".into()],
        vec![format!("{}.com", "a".repeat(64))],
        vec![format!(
            "{}.{}.{}.{}.com",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        )],
        vec!["a.b".into(), "a.b".into()],
    ] {
        bad.dns_domains = domains;
        assert_eq!(
            bad.validate(),
            Err("invalid_profile"),
            "{:?}",
            bad.dns_domains
        );
    }
    bad.dns_domains = (0..8).map(|i| format!("host{i}.example.net")).collect();
    assert_eq!(bad.validate(), Ok(()));
    bad.dns_domains.push("host8.example.net".into());
    assert_eq!(bad.validate(), Err("invalid_profile"));
    let mut ipsec = old;
    ipsec["kind"] = serde_json::json!("ipsec");
    ipsec["dnsDomains"] = serde_json::json!(["a.b"]);
    assert_eq!(
        serde_json::from_value::<Profile>(ipsec).unwrap().validate(),
        Err("invalid_profile")
    );
}
