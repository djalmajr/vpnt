use super::*;

#[test]
fn names_preserve_uid_generation_case_and_the_full_profile_and_default_selectors_cover_both_families()
 {
    let cases = [
        (502, "Case".to_owned(), 1),
        (503, "Case".to_owned(), 1),
        (502, "case".to_owned(), 1),
        (502, "Case".to_owned(), 2),
        (u32::MAX, "Z".repeat(64), u64::MAX),
    ];
    let mut names = BTreeSet::new();
    for (uid, id, generation) in cases {
        let mut registry = Registry::new(Observation::default());
        let reservation = registry
            .reserve(Owner {
                uid,
                profile: id.clone(),
                generation,
            })
            .unwrap();
        let mut p = profile();
        p.id = id.clone();
        p.networks.clear();
        let c = config(&registry, &reservation, &p).unwrap();
        assert!(names.insert(c.name().to_owned()));
        assert!(c.name().len() <= 255 && c.child_name().len() <= 255);
        assert_eq!(c.name().split('-').nth(2).unwrap().len(), id.len() * 2);
        let request = wire("load-conn", c.connection());
        let conn = request.get_section(c.name()).unwrap();
        assert_eq!(
            conn.get_list("local_addrs").unwrap()[0].as_slice(),
            b"192.0.2.2"
        );
        assert_eq!(
            conn.get_list("remote_addrs").unwrap()[0].as_slice(),
            b"198.51.100.3"
        );
        let child = conn
            .get_section("children")
            .unwrap()
            .get_section(c.child_name())
            .unwrap();
        let networks = child.get_list("remote_ts").unwrap();
        assert_eq!(networks.len(), 2);
        assert_eq!(networks[0].as_slice(), b"0.0.0.0/0");
        assert_eq!(networks[1].as_slice(), b"::/0");
    }
}

#[test]
fn usernames_have_explicit_text_types_and_the_same_eap_secret_owner() {
    let mut registry = Registry::new(Observation::default());
    let reservation = registry.reserve(owner("Case", 1)).unwrap();
    for (username, encoded) in [
        ("fixture.user", "fqdn:fixture.user"),
        ("Fixture@Example.com", "email:Fixture@Example.com"),
        ("%any", "fqdn:%any"),
        ("fqdn:#2a", "fqdn:fqdn:#2a"),
        ("email:alice@example.com", "email:email:alice@example.com"),
        ("192.0.2.0/24", "fqdn:192.0.2.0/24"),
        ("{0}:", "fqdn:{0}:"),
        ("a#b", "fqdn:a#b"),
        ("CN=fixture", "fqdn:CN=fixture"),
        ("@fixture", "email:@fixture"),
        ("^fixture", "fqdn:^fixture"),
        ("fixture$", "fqdn:fixture$"),
        ("a,b", "fqdn:a,b"),
        ("jo\u{e3}o", "fqdn:#6a6fc3a36f"),
        (
            "jos\u{e9}@example.com",
            "email:#6a6f73c3a9406578616d706c652e636f6d",
        ),
    ] {
        let mut p = profile();
        p.username = username.into();
        let c = config(&registry, &reservation, &p).unwrap();
        let request = wire("load-conn", c.connection());
        let local = request
            .get_section(c.name())
            .unwrap()
            .get_section("local")
            .unwrap();
        assert_eq!(local.get_text("id"), Some(encoded));
        assert_eq!(local.get_text("eap_id"), Some(encoded));
        let [eap, _] = c.shared(creds()).unwrap();
        let eap = wire("load-shared", eap);
        assert_eq!(eap.get_list("owners").unwrap().len(), 1);
        assert_eq!(
            eap.get_list("owners").unwrap()[0].as_slice(),
            encoded.as_bytes()
        );
    }
}

#[test]
fn usernames_cannot_inject_hex_regex_wildcards_or_control_bytes() {
    let mut registry = Registry::new(Observation::default());
    let reservation = registry.reserve(owner("Case", 1)).unwrap();
    for username in [
        "",
        "#616263",
        "#616263@example.com",
        "^fixture$",
        "^fixture@example.com$",
        "*",
        "*.example.com",
        "fixture*",
        "fixture\0suffix",
        "fixture\nother",
        "fixture\r",
        "fixture\t",
        "fixture\u{7f}",
        "fixture\u{85}",
    ] {
        let mut p = profile();
        p.username = username.into();
        assert!(
            matches!(config(&registry, &reservation, &p), Err(Error::Invalid)),
            "{username:?}"
        );
    }
    let mut p = profile();
    p.username = "x".repeat(201);
    assert!(matches!(
        config(&registry, &reservation, &p),
        Err(Error::Invalid)
    ));
}

#[test]
fn unspecified_gateways_cannot_be_used_as_remote_identities() {
    let mut registry = Registry::new(Observation::default());
    let reservation = registry.reserve(owner("Case", 1)).unwrap();
    for gateway in ["0.0.0.0", "::", "0::0"] {
        let mut p = profile();
        p.gateway = gateway.into();
        assert!(matches!(
            config(&registry, &reservation, &p),
            Err(Error::Invalid)
        ));
    }
}
