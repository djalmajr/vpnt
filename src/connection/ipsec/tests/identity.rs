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
fn usernames_are_opaque_key_id_bytes_even_when_they_look_like_identity_patterns() {
    let mut registry = Registry::new(Observation::default());
    let reservation = registry.reserve(owner("Case", 1)).unwrap();
    for (username, encoded) in [
        ("%any", "keyid:#25616e79"),
        ("*", "keyid:#2a"),
        ("fqdn:#2a", "keyid:#6671646e3a233261"),
        ("192.0.2.0/24", "keyid:#3139322e302e322e302f3234"),
        ("{0}:", "keyid:#7b307d3a"),
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
        assert_eq!(
            eap.get_list("owners").unwrap()[0].as_slice(),
            encoded.as_bytes()
        );
    }
    for gateway in ["0.0.0.0", "::", "0::0"] {
        let mut p = profile();
        p.gateway = gateway.into();
        assert!(matches!(
            config(&registry, &reservation, &p),
            Err(Error::Invalid)
        ));
    }
}
