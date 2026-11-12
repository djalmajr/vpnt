use super::*;

// Mutations: discard a complete batch, reject rekey overlap/transitional
// children, or equate daemon initiation/old rekeyed SAs with active candidates.
#[test]
fn rekey_candidates_are_complete_and_keep_transitional_children_out_of_the_installed_set() {
    let (mut control, harness, observation, registry) = setup("rekey", false);
    control.start(creds(), until(), token()).unwrap();
    let candidates = control.snapshot(until(), token()).unwrap();
    assert_eq!(candidates.len(), 2, "complete rekey candidates missing");
    assert_eq!(
        (
            candidates[0].ike_id,
            candidates[0].child_id,
            candidates[0].active
        ),
        (1, 1, false)
    );
    assert_eq!(
        (
            candidates[1].ike_id,
            candidates[1].child_id,
            candidates[1].active
        ),
        (2, 2, true)
    );
    assert_eq!(candidates[1].reqid, 16383);
    assert_eq!(candidates[1].spi_in, 0xabcd0104);
    assert_eq!(
        candidates[1].remote_ts,
        vec!["10.20.0.0/24".parse().unwrap()]
    );
    assert_eq!(
        candidates[1].vips,
        vec!["10.8.0.2".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(control.phase(), Phase::Initiated);
    settle(&mut control, &harness, &observation, &registry);
}

// Mutations: accept a foreign/malformed SA or return only the valid prefix.
#[test]
fn malformed_or_foreign_snapshot_batches_never_publish_partial_candidates() {
    for mode in [
        "bad-reqid",
        "bad-spi",
        "bad-remote-ts",
        "wide-local-ts",
        "bad-child-name",
        "bad-state",
        "bad-version",
        "bad-endpoint",
        "bad-uniqueid",
        "bad-mode",
        "bad-protocol",
        "bad-vip",
        "bad-child-key",
        "foreign-root",
        "duplicate-ike",
        "root-extra",
        "partial-bad",
        "nonempty-completion",
        "duplicate-spi",
        "zero-port",
        "bad-encap",
        "wide-remote-ts",
        "mismatch-family",
        "responder",
        "zero-ike-spi",
        "spi-width",
        "zero-id",
        "too-many",
        "duplicate-child",
        "zero-reqid",
    ] {
        let (mut control, harness, observation, registry) = setup(mode, false);
        control.start(creds(), until(), token()).unwrap();
        assert!(
            control.snapshot(until(), token()).is_err(),
            "foreign/malformed candidates published: {mode}"
        );
        settle(&mut control, &harness, &observation, &registry);
    }
}

// Mutations: drop IPv6 selectors or require an
// installed child when a complete query reports no SAs.
#[test]
fn ordinary_and_ipv6_candidates_preserve_scope_and_an_empty_query_proves_no_connection() {
    for mode in ["normal", "ipv6", "empty"] {
        let (mut control, harness, observation, registry) = setup(mode, false);
        assert!(control.snapshot(until(), token()).is_err());
        assert!(harness.audit().is_empty());
        control.start(creds(), until(), token()).unwrap();
        let candidates = control.snapshot(until(), token()).unwrap();
        assert_eq!(candidates.len(), usize::from(mode != "empty"));
        if let Some(c) = candidates.first() {
            assert_eq!(
                (c.local_port, c.remote_port, c.udp_encap, c.active),
                (45000, 500, false, true)
            );
            assert_eq!(c.local_ts[0].address().is_ipv6(), mode == "ipv6");
            assert_eq!(c.remote_ts[0].address().is_ipv6(), mode == "ipv6");
        }
        assert_eq!(control.phase(), Phase::Initiated);
        settle(&mut control, &harness, &observation, &registry);
    }
}
