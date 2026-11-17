use super::*;

// Mutations: omit the stats admission, accept PF_KEY or another kernel-*
// backend, drop one required plugin, admit duplicates, loosen the name shape,
// or serialize credentials before the backend query.
#[test]
fn backend_admission_rejects_missing_foreign_or_malformed_lists_before_any_load() {
    for mode in [
        "stats-missing",
        "stats-scalar",
        "stats-section",
        "stats-empty",
        "stats-129",
        "stats-empty-item",
        "stats-invalid-utf8",
        "stats-duplicate",
        "stats-uppercase",
        "stats-underscore",
        "stats-long",
        "stats-pfkey",
        "stats-netlink",
        "stats-no-libipsec",
        "stats-no-pfroute",
        "stats-no-socket",
        "stats-no-vici",
    ] {
        let (mut control, harness, observation, registry) = setup(mode, false);
        let result = control.start(creds(), until(), token());
        assert_eq!(result, Err(Error::Incompatible), "{mode}");
        assert!(
            !format!("{result:?}").contains("fictional-secret"),
            "{mode}"
        );
        assert_eq!(control.phase(), Phase::Dirty, "{mode}");
        assert_eq!(
            harness.audit(),
            ["version", "stats"],
            "{mode}: nothing may be loaded for a refused backend"
        );
        // Never-loaded credentials must not produce load/terminate traffic, and
        // the reservation is retained until the normal retire/release path.
        assert_eq!(control.cleanup(until()), Ok(false), "{mode}");
        assert_eq!(
            harness.audit(),
            ["version", "stats"],
            "{mode}: cleanup of never-loaded credentials"
        );
        settle(&mut control, &harness, &observation, &registry);
    }
}

// Mutation: move load-conn/load-shared before the stats query, or drop the
// stats command while keeping the loads.
#[test]
fn accepted_backend_order_keeps_stats_before_any_credential_serialization() {
    for mode in ["normal", "stats-extra", "stats-128", "stats-name64"] {
        let (mut control, harness, observation, registry) = setup(mode, false);
        control.start(creds(), until(), token()).unwrap();
        assert_eq!(
            harness.audit(),
            [
                "version",
                "stats",
                "load-conn",
                "load-shared",
                "load-shared",
                "initiate"
            ],
            "{mode}"
        );
        settle(&mut control, &harness, &observation, &registry);
    }
}
