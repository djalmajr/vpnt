use super::*;

// Mutations: omit the stats admission, accept PF_KEY or another kernel-*
// backend, drop one required plugin, admit duplicates, loosen the name shape,
// or serialize credentials before the backend query.
const MALFORMED: &[&str] = &[
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
];
// The macOS list stays exactly the patched-runtime one; Linux refuses every
// kernel backend except netlink and requires the same socket/vici pair.
#[cfg(target_os = "macos")]
const PLUGIN_REJECTIONS: &[&str] = &[
    "stats-pfkey",
    "stats-netlink",
    "stats-no-libipsec",
    "stats-no-pfroute",
    "stats-no-socket",
    "stats-no-vici",
];
#[cfg(not(target_os = "macos"))]
const PLUGIN_REJECTIONS: &[&str] = &[
    "stats-foreign-kernel-libipsec",
    "stats-foreign-kernel-pfroute",
    "stats-foreign-kernel-pfkey",
    "stats-foreign-kernel-dummy",
    "stats-drop-kernel-netlink",
    "stats-drop-socket-default",
    "stats-drop-vici",
];

#[test]
fn backend_admission_rejects_missing_foreign_or_malformed_lists_before_any_load() {
    for mode in MALFORMED.iter().chain(PLUGIN_REJECTIONS) {
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

fn complete_exchange(audit: &[String], version: &str) {
    assert_eq!(
        audit,
        [
            "version",
            "stats",
            "load-conn",
            "load-shared",
            "load-shared",
            "initiate"
        ],
        "{version}: a supported daemon must complete the whole VICI sequence"
    );
}

// Mutation: accept any 6.x patch, a pre-release suffix or a distribution
// separator on Linux.
#[cfg(target_os = "linux")]
#[test]
fn linux_accepts_the_tested_6_1_patch_range() {
    for version in ["6.1.0", "6.1.7"] {
        let mode = format!("version-{version}");
        let (mut control, harness, observation, registry) = setup(&mode, false);
        control.start(creds(), until(), token()).unwrap();
        complete_exchange(&harness.audit(), version);
        settle(&mut control, &harness, &observation, &registry);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_rejects_untested_versions_with_a_positive_control_alongside() {
    for version in [
        "6.0.3", "6.2.0", "6.1", "6.1.0rc1", "6.1.0-2", "6.1.0.1", "empty",
    ] {
        let mode = format!("version-{version}");
        let (mut control, harness, observation, registry) = setup(&mode, false);
        let result = control.start(creds(), until(), token());
        assert_eq!(result, Err(Error::Incompatible), "{version}");
        assert_eq!(harness.audit(), ["version"], "{version}: no stats query");
        assert_eq!(control.cleanup(until()), Ok(false), "{version}");
        assert_eq!(
            harness.audit(),
            ["version"],
            "{version}: no cleanup traffic for refused credentials"
        );
        settle(&mut control, &harness, &observation, &registry);

        // The same loop proves the refusal is about the version, not the
        // fixture: an adjacent supported patch still completes the exchange.
        let (mut control, harness, observation, registry) = setup("version-6.1.7", false);
        control.start(creds(), until(), token()).unwrap();
        complete_exchange(&harness.audit(), "6.1.7");
        settle(&mut control, &harness, &observation, &registry);
    }
}

// The macOS rule is unchanged: libipsec/pfroute and exactly 6.1.0.
#[cfg(target_os = "macos")]
#[test]
fn macos_keeps_the_patched_runtime_admission() {
    let (mut control, harness, observation, registry) = setup("version-6.1.0", false);
    control.start(creds(), until(), token()).unwrap();
    complete_exchange(&harness.audit(), "6.1.0");
    settle(&mut control, &harness, &observation, &registry);

    // A refused version stops before `stats`; a foreign backend is only
    // visible in the `stats` reply.
    for (mode, audit) in [
        ("version-6.1.7", &["version"][..]),
        ("stats-foreign-kernel-netlink", &["version", "stats"][..]),
    ] {
        let (mut control, harness, observation, registry) = setup(mode, false);
        let result = control.start(creds(), until(), token());
        assert_eq!(result, Err(Error::Incompatible), "{mode}");
        assert_eq!(harness.audit(), audit, "{mode}");
        assert_eq!(control.cleanup(until()), Ok(false), "{mode}");
        settle(&mut control, &harness, &observation, &registry);
    }
}
