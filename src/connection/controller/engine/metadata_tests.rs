use super::*;
use std::fs;
mod harness;
use harness::{Harness, profile};

#[test]
fn snapshot_refresh_preserves_a_live_profile_and_exposes_edited_new_and_removed_metadata() {
    let mut h = Harness::new(vec![profile("one"), profile("two")]);
    h.connect("one");
    let mut two = profile("two");
    two.name = "Edited inactive".into();
    h.store().save(two.clone()).unwrap();
    h.store().save(profile("three")).unwrap();
    let Message::Snapshot {
        profiles,
        connections,
        ..
    } = h.snapshot()
    else {
        panic!("metadata must be refreshed")
    };
    assert_eq!(profiles.len(), 3);
    assert!(profiles.contains(&two));
    assert!(
        connections
            .iter()
            .any(|s| s.id == "one" && s.generation == 1 && s.state == ConnectionState::Connected)
    );
    assert!(
        connections
            .iter()
            .any(|s| s.id == "two" && s.generation == 1 && s.state == ConnectionState::Off)
    );
    assert_eq!(
        h.store().remove("one"),
        Err(crate::storage::StoreError::Busy)
    );
    h.store().remove("two").unwrap();
    let Message::Snapshot { profiles, .. } = h.snapshot() else {
        panic!("removed metadata must be refreshed")
    };
    assert!(!profiles.iter().any(|p| p.id == "two"));
    h.cleanup.store(false, Ordering::Release);
    h.send(Command::Disconnect {
        id: "one".into(),
        generation: 2,
    });
    h.wait(|m|matches!(m,Message::Changed{profile_id,state:ConnectionState::Disconnecting,..}if profile_id=="one"));
    assert_eq!(
        h.store().remove("one"),
        Err(crate::storage::StoreError::Busy)
    );
    h.cleanup.store(true, Ordering::Release);
    h.wait(|m|matches!(m,Message::Changed{profile_id,state:ConnectionState::Off,..}if profile_id=="one"));
    h.store().remove("one").unwrap();
}

#[test]
fn a_rejected_refresh_cannot_partially_edit_idle_slots_or_cancel_a_live_slot() {
    let original = vec![profile("a-idle"), profile("z-live")];
    let mut h = Harness::new(original.clone());
    h.connect("z-live");
    let mut changed = original.clone();
    for p in &mut changed {
        p.name = "Changed externally".into();
    }
    fs::write(
        h.root.join("profiles.json"),
        serde_json::to_vec(&serde_json::json!({"version":1,"profiles":changed})).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        h.snapshot(),
        Message::Failed {
            error: ErrorCode::ProfileBusy,
            ..
        }
    ));
    fs::write(
        h.root.join("profiles.json"),
        serde_json::to_vec(&serde_json::json!({"version":1,"profiles":original})).unwrap(),
    )
    .unwrap();
    let Message::Snapshot {
        profiles,
        connections,
        ..
    } = h.snapshot()
    else {
        panic!("restored catalog must remain usable")
    };
    assert_eq!(profiles, original);
    assert!(
        connections
            .iter()
            .any(|s| s.id == "a-idle" && s.generation == 0 && s.state == ConnectionState::Off),
        "failed refresh must not advance an idle generation"
    );
    assert!(
        connections.iter().any(|s| s.id == "z-live"
            && s.generation == 1
            && s.state == ConnectionState::Connected)
    );
}

#[test]
fn ipsec_metadata_is_visible_without_dispatching_it_to_the_ssl_worker() {
    let mut p = profile("ipsec");
    p.kind = VpnKind::Ipsec;
    let mut h = Harness::new(vec![p.clone()]);
    let Message::Snapshot { profiles, .. } = h.snapshot() else {
        panic!("IPsec metadata must be visible")
    };
    assert_eq!(profiles, vec![p]);
    let id = h.send(Command::Connect {
        id: "ipsec".into(),
        generation: 1,
        interval: crate::preferences::ProbeInterval::TEN,
        credentials: Credentials {
            password: "fictional".into(),
            psk: "".into(),
        },
    });
    let reply =
        h.wait(|m| matches!(m,Message::Accepted{id:got}|Message::Failed{id:got,..} if *got==id));
    assert!(matches!(
        reply,
        Message::Failed {
            error: ErrorCode::MissingProgram,
            ..
        }
    ));
    let Message::Snapshot { connections, .. } = h.snapshot() else {
        panic!("unsupported connect cannot change metadata")
    };
    assert!(
        connections
            .iter()
            .all(|s| s.generation == 0 && s.state == ConnectionState::Off)
    );
}
