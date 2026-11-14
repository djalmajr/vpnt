use std::time::{Duration, Instant};
use vpnt::{app::App, bridge::Command, session::ConnectionState};

// Mutation captured: starting the normal app with sample profiles misrepresents fictional VPNs as real.
#[test]
fn normal_startup_contains_no_demo_profiles_and_rejects_demo_commands() {
    let mut app = App::new();
    assert!(app.snapshot().vpns.is_empty());
    assert!(
        app.dispatch(Command::SetDemoState {
            id: "cluster".into(),
            state: ConnectionState::Connected
        })
        .is_err()
    );
}

// Mutation captured: a scheduled connection result after cancel leaves the panel connected again.
#[test]
fn cancelling_through_the_application_keeps_the_profile_disconnected() {
    let mut app = App::demo();
    let now = Instant::now();
    app.dispatch_at(
        Command::Toggle {
            id: "cluster".into(),
        },
        now,
    )
    .unwrap();
    app.dispatch_at(
        Command::Toggle {
            id: "cluster".into(),
        },
        now,
    )
    .unwrap();
    let state = app.snapshot_at(now + Duration::from_secs(5));
    assert_eq!(state.vpns[0].state, ConnectionState::Off);
    assert_eq!(state.vpns[1].state, ConnectionState::Off);
}

// Mutation captured: disconnect-all stopping only the first profile leaves a second tunnel running.
#[test]
fn disconnect_all_operates_on_each_profile() {
    let mut app = App::demo();
    let now = Instant::now();
    for id in ["cluster", "office"] {
        app.dispatch_at(
            Command::SetDemoState {
                id: id.into(),
                state: ConnectionState::Connected,
            },
            now,
        )
        .unwrap();
    }
    app.dispatch_at(Command::DisconnectAll {}, now).unwrap();
    let snapshot = app.snapshot_at(now + Duration::from_secs(2));
    assert!(
        snapshot
            .vpns
            .iter()
            .all(|vpn| vpn.state == ConnectionState::Off)
    );
}

// Mutation captured: reusing reconnect for a probe drops a healthy tunnel during a manual check.
#[test]
fn checking_a_connected_tunnel_does_not_reconnect_it() {
    let mut app = App::demo();
    let now = Instant::now();
    app.dispatch_at(
        Command::SetDemoState {
            id: "cluster".into(),
            state: ConnectionState::Connected,
        },
        now,
    )
    .unwrap();
    let snapshot = app
        .dispatch_at(
            Command::Probe {
                id: "cluster".into(),
            },
            now,
        )
        .unwrap();
    assert_eq!(snapshot.vpns[0].state, ConnectionState::Connected);
}
