use vpnt::session::{Completion, ConnectionState, Session};

// Mutation captured: accepting a completion from before cancellation reconnects the VPN.
#[test]
fn cancelling_a_connection_rejects_its_late_completion() {
    let mut session = Session::default();
    let old = session.connect();
    session.disconnect();
    assert!(!session.complete(old, Completion::TunnelReady));
    assert_eq!(session.state(), ConnectionState::Disconnecting);
}

// Mutation captured: applying an old probe failure makes the new tunnel unresponsive.
#[test]
fn reconnecting_rejects_a_probe_from_the_previous_tunnel() {
    let mut session = Session::default();
    let old = session.connect();
    session.complete(old, Completion::TunnelReady);
    session.complete(old, Completion::ProbePassed);
    session.complete(old, Completion::ProbeFailed);
    assert_eq!(session.state(), ConnectionState::Unresponsive);
    let current = session.reconnect();
    assert!(!session.complete(old, Completion::ProbeFailed));
    assert!(session.complete(current, Completion::TunnelReady));
    assert!(session.complete(current, Completion::ProbePassed));
    assert_eq!(session.state(), ConnectionState::Connected);
    assert!(!session.complete(old, Completion::ProbeFailed));
    assert_eq!(session.state(), ConnectionState::Connected);
}

// Mutation captured: trusting the process exit alone incorrectly labels an untested tunnel connected.
#[test]
fn a_ready_tunnel_is_connected_only_after_a_successful_probe() {
    let mut session = Session::default();
    let generation = session.connect();
    assert!(session.complete(generation, Completion::TunnelReady));
    assert_eq!(session.state(), ConnectionState::Verifying);
    assert!(session.complete(generation, Completion::ProbeFailed));
    assert_eq!(session.state(), ConnectionState::Unresponsive);
}

// Mutation captured: a constant generation makes checks target a different connection attempt.
#[test]
fn every_operation_exposes_its_current_generation() {
    let mut session = Session::default();
    let first = session.connect();
    assert_eq!(session.generation(), first);
    let second = session.reconnect();
    assert!(second > first);
    assert_eq!(session.generation(), second);
    let stopped = session.disconnect();
    assert!(stopped > second);
    assert_eq!(session.generation(), stopped);
}

// Mutation captured: ignoring the active guard marks an inactive VPN as dropped, or hides a real drop.
#[test]
fn unexpected_exit_only_changes_a_running_session() {
    let mut session = Session::default();
    assert!(!session.complete(0, Completion::UnexpectedExit));
    assert_eq!(session.state(), ConnectionState::Off);
    let current = session.connect();
    assert!(session.complete(current, Completion::UnexpectedExit));
    assert_eq!(session.state(), ConnectionState::Dropped);
}

// Mutation captured: removing a failure arm leaves the VPN indefinitely connecting.
#[test]
fn connection_failures_preserve_their_user_visible_reason() {
    for (completion, expected) in [
        (
            Completion::CredentialsRejected,
            ConnectionState::CredentialsRejected,
        ),
        (Completion::GatewayTimeout, ConnectionState::GatewayTimeout),
    ] {
        let mut session = Session::default();
        let current = session.connect();
        assert!(session.complete(current, completion));
        assert_eq!(session.state(), expected);
    }
}
