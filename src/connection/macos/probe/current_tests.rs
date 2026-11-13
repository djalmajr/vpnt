//! Deterministic regressions for cancel/expiry precedence and the single
//! absolute run deadline. The fake current is bounded; no external traffic.
use super::{
    Kind, Link, Method, Outcome, finish, run, run_until,
    utun_tests::{canceled, interface, profile},
};
use crate::{
    connection::macos::interfaces::Interface,
    model::{Profile, VpnKind},
};
use std::{
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

enum Action {
    Fixed(bool),
    SetCancel(Arc<AtomicBool>, bool),
    SleepOnce(Duration, Arc<AtomicBool>),
}
impl Action {
    fn get(&self) -> bool {
        match self {
            Action::Fixed(value) => *value,
            Action::SetCancel(flag, value) => {
                flag.store(true, Ordering::Release);
                *value
            }
            Action::SleepOnce(duration, slept) => {
                if !slept.swap(true, Ordering::AcqRel) {
                    thread::sleep(*duration);
                }
                true
            }
        }
    }
}
struct ScriptedLink {
    interface: Interface,
    action: Action,
    kind: Kind,
}
impl Link for ScriptedLink {
    fn interface(&self) -> &Interface {
        &self.interface
    }
    fn current(&self) -> bool {
        self.action.get()
    }
    fn kind(&self) -> Kind {
        self.kind
    }
}

fn future() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
fn ipsec_profile(port: u16) -> Profile {
    profile(VpnKind::Ipsec, "127.0.0.1", port)
}
fn loopback() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}
fn no_accept(listener: &TcpListener) {
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}
fn link(action: Action) -> ScriptedLink {
    ScriptedLink {
        interface: interface(1, &["127.0.0.1"]),
        action,
        kind: Kind::Ipsec,
    }
}

// Mutation: skip the post-current cancel check in run_until.
#[test]
fn cancel_after_failed_current_is_canceled_in_run() {
    let cancel = canceled(false);
    let link = link(Action::SetCancel(cancel.clone(), false));
    assert_eq!(
        run_until(&link, &ipsec_profile(9), cancel.as_ref(), future(), true),
        Outcome::Canceled
    );
}

// Mutation: skip the post-current cancel check even for a true current.
#[test]
fn cancel_after_successful_current_is_canceled_in_run() {
    let cancel = canceled(false);
    let link = link(Action::SetCancel(cancel.clone(), true));
    assert_eq!(
        run_until(&link, &ipsec_profile(9), cancel.as_ref(), future(), true),
        Outcome::Canceled
    );
}

// Mutation: ignore the cancel observed around finish()'s current.
#[test]
fn cancel_after_current_is_canceled_in_finish() {
    let cancel = canceled(false);
    let link = link(Action::SetCancel(cancel.clone(), false));
    assert_eq!(
        finish(&link, Method::Tcp, cancel.as_ref(), future()),
        Outcome::Canceled
    );
}

// Mutation: use a fresh now+timeout instead of the supplied absolute deadline.
#[test]
fn expired_entry_never_connects_or_reports_responsive() {
    let listener = loopback();
    let port = listener.local_addr().unwrap().port();
    let past = Instant::now() - Duration::from_millis(1);
    assert_eq!(
        run_until(
            &link(Action::Fixed(true)),
            &ipsec_profile(port),
            canceled(false).as_ref(),
            past,
            true
        ),
        Outcome::Unresponsive
    );
    no_accept(&listener);
}

// Mutation: rebase the deadline after the consumed current; the bounded
// 50 ms fixture must not reach the real loopback listener or report Responsive.
#[test]
fn consumed_budget_after_current_never_connects_or_reports_responsive() {
    let listener = loopback();
    let port = listener.local_addr().unwrap().port();
    let slow = Action::SleepOnce(Duration::from_millis(50), Arc::new(AtomicBool::new(false)));
    let started = Instant::now();
    let outcome = run(
        &link(slow),
        &ipsec_profile(port),
        canceled(false).as_ref(),
        Duration::from_millis(20),
        true,
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "bounded fixture"
    );
    assert_eq!(outcome, Outcome::Unresponsive);
    no_accept(&listener);
}

// Mutation: drop the post-current deadline recheck in finish.
#[test]
fn slow_current_after_deadline_never_reports_responsive_in_finish() {
    let slow = Action::SleepOnce(Duration::from_millis(50), Arc::new(AtomicBool::new(false)));
    let deadline = Instant::now() + Duration::from_millis(20);
    assert_eq!(
        finish(&link(slow), Method::Tcp, canceled(false).as_ref(), deadline),
        Outcome::Unresponsive
    );
}
