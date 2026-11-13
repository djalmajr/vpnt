//! Factory capability dispatch through the real engine channel and parser.
//! The test factory delegates attempts to the real Fixture; product
//! NativeFactory stays Ssl-only.
use super::*;
use crate::{
    connection::routes::Coordinator,
    helper::protocol::{Command, ErrorCode, Message},
    model::{Profile, VpnKind},
    secrets::{Credentials, Secret},
    session::ConnectionState,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

/// Test-only capability wrapper: the actual attempt factory is the real
/// Fixture; only the advertised kind support is selectable/revocable.
struct CapabilityFactory {
    fixture: Fixture,
    ssl: Arc<AtomicBool>,
    ipsec: Arc<AtomicBool>,
}
impl Factory for CapabilityFactory {
    type Attempt = FixtureAttempt;
    fn supports(&self, kind: VpnKind) -> bool {
        match kind {
            VpnKind::Ssl => self.ssl.load(Ordering::Acquire),
            VpnKind::Ipsec => self.ipsec.load(Ordering::Acquire),
        }
    }
    fn create(
        &self,
        profile: Profile,
        uid: u32,
        generation: u64,
        credentials: Credentials,
        canceled: Arc<AtomicBool>,
    ) -> Self::Attempt {
        self.fixture
            .create(profile, uid, generation, credentials, canceled)
    }
    fn idle(&self) -> bool {
        self.fixture.idle()
    }
}

/// Build the same Harness from the private parent fields, with the capability
/// wrapper instead of the default Fixture. No public test getter is added.
fn capability_harness(
    profiles: Vec<Profile>,
    ssl: bool,
    ipsec: bool,
) -> (Harness, Arc<AtomicBool>) {
    let kernel = Arc::new(Mutex::new(Kernel::default()));
    let routes = Arc::new(Mutex::new(Coordinator::new(Table(kernel.clone())).unwrap()));
    let ssl = Arc::new(AtomicBool::new(ssl));
    let ipsec = Arc::new(AtomicBool::new(ipsec));
    let factory = CapabilityFactory {
        fixture: Fixture {
            uid: 501,
            kernel: kernel.clone(),
            routes,
        },
        ssl: ssl.clone(),
        ipsec,
    };
    let (input, requests) = mpsc::sync_channel(64);
    let (output, receiver) = mpsc::sync_channel(64);
    let timing = Timing {
        connect: Duration::from_secs(5),
        probe: Duration::from_secs(1),
        interval: Duration::from_secs(60),
        poll: Duration::from_millis(2),
    };
    let worker = thread::spawn(move || run(factory, 501, profiles, requests, output, timing));
    (
        Harness {
            input: Some(input),
            output: receiver,
            kernel,
            worker: Some(worker),
            seen: vec![],
            next_request: 0,
        },
        ssl,
    )
}

fn ipsec_profile(id: &str) -> Profile {
    let mut profile = profile(id);
    profile.kind = VpnKind::Ipsec;
    profile
}
fn ssl_credentials() -> Credentials {
    Credentials {
        password: Secret::from("fixture-password"),
        psk: Secret::from(""),
    }
}
fn ipsec_credentials() -> Credentials {
    Credentials {
        password: Secret::from("fixture-password"),
        psk: Secret::from("fixture-psk"),
    }
}
fn connect(harness: &mut Harness, id: &str, generation: u64, credentials: Credentials) -> String {
    harness.command(Command::Connect {
        id: id.into(),
        generation,
        credentials,
    })
}
fn failed(harness: &Harness, id: &str, error: ErrorCode) -> bool {
    harness.seen.iter().any(|message| {
        matches!(message, Message::Failed { id: failed, error: actual } if failed == id && *actual == error)
    })
}

#[test]
fn default_factory_refuses_ipsec() {
    let mut harness = Harness::new(vec![ipsec_profile("one")], 64);
    let id = connect(&mut harness, "one", 1, ipsec_credentials());
    harness.wait(|h| {
        failed(h, &id, ErrorCode::MissingProgram) || !h.kernel.lock().unwrap().attempts.is_empty()
    });
    assert!(failed(&harness, &id, ErrorCode::MissingProgram));
    assert!(harness.kernel.lock().unwrap().attempts.is_empty());
    assert_eq!(harness.snapshot_states()[0].generation, 0);
    harness.finish();
}

#[test]
fn default_ssl_still_works() {
    let mut harness = Harness::new(vec![profile("one")], 64);
    connect(&mut harness, "one", 1, ssl_credentials());
    harness.started("one", 1);
    harness.control("one", 1, |control| {
        control.ready = true;
        control.responsive = true;
    });
    harness.wait(|h| h.state("one", 1, ConnectionState::Connected));
    harness.control("one", 1, |control| control.cleanup_allowed = true);
    harness.finish();
}

#[test]
fn capability_factory_accepts_valid_ipsec() {
    let (mut harness, _) = capability_harness(vec![ipsec_profile("one")], false, true);
    let id = connect(&mut harness, "one", 1, ipsec_credentials());
    harness.wait(|h| {
        h.kernel
            .lock()
            .unwrap()
            .attempts
            .contains_key(&("one".into(), 1))
            || failed(h, &id, ErrorCode::MissingProgram)
    });
    assert!(!failed(&harness, &id, ErrorCode::MissingProgram));
    harness.started("one", 1);
    harness.control("one", 1, |control| {
        control.ready = true;
        control.hold_probe = true;
    });
    harness.wait(|h| h.state("one", 1, ConnectionState::Verifying));
    assert!(!harness.state("one", 1, ConnectionState::Connected));
    assert!(!harness.kernel.lock().unwrap().routes.is_empty());
    harness.control("one", 1, |control| {
        control.hold_probe = false;
        control.responsive = true;
    });
    harness.wait(|h| h.state("one", 1, ConnectionState::Connected));
    harness.control("one", 1, |control| control.cleanup_allowed = true);
    harness.finish();
    assert!(harness.kernel.lock().unwrap().routes.is_empty());
}

#[test]
fn ipsec_missing_psk_is_invalid_secret() {
    let (mut harness, _) = capability_harness(vec![ipsec_profile("one")], false, true);
    let credentials = Credentials {
        password: Secret::from("fixture-password"),
        psk: Secret::from(""),
    };
    let id = connect(&mut harness, "one", 1, credentials);
    harness.wait(|h| {
        failed(h, &id, ErrorCode::InvalidSecret) || !h.kernel.lock().unwrap().attempts.is_empty()
    });
    assert!(failed(&harness, &id, ErrorCode::InvalidSecret));
    assert!(harness.kernel.lock().unwrap().attempts.is_empty());
    assert_eq!(harness.snapshot_states()[0].generation, 0);
    harness.finish();
}

#[test]
fn factory_denying_ssl_is_missing_program() {
    let (mut harness, _) = capability_harness(vec![profile("one")], false, false);
    let id = connect(&mut harness, "one", 1, ssl_credentials());
    harness.wait(|h| {
        failed(h, &id, ErrorCode::MissingProgram) || !h.kernel.lock().unwrap().attempts.is_empty()
    });
    assert!(failed(&harness, &id, ErrorCode::MissingProgram));
    assert!(harness.kernel.lock().unwrap().attempts.is_empty());
    harness.finish();
}

#[test]
fn revocation_keeps_active_generation_and_route() {
    let (mut harness, ssl) = capability_harness(vec![profile("one")], true, false);
    connect(&mut harness, "one", 1, ssl_credentials());
    harness.started("one", 1);
    harness.control("one", 1, |control| {
        control.ready = true;
        control.responsive = true;
    });
    harness.wait(|h| h.state("one", 1, ConnectionState::Connected));
    assert!(!harness.kernel.lock().unwrap().routes.is_empty());
    ssl.store(false, Ordering::Release);
    let id = connect(&mut harness, "one", 2, ssl_credentials());
    harness.wait(|h| {
        failed(h, &id, ErrorCode::MissingProgram)
            || h.kernel.lock().unwrap().attempts.len() > 1
            || h.kernel.lock().unwrap().routes.is_empty()
    });
    assert!(failed(&harness, &id, ErrorCode::MissingProgram));
    // A revoked replacement must not cancel the active generation or release
    // its owned route; give a wrong implementation time to do so.
    thread::sleep(Duration::from_millis(50));
    assert!(harness.state("one", 1, ConnectionState::Connected));
    assert!(!harness.state("one", 2, ConnectionState::Connecting));
    assert_eq!(harness.kernel.lock().unwrap().attempts.len(), 1);
    assert!(!harness.kernel.lock().unwrap().routes.is_empty());
    let states = harness.snapshot_states();
    assert!(states.iter().any(|status| status.id == "one"
        && status.generation == 1
        && status.state == ConnectionState::Connected));
    harness.control("one", 1, |control| control.cleanup_allowed = true);
    harness.finish();
    assert!(harness.kernel.lock().unwrap().routes.is_empty());
}
