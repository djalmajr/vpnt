//! Focused tests for the adapter. Every send goes through the production
//! [`kernel::send`] driver and the real [`Decision`] kernel; only the native
//! `Channel` is replaced by a recording fake. Nothing here requests permission,
//! reads notification settings or delivers anything to the OS.

use super::kernel::{self, Callback, Channel, Decision, Handle, Shared, Status, Step};
use super::{Adapter, MAX_BODY, MAX_ID, MAX_TITLE, bounded, supported_bundle};
use crate::notifications::{Notice, Notifier};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Scripted answer for one authorization status plus a call log.
struct Config {
    status: Status,
    granted: bool,
    duplicate: usize,
    defer_authorize: bool,
    revoke_during_authorize: Option<Arc<AtomicBool>>,
}

#[derive(Default)]
struct Log {
    settings: usize,
    authorize: usize,
    delivered: Vec<(String, String, String)>,
}

#[derive(Clone)]
pub(crate) struct FakeService {
    config: Arc<Config>,
    log: Arc<Mutex<Log>>,
    /// Authorization answer held back to model the real async round trip.
    pending: Arc<Mutex<Option<Callback<bool>>>>,
}

impl FakeService {
    pub(super) fn new(status: Status) -> Self {
        Self {
            config: Arc::new(Config {
                status,
                granted: false,
                duplicate: 0,
                defer_authorize: false,
                revoke_during_authorize: None,
            }),
            log: Arc::new(Mutex::new(Log::default())),
            pending: Arc::new(Mutex::new(None)),
        }
    }

    /// Replace the scripted config, keeping the shared log.
    fn with(&self, apply: impl FnOnce(&mut Config)) -> Self {
        let mut config = Config {
            status: self.config.status,
            granted: self.config.granted,
            duplicate: self.config.duplicate,
            defer_authorize: self.config.defer_authorize,
            revoke_during_authorize: self.config.revoke_during_authorize.clone(),
        };
        apply(&mut config);
        Self {
            config: Arc::new(config),
            log: self.log.clone(),
            pending: self.pending.clone(),
        }
    }

    fn granting(&self) -> Self {
        self.with(|config| config.granted = true)
    }

    /// Invoke every reported callback this many extra times.
    fn duplicate_callbacks(&self, extra: usize) -> Self {
        self.with(|config| config.duplicate = extra)
    }

    /// Hold the authorization answer until [`FakeService::complete_authorization`],
    /// so another settings callback can arrive while the request is in flight.
    fn defer_authorize(&self) -> Self {
        self.with(|config| config.defer_authorize = true)
    }

    fn complete_authorization(&self) {
        let callback = self.pending.lock().unwrap().take();
        if let Some(mut done) = callback {
            if self.config.duplicate > 0 {
                done(self.config.granted);
            }
            done(self.config.granted);
        }
    }

    /// Revoke the caller's token while the authorization request is in flight.
    fn revoke_during_authorize(&self, token: Arc<AtomicBool>) -> Self {
        self.with(|config| config.revoke_during_authorize = Some(token))
    }

    pub(super) fn handle(&self) -> Handle {
        Arc::new(self.clone())
    }

    fn settings_calls(&self) -> usize {
        self.log.lock().unwrap().settings
    }

    fn authorize_calls(&self) -> usize {
        self.log.lock().unwrap().authorize
    }

    fn delivered(&self) -> Vec<(String, String, String)> {
        self.log.lock().unwrap().delivered.clone()
    }

    fn delivered_ids(&self) -> Vec<String> {
        self.delivered().into_iter().map(|(id, _, _)| id).collect()
    }
}

impl Channel for FakeService {
    fn settings(&self, mut done: Callback<Status>) {
        self.log.lock().unwrap().settings += 1;
        for _ in 0..=self.config.duplicate {
            done(self.config.status);
        }
    }

    fn authorize(&self, mut done: Callback<bool>) {
        self.log.lock().unwrap().authorize += 1;
        if let Some(token) = &self.config.revoke_during_authorize {
            token.store(false, Ordering::Release);
        }
        if self.config.defer_authorize {
            *self.pending.lock().unwrap() = Some(done);
            return;
        }
        for _ in 0..=self.config.duplicate {
            done(self.config.granted);
        }
    }

    fn deliver(&self, notice: Notice) {
        self.log
            .lock()
            .unwrap()
            .delivered
            .push((notice.id, notice.title, notice.body));
    }
}

fn token(live: bool) -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(live))
}

fn sample() -> Notice {
    Notice {
        id: "episode-7".to_string(),
        title: "Connection lost".to_string(),
        body: "The tunnel stopped responding.".to_string(),
        current: token(true),
    }
}

fn adapter(fake: &FakeService) -> Adapter {
    Adapter::for_test(true, fake.clone())
}

#[test]
fn denied_settings_never_request_or_deliver() {
    let fake = FakeService::new(Status::Denied);
    adapter(&fake).send(sample());
    assert_eq!(fake.settings_calls(), 1);
    assert_eq!(fake.authorize_calls(), 0);
    assert!(fake.delivered().is_empty());
}

#[test]
fn unsupported_settings_never_request_or_deliver() {
    let fake = FakeService::new(Status::Unsupported);
    adapter(&fake).send(sample());
    assert_eq!(fake.authorize_calls(), 0);
    assert!(fake.delivered().is_empty());
}

#[test]
fn not_determined_requests_once_then_delivers_once() {
    let fake = FakeService::new(Status::NotDetermined).granting();
    adapter(&fake).send(sample());
    assert_eq!(fake.settings_calls(), 1);
    assert_eq!(fake.authorize_calls(), 1);
    assert_eq!(fake.delivered_ids(), vec!["episode-7".to_string()]);
}

#[test]
fn authorized_settings_deliver_without_requesting() {
    let fake = FakeService::new(Status::Authorized);
    adapter(&fake).send(sample());
    assert_eq!(fake.authorize_calls(), 0);
    assert_eq!(fake.delivered_ids(), vec!["episode-7".to_string()]);
}

#[test]
fn declined_authorization_delivers_nothing() {
    let fake = FakeService::new(Status::NotDetermined);
    adapter(&fake).send(sample());
    assert_eq!(fake.authorize_calls(), 1);
    assert!(fake.delivered().is_empty());
}

#[test]
fn revoked_before_send_touches_no_service() {
    let fake = FakeService::new(Status::NotDetermined).granting();
    let mut notice = sample();
    notice.current = token(false);
    adapter(&fake).send(notice);
    assert_eq!(fake.settings_calls(), 0);
    assert_eq!(fake.authorize_calls(), 0);
    assert!(fake.delivered().is_empty());
}

#[test]
fn revoked_before_the_authorization_request_is_not_requested() {
    let live = token(true);
    let fake = FakeService::new(Status::NotDetermined).granting();
    let mut decision = Decision::new(notice_with_token(live.clone()));
    assert_eq!(decision.on_settings(Status::NotDetermined), Step::Request);
    let state: Shared = Arc::new(Mutex::new(decision));
    // Revoked between the settings answer and the request itself.
    live.store(false, Ordering::Release);
    kernel::authorize(state, fake.handle());
    assert_eq!(fake.authorize_calls(), 0);
    assert!(fake.delivered().is_empty());
}

#[test]
fn revoked_while_authorization_pending_does_not_deliver() {
    let live = token(true);
    let fake = FakeService::new(Status::NotDetermined)
        .granting()
        .revoke_during_authorize(live.clone());
    let mut notice = sample();
    notice.current = live;
    adapter(&fake).send(notice);
    assert_eq!(fake.authorize_calls(), 1);
    assert!(fake.delivered().is_empty());
}

#[test]
fn revoked_between_decision_and_delivery_yields_no_notice() {
    let live = token(true);
    let mut decision = Decision::new(notice_with_token(live.clone()));
    assert_eq!(decision.on_settings(Status::Authorized), Step::Deliver);
    live.store(false, Ordering::Release);
    assert!(decision.take_notice().is_none());
}

#[test]
fn stale_token_at_settings_drops_before_requesting() {
    let live = token(true);
    let mut decision = Decision::new(notice_with_token(live.clone()));
    live.store(false, Ordering::Release);
    assert_eq!(decision.on_settings(Status::NotDetermined), Step::Drop);
}

#[test]
fn duplicate_settings_callback_requests_and_delivers_once() {
    let fake = FakeService::new(Status::NotDetermined)
        .granting()
        .duplicate_callbacks(1);
    adapter(&fake).send(sample());
    assert_eq!(fake.settings_calls(), 1);
    assert_eq!(fake.authorize_calls(), 1);
    assert_eq!(fake.delivered().len(), 1);
}

#[test]
fn duplicate_settings_callback_while_authorization_pending_requests_once() {
    let fake = FakeService::new(Status::NotDetermined)
        .granting()
        .duplicate_callbacks(1)
        .defer_authorize();
    adapter(&fake).send(sample());
    assert_eq!(fake.settings_calls(), 1);
    assert_eq!(fake.authorize_calls(), 1);
    assert!(fake.delivered().is_empty());
    fake.complete_authorization();
    assert_eq!(fake.delivered_ids(), vec!["episode-7".to_string()]);
}

#[test]
fn duplicate_authorization_callback_delivers_once() {
    let fake = FakeService::new(Status::NotDetermined)
        .granting()
        .duplicate_callbacks(1);
    adapter(&fake).send(sample());
    assert_eq!(fake.delivered().len(), 1);
}

#[test]
fn unavailable_adapter_never_touches_the_service() {
    let fake = FakeService::new(Status::Authorized);
    Adapter::for_test(false, fake.clone()).send(sample());
    assert_eq!(fake.settings_calls(), 0);
    assert_eq!(fake.authorize_calls(), 0);
    assert!(fake.delivered().is_empty());
}

#[test]
fn empty_fields_are_rejected_before_the_service() {
    let mutations: [fn(&mut Notice); 3] = [
        |notice: &mut Notice| notice.id.clear(),
        |notice: &mut Notice| notice.title.clear(),
        |notice: &mut Notice| notice.body.clear(),
    ];
    for mutate in mutations {
        let fake = FakeService::new(Status::Authorized);
        let mut notice = sample();
        mutate(&mut notice);
        adapter(&fake).send(notice);
        assert_eq!(fake.settings_calls(), 0);
        assert!(fake.delivered().is_empty());
    }
}

#[test]
fn oversized_fields_are_rejected_before_the_service() {
    let long = "x".repeat(MAX_BODY + 1);
    let mut notice = sample();
    notice.body = long;
    let fake = FakeService::new(Status::Authorized);
    adapter(&fake).send(notice);
    assert_eq!(fake.settings_calls(), 0);

    let mut notice = sample();
    notice.id = "i".repeat(MAX_ID + 1);
    let fake = FakeService::new(Status::Authorized);
    adapter(&fake).send(notice);
    assert_eq!(fake.settings_calls(), 0);

    let mut notice = sample();
    notice.title = "t".repeat(MAX_TITLE + 1);
    let fake = FakeService::new(Status::Authorized);
    adapter(&fake).send(notice);
    assert_eq!(fake.settings_calls(), 0);
}

#[test]
fn exact_limits_are_accepted_and_payload_is_preserved() {
    let mut notice = sample();
    notice.id = "i".repeat(MAX_ID);
    notice.title = "t".repeat(MAX_TITLE);
    notice.body = "b".repeat(MAX_BODY);
    let expected = (notice.id.clone(), notice.title.clone(), notice.body.clone());
    let fake = FakeService::new(Status::Authorized);
    adapter(&fake).send(notice);
    assert_eq!(fake.delivered(), vec![expected]);
}

#[test]
fn bundle_gate_admits_only_the_application_bundle() {
    assert!(supported_bundle(Some(super::BUNDLE_ID)));
    assert!(!supported_bundle(None));
    assert!(!supported_bundle(Some("dev.vpnt.app.preview")));
    assert!(!supported_bundle(Some("com.apple.dt.XCTest.tool")));
}

#[test]
fn bounded_is_pure_and_rejects_the_same_values_the_adapter_drops() {
    assert!(bounded(sample()).is_some());
    let mut empty = sample();
    empty.id.clear();
    assert!(bounded(empty).is_none());
}

/// The test binary is not the application bundle, so construction reports
/// unavailable and must not read settings, request authorization or deliver.
/// This is the only place the real `NSBundle` is consulted.
#[test]
fn current_bundle_is_unavailable_outside_the_application() {
    assert!(Adapter::current_bundle().is_none());
}

#[test]
fn kernel_send_is_reachable_directly() {
    let fake = FakeService::new(Status::Authorized);
    kernel::send(sample(), fake.handle());
    assert_eq!(fake.delivered_ids(), vec!["episode-7".to_string()]);
}

fn notice_with_token(current: Arc<AtomicBool>) -> Notice {
    Notice {
        current,
        ..sample()
    }
}
