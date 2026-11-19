use super::*;
use std::{
    sync::{
        atomic::AtomicUsize,
        mpsc::{self, Receiver, Sender},
    },
    thread,
};

struct FixtureRuntime {
    polls: Arc<AtomicUsize>,
    started: Sender<(u64, Locale)>,
    completions: Receiver<(u64, ResultSnapshot)>,
    stopped: Sender<()>,
}
impl Drop for FixtureRuntime {
    fn drop(&mut self) {
        let _ = self.stopped.send(());
    }
}
impl Runtime for FixtureRuntime {
    fn poll(&mut self) {
        self.polls.fetch_add(1, Ordering::Relaxed);
    }

    fn take_admin_result(&mut self) -> Option<(u64, ResultSnapshot)> {
        self.completions.try_recv().ok()
    }

    fn take_component_result(&mut self) -> Option<(u64, ResultSnapshot)> {
        None
    }

    fn observe_request(&mut self, _: &Request) {}

    fn starting(&self) -> bool {
        false
    }

    fn begin_change(
        &mut self,
        command: Command,
        locale: Locale,
        _: Instant,
    ) -> Result<u64, &'static str> {
        let Command::RemoveProfile { id } = command else {
            return Err("invalid_request");
        };
        let token = match id.as_str() {
            "one" => 7,
            "two" => 8,
            _ => return Err("invalid_request"),
        };
        self.started.send((token, locale)).unwrap();
        Ok(token)
    }

    fn dispatch(&mut self, command: Command, _: Instant) -> ResultSnapshot {
        assert!(matches!(
            command,
            Command::GetSnapshot {} | Command::Disconnect { .. }
        ));
        Ok(snapshot())
    }

    fn perform_automatic(&mut self, _: impl Fn() -> bool) {}
}

fn snapshot() -> Snapshot {
    Snapshot {
        demo: false,
        helper: "installed",
        ..App::demo().snapshot()
    }
}

struct Fixture {
    actor: Option<Actor>,
    replies: Receiver<Reply>,
    started: Receiver<(u64, Locale)>,
    completions: Sender<(u64, ResultSnapshot)>,
    stopped: Receiver<()>,
    polls: Arc<AtomicUsize>,
}
impl Fixture {
    fn new() -> Self {
        let (started, begins) = mpsc::channel();
        let (complete, completions) = mpsc::channel();
        let (stop, stopped) = mpsc::channel();
        let (reply, replies) = mpsc::channel();
        let polls = Arc::new(AtomicUsize::new(0));
        let runtime = FixtureRuntime {
            polls: polls.clone(),
            started,
            completions,
            stopped: stop,
        };
        let actor = Actor::spawn_with(
            move || (None, Some(runtime)),
            move |response| {
                let _ = reply.send(response);
            },
        )
        .unwrap();
        Self {
            actor: Some(actor),
            replies,
            started: begins,
            completions: complete,
            stopped,
            polls,
        }
    }

    fn send(&self, id: &str, command: Command) {
        let actor = self.actor.as_ref().unwrap();
        actor
            .send(
                Request {
                    id: id.into(),
                    command,
                    locale: Some(Locale::PtBr),
                },
                Instant::now(),
            )
            .unwrap();
    }

    fn reply(&self) -> Reply {
        self.replies.recv_timeout(Duration::from_secs(2)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.actor.take());
        let _ = self.stopped.recv_timeout(Duration::from_secs(2));
    }
}

#[test]
fn actor_polls_without_requests_and_replies_to_get_snapshot() {
    let fixture = Fixture::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while fixture.polls.load(Ordering::Relaxed) < 3 {
        assert!(Instant::now() < deadline, "actor did not poll while idle");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        fixture
            .actor
            .as_ref()
            .unwrap()
            .idle_cycles
            .load(Ordering::Acquire)
            >= 2
    );
    fixture.send("snapshot", Command::GetSnapshot {});
    let reply = fixture.reply();
    assert_eq!(reply.id, "snapshot");
    assert!(reply.error.is_none());
    assert_eq!(reply.snapshot.unwrap().helper, "installed");
}

#[test]
fn actor_correlates_administrative_replies_by_token_out_of_order() {
    let fixture = Fixture::new();
    fixture.send("first-admin", Command::RemoveProfile { id: "one".into() });
    fixture.send("second-admin", Command::RemoveProfile { id: "two".into() });
    assert_eq!(
        fixture
            .started
            .recv_timeout(Duration::from_secs(2))
            .unwrap(),
        (7, Locale::PtBr)
    );
    assert_eq!(
        fixture
            .started
            .recv_timeout(Duration::from_secs(2))
            .unwrap(),
        (8, Locale::PtBr)
    );

    fixture.send("snapshot", Command::GetSnapshot {});
    assert_eq!(fixture.reply().id, "snapshot");
    fixture.completions.send((999, Ok(snapshot()))).unwrap();
    fixture.completions.send((8, Err("profile_busy"))).unwrap();
    fixture.completions.send((7, Ok(snapshot()))).unwrap();
    let second = fixture.reply();
    assert_eq!(second.id, "second-admin");
    assert_eq!(second.error.as_deref(), Some("profile_busy"));
    let first = fixture.reply();
    assert_eq!(first.id, "first-admin");
    assert!(first.snapshot.is_some());
}

#[test]
fn blocked_certificate_listing_does_not_block_actor() {
    let (started, _begins) = mpsc::channel();
    let (complete, completions) = mpsc::channel();
    let (stop, stopped) = mpsc::channel();
    let (reply, replies) = mpsc::channel();
    let (list_started, list_begins) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
    let polls = Arc::new(AtomicUsize::new(0));
    let runtime = FixtureRuntime {
        polls: polls.clone(),
        started,
        completions,
        stopped: stop,
    };
    let actor = Actor::spawn_with_listing(
        move || (None, Some(runtime)),
        move |r| {
            let _ = reply.send(r);
        },
        move |id, _| {
            let _ = list_started.send(());
            let _ = release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3));
            Reply::error(id, "token_unavailable")
        },
    )
    .unwrap();
    let send = |id: &str, command| {
        actor
            .send(
                Request {
                    id: id.into(),
                    command,
                    locale: None,
                },
                Instant::now(),
            )
            .unwrap()
    };
    send(
        "listing",
        Command::ListCertificates {
            module: "/fixture.so".into(),
        },
    );
    list_begins.recv_timeout(Duration::from_secs(2)).unwrap();
    let before = polls.load(Ordering::Relaxed);
    send("snapshot", Command::GetSnapshot {});
    send("disconnect", Command::Disconnect { id: "one".into() });
    send(
        "duplicate",
        Command::ListCertificates {
            module: "/fixture.so".into(),
        },
    );
    let a = replies.recv_timeout(Duration::from_millis(500));
    let b = replies.recv_timeout(Duration::from_millis(500));
    let duplicate = replies.recv_timeout(Duration::from_millis(500));
    let after = polls.load(Ordering::Relaxed);
    let _ = release.send(());
    let listing = replies.recv_timeout(Duration::from_secs(2));
    drop(actor);
    drop(complete);
    let _ = stopped.recv_timeout(Duration::from_secs(2));
    let ids = [a.unwrap().id, b.unwrap().id];
    assert_eq!(ids, ["snapshot", "disconnect"]);
    let duplicate = duplicate.unwrap();
    assert_eq!(duplicate.id, "duplicate");
    assert_eq!(duplicate.error.as_deref(), Some("token_unavailable"));
    assert!(after > before, "poll must continue during listing");
    assert_eq!(listing.unwrap().id, "listing");
}

#[test]
fn actor_listing_reports_an_untrusted_module_distinctly() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("vpnt-actor-module-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let module = dir.join("token.so");
    std::fs::write(&module, b"not a library").unwrap();
    std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o664)).unwrap();
    let reply = super::list_certificates("one".into(), module.to_string_lossy().into_owned());
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(reply.id, "one");
    assert_eq!(reply.error.as_deref(), Some("untrusted_module"));
    assert!(reply.certificates.is_none());
}

#[test]
fn the_production_listing_deadline_is_thirty_seconds() {
    // The injectable deadline is a test seam: production keeps 30 s.
    assert_eq!(LISTING_TIMEOUT, Duration::from_secs(30));
}

#[test]
fn a_listing_that_misses_its_deadline_reports_once_and_discards_the_late_answer() {
    let (reply, replies) = mpsc::channel();
    let (started, begins) = mpsc::channel();
    let (release, release_rx) = mpsc::channel::<()>();
    let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
    let calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = calls.clone();
    let actor = Actor::spawn_with_listing_timeout::<FixtureRuntime>(
        || (None, None),
        move |r| {
            let _ = reply.send(r);
        },
        move |id, _| {
            if provider_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                let _ = started.send(());
                let _ = release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5));
                Reply::error(id, "late_answer")
            } else {
                Reply {
                    id,
                    ..Reply::default()
                }
            }
        },
        Duration::from_millis(100),
    )
    .unwrap();
    let list = |id: &str| {
        actor
            .send(
                Request {
                    id: id.into(),
                    locale: None,
                    command: Command::ListCertificates {
                        module: "/fixture.so".into(),
                    },
                },
                Instant::now(),
            )
            .unwrap()
    };
    list("listing");
    begins.recv_timeout(Duration::from_secs(2)).unwrap();
    let timed_out = replies.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(timed_out.id, "listing");
    assert_eq!(timed_out.error.as_deref(), Some("token_unavailable"));
    // The exclusion holds until the provider returns.
    list("busy");
    let busy = replies.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(busy.id, "busy");
    assert_eq!(busy.error.as_deref(), Some("token_unavailable"));
    release.send(()).unwrap();
    let mut accepted = None;
    for attempt in 0..100 {
        thread::sleep(Duration::from_millis(20));
        assert!(
            replies.try_recv().is_err(),
            "the late answer must never reach the webview"
        );
        list(&format!("after-{attempt}"));
        let response = replies.recv_timeout(Duration::from_secs(2)).unwrap();
        if response.error.is_none() {
            accepted = Some(response);
            break;
        }
        assert_eq!(response.error.as_deref(), Some("token_unavailable"));
    }
    let accepted = accepted.expect("the slot must be free once the provider returns");
    assert!(accepted.id.starts_with("after-"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(actor);
}

#[test]
fn a_listing_reply_carries_hex_ids_and_optional_metadata() {
    use crate::connection::ovpn::pkcs11::CertificateInfo;
    let view = certificate_view(CertificateInfo {
        id: vec![0x00, 0x0a, 0xff],
        subject: Some("subject".into()),
        issuer: None,
        not_before: Some("Oct  1 00:00:00 2026 GMT".into()),
        not_after: None,
    });
    assert_eq!(view.id, "000aff");
    assert_eq!(view.subject.as_deref(), Some("subject"));
    assert_eq!(view.issuer, None);
    assert_eq!(view.not_before.as_deref(), Some("Oct  1 00:00:00 2026 GMT"));
    assert_eq!(view.not_after, None);

    let other = certificate_view(CertificateInfo {
        id: vec![0x01, 0x10],
        subject: None,
        issuer: Some("issuer".into()),
        not_before: None,
        not_after: Some("Nov  1 00:00:00 2026 GMT".into()),
    });
    assert_eq!(other.id, "0110");
    assert_eq!(other.subject, None);
    assert_eq!(other.issuer.as_deref(), Some("issuer"));
    assert_eq!(other.not_before, None);
    assert_eq!(other.not_after.as_deref(), Some("Nov  1 00:00:00 2026 GMT"));
}

#[test]
fn an_invalid_module_is_refused_while_another_listing_holds_the_slot() {
    let (reply, replies) = mpsc::channel();
    let (started, begins) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
    let actor = Actor::spawn_with_listing::<FixtureRuntime>(
        || (None, None),
        move |r| {
            let _ = reply.send(r);
        },
        move |id, _| {
            let _ = started.send(());
            let _ = release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5));
            Reply::error(id, "token_unavailable")
        },
    )
    .unwrap();
    let list = |id: &str, module: &str| {
        actor
            .send(
                Request {
                    id: id.into(),
                    locale: None,
                    command: Command::ListCertificates {
                        module: module.into(),
                    },
                },
                Instant::now(),
            )
            .unwrap()
    };
    list("busy", "/fixture.so");
    begins.recv_timeout(Duration::from_secs(2)).unwrap();
    list("invalid", "relative.so");
    let refused = replies.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(refused.id, "invalid");
    assert_eq!(refused.error.as_deref(), Some("invalid_module"));
    // The busy listing still owns the slot and answers only after the release.
    release.send(()).unwrap();
    let busy = replies.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(busy.id, "busy");
    assert_eq!(busy.error.as_deref(), Some("token_unavailable"));
    drop(actor);
}
