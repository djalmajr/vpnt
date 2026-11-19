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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
