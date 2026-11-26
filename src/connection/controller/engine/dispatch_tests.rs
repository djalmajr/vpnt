//! Focused dispatch tests for the controller-wide probe cadence preference.
//! The factory never creates an attempt here: these tests exercise the slot
//! bookkeeping that a later launch reads.
use super::dispatch::dispatch_with_diagnostics;
use super::*;
use crate::{diagnostic_sink::Memory, preferences::ProbeInterval};

struct InertAttempt;
impl Attempt for InertAttempt {
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        Ok(true)
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        Ok(())
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        Ok(true)
    }
    fn cleanup(&mut self) -> bool {
        true
    }
}

struct InertFactory;
impl Factory for InertFactory {
    type Attempt = InertAttempt;
    fn create(
        &self,
        _: Profile,
        _: u32,
        _: u64,
        _: Credentials,
        _: Arc<AtomicBool>,
    ) -> Self::Attempt {
        InertAttempt
    }
    fn idle(&self) -> bool {
        true
    }
}

fn profile(id: &str) -> Profile {
    serde_json::from_value(serde_json::json!({"id":id,"name":id,"kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap()
}

fn slot<'scope>(id: &str, interval: u64) -> Slot<'scope> {
    Slot {
        profile: profile(id),
        generation: 0,
        state: ConnectionState::Off,
        failures: 0,
        cleaning: false,
        failure: None,
        interval: ProbeClock::new(Duration::from_secs(interval)),
        worker: None,
        pending: None,
    }
}

fn credentials() -> Credentials {
    Credentials {
        password: "fictional".into(),
        psk: "".into(),
    }
}

#[test]
fn dispatch_diagnostics_record_slot_and_generation_rejections_and_disconnects() {
    let interval = ProbeClock::new(Duration::from_secs(10));
    thread::scope(|scope| {
        let canceled = Arc::new(AtomicBool::new(false));
        let mut live = slot("one", 10);
        live.generation = 2;
        live.state = ConnectionState::Connected;
        live.worker = Some(Worker {
            generation: 2,
            request: "connect".into(),
            signals: Signals {
                canceled: canceled.clone(),
                probe: Arc::default(),
                state: Arc::default(),
                exit: Arc::new(ExitRequested::new(Duration::from_secs(1))),
            },
            thread: scope.spawn(|| Finished {
                state: ConnectionState::Off,
                error: None,
                step: None,
            }),
        });
        let mut slots = BTreeMap::from([("one".into(), live)]);
        let mut output = VecDeque::new();
        let mut diagnostics = Vec::new();
        let mut run = |command| {
            dispatch_with_diagnostics(
                Request {
                    id: "request".into(),
                    command,
                },
                &InertFactory,
                &mut slots,
                &mut output,
                &interval,
                false,
                false,
                &mut Memory(&mut diagnostics),
            );
            std::mem::take(&mut output)
        };
        for (id, error) in [
            ("missing", ErrorCode::ProfileNotFound),
            ("one", ErrorCode::InvalidRequest),
        ] {
            for command in [
                Command::Connect {
                    id: id.into(),
                    generation: 1,
                    interval: ProbeInterval::TEN,
                    credentials: credentials(),
                },
                Command::Disconnect {
                    id: id.into(),
                    generation: 1,
                },
                Command::Probe {
                    id: id.into(),
                    generation: 1,
                },
            ] {
                let messages = run(command);
                assert!(
                    matches!(messages.front(), Some(Message::Failed { id, error: code }) if id == "request" && *code == error)
                );
                assert_eq!(messages.len(), 1);
            }
        }
        assert!(!canceled.load(Ordering::Acquire));
        let messages = run(Command::Disconnect {
            id: "one".into(),
            generation: 3,
        });
        assert!(matches!(messages.front(), Some(Message::Accepted { id }) if id == "request"));
        assert!(matches!(
            messages.get(1),
            Some(Message::Changed {
                generation: 3,
                state: ConnectionState::Disconnecting,
                ..
            })
        ));
        assert!(canceled.load(Ordering::Acquire));
        slots
            .get_mut("one")
            .unwrap()
            .worker
            .take()
            .unwrap()
            .thread
            .join()
            .unwrap();
        dispatch_with_diagnostics(
            Request {
                id: "request".into(),
                command: Command::Disconnect {
                    id: "one".into(),
                    generation: 4,
                },
            },
            &InertFactory,
            &mut slots,
            &mut output,
            &interval,
            false,
            false,
            &mut Memory(&mut diagnostics),
        );
        assert!(matches!(
            output.get(1),
            Some(Message::Changed {
                generation: 4,
                state: ConnectionState::Off,
                ..
            })
        ));
        assert_eq!(
            std::str::from_utf8(&diagnostics).unwrap(),
            concat!(
                "vpnt-helper: engine: command=connect event=failed id=missing generation=1 slot_generation=none error=ProfileNotFound\n",
                "vpnt-helper: engine: command=disconnect event=failed id=missing generation=1 slot_generation=none error=ProfileNotFound\n",
                "vpnt-helper: engine: command=probe event=failed id=missing generation=1 slot_generation=none error=ProfileNotFound\n",
                "vpnt-helper: engine: command=connect event=failed id=one generation=1 slot_generation=2 error=InvalidRequest\n",
                "vpnt-helper: engine: command=disconnect event=failed id=one generation=1 slot_generation=2 error=InvalidRequest\n",
                "vpnt-helper: engine: command=probe event=failed id=one generation=1 slot_generation=2 error=InvalidRequest\n",
                "vpnt-helper: engine: command=disconnect event=accepted id=one generation=3 worker=true\n",
                "vpnt-helper: engine: command=disconnect event=accepted id=one generation=4 worker=false\n",
            )
        );
    });
}

#[test]
fn set_probe_interval_replaces_the_default_and_every_slot_clock_and_accepts() {
    let default = ProbeClock::new(Duration::from_secs(10));
    let mut slots = BTreeMap::from([
        ("one".into(), slot("one", 30)),
        ("two".into(), slot("two", 10)),
    ]);
    // A launched worker holds a clone of its slot clock; the preference must
    // reach it in place, not through a new clock.
    let live = slots["two"].interval.clone();
    let mut outgoing = VecDeque::new();
    dispatch(
        Request {
            id: "one".into(),
            command: Command::SetProbeInterval {
                interval: ProbeInterval::SIXTY,
            },
        },
        &InertFactory,
        &mut slots,
        &mut outgoing,
        &default,
        false,
        false,
    );
    assert_eq!(default.get(), Duration::from_secs(60));
    assert_eq!(slots["one"].interval.get(), Duration::from_secs(60));
    assert_eq!(
        slots["two"].interval.get(),
        Duration::from_secs(60),
        "every slot clock must follow the preference"
    );
    assert_eq!(
        live.get(),
        Duration::from_secs(60),
        "a cloned live-worker clock is updated in place"
    );
    // A cadence preference carries no connection authority: the slot is idle
    // and no state message is fabricated.
    assert_eq!(slots["one"].state, ConnectionState::Off);
    assert_eq!(slots["one"].generation, 0);
    assert_eq!(outgoing.len(), 1);
    assert!(matches!(
        outgoing.front(),
        Some(Message::Accepted { id }) if id == "one"
    ));
}

#[test]
fn connect_carries_its_generation_interval_and_resets_a_failure_streak() {
    let default = ProbeClock::new(Duration::from_secs(10));
    let mut slots = BTreeMap::from([("one".into(), slot("one", 10))]);
    slots.get_mut("one").unwrap().failures = 3;
    slots.get_mut("one").unwrap().state = ConnectionState::Unresponsive;
    let mut outgoing = VecDeque::new();
    dispatch(
        Request {
            id: "one".into(),
            command: Command::Connect {
                id: "one".into(),
                generation: 1,
                interval: ProbeInterval::THIRTY,
                credentials: credentials(),
            },
        },
        &InertFactory,
        &mut slots,
        &mut outgoing,
        &default,
        false,
        false,
    );
    assert_eq!(slots["one"].generation, 1);
    assert_eq!(slots["one"].state, ConnectionState::Connecting);
    assert_eq!(slots["one"].failures, 0);
    assert_eq!(slots["one"].interval.get(), Duration::from_secs(30));
    assert!(slots["one"].pending.is_some());
    // Connect's own interval does not rewrite the controller default.
    assert_eq!(default.get(), Duration::from_secs(10));
    assert!(matches!(
        outgoing.front(),
        Some(Message::Accepted { id }) if id == "one"
    ));
    assert!(matches!(
        outgoing.get(1),
        Some(Message::Changed {
            generation: 1,
            state: ConnectionState::Connecting,
            failures: 0,
            cleaning: false,
            ..
        })
    ));
}

#[test]
fn production_default_probe_cadence_is_ten_seconds() {
    // The controller default seeds every non-Connect clock; the pre-preference
    // production value was 30 s.
    assert_eq!(Timing::default().interval, Duration::from_secs(10));
}

struct BlockedFactory(AtomicBool);
impl Factory for BlockedFactory {
    type Attempt = InertAttempt;
    fn create(
        &self,
        _: Profile,
        _: u32,
        _: u64,
        _: Credentials,
        _: Arc<AtomicBool>,
    ) -> Self::Attempt {
        InertAttempt
    }
    fn idle(&self) -> bool {
        true
    }
    fn cleanup_blocked(&self, profile: &Profile) -> bool {
        profile.id == "one" && self.0.load(Ordering::SeqCst)
    }
    fn verify_cleanup(&self, profile: &Profile) -> bool {
        if profile.id == "one" {
            self.0.store(false, Ordering::SeqCst);
        }
        true
    }
}

#[test]
fn cleanup_verification_refuses_a_profile_with_queued_connection() {
    let factory = BlockedFactory(AtomicBool::new(false));
    let mut slots = BTreeMap::from([("one".into(), slot("one", 10))]);
    let mut out = VecDeque::new();
    let interval = ProbeClock::new(Duration::from_secs(10));
    dispatch(
        Request {
            id: "connect".into(),
            command: Command::Connect {
                id: "one".into(),
                generation: 1,
                interval: ProbeInterval::TEN,
                credentials: credentials(),
            },
        },
        &factory,
        &mut slots,
        &mut out,
        &interval,
        true,
        false,
    );
    assert!(slots["one"].pending.is_some());
    out.clear();
    factory.0.store(true, Ordering::SeqCst);
    dispatch(
        Request {
            id: "verify".into(),
            command: Command::VerifyCleanup {
                profile: "one".into(),
            },
        },
        &factory,
        &mut slots,
        &mut out,
        &interval,
        true,
        false,
    );
    assert!(matches!(
        out.pop_front(),
        Some(Message::Failed {
            error: ErrorCode::ProfileBusy,
            ..
        })
    ));
    assert!(
        factory.0.load(Ordering::SeqCst),
        "verification must not run while the profile is queued"
    );
    slots.get_mut("one").unwrap().pending = None;
    dispatch(
        Request {
            id: "verify-idle".into(),
            command: Command::VerifyCleanup {
                profile: "one".into(),
            },
        },
        &factory,
        &mut slots,
        &mut out,
        &interval,
        true,
        false,
    );
    assert!(matches!(out.pop_front(), Some(Message::Snapshot { .. })));
    assert!(!factory.0.load(Ordering::SeqCst));
}

#[test]
fn cleanup_capability_preserves_legacy_snapshot_and_guards_connect() {
    let factory = BlockedFactory(AtomicBool::new(true));
    let mut slots = BTreeMap::from([
        ("one".into(), slot("one", 10)),
        ("two".into(), slot("two", 10)),
    ]);
    let mut out = VecDeque::new();
    let interval = ProbeClock::new(Duration::from_secs(10));
    for (capable, expected) in [
        (false, ConnectionState::Off),
        (true, ConnectionState::CleanupUnconfirmed),
    ] {
        dispatch(
            Request {
                id: "snapshot".into(),
                command: Command::Snapshot {},
            },
            &factory,
            &mut slots,
            &mut out,
            &interval,
            capable,
            false,
        );
        let Some(Message::Snapshot { connections, .. }) = out.pop_front() else {
            panic!("snapshot expected")
        };
        assert_eq!(
            connections.iter().find(|c| c.id == "one").unwrap().state,
            expected
        );
    }
    let connect = |id: &str| Request {
        id: id.into(),
        command: Command::Connect {
            id: id.into(),
            generation: 1,
            interval: ProbeInterval::THIRTY,
            credentials: credentials(),
        },
    };
    dispatch(
        connect("one"),
        &factory,
        &mut slots,
        &mut out,
        &interval,
        true,
        false,
    );
    assert!(matches!(
        out.pop_front(),
        Some(Message::Failed {
            error: ErrorCode::ProfileBusy,
            ..
        })
    ));
    assert!(slots["one"].pending.is_none());
    dispatch(
        connect("two"),
        &factory,
        &mut slots,
        &mut out,
        &interval,
        true,
        false,
    );
    assert!(matches!(out.pop_front(), Some(Message::Accepted { .. })));
    out.clear();
    let verify = || Request {
        id: "verify".into(),
        command: Command::VerifyCleanup {
            profile: "one".into(),
        },
    };
    dispatch(
        verify(),
        &factory,
        &mut slots,
        &mut out,
        &interval,
        false,
        false,
    );
    assert!(matches!(
        out.pop_front(),
        Some(Message::Failed {
            error: ErrorCode::Unavailable,
            ..
        })
    ));
    assert!(factory.0.load(Ordering::SeqCst));
    dispatch(
        verify(),
        &factory,
        &mut slots,
        &mut out,
        &interval,
        true,
        false,
    );
    let Some(Message::Snapshot { connections, .. }) = out.pop_front() else {
        panic!("snapshot expected")
    };
    assert_eq!(
        connections.iter().find(|c| c.id == "one").unwrap().state,
        ConnectionState::Off
    );
    dispatch(
        connect("one"),
        &factory,
        &mut slots,
        &mut out,
        &interval,
        true,
        false,
    );
    assert!(matches!(out.pop_front(), Some(Message::Accepted { .. })));
}

#[cfg(target_os = "macos")]
mod recovery {
    use super::*;

    struct ObservingFactory(crate::connection::macos::fence_recovery::tests::RecoveryFixture);
    impl Factory for ObservingFactory {
        type Attempt = InertAttempt;
        fn create(
            &self,
            _: Profile,
            _: u32,
            _: u64,
            _: Credentials,
            _: Arc<AtomicBool>,
        ) -> Self::Attempt {
            InertAttempt
        }
        fn idle(&self) -> bool {
            true
        }
        fn cleanup_blocked(&self, profile: &Profile) -> bool {
            self.0.blocked(profile)
        }
        fn verify_cleanup(&self, profile: &Profile) -> bool {
            self.0.verify(profile)
        }
    }

    #[test]
    fn recovery_snapshot_dispatch_blocks_one_profile_then_verify_releases_it() {
        let factory = ObservingFactory(
            crate::connection::macos::fence_recovery::tests::RecoveryFixture::new(),
        );
        let mut slots = BTreeMap::from([
            ("one".into(), slot("one", 10)),
            ("two".into(), slot("two", 10)),
        ]);
        let mut out = VecDeque::new();
        let clock = ProbeClock::new(Duration::from_secs(10));
        let send = |id: &str, command, slots: &mut _, out: &mut _| {
            dispatch(
                Request {
                    id: id.into(),
                    command,
                },
                &factory,
                slots,
                out,
                &clock,
                true,
                false,
            )
        };
        send("snap", Command::Snapshot {}, &mut slots, &mut out);
        let Some(Message::Snapshot { connections, .. }) = out.pop_front() else {
            panic!("snapshot")
        };
        assert_eq!(
            connections.iter().find(|c| c.id == "one").unwrap().state,
            ConnectionState::CleanupUnconfirmed
        );
        assert!(factory.0.fence_exists());
        let connect = |id: &str| Command::Connect {
            id: id.into(),
            generation: 1,
            interval: ProbeInterval::TEN,
            credentials: credentials(),
        };
        send("one-request", connect("one"), &mut slots, &mut out);
        assert!(matches!(
            out.pop_front(),
            Some(Message::Failed {
                error: ErrorCode::ProfileBusy,
                ..
            })
        ));
        send("two-request", connect("two"), &mut slots, &mut out);
        assert!(matches!(out.pop_front(), Some(Message::Accepted { .. })));
        out.clear();
        factory.0.remove_observed_route();
        send(
            "verify",
            Command::VerifyCleanup {
                profile: "one".into(),
            },
            &mut slots,
            &mut out,
        );
        let Some(Message::Snapshot { connections, .. }) = out.pop_front() else {
            panic!("verified snapshot")
        };
        assert_eq!(
            connections.iter().find(|c| c.id == "one").unwrap().state,
            ConnectionState::Off
        );
        assert!(!factory.0.fence_exists());
        send("one-retry", connect("one"), &mut slots, &mut out);
        assert!(matches!(out.pop_front(), Some(Message::Accepted { .. })));
    }
}
