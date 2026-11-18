use super::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, atomic::AtomicUsize, mpsc},
    thread,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Counters {
    ready: usize,
    healthy: usize,
    probe: usize,
    cleanup: usize,
    cleanup_failures: usize,
    cleanup_times: Vec<Instant>,
    start_expires: Option<Instant>,
}

struct Scripted {
    canceled: Arc<AtomicBool>,
    counters: Arc<Mutex<Counters>>,
    start_delay: Duration,
    ready_delay: Duration,
    ready: bool,
    cancel_on_start: bool,
    fail_healthy: bool,
}

impl Attempt for Scripted {
    fn start(&mut self, _: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        self.counters.lock().unwrap().start_expires = Some(expires);
        thread::sleep(self.start_delay);
        if self.cancel_on_start {
            self.canceled.store(true, Ordering::Release);
        }
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        self.counters.lock().unwrap().ready += 1;
        thread::sleep(self.ready_delay);
        Ok(self.ready)
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        self.counters.lock().unwrap().healthy += 1;
        if self.fail_healthy {
            return Err(Failure::at(Step::Health));
        }
        Ok(())
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        self.counters.lock().unwrap().probe += 1;
        Ok(true)
    }
    fn cleanup(&mut self) -> bool {
        let mut counters = self.counters.lock().unwrap();
        counters.cleanup += 1;
        counters.cleanup_times.push(Instant::now());
        if counters.cleanup_failures > 0 {
            counters.cleanup_failures -= 1;
            return false;
        }
        true
    }
}

fn signals(canceled: Arc<AtomicBool>) -> Signals {
    Signals {
        canceled,
        probe: Arc::new(AtomicBool::new(false)),
        state: Arc::new(Mutex::new(None)),
        exit: Arc::new(ExitRequested::new(CLEANUP_BUDGET)),
    }
}

fn timing(connect: Duration) -> Timing {
    Timing {
        connect,
        probe: Duration::from_secs(1),
        interval: Duration::from_secs(1),
        health: Duration::from_millis(100),
        poll: Duration::from_millis(5),
    }
}
fn clock(seconds: u64) -> ProbeClock {
    ProbeClock::new(Duration::from_secs(seconds))
}

#[derive(Debug)]
enum HealthEvent {
    Healthy(Instant),
    Probe,
    Cleanup(Progress),
}

struct HealthAttempt {
    events: mpsc::Sender<HealthEvent>,
    state: Arc<Mutex<Option<Progress>>>,
    calls: usize,
    fail_on: usize,
}
impl Attempt for HealthAttempt {
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        Ok(true)
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        self.calls += 1;
        self.events
            .send(HealthEvent::Healthy(Instant::now()))
            .unwrap();
        if self.calls == self.fail_on {
            Err(Failure::at(Step::Health))
        } else {
            Ok(())
        }
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        self.events.send(HealthEvent::Probe).unwrap();
        Ok(true)
    }
    fn cleanup(&mut self) -> bool {
        self.events
            .send(HealthEvent::Cleanup(self.state.lock().unwrap().unwrap()))
            .unwrap();
        true
    }
}

struct HealthRun {
    canceled: Arc<AtomicBool>,
    probe: Arc<AtomicBool>,
    state: Arc<Mutex<Option<Progress>>>,
    events: mpsc::Receiver<HealthEvent>,
    worker: Option<thread::JoinHandle<Finished>>,
    /// Bound for a check that must follow its trigger at once (initial and
    /// post-probe), kept well below `health` so the next periodic check can
    /// never stand in for a missing mandatory revalidation.
    prompt: Duration,
}
impl HealthRun {
    fn start(poll: Duration, health: Duration, fail_on: usize) -> Self {
        let signals = signals(Arc::new(AtomicBool::new(false)));
        let (events, receiver) = mpsc::channel();
        let attempt = HealthAttempt {
            events,
            state: signals.state.clone(),
            calls: 0,
            fail_on,
        };
        let mut run = Self {
            canceled: signals.canceled.clone(),
            probe: signals.probe.clone(),
            state: signals.state.clone(),
            events: receiver,
            worker: None,
            // 150 ms absorbs scheduling on a loaded runner; the cap keeps it
            // well below `health`.
            prompt: (poll * 4).max(Duration::from_millis(150)).min(health / 4),
        };
        let timing = Timing {
            poll,
            health,
            ..timing(Duration::from_secs(1))
        };
        run.worker = Some(thread::spawn(move || {
            super::run(attempt, signals, timing, clock(3600))
        }));
        run
    }
    fn event(&self) -> HealthEvent {
        self.events.recv_timeout(Duration::from_secs(2)).unwrap()
    }
    fn healthy(&self) -> Instant {
        match self.event() {
            HealthEvent::Healthy(at) => at,
            other => panic!("expected health check, received {other:?}"),
        }
    }
    fn healthy_promptly(&self) -> Instant {
        match self.events.recv_timeout(self.prompt) {
            Ok(HealthEvent::Healthy(at)) => at,
            other => panic!("expected an immediate health check, received {other:?}"),
        }
    }
    fn initial_probe(&self) -> Instant {
        self.healthy_promptly(); // The first connected-loop health check is immediate.
        assert!(matches!(self.event(), HealthEvent::Probe));
        // A separate mandatory revalidation follows the probe at once; the
        // periodic check is at least `health` away and cannot satisfy this.
        self.healthy_promptly()
    }
    fn quiet_for(&self, duration: Duration) {
        assert!(matches!(
            self.events.recv_timeout(duration),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
    }
    fn finish(&mut self) -> Finished {
        self.worker.take().unwrap().join().unwrap()
    }
    fn assert_dropped(&mut self) {
        match self.event() {
            HealthEvent::Cleanup(progress) => assert_eq!(
                progress,
                Progress {
                    state: ConnectionState::Dropped,
                    failures: 0,
                    cleaning: true,
                    failure: Some(health_note()),
                }
            ),
            other => panic!("expected failure cleanup, received {other:?}"),
        }
        let finished = self.finish();
        assert_eq!(finished.state, ConnectionState::Dropped);
        assert_eq!(finished.error, Some(ErrorCode::BackendFailure));
        assert_eq!(finished.step, Some(Step::Health));
        assert!(self.canceled.load(Ordering::Acquire));
        assert_eq!(
            *self.state.lock().unwrap(),
            Some(Progress {
                state: ConnectionState::Dropped,
                failures: 0,
                cleaning: false,
                failure: Some(health_note()),
            })
        );
    }
}
fn health_note() -> crate::helper::protocol::FailureNote {
    crate::helper::protocol::FailureNote {
        code: ErrorCode::BackendFailure,
        step: Step::Health,
    }
}
impl Drop for HealthRun {
    fn drop(&mut self) {
        self.canceled.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn connected_health_is_immediate_then_counted_by_health_cadence_not_poll() {
    let health = Duration::from_millis(400);
    let run = HealthRun::start(Duration::from_millis(5), health, 0);
    let last = run.initial_probe();
    // Exactly two health calls (initial + post-probe), despite at least forty
    // poll periods in this observation window. Then periodic health must resume.
    run.quiet_for(health / 2);
    let next = run.healthy();
    assert!(next.duration_since(last) >= health);
    run.quiet_for(health / 2);
}

#[test]
fn connected_health_wait_keeps_cancellation_within_one_poll() {
    let poll = Duration::from_millis(400);
    let mut run = HealthRun::start(poll, Duration::from_secs(2), 0);
    run.initial_probe();
    // Observe the worker sleeping between polls before canceling: it notices
    // within the rest of that poll, about half of one, which leaves cleanup
    // and the join the other half, 200 ms, on a loaded runner. A worker that
    // waits one poll more, or out the two-second health period, overruns.
    run.quiet_for(poll / 2);
    let canceled_at = Instant::now();
    run.canceled.store(true, Ordering::Release);
    let finished = run.finish();
    assert!(canceled_at.elapsed() <= poll);
    assert_eq!(finished.state, ConnectionState::Off);
    assert_eq!(finished.error, None);
    assert!(matches!(
        run.event(),
        HealthEvent::Cleanup(Progress {
            state: ConnectionState::Disconnecting,
            cleaning: false,
            ..
        })
    ));
}

#[test]
fn connected_health_command_probe_is_prompt_revalidated_and_resets_health_clock() {
    let poll = Duration::from_millis(10);
    // Long enough that the periodic check, about half of it away when the
    // command arrives, cannot pass for the prompt probe even with `prompt`
    // sized for a loaded runner.
    let health = Duration::from_secs(1);
    let run = HealthRun::start(poll, health, 0);
    run.initial_probe();
    run.quiet_for(health / 2);
    run.probe.store(true, Ordering::Release);
    assert!(matches!(
        run.events.recv_timeout(run.prompt).unwrap(),
        HealthEvent::Probe
    ));
    let revalidated = run.healthy_promptly();
    // Cross the old deadline without another check; only the post-probe
    // revalidation's new deadline should trigger the next periodic check.
    run.quiet_for(health * 3 / 4);
    assert!(run.healthy().duration_since(revalidated) >= health);
}

#[test]
fn connected_health_initial_or_periodic_failure_preserves_dropped_and_cleanup() {
    for fail_on in [1, 3] {
        let mut run = HealthRun::start(
            Duration::from_millis(5),
            Duration::from_millis(400),
            fail_on,
        );
        if fail_on == 3 {
            run.initial_probe();
        }
        run.healthy();
        run.assert_dropped();
    }
}

#[test]
fn connected_health_post_command_probe_failure_preserves_dropped_and_cleanup() {
    let mut run = HealthRun::start(Duration::from_millis(5), Duration::from_secs(1), 3);
    run.initial_probe();
    run.probe.store(true, Ordering::Release);
    assert!(matches!(run.event(), HealthEvent::Probe));
    // The failing third call must be the immediate post-probe revalidation,
    // which precedes any Connected publication for that probe.
    run.healthy_promptly();
    run.assert_dropped();
}

#[test]
fn slow_start_times_out_before_ready_and_cleans_up() {
    let before = Instant::now();
    let counters = Arc::new(Mutex::new(Counters::default()));
    let canceled = Arc::new(AtomicBool::new(false));
    let attempt = Scripted {
        canceled: canceled.clone(),
        counters: counters.clone(),
        start_delay: Duration::from_millis(250),
        ready_delay: Duration::ZERO,
        ready: true,
        cancel_on_start: false,
        fail_healthy: true,
    };
    let finished = run(
        attempt,
        signals(canceled),
        timing(Duration::from_millis(150)),
        clock(1),
    );
    assert_eq!(finished.state, ConnectionState::GatewayTimeout);
    assert_eq!(finished.error, Some(ErrorCode::BackendFailure));
    let counters = counters.lock().unwrap();
    assert_eq!(counters.ready, 0);
    assert_eq!(counters.healthy, 0);
    assert_eq!(counters.probe, 0);
    assert!(counters.cleanup >= 1, "timeout must still clean up");
    let expires = counters.start_expires.unwrap();
    assert!(
        expires >= before && expires <= before + Duration::from_millis(250),
        "start received a rebased deadline: {:?}",
        expires.saturating_duration_since(before)
    );
}

#[test]
fn slow_ready_true_after_expiry_times_out_without_healthy_or_probe() {
    let counters = Arc::new(Mutex::new(Counters::default()));
    let canceled = Arc::new(AtomicBool::new(false));
    let attempt = Scripted {
        canceled: canceled.clone(),
        counters: counters.clone(),
        start_delay: Duration::from_millis(100),
        ready_delay: Duration::from_millis(250),
        ready: true,
        cancel_on_start: false,
        fail_healthy: true,
    };
    let finished = run(
        attempt,
        signals(canceled),
        timing(Duration::from_millis(300)),
        clock(1),
    );
    assert_eq!(finished.state, ConnectionState::GatewayTimeout);
    assert_eq!(finished.error, Some(ErrorCode::BackendFailure));
    let counters = counters.lock().unwrap();
    assert_eq!(counters.ready, 1);
    assert_eq!(counters.healthy, 0);
    assert_eq!(counters.probe, 0);
    assert!(counters.cleanup >= 1);
}

#[test]
fn canceled_and_expired_returns_off_not_timeout() {
    let counters = Arc::new(Mutex::new(Counters::default()));
    let canceled = Arc::new(AtomicBool::new(false));
    let attempt = Scripted {
        canceled: canceled.clone(),
        counters: counters.clone(),
        start_delay: Duration::from_millis(200),
        ready_delay: Duration::ZERO,
        ready: true,
        cancel_on_start: true,
        fail_healthy: false,
    };
    let finished = run(
        attempt,
        signals(canceled),
        timing(Duration::from_millis(100)),
        clock(1),
    );
    assert_eq!(finished.state, ConnectionState::Off);
    assert_eq!(finished.error, None);
    let counters = counters.lock().unwrap();
    assert_eq!(counters.ready, 0);
    assert!(counters.cleanup >= 1);
}

#[test]
fn timeout_waits_for_cleanup_success() {
    let counters = Arc::new(Mutex::new(Counters::default()));
    counters.lock().unwrap().cleanup_failures = 2;
    let canceled = Arc::new(AtomicBool::new(false));
    let attempt = Scripted {
        canceled: canceled.clone(),
        counters: counters.clone(),
        start_delay: Duration::from_millis(150),
        ready_delay: Duration::ZERO,
        ready: true,
        cancel_on_start: false,
        fail_healthy: false,
    };
    let finished = run(
        attempt,
        signals(canceled),
        timing(Duration::from_millis(100)),
        clock(1),
    );
    assert_eq!(finished.state, ConnectionState::GatewayTimeout);
    assert!(
        counters.lock().unwrap().cleanup >= 3,
        "cleanup was skipped or not retried"
    );
}

#[test]
fn cleanup_retries_back_off_and_cap_at_one_second() {
    for delays in [
        vec![
            Duration::from_millis(5),
            Duration::from_millis(10),
            Duration::from_millis(20),
        ],
        vec![
            Duration::from_millis(600),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ],
    ] {
        let counters = Arc::new(Mutex::new(Counters {
            cleanup_failures: delays.len(),
            ..Counters::default()
        }));
        let canceled = Arc::new(AtomicBool::new(true));
        let attempt = Scripted {
            canceled: canceled.clone(),
            counters: counters.clone(),
            start_delay: Duration::ZERO,
            ready_delay: Duration::ZERO,
            ready: true,
            cancel_on_start: false,
            fail_healthy: false,
        };
        let mut timing = timing(Duration::from_secs(1));
        timing.poll = delays[0];
        let finished = run(attempt, signals(canceled), timing, clock(1));
        assert_eq!(finished.state, ConnectionState::Off);
        let counters = counters.lock().unwrap();
        assert_eq!(counters.cleanup, delays.len() + 1);
        for (pair, expected) in counters.cleanup_times.windows(2).zip(delays) {
            let elapsed = pair[1].duration_since(pair[0]);
            assert!(elapsed >= expected, "cleanup retried before {expected:?}");
            assert!(
                elapsed < expected + Duration::from_millis(400),
                "cleanup backoff exceeded its cap: {elapsed:?}"
            );
        }
    }
}

/// Scripted traffic probe outcomes, consumed in order; an exhausted script
/// answers responsively. Counters live outside so the test thread can wait on
/// an actual probe instead of sleeping for an arbitrary span.
struct Streak {
    probes: Arc<AtomicUsize>,
    outcomes: Arc<Mutex<VecDeque<bool>>>,
}
impl Attempt for Streak {
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
        self.probes.fetch_add(1, Ordering::AcqRel);
        Ok(self.outcomes.lock().unwrap().pop_front().unwrap_or(true))
    }
    fn cleanup(&mut self) -> bool {
        true
    }
}

struct StreakSignal {
    canceled: Arc<AtomicBool>,
    probe: Arc<AtomicBool>,
    state: Arc<Mutex<Option<Progress>>>,
    probes: Arc<AtomicUsize>,
}
fn streak(outcomes: impl IntoIterator<Item = bool>) -> (StreakSignal, Streak) {
    let canceled = Arc::new(AtomicBool::new(false));
    let probe = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(None));
    let probes = Arc::new(AtomicUsize::new(0));
    let attempt = Streak {
        probes: probes.clone(),
        outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
    };
    let signal = StreakSignal {
        canceled,
        probe,
        state,
        probes,
    };
    (signal, attempt)
}
impl StreakSignal {
    fn spend(&self) -> Signals {
        Signals {
            canceled: self.canceled.clone(),
            probe: self.probe.clone(),
            state: self.state.clone(),
            exit: Arc::new(ExitRequested::new(CLEANUP_BUDGET)),
        }
    }
    /// Wait until probe `target` has actually run *and* the worker published a
    /// status matching `expected`, with a deadline. Waiting on the probe count
    /// alone can return the previous publication: `Attempt::probe` increments
    /// before the worker computes and stores its `Progress`.
    fn progress(&self, target: usize, expected: impl Fn(&Progress) -> bool) -> Progress {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if self.probes.load(Ordering::Acquire) >= target {
                let mut state = self.state.lock().unwrap();
                if state.as_ref().is_some_and(&expected) {
                    // Consume the publication. A later saturated probe may
                    // publish the same value, but cannot reuse this one.
                    return state.take().unwrap();
                }
            }
            assert!(
                Instant::now() < deadline,
                "probe {target} did not publish the expected progress"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn failed_probes_saturate_at_three_and_a_responsive_probe_resets_the_streak() {
    let (signal, attempt) = streak([false, false, false, false, true]);
    let (canceled, probe) = (signal.canceled.clone(), signal.probe.clone());
    let handle = thread::spawn({
        let signals = signal.spend();
        move || {
            run(
                attempt,
                signals,
                timing(Duration::from_secs(5)),
                clock(3600),
            )
        }
    });
    let first = signal.progress(1, |progress| {
        progress.state == ConnectionState::Unresponsive
    });
    assert_eq!(first.state, ConnectionState::Unresponsive);
    assert_eq!(first.failures, 1);
    // A command probe is an actual traffic probe: it counts even though the
    // 3600 s timer cadence is nowhere near due.
    for (target, failures) in [(2, 2), (3, 3), (4, 3)] {
        probe.store(true, Ordering::Release);
        let progress = signal.progress(target, |progress| {
            progress.state == ConnectionState::Unresponsive
        });
        assert_eq!(progress.state, ConnectionState::Unresponsive);
        assert_eq!(progress.failures, failures, "counter did not saturate");
    }
    probe.store(true, Ordering::Release);
    let recovered = signal.progress(5, |progress| progress.state == ConnectionState::Connected);
    assert_eq!(recovered.state, ConnectionState::Connected);
    assert_eq!(
        recovered.failures, 0,
        "responsive probe must reset the streak"
    );
    canceled.store(true, Ordering::Release);
    assert_eq!(handle.join().unwrap().state, ConnectionState::Off);
}

#[test]
fn shortening_the_live_clock_makes_the_next_timer_probe_due_from_the_last_probe() {
    let (signal, attempt) = streak([]);
    let (canceled, interval) = (signal.canceled.clone(), clock(600));
    let live = interval.clone();
    let handle = thread::spawn({
        let signals = signal.spend();
        move || run(attempt, signals, timing(Duration::from_secs(5)), interval)
    });
    // First probe is immediately due because no probe has happened yet.
    assert_eq!(
        signal
            .progress(1, |progress| progress.state == ConnectionState::Connected)
            .state,
        ConnectionState::Connected
    );
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        signal.probes.load(Ordering::Acquire),
        1,
        "a 600 s cadence must not probe again inside a 200 ms window"
    );
    // Replacing the shared duration is read live, from the last actual probe.
    live.set(Duration::from_millis(20));
    signal.progress(3, |progress| progress.state == ConnectionState::Connected);
    canceled.store(true, Ordering::Release);
    assert_eq!(handle.join().unwrap().state, ConnectionState::Off);
}

/// Read the published slot from inside cleanup, so no scheduler can skip the
/// pre-cleanup status; after run returns the same slot must hold the finish.
#[test]
fn cleanup_publications_preserve_failure_and_only_user_cancel_disconnects() {
    struct Observe {
        state: Arc<Mutex<Option<Progress>>>,
        observed: Arc<Mutex<Vec<Progress>>>,
        failure: Option<ConnectionState>,
    }
    impl Attempt for Observe {
        fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
            Err(Failure {
                state: self.failure.unwrap(),
                error: ErrorCode::BackendFailure,
                step: Step::Egress,
            })
        }
        fn ready(&mut self) -> Result<bool, Failure> {
            unreachable!()
        }
        fn healthy(&mut self) -> Result<(), Failure> {
            unreachable!()
        }
        fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
            unreachable!()
        }
        fn cleanup(&mut self) -> bool {
            self.observed
                .lock()
                .unwrap()
                .push(self.state.lock().unwrap().unwrap());
            self.observed.lock().unwrap().len() == 3
        }
    }
    for failure in [
        Some(ConnectionState::GatewayTimeout),
        Some(ConnectionState::CredentialsRejected),
        Some(ConnectionState::Dropped),
        Some(ConnectionState::MissingProgram),
        None,
    ] {
        let signals = signals(Arc::new(AtomicBool::new(failure.is_none())));
        let state = signals.state.clone();
        let observed = Arc::new(Mutex::new(vec![]));
        let result = run(
            Observe {
                state: state.clone(),
                observed: observed.clone(),
                failure,
            },
            signals,
            timing(Duration::from_secs(1)),
            clock(1),
        );
        // The note travels with the first failed status, so the transition
        // the app logs already carries it; a user cancel has none.
        let note = failure.map(|_| crate::helper::protocol::FailureNote {
            code: ErrorCode::BackendFailure,
            step: Step::Egress,
        });
        let before = Progress {
            state: failure.unwrap_or(ConnectionState::Disconnecting),
            failures: 0,
            cleaning: failure.is_some(),
            failure: note,
        };
        assert_eq!(*observed.lock().unwrap(), vec![before; 3]);
        assert_eq!(result.state, failure.unwrap_or(ConnectionState::Off));
        assert_eq!(result.step, failure.map(|_| Step::Egress));
        if failure.is_some() {
            assert_eq!(
                *state.lock().unwrap(),
                Some(Progress {
                    cleaning: false,
                    ..before
                })
            );
        }
    }
}
#[test]
fn cleanup_backoff_switches_caps_at_thirty_seconds_without_a_terminal_deadline() {
    assert_eq!(
        cleanup_delay(Duration::from_secs(1), Duration::from_secs(29)),
        Duration::from_secs(1)
    );
    assert_eq!(
        cleanup_delay(Duration::from_secs(1), Duration::from_secs(30)),
        Duration::from_secs(2)
    );
    assert_eq!(
        cleanup_delay(Duration::from_secs(2), Duration::from_secs(32)),
        Duration::from_secs(4)
    );
    assert_eq!(
        cleanup_delay(Duration::from_secs(4), Duration::from_secs(36)),
        Duration::from_secs(5)
    );
    assert_eq!(
        cleanup_delay(Duration::from_secs(5), Duration::from_secs(3600)),
        Duration::from_secs(5)
    );
}

#[test]
fn exit_before_cleanup_uses_later_cleanup_start_for_budget() {
    struct Delayed {
        start: mpsc::Sender<()>,
        first_cleanup: mpsc::Sender<Instant>,
        abandon: mpsc::Sender<Instant>,
        seen: bool,
        release: Arc<AtomicBool>,
    }
    impl Attempt for Delayed {
        fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
            self.start.send(()).unwrap();
            thread::sleep(Duration::from_millis(180));
            Ok(())
        }
        fn ready(&mut self) -> Result<bool, Failure> {
            Ok(false)
        }
        fn healthy(&mut self) -> Result<(), Failure> {
            Ok(())
        }
        fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
            Ok(false)
        }
        fn cleanup(&mut self) -> bool {
            if !self.seen {
                self.first_cleanup.send(Instant::now()).unwrap();
                self.seen = true;
            }
            self.release.load(Ordering::Acquire)
        }
        fn abandon(&mut self, _: Reason) -> Result<(), AbandonError> {
            self.abandon.send(Instant::now()).unwrap();
            Ok(())
        }
    }
    struct Guard {
        release: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<Finished>>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            self.release.store(true, Ordering::Release);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }
    let (start_tx, start_rx) = mpsc::channel();
    let (cleanup_tx, cleanup_rx) = mpsc::channel();
    let (abandon_tx, abandon_rx) = mpsc::channel();
    let release = Arc::new(AtomicBool::new(false));
    let canceled = Arc::new(AtomicBool::new(false));
    let exit = Arc::new(ExitRequested::new(Duration::from_millis(120)));
    let signals = Signals {
        canceled: canceled.clone(),
        probe: Arc::new(AtomicBool::new(false)),
        state: Arc::new(Mutex::new(None)),
        exit: exit.clone(),
    };
    let attempt = Delayed {
        start: start_tx,
        first_cleanup: cleanup_tx,
        abandon: abandon_tx,
        seen: false,
        release: release.clone(),
    };
    let mut guard = Guard {
        release,
        handle: Some(thread::spawn(move || {
            super::run(attempt, signals, timing(Duration::from_secs(2)), clock(1))
        })),
    };
    start_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    exit.request();
    canceled.store(true, Ordering::Release);
    let cleanup_start = cleanup_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let abandoned = abandon_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(abandoned.duration_since(cleanup_start) >= Duration::from_millis(120));
    let finished = guard.handle.take().unwrap().join().unwrap();
    assert_eq!(finished.state, ConnectionState::Off);
}

/// The first traffic probe verifies the new tunnel (`Verify`); a failure of a
/// later probe keeps the attempt's own step (`Health`).
#[test]
fn the_initial_probe_failure_is_verify_and_a_later_one_keeps_its_step() {
    struct Probing {
        probes: usize,
        fail_on: usize,
    }
    impl Attempt for Probing {
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
            self.probes += 1;
            if self.probes == self.fail_on {
                Err(Failure::at(Step::Health))
            } else {
                Ok(true)
            }
        }
        fn cleanup(&mut self) -> bool {
            true
        }
    }
    for (fail_on, expected) in [(1, Step::Verify), (2, Step::Health)] {
        let signals = signals(Arc::new(AtomicBool::new(false)));
        let state = signals.state.clone();
        let mut timing = timing(Duration::from_secs(1));
        timing.health = Duration::from_millis(1);
        let started = Instant::now();
        let result = run(
            Probing { probes: 0, fail_on },
            signals,
            timing,
            ProbeClock::new(Duration::from_millis(5)),
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(result.state, ConnectionState::Dropped);
        assert_eq!(result.step, Some(expected), "probe {fail_on}");
        assert_eq!(
            state.lock().unwrap().unwrap().failure.map(|note| note.step),
            Some(expected)
        );
    }
}

/// A connection deadline keeps the step the attempt was at: the failure it
/// replaces, or `Tunnel` while the attempt was still waiting to be ready.
#[test]
fn a_timeout_keeps_the_step_the_attempt_was_at() {
    struct Slow {
        start: Result<(), Step>,
        delay: Duration,
    }
    impl Attempt for Slow {
        fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
            thread::sleep(self.delay);
            self.start.map_err(Failure::at)
        }
        fn ready(&mut self) -> Result<bool, Failure> {
            Ok(false)
        }
        fn healthy(&mut self) -> Result<(), Failure> {
            unreachable!()
        }
        fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
            unreachable!()
        }
        fn cleanup(&mut self) -> bool {
            true
        }
    }
    for (start, delay, expected) in [
        (Err(Step::Egress), Duration::from_millis(30), Step::Egress),
        (Ok(()), Duration::from_millis(30), Step::Tunnel),
        (Ok(()), Duration::ZERO, Step::Tunnel),
    ] {
        let result = run(
            Slow { start, delay },
            signals(Arc::new(AtomicBool::new(false))),
            timing(Duration::from_millis(10)),
            clock(1),
        );
        assert_eq!(result.state, ConnectionState::GatewayTimeout);
        assert_eq!(result.step, Some(expected), "{start:?} after {delay:?}");
    }
}
