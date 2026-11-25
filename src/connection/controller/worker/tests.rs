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
    Probe(Instant),
    Cleanup(Progress, Instant),
}

/// Optional park points for a test that needs to arm a signal while the
/// worker is between the event and the state update that follows it.
#[derive(Default)]
struct Gates {
    healthy_call: Option<usize>,
    healthy_release: Option<mpsc::Receiver<()>>,
    probe_call: Option<usize>,
    probe_release: Option<mpsc::Receiver<()>>,
    revalidation_call: Option<usize>,
    revalidation_release: Option<mpsc::Receiver<()>>,
    /// Startup budget override for the tests that pause inside `ready`.
    connect: Option<Duration>,
}

struct HealthAttempt {
    events: mpsc::Sender<HealthEvent>,
    state: Arc<Mutex<Option<Progress>>>,
    calls: usize,
    probe_calls: usize,
    fail_on: usize,
    gates: Gates,
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
        if self.gates.healthy_call == Some(self.calls) {
            let _ = self.gates.healthy_release.as_ref().unwrap().recv();
        }
        if self.gates.revalidation_call == Some(self.calls) {
            let _ = self.gates.revalidation_release.as_ref().unwrap().recv();
        }
        if self.calls == self.fail_on {
            Err(Failure::at(Step::Health))
        } else {
            Ok(())
        }
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        self.probe_calls += 1;
        self.events
            .send(HealthEvent::Probe(Instant::now()))
            .unwrap();
        if self.gates.probe_call == Some(self.probe_calls) {
            let _ = self.gates.probe_release.as_ref().unwrap().recv();
        }
        Ok(true)
    }
    fn cleanup(&mut self) -> bool {
        self.events
            .send(HealthEvent::Cleanup(
                self.state.lock().unwrap().unwrap(),
                Instant::now(),
            ))
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
    /// Worker-stamped instant recorded as `worker::run` returns.
    finished_at: Arc<Mutex<Option<Instant>>>,
    /// Single bound for every immediate follow-up, measured between instants
    /// recorded by the worker thread.
    prompt: Duration,
}
impl HealthRun {
    fn start(poll: Duration, health: Duration, fail_on: usize) -> Self {
        Self::start_with_gates(poll, health, fail_on, Gates::default())
    }
    fn start_with_gates(poll: Duration, health: Duration, fail_on: usize, gates: Gates) -> Self {
        let connect = gates.connect.unwrap_or(Duration::from_secs(1));
        let signals = signals(Arc::new(AtomicBool::new(false)));
        let (events, receiver) = mpsc::channel();
        let attempt = HealthAttempt {
            events,
            state: signals.state.clone(),
            calls: 0,
            probe_calls: 0,
            fail_on,
            gates,
        };
        let mut run = Self {
            canceled: signals.canceled.clone(),
            probe: signals.probe.clone(),
            state: signals.state.clone(),
            events: receiver,
            worker: None,
            finished_at: Arc::new(Mutex::new(None)),
            // The supported 3 s pause needs slack; delays above 3.5 s are
            // reported by the worker's own timestamps.
            prompt: Duration::from_millis(3500),
        };
        let timing = Timing {
            connect,
            poll,
            health,
            ..timing(Duration::from_secs(1))
        };
        let finished_at = run.finished_at.clone();
        run.worker = Some(thread::spawn(move || {
            let finished = super::run(attempt, signals, timing, clock(3600));
            *finished_at.lock().unwrap() = Some(Instant::now());
            finished
        }));
        run
    }
    fn event(&self) -> HealthEvent {
        // Guard against a hung worker only: the periodic-check tests wait a
        // full `health` for the next event, and a loaded runner can suspend
        // the worker far beyond that. No assertion is made about this time.
        self.events.recv_timeout(Duration::from_secs(60)).unwrap()
    }
    fn healthy(&self) -> Instant {
        match self.event() {
            HealthEvent::Healthy(at) => at,
            other => panic!("expected health check, received {other:?}"),
        }
    }
    fn wait_connected(&self) {
        // `Connected` is published immediately before the worker's next poll
        // sleep, so this is the closest observable anchor for that phase.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if matches!(
                *self.state.lock().unwrap(),
                Some(Progress {
                    state: ConnectionState::Connected,
                    ..
                })
            ) {
                return;
            }
            assert!(Instant::now() < deadline, "Connected was never published");
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn healthy_promptly(&self) -> Instant {
        match self.events.recv_timeout(self.prompt) {
            Ok(HealthEvent::Healthy(at)) => at,
            other => panic!("expected an immediate health check, received {other:?}"),
        }
    }
    fn probe_now(&self) -> Instant {
        match self.event() {
            HealthEvent::Probe(at) => at,
            other => panic!("expected a probe, received {other:?}"),
        }
    }
    fn assert_prompt(&self, phase: &str, trigger: &str, from: Instant, to: Instant) {
        assert!(
            to.duration_since(from) <= self.prompt,
            "{phase} came {:?} after {trigger}, limit {:?}",
            to.duration_since(from),
            self.prompt
        );
    }
    fn assert_command_latency(&self, armed: Instant, probed: Instant, poll: Duration) {
        let limit = self.prompt + poll;
        assert!(
            probed.duration_since(armed) <= limit,
            "command probe came {:?} after it was available, limit {:?}",
            probed.duration_since(armed),
            limit
        );
    }
    fn assert_periodic_ceiling(
        &self,
        anchor: Instant,
        periodic: Instant,
        health: Duration,
        poll: Duration,
    ) {
        let limit = health + poll + self.prompt;
        assert!(
            periodic.duration_since(anchor) <= limit,
            "periodic health came {:?} after the reset, limit {:?}",
            periodic.duration_since(anchor),
            limit
        );
    }
    fn finished_at(&self) -> Instant {
        self.finished_at
            .lock()
            .unwrap()
            .expect("worker did not return")
    }
    fn initial_probe(&self) -> Instant {
        let initial_health = self.healthy_promptly(); // Startup has the same bound.
        let probed = self.probe_now();
        self.assert_prompt("initial probe", "the first health", initial_health, probed);
        // A separate mandatory revalidation follows the probe at once; the
        // periodic check is at least `health` away and cannot satisfy this.
        let revalidated = self.healthy_promptly();
        self.assert_prompt("revalidation", "the probe", probed, revalidated);
        revalidated
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
            HealthEvent::Cleanup(progress, _) => assert_eq!(
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
fn sleep_until(deadline: Instant) {
    let wait = deadline.saturating_duration_since(Instant::now());
    if !wait.is_zero() {
        thread::sleep(wait);
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
    let poll = Duration::from_secs(12);
    // Only B and C override the fixture's 1 s startup budget: a single 3 s
    // pause in `ready` must not turn the connected loop into a timeout.
    let mut run = HealthRun::start_with_gates(
        poll,
        Duration::from_secs(48),
        0,
        Gates {
            connect: Some(Duration::from_secs(10)),
            ..Gates::default()
        },
    );
    // The revalidation event is stamped just before the worker publishes
    // `Connected` and sleeps, so it anchors the wake-to-cleanup phase.
    let revalidated = run.initial_probe();
    run.wait_connected();
    // Anchor the cancel to the published `Connected` state, not to the earlier
    // health event: a delay between the event and the sleep cannot shift the
    // observed phase. Correct: wake by anchor + poll, measured from
    // anchor + poll/2, so about 6 s (9 s with a 3 s pause before the sleep or
    // before the join). One poll more costs >= 18 s; the health period costs
    // >= 42 s. The 12 s limit stays ~6 s clear of both paths after the
    // supported 3 s pause.
    let anchor = Instant::now();
    let wait = (anchor + poll / 2).saturating_duration_since(Instant::now());
    if !wait.is_zero() {
        run.quiet_for(wait);
    }
    let canceled_at = Instant::now();
    run.canceled.store(true, Ordering::Release);
    // The worker timestamps its own cleanup entry. A delay of the test thread
    // before the join cannot be mistaken for a late cancellation.
    let cleanup_at = match run.event() {
        HealthEvent::Cleanup(
            Progress {
                state: ConnectionState::Disconnecting,
                cleaning: false,
                ..
            },
            at,
        ) => at,
        other => panic!("expected disconnect cleanup, received {other:?}"),
    };
    assert!(cleanup_at.duration_since(canceled_at) <= poll);
    // Wake-to-cleanup gets its own bound. The anchor already includes one
    // poll; the remaining allowed gap is the supported 3 s pause between the
    // revalidation and the start of the sleep.
    assert!(
        cleanup_at.duration_since(revalidated + poll) <= run.prompt,
        "wake to cleanup exceeded {:?}",
        run.prompt
    );
    let finished = run.finish();
    // The worker also stamps its own return; a delay after cleanup is part of
    // the same one-poll property.
    assert!(run.finished_at().duration_since(canceled_at) <= poll);
    // The 12 s total still leaves slack after the poll wake; the tail phase
    // gets its own worker-stamped bound so a 4 s delay cannot hide there.
    assert!(
        run.finished_at().duration_since(cleanup_at) <= run.prompt,
        "cleanup to Off exceeded {:?}",
        run.prompt
    );
    assert_eq!(finished.state, ConnectionState::Off);
    assert_eq!(finished.error, None);
}

#[test]
fn connected_health_command_probe_is_prompt_revalidated_and_resets_health_clock() {
    let poll = Duration::from_millis(20);
    // A 3 s pause after either reset still leaves ~2 s before the periodic
    // check is due, so the command probe is read first. The two deadline
    // crossings cost about 2 * health, keeping the case near 10 s.
    let health = Duration::from_secs(5);
    // Park the worker inside both post-probe revalidations and inside the
    // command probe. Event order, not a short deadline, proves promptness and
    // both clock resets. The first park lets the initial deadline expire; the
    // second lets the deadline from the initial reset expire while the command
    // revalidation is still before its own reset. A reset only after the
    // initial probe then shows a periodic Healthy before the next Probe.
    let (release_healthy, healthy_gate) = mpsc::channel();
    let (release_probe, probe_gate) = mpsc::channel();
    let (release_revalidation, revalidation_gate) = mpsc::channel();
    let gates = Gates {
        healthy_call: Some(2),
        healthy_release: Some(healthy_gate),
        probe_call: Some(2),
        probe_release: Some(probe_gate),
        revalidation_call: Some(3),
        revalidation_release: Some(revalidation_gate),
        connect: Some(Duration::from_secs(10)),
    };
    let run = HealthRun::start_with_gates(poll, health, 0, gates);
    // Declared after `run` so a panic drops the senders (releasing all parks)
    // before `HealthRun::drop` joins the worker.
    let _releases = (release_healthy, release_probe, release_revalidation);
    let first = run.healthy_promptly();
    let initial_probe = run.probe_now();
    run.assert_prompt("initial probe", "the first health", first, initial_probe);
    let initial_revalidation = run.healthy();
    run.assert_prompt(
        "revalidation",
        "the probe",
        initial_probe,
        initial_revalidation,
    );
    sleep_until(first + health);
    run.probe.store(true, Ordering::Release);
    _releases.0.send(()).unwrap();
    // Timing starts at the gate release: before it the worker is parked on
    // purpose and cannot read the command.
    let first_command_released = Instant::now();
    // The reset made by the parked revalidation happens before this Probe is
    // observed, so the Probe's receipt is an upper bound for that reset even
    // if the test thread is paused before the later gates are released.
    let command_probe = run.probe_now();
    run.assert_command_latency(first_command_released, command_probe, poll);
    // Arm the next command while the worker is parked inside this probe: the
    // only Healthy that can precede it is the mandatory revalidation.
    run.probe.store(true, Ordering::Release);
    _releases.1.send(()).unwrap();
    let command_revalidation = match run.event() {
        HealthEvent::Healthy(at) => at,
        other => panic!("expected post-probe revalidation, received {other:?}"),
    };
    run.assert_prompt(
        "revalidation",
        "the probe",
        command_probe,
        command_revalidation,
    );
    assert!(command_revalidation.duration_since(first) >= health);
    // The deadline set by the initial reset passes while this revalidation is
    // still parked before its own reset. With the command reset present, the
    // next Probe wins; without it, a periodic Healthy comes first.
    sleep_until(command_probe + health);
    _releases.2.send(()).unwrap();
    // The second command was armed while the worker waited in the third gate.
    let second_command_released = Instant::now();
    let second_probe = run.probe_now();
    run.assert_command_latency(second_command_released, second_probe, poll);
    let revalidated = match run.event() {
        HealthEvent::Healthy(at) => at,
        other => panic!("expected post-probe revalidation, received {other:?}"),
    };
    run.assert_prompt("revalidation", "the probe", second_probe, revalidated);
    assert!(revalidated.duration_since(first) >= health);
}

#[test]
fn connected_health_command_revalidation_restarts_health_cadence() {
    let poll = Duration::from_millis(20);
    let health = Duration::from_secs(5);
    // No gates and a single command: the revalidation's timestamp is adjacent
    // to its reset, so the next periodic health must be a full `health` later.
    // A 3 s pause in either thread only moves the observed timestamp, never
    // the lower bound proved here.
    let run = HealthRun::start_with_gates(
        poll,
        health,
        0,
        Gates {
            connect: Some(Duration::from_secs(10)),
            ..Gates::default()
        },
    );
    let first_health = run.healthy_promptly();
    let initial_probe = run.probe_now();
    run.assert_prompt(
        "initial probe",
        "the first health",
        first_health,
        initial_probe,
    );
    let initial_revalidation = run.healthy();
    run.assert_prompt(
        "revalidation",
        "the probe",
        initial_probe,
        initial_revalidation,
    );
    // Observe the first periodic health before any command can overwrite a
    // shortened initial deadline.
    let first_periodic = run.healthy();
    assert!(first_periodic.duration_since(initial_revalidation) >= health);
    run.assert_periodic_ceiling(initial_revalidation, first_periodic, health, poll);
    run.probe.store(true, Ordering::Release);
    let command_armed = Instant::now();
    let command_probe = run.probe_now();
    run.assert_command_latency(command_armed, command_probe, poll);
    let revalidated = run.healthy();
    run.assert_prompt("revalidation", "the probe", command_probe, revalidated);
    let periodic = run.healthy();
    assert!(periodic.duration_since(revalidated) >= health);
    run.assert_periodic_ceiling(revalidated, periodic, health, poll);
}

#[test]
fn connected_health_command_after_initial_revalidation_is_prompt() {
    let poll = Duration::from_millis(20);
    let health = Duration::from_secs(5);
    // The base's early-command scenario: no gates, command armed right after
    // the initial revalidation and, as the base did, 500 ms into the first
    // idle interval, both well before any periodic health.
    for idle in [Duration::ZERO, Duration::from_millis(500)] {
        let run = HealthRun::start_with_gates(
            poll,
            health,
            0,
            Gates {
                connect: Some(Duration::from_secs(10)),
                ..Gates::default()
            },
        );
        let first = run.healthy_promptly();
        let initial_probe = run.probe_now();
        run.assert_prompt("initial probe", "the first health", first, initial_probe);
        let initial_revalidation = run.healthy();
        run.assert_prompt(
            "revalidation",
            "the probe",
            initial_probe,
            initial_revalidation,
        );
        if !idle.is_zero() {
            run.quiet_for(idle);
        }
        run.probe.store(true, Ordering::Release);
        let command_armed = Instant::now();
        let command_probe = run.probe_now();
        run.assert_command_latency(command_armed, command_probe, poll);
        let command_revalidation = run.healthy();
        run.assert_prompt(
            "revalidation",
            "the probe",
            command_probe,
            command_revalidation,
        );
    }
}

#[test]
fn connected_health_cancel_in_first_idle_poll_with_short_poll() {
    let poll = Duration::from_millis(400);
    // The base's short-poll scenario: cancel in the first idle interval while
    // no command is pending, so the entire poll is the allowed phase.
    let mut run = HealthRun::start_with_gates(
        poll,
        Duration::from_secs(5),
        0,
        Gates {
            connect: Some(Duration::from_secs(10)),
            ..Gates::default()
        },
    );
    let revalidated = run.initial_probe();
    run.wait_connected();
    let anchor = Instant::now();
    let wait = (anchor + poll / 2).saturating_duration_since(Instant::now());
    if !wait.is_zero() {
        run.quiet_for(wait);
    }
    let canceled_at = Instant::now();
    run.canceled.store(true, Ordering::Release);
    let cleanup_at = match run.event() {
        HealthEvent::Cleanup(
            Progress {
                state: ConnectionState::Disconnecting,
                cleaning: false,
                ..
            },
            at,
        ) => at,
        other => panic!("expected disconnect cleanup, received {other:?}"),
    };
    let limit = poll + run.prompt;
    assert!(
        cleanup_at.duration_since(canceled_at) <= limit,
        "cleanup came {:?} after cancel, limit {:?}",
        cleanup_at.duration_since(canceled_at),
        limit
    );
    // The phase also has a bound from its start: the first sleep begins right
    // after the revalidation, so a longer first sleep cannot hide behind the
    // part of the poll that elapsed before the cancel.
    assert!(
        cleanup_at.duration_since(revalidated + poll) <= run.prompt,
        "wake to cleanup came {:?} after the first poll, limit {:?}",
        cleanup_at.duration_since(revalidated + poll),
        run.prompt
    );
    let finished = run.finish();
    assert!(run.finished_at().duration_since(canceled_at) <= limit);
    assert_eq!(finished.state, ConnectionState::Off);
    assert_eq!(finished.error, None);
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
    let probed = run.probe_now();
    // The failing third call must be the immediate post-probe revalidation,
    // which precedes any Connected publication for that probe.
    let revalidated = run.healthy_promptly();
    run.assert_prompt("revalidation", "the probe", probed, revalidated);
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
    /// Change the epoch between iterations, after one failure was published:
    /// changing it during a probe would look like a retry on Linux.
    bump_epoch_after_first: bool,
    healthy_calls: usize,
    epoch: u64,
    epoch_bumped: Arc<AtomicBool>,
    /// Set by the test once it consumed the first publication. Until then
    /// the epoch stays put, so the retry probe a new epoch starts on Linux
    /// cannot publish before the first one was read.
    first_read: Arc<AtomicBool>,
}
impl Attempt for Streak {
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        Ok(true)
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        // #1 is the startup check and #2 the revalidation after the first
        // probe; from #3 on, the call at the top of an iteration changes the
        // epoch, before the comparison, once the test read the first result.
        self.healthy_calls += 1;
        if self.bump_epoch_after_first
            && self.epoch == 0
            && self.healthy_calls >= 3
            && self.first_read.load(Ordering::Acquire)
        {
            self.epoch = 1;
            self.epoch_bumped.store(true, Ordering::Release);
        }
        Ok(())
    }
    fn restart_epoch(&self) -> u64 {
        self.epoch
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
        bump_epoch_after_first: false,
        healthy_calls: 0,
        epoch: 0,
        epoch_bumped: Arc::new(AtomicBool::new(false)),
        first_read: Arc::new(AtomicBool::new(false)),
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
fn first_failed_probe_stays_connected_and_the_second_announces_unresponsive() {
    let (signal, attempt) = streak([true, false, false, false, true, false]);
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
    use ConnectionState::{Connected, Unresponsive};
    let checked = std::panic::catch_unwind(|| {
        for (index, expected) in [
            (Connected, 0),
            (Connected, 0),
            (Unresponsive, 2),
            (Unresponsive, 3),
            (Connected, 0),
            (Connected, 0),
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                probe.store(true, Ordering::Release);
            }
            let status =
                signal.progress(index + 1, |p| matches!(p.state, Connected | Unresponsive));
            assert_eq!(
                (status.state, status.failures),
                expected,
                "probe {}",
                index + 1
            );
        }
    });
    canceled.store(true, Ordering::Release);
    assert_eq!(handle.join().unwrap().state, ConnectionState::Off);
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
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
    let first = signal.progress(1, |progress| progress.failures == 1);
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
fn restart_epoch_resets_the_failure_streak() {
    let (signal, mut attempt) = streak([true, false, false, false]);
    attempt.bump_epoch_after_first = true;
    let epoch_bumped = Arc::clone(&attempt.epoch_bumped);
    let first_read = Arc::clone(&attempt.first_read);
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
    let first = signal.progress(1, |p| p.state == ConnectionState::Connected);
    assert_eq!(
        (first.state, first.failures),
        (ConnectionState::Connected, 0)
    );
    assert_eq!(
        signal.probes.load(Ordering::Acquire),
        1,
        "the epoch changed before the first publication was read"
    );
    for (target, expected) in [
        (2, (ConnectionState::Connected, 0)),
        (3, (ConnectionState::Unresponsive, 2)),
    ] {
        signal.probe.store(true, Ordering::Release);
        let progress = signal.progress(target, |_| true);
        assert_eq!((progress.state, progress.failures), expected);
    }
    first_read.store(true, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !epoch_bumped.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "the worker did not change epoch");
        thread::sleep(Duration::from_millis(1));
    }
    // The new epoch schedules the retry probe by itself on both systems;
    // a manual request could schedule an extra probe alongside that retry.
    let after_restart = signal.progress(4, |_| true);
    signal.canceled.store(true, Ordering::Release);
    assert_eq!(handle.join().unwrap().state, ConnectionState::Off);
    assert_eq!(
        (after_restart.state, after_restart.failures),
        (ConnectionState::Unresponsive, 1),
        "a new epoch must reset the streak and discard the previous proof"
    );
}

#[cfg(not(target_os = "linux"))]
mod connected_phase {
    use super::*;

    #[derive(Default)]
    struct Tick {
        phase: Option<ConnectionState>,
        request: bool,
        timer_due: bool,
        responsive: bool,
        restart_during_probe: bool,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Observation(usize, Option<(ConnectionState, u32)>);

    struct AttemptScript<'a> {
        ticks: std::vec::IntoIter<Tick>,
        current: Tick,
        observations: &'a mut Vec<Observation>,
        signals: &'a Signals,
        clock: ProbeClock,
        probes: usize,
        epoch: u64,
        revalidating: bool,
    }

    impl Attempt for AttemptScript<'_> {
        fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
            Ok(())
        }

        fn ready(&mut self) -> Result<bool, Failure> {
            Ok(true)
        }

        fn healthy(&mut self) -> Result<(), Failure> {
            if std::mem::take(&mut self.revalidating) {
                return Ok(());
            }
            let publication = self.signals.state.lock().unwrap().take();
            if let Some(progress) = publication {
                assert!(!progress.cleaning);
                assert_eq!(progress.failure, None);
            }
            self.observations.push(Observation(
                std::mem::take(&mut self.probes),
                publication.map(|p| (p.state, p.failures)),
            ));
            if let Some(tick) = self.ticks.next() {
                self.clock.set(if tick.timer_due {
                    Duration::ZERO
                } else {
                    Duration::from_secs(3600)
                });
                self.signals.probe.store(tick.request, Ordering::Release);
                self.current = tick;
            } else {
                self.signals.canceled.store(true, Ordering::Release);
            }
            Ok(())
        }

        fn phase(&self) -> Option<ConnectionState> {
            self.current.phase
        }

        fn restart_epoch(&self) -> u64 {
            self.epoch
        }

        fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
            self.probes += 1;
            self.revalidating = true;
            if self.current.restart_during_probe {
                self.epoch += 1;
            }
            Ok(self.current.responsive)
        }

        fn cleanup(&mut self) -> bool {
            true
        }
    }

    fn observe(ticks: Vec<Tick>) -> Vec<Observation> {
        let fixture = signals(Arc::new(AtomicBool::new(false)));
        let mut observations = Vec::new();
        let cadence = clock(3600);
        let attempt = AttemptScript {
            ticks: ticks.into_iter(),
            current: Tick::default(),
            observations: &mut observations,
            signals: &fixture,
            clock: cadence.clone(),
            probes: 0,
            epoch: 0,
            revalidating: false,
        };
        let mut timing = timing(Duration::from_secs(1));
        timing.health = Duration::ZERO;
        let finished = run(
            attempt,
            Signals {
                canceled: fixture.canceled.clone(),
                probe: fixture.probe.clone(),
                state: fixture.state.clone(),
                exit: fixture.exit.clone(),
            },
            timing,
            cadence,
        );
        assert_eq!(finished.state, ConnectionState::Off);
        let mut observations = observations.into_iter();
        assert_eq!(
            observations.next(),
            Some(Observation(0, Some((ConnectionState::Verifying, 0))))
        );
        observations.collect()
    }

    #[test]
    fn connected_approval_and_reconnecting_suspend_probes_and_resume_cadence() {
        use ConnectionState::{AwaitingApproval, Connected, Reconnecting, Unresponsive};

        let observations = observe(vec![
            Tick {
                responsive: true,
                ..Tick::default()
            },
            Tick {
                phase: Some(AwaitingApproval),
                request: true,
                ..Tick::default()
            },
            Tick {
                phase: Some(AwaitingApproval),
                timer_due: true,
                ..Tick::default()
            },
            Tick {
                phase: Some(Reconnecting),
                timer_due: true,
                ..Tick::default()
            },
            Tick {
                phase: Some(Reconnecting),
                request: true,
                ..Tick::default()
            },
            Tick::default(),
            Tick {
                timer_due: true,
                responsive: true,
                ..Tick::default()
            },
        ]);
        assert_eq!(
            observations,
            [
                Observation(1, Some((Connected, 0))),
                Observation(0, Some((AwaitingApproval, 0))),
                Observation(0, None),
                Observation(0, Some((Reconnecting, 0))),
                Observation(0, None),
                // Leaving the phase probes at once, without a timer or request,
                // and publishes the result in place of the stale phase.
                Observation(1, Some((Unresponsive, 1))),
                Observation(1, Some((Connected, 0))),
            ],
        );
    }

    #[test]
    fn connected_phase_exit_probes_at_once_and_then_keeps_the_cadence() {
        use ConnectionState::{AwaitingApproval, Connected};

        let observations = observe(vec![
            Tick {
                responsive: true,
                ..Tick::default()
            },
            Tick {
                phase: Some(AwaitingApproval),
                ..Tick::default()
            },
            Tick {
                responsive: true,
                ..Tick::default()
            },
            Tick::default(),
        ]);
        assert_eq!(
            observations,
            [
                Observation(1, Some((Connected, 0))),
                Observation(0, Some((AwaitingApproval, 0))),
                Observation(1, Some((Connected, 0))),
                Observation(0, None),
            ],
        );
    }

    #[test]
    fn connected_probe_crossing_a_restart_is_retried_once_without_a_request() {
        use ConnectionState::{Connected, Unresponsive};

        let observations = observe(vec![
            Tick {
                responsive: true,
                ..Tick::default()
            },
            Tick {
                request: true,
                restart_during_probe: true,
                ..Tick::default()
            },
            Tick::default(),
            Tick::default(),
        ]);
        assert_eq!(
            observations,
            [
                Observation(1, Some((Connected, 0))),
                Observation(1, None),
                Observation(1, Some((Unresponsive, 1))),
                Observation(0, None),
            ],
        );
    }

    #[test]
    fn connected_approval_clears_existing_failures_without_an_epoch_change() {
        use ConnectionState::{AwaitingApproval, Connected, Unresponsive};

        // A healthy tunnel tolerates one failure. The phase clears both its
        // capped streak and its positive proof, even in the same epoch.
        let observations = observe(vec![
            Tick {
                responsive: true,
                ..Tick::default()
            },
            Tick {
                request: true,
                ..Tick::default()
            },
            Tick {
                request: true,
                ..Tick::default()
            },
            Tick {
                phase: Some(AwaitingApproval),
                ..Tick::default()
            },
            Tick {
                request: true,
                ..Tick::default()
            },
            Tick {
                request: true,
                ..Tick::default()
            },
        ]);
        assert_eq!(
            observations,
            [
                Observation(1, Some((Connected, 0))),
                Observation(1, Some((Connected, 0))),
                Observation(1, Some((Unresponsive, 2))),
                Observation(0, Some((AwaitingApproval, 0))),
                Observation(1, Some((Unresponsive, 1))),
                Observation(1, Some((Unresponsive, 2))),
            ],
        );
    }

    #[test]
    fn connected_probe_crossing_a_restart_cannot_publish_its_stale_sample() {
        use ConnectionState::{Connected, Unresponsive};

        for responsive in [true, false] {
            let observations = observe(vec![
                Tick {
                    responsive: true,
                    ..Tick::default()
                },
                Tick {
                    request: true,
                    responsive,
                    restart_during_probe: true,
                    ..Tick::default()
                },
                Tick {
                    request: true,
                    ..Tick::default()
                },
            ]);
            assert_eq!(
                observations,
                [
                    Observation(1, Some((Connected, 0))),
                    Observation(1, None),
                    Observation(1, Some((Unresponsive, 1))),
                ],
                "stale probe returned responsive={responsive}"
            );
        }
    }
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
