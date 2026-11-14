use super::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, atomic::AtomicUsize},
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
            return Err(Failure::unavailable());
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
    }
}

fn timing(connect: Duration) -> Timing {
    Timing {
        connect,
        probe: Duration::from_secs(1),
        interval: Duration::from_secs(1),
        poll: Duration::from_millis(5),
    }
}
fn clock(seconds: u64) -> ProbeClock {
    ProbeClock::new(Duration::from_secs(seconds))
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
