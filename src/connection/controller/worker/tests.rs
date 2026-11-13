use super::*;
use std::{
    sync::{Arc, Mutex},
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
    );
    assert_eq!(finished.state, ConnectionState::GatewayTimeout);
    assert!(
        counters.lock().unwrap().cleanup >= 3,
        "cleanup was skipped or not retried"
    );
}
