//! Concrete native IPsec attempt: ledger admission, owned UTUN pin, typed
//! routes and the existing Control/Registry observation path.
mod cleanup;
mod domain;
mod health;
mod ownership;
mod start;

use super::*;
use crate::connection::{
    ipsec::{
        Admission, Candidate, Control, NativeContext, NativeLedger, Registry, Reservation,
        UserspaceObserver,
    },
    macos::{routing::InterfaceToken, vip::ConfiguredUtun},
    routes::Owner,
};
pub(super) use domain::NativeDomain;
use ownership::{OwnedLease, keep_for_control};
use std::{
    net::IpAddr,
    sync::{MutexGuard, TryLockError},
    thread,
    time::{Duration, Instant},
};

pub(super) type IpsecControl<'a> = Control<UserspaceObserver<'a, NativeLedger<'a>>, Admission<'a>>;

pub(super) struct NativeIpsecAttempt<'a> {
    pub(super) domain: NativeDomain<'a>,
    pub(super) routes: Routes<'a>,
    pub(super) profiles: Arc<Profiles>,
    pub(super) profile: Profile,
    pub(super) owner: Owner,
    pub(super) canceled: Arc<AtomicBool>,
    pub(super) profile_use: Option<ProfileUse>,
    pub(super) credentials: Option<Credentials>,
    pub(super) reservation: Option<Reservation>,
    pub(super) admission: Option<Admission<'a>>,
    pub(super) control: Option<IpsecControl<'a>>,
    pub(super) configured: Option<Arc<ConfiguredUtun<'a>>>,
    pub(super) token: Option<InterfaceToken>,
    pub(super) lease: Option<OwnedLease>,
    pub(super) expires: Option<Instant>,
    pub(super) selected_vips: Vec<IpAddr>,
    pub(super) selected_networks: Vec<String>,
}

impl<'a> NativeIpsecAttempt<'a> {
    pub(in crate::connection::controller::native) fn new(
        domain: NativeDomain<'a>,
        routes: Routes<'a>,
        profiles: Arc<Profiles>,
        profile: Profile,
        owner: Owner,
        credentials: Credentials,
        canceled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            domain,
            routes,
            profiles,
            owner,
            profile,
            canceled,
            profile_use: None,
            credentials: Some(credentials),
            reservation: None,
            admission: None,
            control: None,
            configured: None,
            token: None,
            lease: None,
            expires: None,
            selected_vips: Vec::new(),
            selected_networks: Vec::new(),
        }
    }
}

impl Attempt for NativeIpsecAttempt<'_> {
    fn start(&mut self, canceled: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        self.start_driver(canceled, expires)
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        self.ready_driver()
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        self.healthy_driver()
    }
    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        self.probe_driver(canceled, timeout)
    }
    fn cleanup(&mut self) -> bool {
        self.cleanup_driver()
    }
}

fn unavailable() -> Failure {
    Failure::unavailable()
}

fn check(expires: Instant, canceled: &AtomicBool) -> Result<(), Failure> {
    if canceled.load(Ordering::Acquire) || Instant::now() >= expires {
        return Err(unavailable());
    }
    Ok(())
}

fn bounded(expires: Instant, canceled: &AtomicBool) -> Result<Duration, Failure> {
    check(expires, canceled)?;
    let remaining = expires
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(3));
    if remaining.is_zero() {
        return Err(unavailable());
    }
    Ok(remaining)
}

fn lock_until<'a, T>(
    mutex: &'a Mutex<T>,
    expires: Instant,
    canceled: &AtomicBool,
) -> Result<MutexGuard<'a, T>, Failure> {
    loop {
        check(expires, canceled)?;
        match mutex.try_lock() {
            Ok(guard) => {
                check(expires, canceled)?;
                return Ok(guard);
            }
            Err(TryLockError::Poisoned(_)) => return Err(unavailable()),
            Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(2)),
        }
    }
}

fn profile_failure(error: StoreError) -> Failure {
    Failure {
        state: ConnectionState::Dropped,
        error: match error {
            StoreError::Busy => ErrorCode::ProfileBusy,
            StoreError::NotFound => ErrorCode::ProfileNotFound,
            _ => ErrorCode::UntrustedConfiguration,
        },
    }
}

fn missing_program() -> Failure {
    Failure {
        state: ConnectionState::MissingProgram,
        error: ErrorCode::MissingProgram,
    }
}

fn same_selection(
    candidate: &Candidate,
    networks: &[String],
    vips: &[IpAddr],
    nets: &[String],
) -> bool {
    let left: std::collections::BTreeSet<_> = candidate.vips.iter().copied().collect();
    let right: std::collections::BTreeSet<_> = vips.iter().copied().collect();
    left == right && networks == nets
}
