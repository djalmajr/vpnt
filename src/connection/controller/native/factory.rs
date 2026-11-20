//! Native factory: SSL always, IPsec only through a real available domain.
use super::NativeAttempt;
use super::ipsec::{NativeDomain, NativeIpsecAttempt};
use super::*;

pub(super) struct NativeFactory<'a> {
    routes: Routes<'a>,
    profiles: Arc<Profiles>,
    domain: Option<NativeDomain<'a>>,
    fence_root: std::path::PathBuf,
    fence_owner: u32,
    recovery: Mutex<crate::connection::macos::fence_recovery::Recovery>,
    /// `journaled` of each SSL attempt still alive, for the exit watchdog.
    journals: Mutex<Vec<std::sync::Weak<AtomicBool>>>,
}

impl<'a> NativeFactory<'a> {
    #[cfg(test)]
    pub(super) fn fixture_fence_root(mut self, root: std::path::PathBuf, owner: u32) -> Self {
        self.recovery = Mutex::new(crate::connection::macos::fence_recovery::Recovery::new(
            &root, owner, owner,
        ));
        self.fence_root = root;
        self.fence_owner = owner;
        self
    }
    #[cfg(test)]
    pub(super) fn fixture_hold_journals(
        &self,
    ) -> std::sync::MutexGuard<'_, Vec<std::sync::Weak<AtomicBool>>> {
        self.journals.lock().unwrap()
    }
    pub(super) fn new(
        routes: Routes<'a>,
        profiles: Arc<Profiles>,
        domain: Option<NativeDomain<'a>>,
        uid: u32,
    ) -> Self {
        Self {
            routes,
            profiles,
            domain,
            fence_root: crate::helper::paths::STATE.into(),
            fence_owner: 0,
            recovery: Mutex::new(crate::connection::macos::fence_recovery::Recovery::new(
                std::path::Path::new(crate::helper::paths::STATE),
                0,
                uid,
            )),
            journals: Mutex::new(Vec::new()),
        }
    }
}

pub(super) enum AttemptKind<'a> {
    Ssl(NativeAttempt<'a>),
    Ipsec(NativeIpsecAttempt<'a>),
    Denied(DeniedAttempt),
}

impl Attempt for AttemptKind<'_> {
    fn start(&mut self, canceled: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        match self {
            Self::Ssl(attempt) => attempt.start(canceled, expires),
            Self::Ipsec(attempt) => attempt.start(canceled, expires),
            Self::Denied(attempt) => attempt.start(canceled, expires),
        }
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        match self {
            Self::Ssl(attempt) => attempt.ready(),
            Self::Ipsec(attempt) => attempt.ready(),
            Self::Denied(attempt) => attempt.ready(),
        }
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        match self {
            Self::Ssl(attempt) => attempt.healthy(),
            Self::Ipsec(attempt) => attempt.healthy(),
            Self::Denied(attempt) => attempt.healthy(),
        }
    }
    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        match self {
            Self::Ssl(attempt) => attempt.probe(canceled, timeout),
            Self::Ipsec(attempt) => attempt.probe(canceled, timeout),
            Self::Denied(attempt) => attempt.probe(canceled, timeout),
        }
    }
    fn cleanup(&mut self) -> bool {
        match self {
            Self::Ssl(attempt) => attempt.cleanup(),
            Self::Ipsec(attempt) => attempt.cleanup(),
            Self::Denied(attempt) => attempt.cleanup(),
        }
    }
    fn abandon(&mut self, reason: Reason) -> Result<(), AbandonError> {
        match self {
            Self::Ssl(attempt) => attempt.abandon(reason),
            Self::Ipsec(_) => Err(AbandonError::Unsupported),
            Self::Denied(_) => Ok(()),
        }
    }
}

/// Real denied admission when the host has no IPsec domain. It performs no
/// operation, but never pretends readiness or success.
pub(super) struct DeniedAttempt;
impl Attempt for DeniedAttempt {
    /// Without a domain the host has no usable IPsec component.
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        Err(Failure {
            state: ConnectionState::MissingProgram,
            error: ErrorCode::MissingProgram,
            step: Step::Runtime,
        })
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        Err(Failure::at(Step::Tunnel))
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        Err(Failure::at(Step::Health))
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        Err(Failure::at(Step::Health))
    }
    fn cleanup(&mut self) -> bool {
        true
    }
}

impl<'a> Factory for NativeFactory<'a> {
    type Attempt = AttemptKind<'a>;
    fn profiles(&self) -> Result<Option<Vec<Profile>>, ErrorCode> {
        self.profiles
            .load()
            .map(Some)
            .map_err(|_| ErrorCode::UntrustedConfiguration)
    }
    fn supports(&self, kind: VpnKind) -> bool {
        kind == VpnKind::Ssl || (kind == VpnKind::Ipsec && self.domain.is_some())
    }
    fn cleanup_blocked(&self, profile: &Profile) -> bool {
        self.recovery
            .lock()
            .map_or(true, |recovery| recovery.blocked(profile))
    }
    fn verify_cleanup(&self, profile: &Profile) -> bool {
        self.recovery.lock().is_ok_and(|mut recovery| {
            self.profiles
                .with_live(|live| recovery.verify(profile, live))
                .unwrap_or(false)
        })
    }
    fn create(
        &self,
        profile: Profile,
        uid: u32,
        generation: u64,
        credentials: Credentials,
        canceled: Arc<AtomicBool>,
    ) -> Self::Attempt {
        if profile.kind == VpnKind::Ovpn {
            return AttemptKind::Denied(DeniedAttempt);
        }
        if profile.kind == VpnKind::Ipsec {
            return match self.domain.clone() {
                Some(domain) => {
                    let owner = Owner {
                        uid,
                        profile: profile.id.clone(),
                        generation,
                    };
                    AttemptKind::Ipsec(NativeIpsecAttempt::new(
                        domain,
                        self.routes.clone(),
                        self.profiles.clone(),
                        profile,
                        owner,
                        credentials,
                        canceled,
                    ))
                }
                None => AttemptKind::Denied(DeniedAttempt),
            };
        }
        let journaled = Arc::new(AtomicBool::new(false));
        let mut journals = self
            .journals
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        journals.retain(|flag| flag.strong_count() > 0);
        journals.push(Arc::downgrade(&journaled));
        drop(journals);
        AttemptKind::Ssl(NativeAttempt {
            owner: Owner {
                uid,
                profile: profile.id.clone(),
                generation,
            },
            profile,
            profiles: self.profiles.clone(),
            profile_use: None,
            credentials: Some(credentials),
            routes: self.routes.clone(),
            canceled,
            before: None,
            before_routes: None,
            client: None,
            egress: None,
            link: None,
            token: None,
            requires_transport_default: false,
            lease: None,
            dns: None,
            spawn_attempted: false,
            stopped: false,
            uncertain_cleanup: false,
            fence_root: self.fence_root.clone(),
            fence_owner: self.fence_owner,
            journaled,
        })
    }
    /// A registry held by a concurrent `create` counts as an unjournaled attempt.
    fn unjournaled(&self) -> bool {
        self.journals.try_lock().map_or(true, |journals| {
            journals
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .any(|flag| !flag.load(Ordering::Acquire))
        })
    }
    fn idle(&self) -> bool {
        let routes_idle = {
            let Ok(mut routes) = self.routes.try_lock() else {
                return false;
            };
            routes.retry_cleanup();
            routes.backend_mut().reap_retired().is_ok()
                && !routes.has_resources()
                && !routes.backend_mut().has_resources()
        };
        let domain_idle = self.domain.as_ref().is_none_or(NativeDomain::idle);
        routes_idle && domain_idle && self.profiles.idle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_ipsec_never_claims_success_or_readiness() {
        let mut denied = DeniedAttempt;
        let failure = denied
            .start(
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(failure.state, ConnectionState::MissingProgram);
        assert_eq!(failure.error, ErrorCode::MissingProgram);
        assert_eq!(failure.step, Step::Runtime);
        assert!(denied.ready().is_err());
        assert!(denied.healthy().is_err());
        assert!(
            denied
                .probe(&AtomicBool::new(false), Duration::from_secs(1))
                .is_err()
        );
        assert!(denied.cleanup());
        let mut dispatch = AttemptKind::Denied(DeniedAttempt);
        assert_eq!(dispatch.abandon(Reason::ObservationFailed), Ok(()));
    }
}
