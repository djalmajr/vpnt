//! Native factory: SSL always, IPsec only through a real available domain.
use super::NativeAttempt;
use super::ipsec::{NativeDomain, NativeIpsecAttempt};
use super::*;

pub(super) struct NativeFactory<'a> {
    routes: Routes<'a>,
    profiles: Arc<Profiles>,
    domain: Option<NativeDomain<'a>>,
}

impl<'a> NativeFactory<'a> {
    pub(super) fn new(
        routes: Routes<'a>,
        profiles: Arc<Profiles>,
        domain: Option<NativeDomain<'a>>,
    ) -> Self {
        Self {
            routes,
            profiles,
            domain,
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
}

/// Real denied admission when the host has no IPsec domain. It performs no
/// operation, but never pretends readiness or success.
pub(super) struct DeniedAttempt;
impl Attempt for DeniedAttempt {
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        Err(Failure {
            state: ConnectionState::MissingProgram,
            error: ErrorCode::MissingProgram,
        })
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        Err(Failure::unavailable())
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        Err(Failure::unavailable())
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        Err(Failure::unavailable())
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
    fn create(
        &self,
        profile: Profile,
        uid: u32,
        generation: u64,
        credentials: Credentials,
        canceled: Arc<AtomicBool>,
    ) -> Self::Attempt {
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
            link: None,
            token: None,
            lease: None,
            spawn_attempted: false,
            stopped: false,
            uncertain_cleanup: false,
        })
    }
    fn idle(&self) -> bool {
        let routes_idle = {
            let Ok(mut routes) = self.routes.lock() else {
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
        assert!(denied.ready().is_err());
        assert!(denied.healthy().is_err());
        assert!(
            denied
                .probe(&AtomicBool::new(false), Duration::from_secs(1))
                .is_err()
        );
        assert!(denied.cleanup());
    }
}
