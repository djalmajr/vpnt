//! Linux controller entry point.
use super::{Attempt, Factory, Failure, Timing, engine, profiles::Profiles};
mod ovpn;
mod tunnel;
use crate::{
    helper::protocol::{ErrorCode, Message, Request},
    model::{Profile, VpnKind},
    secrets::Credentials,
};
use ovpn::{OvpnAttempt, RealNetwork, RealTunnel};
use std::{
    sync::{
        Arc,
        atomic::AtomicBool,
        mpsc::{Receiver, SyncSender},
    },
    time::{Duration, Instant},
};
use tunnel::TunnelAttempt;

pub fn run_linux(
    uid: u32,
    requests: Receiver<Request>,
    output: SyncSender<Message>,
) -> Result<(), ErrorCode> {
    let current = unsafe { libc::geteuid() };
    if uid == 0 || current == 0 || uid != current {
        return Err(ErrorCode::PermissionDenied);
    }
    let profiles =
        Arc::new(Profiles::for_current_user().map_err(|_| ErrorCode::UntrustedConfiguration)?);
    let initial = profiles
        .load()
        .map_err(|_| ErrorCode::UntrustedConfiguration)?;
    engine::run(
        LinuxFactory { profiles },
        uid,
        initial,
        requests,
        output,
        Timing::default(),
    )
}

enum LinuxAttempt {
    Ovpn(Box<OvpnAttempt<RealNetwork, RealTunnel>>),
    Tunnel(Box<TunnelAttempt>),
}

impl Attempt for LinuxAttempt {
    fn start(&mut self, canceled: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        match self {
            Self::Ovpn(attempt) => attempt.start(canceled, expires),
            Self::Tunnel(attempt) => attempt.start(canceled, expires),
        }
    }

    fn ready(&mut self) -> Result<bool, Failure> {
        match self {
            Self::Ovpn(attempt) => attempt.ready(),
            Self::Tunnel(attempt) => attempt.ready(),
        }
    }

    fn phase(&self) -> Option<crate::session::ConnectionState> {
        match self {
            Self::Ovpn(attempt) => attempt.phase(),
            Self::Tunnel(attempt) => attempt.phase(),
        }
    }

    fn restart_epoch(&self) -> u64 {
        match self {
            Self::Ovpn(attempt) => attempt.restart_epoch(),
            Self::Tunnel(attempt) => attempt.restart_epoch(),
        }
    }

    fn healthy(&mut self) -> Result<(), Failure> {
        match self {
            Self::Ovpn(attempt) => attempt.healthy(),
            Self::Tunnel(attempt) => attempt.healthy(),
        }
    }

    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        match self {
            Self::Ovpn(attempt) => attempt.probe(canceled, timeout),
            Self::Tunnel(attempt) => attempt.probe(canceled, timeout),
        }
    }

    fn probe_busy(&self) -> bool {
        match self {
            Self::Ovpn(attempt) => attempt.probe_busy(),
            Self::Tunnel(attempt) => attempt.probe_busy(),
        }
    }

    fn cleanup(&mut self) -> bool {
        match self {
            Self::Ovpn(attempt) => attempt.cleanup(),
            Self::Tunnel(attempt) => attempt.cleanup(),
        }
    }

    fn abandon(
        &mut self,
        reason: crate::helper::runtime::cleanup::Reason,
    ) -> Result<(), super::AbandonError> {
        match self {
            Self::Ovpn(attempt) => attempt.abandon(reason),
            Self::Tunnel(attempt) => attempt.abandon(reason),
        }
    }
}

struct LinuxFactory {
    profiles: Arc<Profiles>,
}
impl Factory for LinuxFactory {
    type Attempt = LinuxAttempt;
    fn profiles(&self) -> Result<Option<Vec<Profile>>, ErrorCode> {
        self.profiles
            .load()
            .map(Some)
            .map_err(|_| ErrorCode::UntrustedConfiguration)
    }
    fn supports(&self, kind: VpnKind) -> bool {
        matches!(kind, VpnKind::Ovpn | VpnKind::Ipsec | VpnKind::Ssl)
    }
    fn create(
        &self,
        profile: Profile,
        uid: u32,
        _: u64,
        credentials: Credentials,
        _: Arc<AtomicBool>,
    ) -> Self::Attempt {
        match profile.kind {
            VpnKind::Ovpn => LinuxAttempt::Ovpn(Box::new(OvpnAttempt::new(profile, uid))),
            VpnKind::Ipsec | VpnKind::Ssl => {
                LinuxAttempt::Tunnel(Box::new(TunnelAttempt::new(profile, credentials)))
            }
        }
    }
    fn idle(&self) -> bool {
        true
    }
}
#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
