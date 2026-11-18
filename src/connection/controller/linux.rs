//! Linux controller entry point.
use super::{Factory, Timing, engine, profiles::Profiles};
mod ovpn;
use crate::{
    helper::protocol::{ErrorCode, Message, Request},
    model::{Profile, VpnKind},
    secrets::Credentials,
};
use ovpn::{OvpnAttempt, RealNetwork, RealTunnel};
use std::sync::{
    Arc,
    atomic::AtomicBool,
    mpsc::{Receiver, SyncSender},
};

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

struct LinuxFactory {
    profiles: Arc<Profiles>,
}
impl Factory for LinuxFactory {
    type Attempt = OvpnAttempt<RealNetwork, RealTunnel>;
    fn profiles(&self) -> Result<Option<Vec<Profile>>, ErrorCode> {
        self.profiles
            .load()
            .map(Some)
            .map_err(|_| ErrorCode::UntrustedConfiguration)
    }
    fn supports(&self, kind: VpnKind) -> bool {
        kind == VpnKind::Ovpn
    }
    fn create(
        &self,
        profile: Profile,
        uid: u32,
        _: u64,
        _: Credentials,
        _: Arc<AtomicBool>,
    ) -> Self::Attempt {
        OvpnAttempt::new(profile, uid)
    }
    fn idle(&self) -> bool {
        true
    }
}
#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
