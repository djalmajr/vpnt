//! Linux controller entry point. No VPN driver is available yet.
use super::{Attempt, Factory, Failure, Timing, engine, profiles::Profiles};
use crate::{
    helper::protocol::{ErrorCode, Message, Request, Step},
    model::{Profile, VpnKind},
    secrets::Credentials,
};
use std::{
    sync::{
        Arc,
        atomic::AtomicBool,
        mpsc::{Receiver, SyncSender},
    },
    time::{Duration, Instant},
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
struct UnsupportedAttempt;
impl Factory for LinuxFactory {
    type Attempt = UnsupportedAttempt;
    fn profiles(&self) -> Result<Option<Vec<Profile>>, ErrorCode> {
        self.profiles
            .load()
            .map(Some)
            .map_err(|_| ErrorCode::UntrustedConfiguration)
    }
    fn supports(&self, _: VpnKind) -> bool {
        false
    }
    fn create(
        &self,
        _: Profile,
        _: u32,
        _: u64,
        _: Credentials,
        _: Arc<AtomicBool>,
    ) -> UnsupportedAttempt {
        UnsupportedAttempt
    }
    fn idle(&self) -> bool {
        true
    }
}
impl Attempt for UnsupportedAttempt {
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        Err(Failure::at(Step::Profile))
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        Err(Failure::at(Step::Profile))
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        Err(Failure::at(Step::Profile))
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        Err(Failure::at(Step::Profile))
    }
    fn cleanup(&mut self) -> bool {
        true
    }
}
#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
