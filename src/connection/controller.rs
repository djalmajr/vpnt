//! Controller workers never run on the UI or the pipe-reader thread. The
//! root helper supplies its own profiles/UID; requests contain no executable,
//! interface, route or configuration paths. Shutdown retains pending cleanup.
mod engine;
#[cfg(target_os = "macos")]
mod native;
#[cfg(any(target_os = "macos", test))]
mod profiles;
mod worker;
use crate::{
    helper::protocol::ErrorCode, model::Profile, secrets::Credentials, session::ConnectionState,
};
#[cfg(target_os = "macos")]
pub use native::run_ssl;
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

struct Failure {
    state: ConnectionState,
    error: ErrorCode,
}
impl Failure {
    fn unavailable() -> Self {
        Self {
            state: ConnectionState::Dropped,
            error: ErrorCode::BackendFailure,
        }
    }
}
trait Attempt {
    fn start(&mut self, canceled: &AtomicBool) -> Result<(), Failure>;
    /// true only after owned interface discovery and complete route leases.
    fn ready(&mut self) -> Result<bool, Failure>;
    fn healthy(&mut self) -> Result<(), Failure>;
    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure>;
    /// Stop only owned children; return true only after observed cleanup.
    /// Repeated calls must retain all uncertain resources.
    fn cleanup(&mut self) -> bool;
}
trait Factory: Sync {
    type Attempt: Attempt;
    fn profiles(&self) -> Result<Option<Vec<Profile>>, ErrorCode> {
        Ok(None)
    }
    fn create(
        &self,
        profile: Profile,
        uid: u32,
        generation: u64,
        credentials: Credentials,
        canceled: Arc<AtomicBool>,
    ) -> Self::Attempt;
    /// Includes failed admissions with no public lease/token.
    fn idle(&self) -> bool;
}
#[derive(Clone, Copy)]
struct Timing {
    connect: Duration,
    probe: Duration,
    interval: Duration,
    poll: Duration,
}
impl Default for Timing {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(60),
            probe: Duration::from_secs(5),
            interval: Duration::from_secs(30),
            poll: Duration::from_millis(50),
        }
    }
}
