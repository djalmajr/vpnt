#[cfg(target_os = "macos")]
pub(crate) mod charon_channel;
#[cfg(unix)]
pub mod controller_lock;
#[cfg(unix)]
pub(crate) mod diagnostics;
#[cfg(unix)]
pub(crate) mod fd_guard;
#[cfg(unix)]
pub(crate) mod local_socket;
pub mod paths;
pub mod pinentry;
#[cfg(unix)]
pub mod pinentry_channel;
#[cfg(unix)]
pub mod ppp_config;
#[cfg(unix)]
pub mod ppp_supervisor;
#[cfg(unix)]
pub mod process;
pub mod protocol;
pub(crate) mod redaction;
#[cfg(unix)]
pub mod runtime;
#[cfg(unix)]
pub mod vici;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod server;
#[cfg(target_os = "linux")]
mod user_lock;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod admin_client;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod client;
