#[cfg(unix)]
mod local_socket;
pub mod paths;
pub mod pinentry;
#[cfg(unix)]
pub mod pinentry_channel;
#[cfg(unix)]
pub mod process;
pub mod protocol;
#[cfg(unix)]
pub mod runtime;
#[cfg(unix)]
pub mod vici;
