//! Shared application contracts, independent of the desktop event loop.

pub mod app;
#[cfg(feature = "desktop")]
pub mod assets;
pub mod bridge;
pub mod cli;
#[cfg(unix)]
pub mod connection;
#[cfg(all(target_os = "macos", feature = "desktop"))]
pub mod desktop;
#[cfg(unix)]
mod fs_permissions;
pub mod helper;
#[cfg(target_os = "macos")]
pub mod keychain;
pub mod model;
#[cfg(feature = "desktop")]
pub mod preview;
pub mod secrets;
pub mod session;
#[cfg(unix)]
pub mod storage;
