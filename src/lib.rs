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
#[cfg(all(target_os = "linux", feature = "desktop"))]
#[path = "desktop_linux/mod.rs"]
pub mod desktop;
#[cfg(all(any(target_os = "macos", target_os = "linux"), feature = "desktop"))]
mod desktop_actor;
#[cfg(unix)]
mod fs_permissions;
pub mod helper;
pub mod identifiers;
#[cfg(unix)]
pub mod install;
#[cfg(target_os = "macos")]
pub mod keychain;
pub mod localization;
pub mod model;
#[cfg(target_os = "linux")]
pub mod netd;
pub mod notifications;
pub mod preferences;
#[cfg(feature = "desktop")]
pub mod preview;
#[cfg(target_os = "linux")]
pub mod secret_service;
pub mod secrets;
pub mod session;
#[cfg(unix)]
pub mod storage;
#[cfg(target_os = "linux")]
pub mod tunneld;
// Its only callers are Linux fixtures; elsewhere it would be dead code.
#[cfg(all(test, target_os = "linux"))]
mod test_support;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod broker;
