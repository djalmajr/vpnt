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

#[cfg(target_os = "macos")]
pub mod broker;
