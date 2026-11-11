//! Shared application contracts, independent of the desktop event loop.

pub mod app;
#[cfg(feature = "desktop")]
pub mod assets;
pub mod bridge;
pub mod cli;
#[cfg(all(target_os = "macos", feature = "desktop"))]
pub mod desktop;
pub mod model;
#[cfg(feature = "desktop")]
pub mod preview;
pub mod session;
