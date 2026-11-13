//! Prepared IPsec control primitives. Namespace reservations do not establish
//! ownership of kernel SAs/policies or authorize their deletion.
mod config;
mod control;
mod namespace;
#[cfg(target_os = "macos")]
pub mod pfkey;
#[cfg(target_os = "macos")]
mod producer;
mod snapshot;
pub use config::Config;
pub use control::{Control, Peer, Phase};
pub use namespace::{Observer, Registry, Reservation};
#[cfg(target_os = "macos")]
pub use producer::{InterfaceObservation, KernelClaims, NativeContext, NativeObserver, NativePeer};
pub use snapshot::Candidate;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Busy,
    Exhausted,
    Changed,
    Unavailable,
    Canceled,
    Timeout,
    Incompatible,
    Rejected,
    PermissionDenied,
}

#[cfg(test)]
mod tests;
