//! Prepared IPsec control primitives. Namespace reservations do not establish
//! ownership of kernel SAs/policies or authorize their deletion.
mod config;
mod control;
mod namespace;
mod snapshot;
pub use config::Config;
pub use control::{Control, Peer, Phase};
pub use namespace::{Observer, Registry, Reservation};
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
}

#[cfg(test)]
mod tests;
