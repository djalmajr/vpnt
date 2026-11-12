//! Prepared IPsec control primitives. Namespace reservations do not establish
//! ownership of kernel SAs/policies or authorize their deletion.
mod config;
mod namespace;
pub use config::Config;
pub use namespace::{Observer, Registry, Reservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Busy,
    Exhausted,
    Changed,
    Unavailable,
}

#[cfg(test)]
mod tests;
