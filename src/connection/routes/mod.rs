//! Route policy shared by the privileged controller and its test backend.
//! A successful fixture transaction is not evidence of native route mutation.
mod lease;
mod model;
mod plan;
pub use lease::{AcquireError, Backend, Cleanup, Coordinator, Lease, Owner, Presence};
pub use model::{Address, Error, Key, Network, NextHop, Route};
pub use plan::ppp_networks;
