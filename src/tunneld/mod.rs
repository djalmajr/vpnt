//! Linux tunneld protocol and authenticated runtime client.
pub mod admin;
pub mod attest;
mod backend;
pub mod client;
pub mod handshake;
pub mod ipsec_instance;
pub mod policy;
pub mod protocol;
pub mod server;

pub const SOCKET_PATH: &str = "/run/vpnt/tunneld.sock";
