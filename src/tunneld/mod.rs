//! Linux tunneld protocol and authenticated runtime client.
pub mod client;
pub mod protocol;
pub mod server;

pub const SOCKET_PATH: &str = "/run/vpnt/tunneld.sock";
