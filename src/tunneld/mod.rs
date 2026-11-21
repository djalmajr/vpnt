//! Linux tunneld protocol and authenticated runtime client.
pub mod admin;
pub mod client;
pub mod fortinet_instance;
pub mod handshake;
pub mod policy;
pub mod protocol;
pub mod server;

pub const SOCKET_PATH: &str = "/run/vpnt/tunneld.sock";
