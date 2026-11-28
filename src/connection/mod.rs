#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub mod controller;
pub mod fence;
// Only the Linux instance builds a journal; the shared parser carries its slot.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(crate) mod fortinet_state;
#[cfg(unix)]
pub mod ipsec;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(unix)]
pub mod ovpn;
pub mod routes;
pub mod ssl;
pub(crate) mod ssl_output;
