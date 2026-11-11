use crate::session::ConnectionState;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnKind {
    Ipsec,
    Ssl,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub kind: VpnKind,
    pub gateway: String,
    pub username: String,
    pub networks: Vec<String>,
    pub port: u16,
    pub certificate: String,
    pub probe_host: String,
    pub probe_port: u16,
    pub probe_method: String,
}

impl Profile {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !valid_profile_id(&self.id) {
            return Err("invalid_profile");
        }
        if self.name.trim().is_empty()
            || self.name.len() > 120
            || self.name.chars().any(char::is_control)
        {
            return Err("invalid_name");
        }
        if !valid_host(&self.gateway) || self.port == 0 {
            return Err("invalid_gateway");
        }
        if self.username.len() > 200 || self.username.chars().any(char::is_control) {
            return Err("invalid_profile");
        }
        if self.networks.len() > 64 || self.networks.iter().any(|network| !valid_network(network)) {
            return Err("invalid_network");
        }
        if !valid_host(&self.probe_host)
            || self.probe_port == 0
            || self.probe_port == 22
            || !matches!(self.probe_method.as_str(), "ping_tcp" | "tcp")
        {
            return Err("invalid_probe");
        }
        if self.certificate.len() > 128 || self.certificate.chars().any(char::is_control) {
            return Err("invalid_profile");
        }
        Ok(())
    }
}

pub(crate) fn valid_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_host(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_network(value: &str) -> bool {
    if value.len() > 49 {
        return false;
    }
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    match (address.parse::<IpAddr>(), prefix.parse::<u8>()) {
        (Ok(IpAddr::V4(_)), Ok(number)) => number <= 32 && prefix == number.to_string(),
        (Ok(IpAddr::V6(_)), Ok(number)) => number <= 128 && prefix == number.to_string(),
        _ => false,
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnView {
    pub profile: Profile,
    pub state: ConnectionState,
    pub has_password: bool,
    pub has_psk: bool,
    pub log: Vec<LogEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub state: ConnectionState,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub version: &'static str,
    pub demo: bool,
    pub helper: &'static str,
    pub vpns: Vec<VpnView>,
}
