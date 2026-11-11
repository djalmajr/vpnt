use crate::model::VpnKind;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

/// Owned secret buffers are cleared on drop. Debug never exposes their contents.
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }

    fn valid(&self, required: bool) -> bool {
        (!required || !self.0.is_empty())
            && self.0.len() <= 4096
            && !self.0.contains(['\r', '\n', '\0'])
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(Zeroizing::new(value.into()))
    }
}
impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub password: Secret,
    pub psk: Secret,
}

impl Credentials {
    pub fn validate(&self, kind: VpnKind) -> Result<(), SecretError> {
        if !self.password.valid(true) || !self.psk.valid(kind == VpnKind::Ipsec) {
            return Err(SecretError::InvalidData);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretError {
    Missing,
    Denied,
    Unavailable,
    InvalidData,
}

/// Only presence enters the UI snapshot; loading values requires a user action.
pub trait SecretStore: Send {
    fn contains(&self, id: &str, kind: VpnKind) -> Result<bool, SecretError>;
    fn load(&self, id: &str, kind: VpnKind) -> Result<Credentials, SecretError>;
    fn save(&self, id: &str, kind: VpnKind, credentials: &Credentials) -> Result<(), SecretError>;
    fn remove(&self, id: &str, kind: VpnKind) -> Result<(), SecretError>;
}
