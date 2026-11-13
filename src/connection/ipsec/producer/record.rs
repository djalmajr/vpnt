use super::{Error, Owner};
use crate::connection::macos::process::Identity;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Birth {
    pub pid: u32,
    pub start: (u64, u64),
}
impl From<&Identity> for Birth {
    fn from(id: &Identity) -> Self {
        Self {
            pid: id.pid,
            start: id.start,
        }
    }
}
impl Birth {
    fn valid(&self) -> bool {
        self.pid > 0 && self.pid <= i32::MAX as u32 && self.start.0 > 0 && self.start.1 < 1_000_000
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage {
    Prepared,
    Starting,
    Running,
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u32,
    pub session: String,
    pub uid: u32,
    pub profile: String,
    pub generation: u64,
    pub reqid: u16,
    pub connection: String,
    pub local: std::net::IpAddr,
    pub remote: std::net::IpAddr,
    pub networks: Vec<String>,
    pub controller: Birth,
    pub runtime_hash: String,
    pub configuration_hash: String,
    /// Opaque captured egress index for a protected attempt; absent in legacy
    /// records and for the test-only unbound wrapper.
    #[serde(default)]
    pub transport_interface: Option<NonZeroU16>,
    pub stage: Stage,
    pub child: Option<Birth>,
}
impl Record {
    pub fn owner(&self) -> Owner {
        Owner {
            uid: self.uid,
            profile: self.profile.clone(),
            generation: self.generation,
        }
    }
    pub fn valid(&self) -> Result<(), Error> {
        let encoded: String = self.profile.bytes().map(|b| format!("{b:02x}")).collect();
        if self.version != 1
            || !hex(&self.session, 32)
            || self.uid == 0
            || self.generation == 0
            || !crate::model::valid_profile_id(&self.profile)
            || !(1..=0x3fff).contains(&self.reqid)
            || self.connection != format!("vpnt-{}-{}-{}", self.uid, encoded, self.generation)
            || !crate::connection::routes::Address::unscoped(self.local).valid_gateway()
            || !crate::connection::routes::Address::unscoped(self.remote).valid_gateway()
            || self.local.is_ipv4() != self.remote.is_ipv4()
            || self.networks.is_empty()
            || self.networks.len() > 64
            || self
                .networks
                .iter()
                .any(|n| n.parse::<crate::connection::routes::Network>().is_err())
            || !self.controller.valid()
            || !hex(&self.runtime_hash, 64)
            || !hex(&self.configuration_hash, 64)
            || self.child.as_ref().is_some_and(|c| !c.valid())
            || (self.stage == Stage::Running && self.child.is_none())
            || (matches!(self.stage, Stage::Prepared | Stage::Starting) && self.child.is_some())
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn same_admission(&self, other: &Self) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.stage = Stage::Prepared;
        a.child = None;
        b.stage = Stage::Prepared;
        b.child = None;
        a == b
    }
}
pub(super) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
