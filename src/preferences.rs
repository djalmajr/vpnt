//! Durable user preferences shared by the native bridge, the broker and the
//! helper integration. Values are validated on entry, so no caller can hold an
//! interval the helper would refuse.

pub mod host;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::time::Duration;

/// Closed set of probe intervals offered by the preferences UI.
///
/// The supported values are declared once in `ALL`; every conversion and the
/// JSON decoder read that same list. Construction is checked, so an interval
/// outside the set cannot be built from IPC, storage or JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeInterval(u16);

impl ProbeInterval {
    pub const TEN: Self = Self(10);
    pub const THIRTY: Self = Self(30);
    pub const SIXTY: Self = Self(60);
    const ALL: [Self; 3] = [Self::TEN, Self::THIRTY, Self::SIXTY];

    /// Checked conversion from a wire, stored or computed value.
    pub fn from_seconds(seconds: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.0 == seconds)
    }

    /// Wire and storage representation: whole seconds.
    pub fn seconds(self) -> u16 {
        self.0
    }

    pub fn duration(self) -> Duration {
        Duration::from_secs(u64::from(self.0))
    }
}

impl Default for ProbeInterval {
    fn default() -> Self {
        Self::TEN
    }
}

impl Serialize for ProbeInterval {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for ProbeInterval {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // A JSON string, enum name, float, null or out-of-range integer fails
        // as a `u16` before the domain check sees it.
        let seconds = u16::deserialize(deserializer)?;
        Self::from_seconds(seconds)
            .ok_or_else(|| de::Error::custom("unsupported probe interval in seconds"))
    }
}

/// Preferences that change native behavior. Defaults mirror the existing UI
/// catalog (`ui/src/settings.ts`): 10 seconds, notify on, reconnect off,
/// startup off.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    pub interval: ProbeInterval,
    pub notify: bool,
    pub reconnect: bool,
    pub startup: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            interval: ProbeInterval::default(),
            notify: true,
            reconnect: false,
            startup: false,
        }
    }
}
