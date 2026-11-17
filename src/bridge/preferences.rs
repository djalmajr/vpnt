//! Bridge-only document shape for the preferences command.
//!
//! `Preferences` keeps its portable derive, which serde also accepts in
//! positional form. The application bridge admits only the documented object,
//! and delegates every field rule (closed interval domain, `deny_unknown_fields`,
//! required booleans) to that same `Deserialize`, so no second schema exists.
use crate::preferences::Preferences;
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::fmt;

struct Document;

impl<'de> Visitor<'de> for Document {
    type Value = Preferences;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a preferences object")
    }

    fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
        Preferences::deserialize(MapAccessDeserializer::new(map))
    }
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Preferences, D::Error> {
    // `deserialize_map` sends every object to `visit_map` and rejects a
    // sequence (the positional value form) before any field is read.
    deserializer.deserialize_map(Document)
}
