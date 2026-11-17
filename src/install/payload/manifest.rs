use super::*;
use serde::de::{MapAccess, Visitor};
use std::fmt;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Manifest {
    pub format: u32,
    pub app_version: String,
    pub uid: u32,
    #[serde(deserialize_with = "unique_files")]
    pub files: BTreeMap<String, String>,
}

fn unique_files<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Files;
    impl<'de> Visitor<'de> for Files {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a bounded inventory with unique relative paths")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut files = BTreeMap::new();
            while let Some((name, value)) = map.next_entry::<String, String>()? {
                if files.len() >= 72 || files.insert(name, value).is_some() {
                    return Err(serde::de::Error::custom("invalid inventory"));
                }
            }
            Ok(files)
        }
    }
    deserializer.deserialize_map(Files)
}
