use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum Locale {
    #[serde(rename = "pt-BR")]
    PtBr,
    #[default]
    #[serde(rename = "en-US")]
    EnUs,
}
impl Locale {
    pub fn code(self) -> &'static str {
        match self {
            Self::PtBr => "pt-BR",
            Self::EnUs => "en-US",
        }
    }
    pub fn native(self) -> NativeMessages {
        let catalogs: std::collections::BTreeMap<String, NativeMessages> =
            serde_json::from_str(include_str!("../ui/src/locales/native.json"))
                .expect("compiled native catalogs");
        catalogs
            .into_iter()
            .find(|(key, _)| key == self.code())
            .expect("supported locale")
            .1
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeMessages {
    pub auth_title: String,
    pub auth_prompt: String,
    pub auth_confirm: String,
    pub auth_cancel: String,
}
