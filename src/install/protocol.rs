use super::Error;
use serde::{Deserialize, Serialize};
pub const FORMAT: u32 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Ready { format: u32, version: String },
    Removed { id: String, component_present: bool },
    Failed { id: Option<String>, error: Error },
}
