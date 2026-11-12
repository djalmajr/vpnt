use crate::{
    model::{Profile, Snapshot},
    secrets::Secret,
    session::ConnectionState,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub command: Command,
    #[serde(default)]
    pub locale: Option<crate::localization::Locale>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    // Empty struct variants reject extra fields; serde unit variants do not.
    GetSnapshot {},
    Toggle {
        id: String,
    },
    Reconnect {
        id: String,
    },
    DisconnectAll {},
    Probe {
        id: String,
    },
    SaveProfile {
        profile: Profile,
    },
    RemoveProfile {
        id: String,
    },
    SaveSecrets {
        id: String,
        password: Secret,
        psk: Secret,
    },
    SetDemoState {
        id: String,
        state: ConnectionState,
    },
    InstallHelper {},
    RemoveHelper {},
    Hide {},
    OpenProject {},
    Quit {},
    Resize {
        height: u32,
    },
}

#[derive(Debug, Serialize)]
pub struct Reply {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn parse_request(body: &str) -> Result<Request, &'static str> {
    if body.len() > 65536 {
        return Err("invalid_request");
    }
    let request: Request = serde_json::from_str(body).map_err(|_| "invalid_request")?;
    if request.id.is_empty()
        || request.id.len() > 64
        || !request
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("invalid_request");
    }
    Ok(request)
}

pub fn trusted_origin(origin: &str) -> bool {
    matches!(origin, "vpnt://localhost/index.html" | "vpnt://localhost/")
}
