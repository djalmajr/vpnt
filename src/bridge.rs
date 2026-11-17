use crate::{
    model::{Profile, Snapshot},
    preferences::Preferences,
    secrets::Secret,
    session::ConnectionState,
};
use serde::{Deserialize, Serialize};

mod preferences;

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
    Connect {
        id: String,
    },
    Disconnect {
        id: String,
    },
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
    SetPreferences {
        #[serde(deserialize_with = "preferences::deserialize")]
        preferences: Preferences,
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

#[cfg(test)]
mod explicit_intent_tests {
    use super::*;

    #[test]
    fn parser_accepts_explicit_intent_and_keeps_toggle_legacy() {
        for kind in ["connect", "disconnect", "toggle"] {
            let request = parse_request(&format!(
                r#"{{"id":"request-1","command":{{"type":"{kind}","id":"one"}}}}"#
            ))
            .unwrap();
            match (kind, request.command) {
                ("connect", Command::Connect { id })
                | ("disconnect", Command::Disconnect { id })
                | ("toggle", Command::Toggle { id }) => assert_eq!(id, "one"),
                _ => panic!("wrong typed command"),
            }
        }
    }

    #[test]
    fn parser_rejects_missing_extra_and_unknown_intent_fields() {
        for command in [
            r#"{"type":"connect"}"#,
            r#"{"type":"disconnect"}"#,
            r#"{"type":"connect","id":"one","desired":true}"#,
            r#"{"type":"disconnect","id":"one","generation":1}"#,
            r#"{"type":"disconnect","id":"one","password":"fictional"}"#,
            r#"{"type":"set_desired_state","id":"one"}"#,
        ] {
            assert!(
                parse_request(&format!(r#"{{"id":"request-1","command":{command}}}"#)).is_err()
            );
        }
        assert!(
            parse_request(
                r#"{"id":"request-1","command":{"type":"connect","id":"one"},"extra":true}"#
            )
            .is_err()
        );
    }
}
