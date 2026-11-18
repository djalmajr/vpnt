use crate::helper::protocol::{ErrorCode, FailureNote, Step};
use crate::preferences::Preferences;
use crate::session::ConnectionState;
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Component, Path},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnKind {
    Ipsec,
    Ssl,
    Ovpn,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OvpnTls {
    #[default]
    Pkcs1Only,
    Any,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OvpnSettings {
    pub certificate_id: String,
    pub module: String,
    #[serde(default)]
    pub tls: OvpnTls,
}

impl OvpnSettings {
    fn is_valid(&self) -> bool {
        let path = Path::new(&self.module);
        (2..=128).contains(&self.certificate_id.len())
            && self.certificate_id.len().is_multiple_of(2)
            && self
                .certificate_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && self.module.len() <= 4096
            && !self.module.chars().any(char::is_control)
            && self.module.ends_with(".so")
            && path.is_absolute()
            && !path.components().any(|part| part == Component::ParentDir)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub kind: VpnKind,
    pub gateway: String,
    pub username: String,
    pub networks: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_dns_domains"
    )]
    pub dns_domains: Vec<String>,
    pub port: u16,
    pub certificate: String,
    pub probe_host: String,
    pub probe_port: u16,
    pub probe_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ovpn: Option<OvpnSettings>,
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
        match (self.kind, &self.ovpn) {
            (VpnKind::Ovpn, None) => return Err("invalid_profile"),
            (VpnKind::Ovpn, Some(settings)) => {
                if !settings.is_valid()
                    || !self.username.is_empty()
                    || !self.networks.is_empty()
                    || !self.certificate.is_empty()
                {
                    return Err("invalid_profile");
                }
            }
            (_, Some(_)) => return Err("invalid_profile"),
            (_, None) => {}
        }
        let username_limit = if self.kind == VpnKind::Ssl { 64 } else { 200 };
        if self.username.len() > username_limit || self.username.chars().any(char::is_control) {
            return Err("invalid_profile");
        }
        if self.networks.len() > 64 || self.networks.iter().any(|network| !valid_network(network)) {
            return Err("invalid_network");
        }
        if (!matches!(self.kind, VpnKind::Ssl | VpnKind::Ovpn) && !self.dns_domains.is_empty())
            || self.dns_domains.len() > 8
            || self.dns_domains.iter().any(|domain| {
                !valid_dns_domain(domain) || (self.kind == VpnKind::Ssl && !domain.contains('.'))
            })
            || self
                .dns_domains
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != self.dns_domains.len()
        {
            return Err("invalid_profile");
        }
        if !valid_host(&self.probe_host)
            || self.probe_port == 0
            || self.probe_port == 22
            || !matches!(self.probe_method.as_str(), "ping_tcp" | "tcp")
        {
            return Err("invalid_probe");
        }
        if self.certificate.len() > 128
            || self.certificate.chars().any(char::is_control)
            || (self.kind == VpnKind::Ssl
                && !self.certificate.is_empty()
                && (self.certificate.len() != 64
                    || !self
                        .certificate
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())))
        {
            return Err("invalid_profile");
        }
        Ok(())
    }
}

fn deserialize_dns_domains<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    Ok(Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(|domain| domain.to_ascii_lowercase())
        .collect())
}

fn valid_dns_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
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

/// `FailureView` in `ui/src/model.ts`: the helper's note on a failed attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FailureView {
    pub code: ErrorCode,
    pub step: Step,
}
impl From<FailureNote> for FailureView {
    fn from(note: FailureNote) -> Self {
        Self {
            code: note.code,
            step: note.step,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnView {
    pub cleaning: bool,
    pub cleanup_verifying: bool,
    pub profile: Profile,
    pub state: ConnectionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureView>,
    pub has_password: bool,
    pub has_psk: bool,
    pub log: Vec<LogEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub state: ConnectionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureView>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub version: &'static str,
    pub demo: bool,
    pub helper: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component_operation: Option<&'static str>,
    pub preferences: Preferences,
    pub vpns: Vec<VpnView>,
}

#[cfg(test)]
mod failure_tests {
    use super::*;

    fn profile() -> Profile {
        serde_json::from_value(serde_json::json!({"id":"one","name":"Example","kind":"ssl","gateway":"vpn.example.com","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap()
    }
    fn ovpn_profile() -> Profile {
        serde_json::from_str(concat!(
            r#"{"id":"one","name":"Example","kind":"ovpn","gateway":"vpn.example.com","username":"","networks":[],"dnsDomains":["serpro"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp","#,
            r#""ovpn":{"certificateId":"01ab","module":"/opt/pkcs11/token.so","tls":"any"}}"#
        )).unwrap()
    }

    #[test]
    fn ovpn_round_trip_and_tls_wire_defaults() {
        let profile = ovpn_profile();
        assert_eq!(profile.validate(), Ok(()));
        assert_eq!(profile.kind, VpnKind::Ovpn);
        assert_eq!(profile.ovpn.as_ref().unwrap().tls, OvpnTls::Any);
        let wire = serde_json::to_string(&profile).unwrap();
        assert_eq!(serde_json::from_str::<Profile>(&wire).unwrap(), profile);
        let mut value: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(value["kind"], "ovpn");
        assert_eq!(value["ovpn"]["certificateId"], "01ab");
        assert_eq!(value["ovpn"]["module"], "/opt/pkcs11/token.so");
        assert_eq!(value["ovpn"]["tls"], "any");
        value["ovpn"].as_object_mut().unwrap().remove("tls");
        let defaulted: Profile = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(defaulted.ovpn.as_ref().unwrap().tls, OvpnTls::Pkcs1Only);
        assert_eq!(
            serde_json::to_value(defaulted).unwrap()["ovpn"]["tls"],
            "pkcs1_only"
        );
        value["ovpn"]["unknown"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<Profile>(value).is_err());
    }

    #[test]
    fn legacy_profile_serialization_bytes_are_unchanged() {
        for wire in [
            r#"{"id":"one","name":"Example","kind":"ipsec","gateway":"vpn.example.com","username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"}"#,
            r#"{"id":"one","name":"Example","kind":"ssl","gateway":"vpn.example.com","username":"fictional","networks":[],"dnsDomains":["example.com"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"}"#,
        ] {
            let profile: Profile = serde_json::from_str(wire).unwrap();
            assert_eq!(profile.validate(), Ok(()));
            assert!(profile.ovpn.is_none());
            assert_eq!(serde_json::to_vec(&profile).unwrap(), wire.as_bytes());
        }
    }

    #[test]
    fn ovpn_requires_settings_and_legacy_kinds_reject_them() {
        let mut missing = ovpn_profile();
        missing.ovpn = None;
        assert_eq!(missing.validate(), Err("invalid_profile"));

        let settings = ovpn_profile().ovpn;
        let mut legacy = profile();
        for kind in [VpnKind::Ssl, VpnKind::Ipsec] {
            legacy.kind = kind;
            assert_eq!(legacy.validate(), Ok(()));
            legacy.ovpn.clone_from(&settings);
            assert_eq!(legacy.validate(), Err("invalid_profile"));
            legacy.ovpn = None;
        }
    }

    #[test]
    fn ovpn_certificate_id_and_module_validation() {
        for invalid in [
            "123".into(),
            "AF".into(),
            "0g".into(),
            "".into(),
            "a".repeat(130),
        ] {
            let mut profile = ovpn_profile();
            profile.ovpn.as_mut().unwrap().certificate_id = invalid;
            assert_eq!(profile.validate(), Err("invalid_profile"));
        }
        for valid in ["01".into(), "a".repeat(128)] {
            let mut profile = ovpn_profile();
            profile.ovpn.as_mut().unwrap().certificate_id = valid;
            assert_eq!(profile.validate(), Ok(()));
        }
        for invalid in [
            "opt/token.so".into(),
            "/opt/../token.so".into(),
            "/opt/token.dylib".into(),
            "/opt/token\n.so".into(),
            format!("/{}.so", "é".repeat(2047)),
        ] {
            let mut profile = ovpn_profile();
            profile.ovpn.as_mut().unwrap().module = invalid;
            assert_eq!(profile.validate(), Err("invalid_profile"));
        }
        let mut boundary = ovpn_profile();
        boundary.ovpn.as_mut().unwrap().module = format!("/{}.so", "x".repeat(4092));
        assert_eq!(boundary.validate(), Ok(()));
    }

    #[test]
    fn ovpn_rejects_legacy_fields_without_relaxing_gateway_or_probe() {
        for (field, value) in [
            ("username", serde_json::json!("unused")),
            ("networks", serde_json::json!(["not-a-network"])),
            ("certificate", serde_json::json!("unused")),
        ] {
            let mut wire = serde_json::to_value(ovpn_profile()).unwrap();
            wire[field] = value;
            let profile: Profile = serde_json::from_value(wire).unwrap();
            assert_eq!(profile.validate(), Err("invalid_profile"));
        }
        let mut profile = ovpn_profile();
        profile.gateway = "not a host".into();
        assert_eq!(profile.validate(), Err("invalid_gateway"));
        let mut profile = ovpn_profile();
        profile.probe_port = 22;
        assert_eq!(profile.validate(), Err("invalid_probe"));
    }

    #[test]
    fn ovpn_dns_accepts_a_single_label_but_ssl_requires_a_dot() {
        assert_eq!(ovpn_profile().validate(), Ok(()));
        let mut ssl = profile();
        ssl.dns_domains = vec!["serpro".into()];
        assert_eq!(ssl.validate(), Err("invalid_profile"));
        ssl.dns_domains = vec!["serpro.example".into()];
        assert_eq!(ssl.validate(), Ok(()));

        for domains in [
            vec!["serpro".into(), "serpro".into()],
            vec!["-serpro".into()],
            vec!["serpro.".into()],
            (0..9).map(|i| format!("domain{i}")).collect(),
        ] {
            let mut profile = ovpn_profile();
            profile.dns_domains = domains;
            assert_eq!(profile.validate(), Err("invalid_profile"));
        }
        let mut boundary = ovpn_profile();
        boundary.dns_domains = (0..8).map(|i| format!("domain{i}")).collect();
        assert_eq!(boundary.validate(), Ok(()));
    }

    fn view(failure: Option<FailureView>) -> VpnView {
        VpnView {
            cleaning: false,
            cleanup_verifying: false,
            profile: profile(),
            state: ConnectionState::Dropped,
            failure,
            has_password: true,
            has_psk: false,
            log: vec![LogEntry {
                timestamp: 7,
                state: ConnectionState::Dropped,
                failure,
            }],
        }
    }

    // `ui/src/model.ts`: `failure?: FailureView` on the card and on each log
    // line, with `code` and `step` as snake_case strings, absent when empty.
    #[test]
    fn view_and_log_entry_match_the_ui_failure_contract() {
        let noted = serde_json::to_value(view(Some(FailureView {
            code: ErrorCode::BackendFailure,
            step: Step::Routes,
        })))
        .unwrap();
        let expected = serde_json::json!({"code":"backend_failure","step":"routes"});
        assert_eq!(noted["failure"], expected);
        assert_eq!(noted["log"][0]["failure"], expected);
        assert_eq!(
            noted["log"][0],
            serde_json::json!({"timestamp":7,"state":"dropped","failure":expected})
        );
        let plain = serde_json::to_value(view(None)).unwrap();
        assert!(plain.as_object().unwrap().get("failure").is_none());
        assert_eq!(
            plain["log"][0],
            serde_json::json!({"timestamp":7,"state":"dropped"})
        );
        // Every key the UI reads stays camelCase next to the new field.
        for key in ["cleanupVerifying", "hasPassword", "hasPsk"] {
            assert!(plain.get(key).is_some(), "{key}");
        }
    }

    #[test]
    fn every_step_serializes_as_the_ui_step_name() {
        let names: Vec<_> = [
            Step::Profile,
            Step::Runtime,
            Step::Egress,
            Step::Spawn,
            Step::Tunnel,
            Step::Routes,
            Step::Dns,
            Step::Verify,
            Step::Health,
        ]
        .into_iter()
        .map(|step| serde_json::to_value(step).unwrap())
        .collect();
        assert_eq!(
            names,
            [
                "profile", "runtime", "egress", "spawn", "tunnel", "routes", "dns", "verify",
                "health"
            ]
        );
    }
}
