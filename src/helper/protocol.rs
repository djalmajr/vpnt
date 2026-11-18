//! Private pipe protocol. Runtime commands cannot modify administrative policy.
use crate::{
    model::{Profile, VpnKind, valid_profile_id},
    preferences::ProbeInterval,
    secrets::Credentials,
    session::ConnectionState,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::{BufRead, Write},
};
use zeroize::Zeroizing;

pub const VERSION: u32 = 3;
/// Backwards-compatible capability/version carried by the initial snapshot ID.
/// A v3 helper treats it as an ordinary opaque request ID and echoes it.
pub const WAIT_CAPABILITY_SNAPSHOT_ID: &str = "snapshot-wait-v1";
pub const CLEANUP_PROBE_SNAPSHOT_ID: &str = "snapshot-cleanup-v1";
pub const CLEANUP_ACK_SNAPSHOT_ID: &str = "snapshot-cleanup-ack-v1";
/// Same probe/ack pattern as cleanup: only an app that sends this snapshot ID
/// receives failure notes; the helper answers with the ack ID. A helper that
/// predates it echoes the probe ID and never sends a note.
pub const FAILURE_NOTE_PROBE_SNAPSHOT_ID: &str = "failure-note-v1";
pub const FAILURE_NOTE_ACK_SNAPSHOT_ID: &str = "failure-note-ack-v1";
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Io,
    InvalidRequest,
    TooLarge,
    Truncated,
    UnsupportedVersion,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub command: Command,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Snapshot {},
    #[cfg(unix)]
    Diagnostics {},
    VerifyCleanup {
        profile: String,
    },
    Connect {
        id: String,
        generation: u64,
        interval: ProbeInterval,
        credentials: Credentials,
    },
    Disconnect {
        id: String,
        generation: u64,
    },
    Probe {
        id: String,
        generation: u64,
    },
    /// Global probe cadence for this UID/controller. It carries no credential,
    /// profile or network authority; the closed interval type is the only value.
    SetProbeInterval {
        interval: ProbeInterval,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRequest {
    pub id: String,
    pub command: AdminCommand,
}

// One command is decoded per admin request; boxing the profile would only
// move the allocation and touch every constructor.
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminCommand {
    SaveProfile {
        profile: Profile,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ovpn_config: Option<String>,
    },
    RemoveProfile {
        id: String,
    },
}

impl AdminCommand {
    /// Validates a bridge save before it is sent across the administration channel.
    pub fn for_save(profile: Profile, ovpn_config: Option<String>) -> Result<Self, &'static str> {
        if ovpn_config.is_some() && profile.kind != VpnKind::Ovpn {
            return Err("invalid_profile");
        }
        #[cfg(not(target_os = "linux"))]
        if ovpn_config.is_some() {
            return Err("unsupported");
        }
        #[cfg(target_os = "linux")]
        let ovpn_config = ovpn_config
            .map(|text| {
                crate::connection::ovpn::profile::inspect(text.as_bytes())
                    .map(|config| config.normalized)
                    .map_err(|_| "invalid_ovpn")
            })
            .transpose()?;
        profile.validate()?;
        Ok(Self::SaveProfile {
            profile,
            ovpn_config,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    UntrustedConfiguration,
    ProfileNotFound,
    ProfileBusy,
    InvalidSecret,
    MissingProgram,
    PermissionDenied,
    Unavailable,
    BackendFailure,
}

/// Step of a local attempt where its failure was born.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Profile,
    Runtime,
    Egress,
    Spawn,
    Tunnel,
    Routes,
    Dns,
    Verify,
    Health,
}

/// The helper's note on a failed attempt. A new attempt clears it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureNote {
    pub code: ErrorCode,
    pub step: Step,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelStatus {
    pub id: String,
    pub generation: u64,
    pub state: ConnectionState,
    /// Consecutive failed traffic probes. Only `Unresponsive` carries 1..=3.
    pub failures: u32,
    #[serde(default)]
    pub cleaning: bool,
    /// Sent only after `FAILURE_NOTE_PROBE_SNAPSHOT_ID`; absent from older helpers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureNote>,
}

/// No variant contains credentials or raw client output.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    AdminReady {
        protocol_version: u32,
        version: String,
    },
    PreviousSessionFinishing {
        protocol_version: u32,
        version: String,
    },
    Snapshot {
        id: String,
        protocol_version: u32,
        version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        build: Option<String>,
        profiles: Vec<Profile>,
        connections: Vec<TunnelStatus>,
    },
    #[cfg(unix)]
    Diagnostics {
        id: String,
        status: DiagnosticsStatus,
        logs: Vec<super::diagnostics::Log>,
    },
    Accepted {
        id: String,
    },
    Failed {
        id: String,
        error: ErrorCode,
    },
    Changed {
        profile_id: String,
        generation: u64,
        state: ConnectionState,
        failures: u32,
        #[serde(default)]
        cleaning: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<FailureNote>,
    },
    Fatal {
        error: ErrorCode,
    },
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticsStatus {
    Ready,
    Shared,
    Unavailable,
}

pub fn parse_request(bytes: &[u8]) -> Result<Request, ProtocolError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidRequest)?;
    if !valid_profile_id(&request.id) {
        return Err(ProtocolError::InvalidRequest);
    }
    match &request.command {
        Command::Snapshot {} => {}
        #[cfg(unix)]
        Command::Diagnostics {} => {}
        Command::VerifyCleanup { profile } if valid_profile_id(profile) => {}
        Command::VerifyCleanup { .. } => return Err(ProtocolError::InvalidRequest),
        Command::SetProbeInterval { .. } => {}
        Command::Connect {
            id,
            generation,
            credentials,
            ..
        } => {
            validate_operation(id, *generation)?;
            // The root runtime additionally checks PSK requirements against its
            // own stored profile type, never a type supplied by this request.
            credentials
                .validate_shape()
                .map_err(|_| ProtocolError::InvalidRequest)?;
        }
        Command::Disconnect { id, generation } | Command::Probe { id, generation } => {
            validate_operation(id, *generation)?
        }
    }
    Ok(request)
}

pub fn read_request(reader: &mut impl BufRead) -> Result<Option<Request>, ProtocolError> {
    read_frame(reader, MAX_REQUEST_BYTES)?
        .map(|bytes| parse_request(&bytes))
        .transpose()
}

pub fn read_admin_request(reader: &mut impl BufRead) -> Result<AdminRequest, ProtocolError> {
    let bytes = read_frame(reader, MAX_REQUEST_BYTES)?.ok_or(ProtocolError::InvalidRequest)?;
    // Administration is one-shot. Check EOF before returning anything that a
    // caller could execute, so a second document cannot follow a first mutation.
    if read_frame(reader, MAX_REQUEST_BYTES)?.is_some() {
        return Err(ProtocolError::InvalidRequest);
    }
    let request: AdminRequest =
        serde_json::from_slice(&bytes).map_err(|_| ProtocolError::InvalidRequest)?;
    if !valid_profile_id(&request.id) {
        return Err(ProtocolError::InvalidRequest);
    }
    match &request.command {
        AdminCommand::SaveProfile { profile, .. } => profile
            .validate()
            .map_err(|_| ProtocolError::InvalidRequest)?,
        AdminCommand::RemoveProfile { id } if valid_profile_id(id) => {}
        AdminCommand::RemoveProfile { .. } => return Err(ProtocolError::InvalidRequest),
    }
    Ok(request)
}

pub fn read_message(reader: &mut impl BufRead) -> Result<Option<Message>, ProtocolError> {
    let Some(bytes) = read_frame(reader, MAX_MESSAGE_BYTES)? else {
        return Ok(None);
    };
    let message: Message = match serde_json::from_slice(&bytes) {
        Ok(message) => message,
        Err(_) => {
            // An older helper's body predates this version's field set, so a
            // shape error would mask the skew (a v2 snapshot has no
            // `failures`). Classify from the raw version before rejecting the
            // shape; current-version bodies must still satisfy the strict
            // schema below and are never accepted through this branch.
            if version_skew(&bytes) {
                return Err(ProtocolError::UnsupportedVersion);
            }
            return Err(ProtocolError::InvalidRequest);
        }
    };
    match &message {
        Message::AdminReady {
            protocol_version,
            version,
        }
        | Message::PreviousSessionFinishing {
            protocol_version,
            version,
        } => {
            if *protocol_version != VERSION {
                return Err(ProtocolError::UnsupportedVersion);
            }
            if version.len() > 64 {
                return Err(ProtocolError::InvalidRequest);
            }
        }
        Message::Snapshot {
            id,
            protocol_version,
            version,
            build,
            profiles,
            connections,
        } => {
            if *protocol_version != VERSION {
                return Err(ProtocolError::UnsupportedVersion);
            }
            let mut ids = HashSet::new();
            let mut running = HashSet::new();
            if !valid_profile_id(id)
                || version.len() > 64
                || build
                    .as_ref()
                    .is_some_and(|value| !crate::install::valid_hash(value))
                || profiles.len() > 64
                || profiles
                    .iter()
                    .any(|profile| profile.validate().is_err() || !ids.insert(&profile.id))
                || connections.iter().any(|status| {
                    !ids.contains(&status.id)
                        || !running.insert(&status.id)
                        || !coherent_progress(
                            status.state,
                            status.failures,
                            status.cleaning,
                            status.failure.is_some(),
                        )
                })
            {
                return Err(ProtocolError::InvalidRequest);
            }
        }
        #[cfg(unix)]
        Message::Diagnostics { id, status, logs } => {
            use super::diagnostics::Status;
            let names = [
                "openfortivpn.log",
                "openfortivpn.previous.log",
                "charon.log",
                "charon.previous.log",
            ];
            if !valid_profile_id(id)
                || (*status != DiagnosticsStatus::Ready && !logs.is_empty())
                || (*status == DiagnosticsStatus::Ready
                    && (logs.len() != names.len()
                        || logs.iter().zip(names).any(|(log, name)| {
                            log.name != name
                                || log.text.len() > 65_536
                                || log.lines > 200
                                || log.text.lines().count() != log.lines
                                || (log.status != Status::Present
                                    && (!log.text.is_empty()
                                        || log.modified.is_some()
                                        || log.lines != 0))
                        })))
            {
                return Err(ProtocolError::InvalidRequest);
            }
        }
        Message::Accepted { id } | Message::Failed { id, .. } if !valid_profile_id(id) => {
            return Err(ProtocolError::InvalidRequest);
        }
        Message::Changed {
            profile_id,
            generation,
            state,
            failures,
            cleaning,
            failure,
        } => {
            validate_operation(profile_id, *generation)?;
            if !coherent_progress(*state, *failures, *cleaning, failure.is_some()) {
                return Err(ProtocolError::InvalidRequest);
            }
        }
        _ => {}
    }
    Ok(Some(message))
}

pub fn write_request(writer: &mut impl Write, request: &Request) -> Result<(), ProtocolError> {
    write_frame(writer, request, MAX_REQUEST_BYTES)
}

pub fn write_admin_request(
    writer: &mut impl Write,
    request: &AdminRequest,
) -> Result<(), ProtocolError> {
    write_frame(writer, request, MAX_REQUEST_BYTES)
}

pub fn write_message(writer: &mut impl Write, message: &Message) -> Result<(), ProtocolError> {
    write_frame(writer, message, MAX_MESSAGE_BYTES)
}

fn validate_operation(id: &str, generation: u64) -> Result<(), ProtocolError> {
    if !valid_profile_id(id) || generation == 0 {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

/// Every state except `Unresponsive` means zero consecutive traffic failures.
/// `Unresponsive` always follows at least one actual failed probe, so a counter
/// outside 1..=3 (including zero) is an incoherent wire payload. Cleanup and a
/// failure note belong only to the states a failed attempt ends in.
fn coherent_progress(state: ConnectionState, failures: u32, cleaning: bool, noted: bool) -> bool {
    if (cleaning || noted)
        && !matches!(
            state,
            ConnectionState::Dropped
                | ConnectionState::CredentialsRejected
                | ConnectionState::GatewayTimeout
                | ConnectionState::MissingProgram
        )
    {
        return false;
    }
    match state {
        ConnectionState::Unresponsive => (1..=3).contains(&failures),
        _ => failures == 0,
    }
}

/// True only for a versioned frame (`snapshot`/`admin_ready`) whose numeric
/// `protocol_version` differs from this build's. Every other malformed shape
/// stays `InvalidRequest`; this probe never accepts a body.
fn version_skew(bytes: &[u8]) -> bool {
    // Ignore the per-version body, while keeping serde's duplicate-field
    // rejection for the two fields used to classify the version.
    #[derive(Deserialize)]
    struct Header {
        #[serde(rename = "type")]
        kind: String,
        protocol_version: u64,
    }
    let Ok(header) = serde_json::from_slice::<Header>(bytes) else {
        return false;
    };
    matches!(header.kind.as_str(), "snapshot" | "admin_ready")
        && header.protocol_version != u64::from(VERSION)
}

fn read_frame(
    reader: &mut impl BufRead,
    limit: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, ProtocolError> {
    let mut frame = Zeroizing::new(Vec::new());
    loop {
        let available = reader.fill_buf().map_err(|_| ProtocolError::Io)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(ProtocolError::Truncated)
            };
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let length = end.unwrap_or(available.len());
        if length > limit - frame.len() {
            return Err(ProtocolError::TooLarge);
        }
        frame.extend_from_slice(&available[..length]);
        reader.consume(length + usize::from(end.is_some()));
        if end.is_some() {
            return if frame.is_empty() {
                Err(ProtocolError::InvalidRequest)
            } else {
                Ok(Some(frame))
            };
        }
    }
}

fn write_frame(
    writer: &mut impl Write,
    value: &impl Serialize,
    limit: usize,
) -> Result<(), ProtocolError> {
    let mut bytes =
        Zeroizing::new(serde_json::to_vec(value).map_err(|_| ProtocolError::InvalidRequest)?);
    if bytes.len() > limit {
        return Err(ProtocolError::TooLarge);
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .and_then(|()| writer.flush())
        .map_err(|_| ProtocolError::Io)
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    #[test]
    fn previous_session_finishing_requires_a_compatible_protocol_version() {
        let frame = format!(
            "{{\"type\":\"previous_session_finishing\",\"protocol_version\":{VERSION},\"version\":\"0.1.0\"}}\n"
        );
        assert!(read_message(&mut frame.as_bytes()).is_ok());
        let wrong = frame.replace(
            &format!("\"protocol_version\":{VERSION}"),
            "\"protocol_version\":999",
        );
        assert!(read_message(&mut wrong.as_bytes()).is_err());
    }
    #[test]
    fn snapshot_build_accepts_legacy_and_valid_hash_but_rejects_malformed_identity() {
        for (field, expected) in [
            (String::new(), true),
            (format!(",\"build\":\"{}\"", "a".repeat(64)), true),
            (format!(",\"build\":\"{}\"", "G".repeat(64)), false),
            (String::from(",\"build\":\"short\""), false),
        ] {
            let body = format!(
                "{{\"type\":\"snapshot\",\"id\":\"x\",\"protocol_version\":{VERSION},\"version\":\"0.1.0\",\"profiles\":[],\"connections\":[]{field}}}\n"
            );
            assert_eq!(
                read_message(&mut body.as_bytes()).is_ok(),
                expected,
                "field {field}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn diagnostics_request_never_accepts_a_path_or_uid_override() {
        assert!(parse_request(br#"{"id":"x","command":{"type":"diagnostics"}}"#).is_ok());
        for body in [
            r#"{"id":"x","command":{"type":"diagnostics","path":"/tmp/log"}}"#,
            r#"{"id":"x","command":{"type":"diagnostics","uid":501}}"#,
            r#"{"id":"x","command":{"type":"diagnostics","profile":"another"}}"#,
            r#"{"id":"x","uid":501,"command":{"type":"diagnostics"}}"#,
        ] {
            assert!(parse_request(body.as_bytes()).is_err(), "{body}");
        }
    }
    #[cfg(unix)]
    #[test]
    fn diagnostics_reply_rejects_wrong_order_duplicate_oversize_and_partial_items() {
        let names = [
            "openfortivpn.log",
            "openfortivpn.previous.log",
            "charon.log",
            "charon.previous.log",
        ];
        let logs: Vec<_> = names
            .iter()
            .map(|name| super::super::diagnostics::Log {
                name: (*name).into(),
                status: super::super::diagnostics::Status::Present,
                modified: Some(1),
                lines: 1,
                text: "safe\n".into(),
            })
            .collect();
        fn roundtrip(
            logs: Vec<super::super::diagnostics::Log>,
        ) -> Result<Option<Message>, ProtocolError> {
            let message = Message::Diagnostics {
                id: "diag-1".into(),
                status: DiagnosticsStatus::Ready,
                logs,
            };
            let mut bytes = vec![];
            write_message(&mut bytes, &message).unwrap();
            read_message(&mut &bytes[..])
        }
        assert!(roundtrip(logs.clone()).is_ok());
        let mut duplicate = logs.clone();
        duplicate[1].name = duplicate[0].name.clone();
        assert!(roundtrip(duplicate).is_err());
        let mut oversize = logs.clone();
        oversize[0].text = "x".repeat(65_537);
        assert!(roundtrip(oversize).is_err());
        let mut missing = logs;
        missing[0].status = super::super::diagnostics::Status::Missing;
        assert!(roundtrip(missing).is_err());
    }
    #[test]
    fn cleanup_status_round_trips_and_refuses_cleaning_on_active_states() {
        for state in [
            ConnectionState::GatewayTimeout,
            ConnectionState::CredentialsRejected,
            ConnectionState::Dropped,
            ConnectionState::MissingProgram,
        ] {
            for cleaning in [true, false] {
                let message = Message::Changed {
                    profile_id: "fixture".into(),
                    generation: 1,
                    state,
                    failures: 0,
                    cleaning,
                    failure: None,
                };
                let mut bytes = vec![];
                write_message(&mut bytes, &message).unwrap();
                assert!(
                    matches!(read_message(&mut &bytes[..]).unwrap(), Some(Message::Changed { state: actual, cleaning: c, .. }) if actual == state && c == cleaning)
                );
            }
        }
        for state in [
            ConnectionState::Off,
            ConnectionState::Connected,
            ConnectionState::Disconnecting,
            ConnectionState::Connecting,
            ConnectionState::Unresponsive,
        ] {
            assert!(!coherent_progress(
                state,
                if state == ConnectionState::Unresponsive {
                    1
                } else {
                    0
                },
                true,
                false
            ));
        }
        let status: TunnelStatus =
            serde_json::from_str(r#"{"id":"fixture","generation":1,"state":"off","failures":0}"#)
                .unwrap();
        assert!(!status.cleaning);
    }
}
