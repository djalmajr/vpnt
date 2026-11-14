//! Private pipe protocol. Runtime commands cannot modify administrative policy.
use crate::{
    model::{Profile, valid_profile_id},
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
pub const MAX_REQUEST_BYTES: usize = 65_536;
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

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminCommand {
    SaveProfile { profile: Profile },
    RemoveProfile { id: String },
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelStatus {
    pub id: String,
    pub generation: u64,
    pub state: ConnectionState,
    /// Consecutive failed traffic probes. Only `Unresponsive` carries 1..=3.
    pub failures: u32,
}

/// No variant contains credentials or raw client output.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    AdminReady {
        protocol_version: u32,
        version: String,
    },
    Snapshot {
        id: String,
        protocol_version: u32,
        version: String,
        profiles: Vec<Profile>,
        connections: Vec<TunnelStatus>,
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
    },
    Fatal {
        error: ErrorCode,
    },
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
        AdminCommand::SaveProfile { profile } => profile
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
                || profiles.len() > 64
                || profiles
                    .iter()
                    .any(|profile| profile.validate().is_err() || !ids.insert(&profile.id))
                || connections.iter().any(|status| {
                    !ids.contains(&status.id)
                        || !running.insert(&status.id)
                        || !coherent_progress(status.state, status.failures)
                })
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
        } => {
            validate_operation(profile_id, *generation)?;
            if !coherent_progress(*state, *failures) {
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
/// outside 1..=3 (including zero) is an incoherent wire payload.
fn coherent_progress(state: ConnectionState, failures: u32) -> bool {
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
