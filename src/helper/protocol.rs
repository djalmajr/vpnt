//! Private pipe protocol. Runtime commands cannot modify administrative policy.
#[cfg(unix)]
use crate::connection::ovpn::signing::{Hash, Padding};
use crate::{
    model::{Profile, VpnKind, valid_profile_id},
    preferences::ProbeInterval,
    secrets::Credentials,
    session::ConnectionState,
};
#[cfg(unix)]
use base64::{
    Engine as _,
    alphabet::STANDARD,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
#[cfg(unix)]
use serde::de::{Deserializer, Error as DeserializeError};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fmt;
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

/// Encoded-length ceilings for the remote signer: 16 KiB certificate DER,
/// 512 B signature and the 83 B SHA-512 DigestInfo openvpn can send.
#[cfg(unix)]
pub const SIGN_CERT_MAX_B64: usize = 21_848;
#[cfg(unix)]
pub const SIGN_SIGNATURE_MAX_B64: usize = 684;
#[cfg(unix)]
pub const SIGN_DATA_MAX_B64: usize = 112;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Io,
    InvalidRequest,
    TooLarge,
    Truncated,
    UnsupportedVersion,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub command: Command,
}

#[derive(Debug, Deserialize, Serialize)]
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
    /// App to component. No pending signature request may exist when this
    /// arrives in this slice; the runtime answers `InvalidRequest`.
    #[cfg(unix)]
    SignReply {
        id: u64,
        profile: String,
        generation: u64,
        epoch: u64,
        #[serde(deserialize_with = "deserialize_json_object")]
        result: SignReplyResult,
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
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        if ovpn_config.is_some() {
            return Err("unsupported");
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
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
    /// Component to app. The app never signs in this slice.
    #[cfg(unix)]
    SignRequest {
        id: u64,
        profile: String,
        generation: u64,
        epoch: u64,
        #[serde(deserialize_with = "deserialize_json_object")]
        op: SignOperation,
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

/// Strict base64 text. `Debug` shows only its length: a certificate DER from
/// ICP-Brasil carries the subject's CPF, so neither bytes nor text is logged.
#[cfg(unix)]
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct WireBase64<const LIMIT: usize>(String);

#[cfg(unix)]
impl<const LIMIT: usize> WireBase64<LIMIT> {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn decode(&self) -> Result<Vec<u8>, ProtocolError> {
        strict_base64()
            .decode(self.0.as_bytes())
            .map_err(|_| ProtocolError::InvalidRequest)
    }
}

#[cfg(unix)]
impl<const LIMIT: usize> fmt::Debug for WireBase64<LIMIT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WireBase64").field(&self.0.len()).finish()
    }
}

#[cfg(unix)]
impl<'de, const LIMIT: usize> Deserialize<'de> for WireBase64<LIMIT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty() || text.len() > LIMIT {
            return Err(DeserializeError::custom("invalid encoded length"));
        }
        strict_base64()
            .decode(text.as_bytes())
            .map_err(|_| DeserializeError::custom("invalid base64"))?;
        Ok(Self(text))
    }
}

#[cfg(unix)]
fn strict_base64() -> GeneralPurpose {
    GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new()
            .with_encode_padding(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
            .with_decode_allow_trailing_bits(false),
    )
}

/// `untagged` enums also accept positional sequences for their struct
/// variants. Both signer fields are closed objects on the wire: only a map is
/// accepted, so arrays, strings, numbers and null are refused. The entries are
/// handed on as they arrive, never collected into a map first, so a repeated
/// key reaches the derived decoder, which refuses it like the rest of the
/// protocol does, and `deny_unknown_fields` still applies.
#[cfg(unix)]
fn deserialize_json_object<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

#[cfg(unix)]
pub type CertificateBytes = WireBase64<SIGN_CERT_MAX_B64>;
#[cfg(unix)]
pub type SignatureBytes = WireBase64<SIGN_SIGNATURE_MAX_B64>;
#[cfg(unix)]
pub type SignDataBytes = WireBase64<SIGN_DATA_MAX_B64>;

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateOperationName {
    Certificate,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignOperationName {
    Sign,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pkcs1PaddingName {
    Pkcs1,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PssPaddingName {
    Pss,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PssHashName {
    Sha256,
    Sha384,
    Sha512,
}

#[cfg(unix)]
impl PssHashName {
    fn padding(self) -> Padding {
        match self {
            Self::Sha256 => Padding::Pss(Hash::Sha256),
            Self::Sha384 => Padding::Pss(Hash::Sha384),
            Self::Sha512 => Padding::Pss(Hash::Sha512),
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateOperation {
    pub op: CertificateOperationName,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pkcs1Operation {
    pub op: SignOperationName,
    pub padding: Pkcs1PaddingName,
    pub data: SignDataBytes,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PssOperation {
    pub op: SignOperationName,
    pub padding: PssPaddingName,
    pub hash: PssHashName,
    pub data: SignDataBytes,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SignFields {
    Pkcs1(Pkcs1Operation),
    Pss(PssOperation),
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SignOperation {
    Certificate(CertificateOperation),
    Sign(SignFields),
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignReplyError {
    Canceled,
    Unsupported,
    PinRequired,
    Unavailable,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateReply {
    pub certificate: CertificateBytes,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureReply {
    pub signature: SignatureBytes,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorReply {
    pub error: SignReplyError,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SignReplyResult {
    Certificate(CertificateReply),
    Signature(SignatureReply),
    Error(ErrorReply),
}

#[cfg(unix)]
fn validate_sign_operation(op: &SignOperation) -> Result<(), ProtocolError> {
    let SignOperation::Sign(fields) = op else {
        return Ok(());
    };
    let (padding, data) = match fields {
        SignFields::Pkcs1(fields) => (Padding::Pkcs1, &fields.data),
        SignFields::Pss(fields) => (fields.hash.padding(), &fields.data),
    };
    let bytes = data.decode()?;
    if !padding.accepts(&bytes) {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_sign_result(result: &SignReplyResult) -> Result<(), ProtocolError> {
    match result {
        SignReplyResult::Certificate(reply) => reply.certificate.decode().map(|_| ()),
        SignReplyResult::Signature(reply) => reply.signature.decode().map(|_| ()),
        SignReplyResult::Error(_) => Ok(()),
    }
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
        #[cfg(unix)]
        Command::SignReply {
            profile,
            generation,
            result,
            ..
        } => {
            validate_operation(profile, *generation)?;
            validate_sign_result(result)?;
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
        #[cfg(unix)]
        Message::SignRequest {
            profile,
            generation,
            op,
            ..
        } => {
            validate_operation(profile, *generation)?;
            validate_sign_operation(op)?;
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

#[cfg(all(test, unix))]
mod sign_protocol_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde_json::{Value, json};

    fn encoded(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    /// SHA-512 DigestInfo: the largest input `Padding::accepts` allows for PKCS#1.
    fn digest_info_sha512() -> Vec<u8> {
        let mut data = vec![
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ];
        data.extend(std::iter::repeat_n(7, 64));
        assert_eq!(data.len(), 83);
        data
    }

    fn sign_frame_fields(profile: &str, generation: u64, op: Value) -> String {
        json!({
            "type": "sign_request",
            "id": 7,
            "profile": profile,
            "generation": generation,
            "epoch": 9,
            "op": op
        })
        .to_string()
    }

    fn sign_frame(op: Value) -> String {
        sign_frame_fields("one", 1, op)
    }

    fn reply_frame_fields(profile: &str, generation: u64, result: Value) -> String {
        json!({
            "id": "req-1",
            "command": {
                "type": "sign_reply",
                "id": 7,
                "profile": profile,
                "generation": generation,
                "epoch": 9,
                "result": result
            }
        })
        .to_string()
    }

    fn reply_frame(result: Value) -> String {
        reply_frame_fields("one", 1, result)
    }

    fn pkcs1_op(data: &str) -> Value {
        json!({ "op": "sign", "padding": "pkcs1", "data": data })
    }

    fn read_sign(frame: &str) -> Result<Option<Message>, ProtocolError> {
        let mut framed = frame.to_owned();
        framed.push('\n');
        read_message(&mut framed.as_bytes())
    }

    fn parse_reply(frame: &str) -> Result<Request, ProtocolError> {
        parse_request(frame.as_bytes())
    }

    fn with_field(mut value: Value, key: &str, extra: Value) -> Value {
        value.as_object_mut().unwrap().insert(key.into(), extra);
        value
    }

    fn invalid_request<T>(result: Result<T, ProtocolError>) {
        assert!(matches!(result, Err(ProtocolError::InvalidRequest)));
    }

    #[test]
    fn operation_forms_round_trip_with_exact_json() {
        let digest = digest_info_sha512();
        let digest_b64 = encoded(&digest);
        let pss_data = [0x11u8; 48];
        let pss_b64 = encoded(&pss_data);
        let cases = [
            (
                SignOperation::Certificate(CertificateOperation {
                    op: CertificateOperationName::Certificate,
                }),
                json!({ "op": "certificate" }),
            ),
            (
                SignOperation::Sign(SignFields::Pkcs1(Pkcs1Operation {
                    op: SignOperationName::Sign,
                    padding: Pkcs1PaddingName::Pkcs1,
                    data: WireBase64(digest_b64.clone()),
                })),
                json!({ "op": "sign", "padding": "pkcs1", "data": digest_b64 }),
            ),
            (
                SignOperation::Sign(SignFields::Pss(PssOperation {
                    op: SignOperationName::Sign,
                    padding: PssPaddingName::Pss,
                    hash: PssHashName::Sha384,
                    data: WireBase64(pss_b64.clone()),
                })),
                json!({
                    "op": "sign",
                    "padding": "pss",
                    "hash": "sha384",
                    "data": pss_b64
                }),
            ),
        ];
        for (op, expected_op) in cases {
            let message = Message::SignRequest {
                id: 7,
                profile: "one".into(),
                generation: 1,
                epoch: 9,
                op,
            };
            let expected = json!({
                "type": "sign_request",
                "id": 7,
                "profile": "one",
                "generation": 1,
                "epoch": 9,
                "op": expected_op
            });
            assert_eq!(serde_json::to_value(&message).unwrap(), expected);
            let mut bytes = Vec::new();
            write_message(&mut bytes, &message).unwrap();
            let parsed = read_message(&mut &bytes[..]).unwrap().unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), expected);
        }
    }

    #[test]
    fn result_forms_round_trip_with_exact_json() {
        let signature = encoded(&[0x22u8; 64]);
        let cases = [
            (
                SignReplyResult::Certificate(CertificateReply {
                    certificate: WireBase64("MAA=".into()),
                }),
                json!({ "certificate": "MAA=" }),
            ),
            (
                SignReplyResult::Signature(SignatureReply {
                    signature: WireBase64(signature.clone()),
                }),
                json!({ "signature": signature }),
            ),
            (
                SignReplyResult::Error(ErrorReply {
                    error: SignReplyError::Canceled,
                }),
                json!({ "error": "canceled" }),
            ),
            (
                SignReplyResult::Error(ErrorReply {
                    error: SignReplyError::Unsupported,
                }),
                json!({ "error": "unsupported" }),
            ),
            (
                SignReplyResult::Error(ErrorReply {
                    error: SignReplyError::PinRequired,
                }),
                json!({ "error": "pin_required" }),
            ),
            (
                SignReplyResult::Error(ErrorReply {
                    error: SignReplyError::Unavailable,
                }),
                json!({ "error": "unavailable" }),
            ),
        ];
        for (result, expected_result) in cases {
            let request = Request {
                id: "req-1".into(),
                command: Command::SignReply {
                    id: 7,
                    profile: "one".into(),
                    generation: 1,
                    epoch: 9,
                    result,
                },
            };
            let expected = json!({
                "id": "req-1",
                "command": {
                    "type": "sign_reply",
                    "id": 7,
                    "profile": "one",
                    "generation": 1,
                    "epoch": 9,
                    "result": expected_result
                }
            });
            assert_eq!(serde_json::to_value(&request).unwrap(), expected);
            let mut bytes = Vec::new();
            write_request(&mut bytes, &request).unwrap();
            let parsed = parse_request(&bytes).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), expected);
        }
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_level() {
        let digest = encoded(&digest_info_sha512());
        let operations = [
            json!({ "op": "certificate" }),
            pkcs1_op(&digest),
            json!({
                "op": "sign",
                "padding": "pss",
                "hash": "sha256",
                "data": encoded(&[0u8; 32])
            }),
        ];
        for op in operations {
            assert!(read_sign(&sign_frame(op.clone())).is_ok());
            invalid_request(read_sign(&sign_frame(with_field(op, "extra", json!(1)))));
        }
        let mut message: Value =
            serde_json::from_str(&sign_frame(json!({"op":"certificate"}))).unwrap();
        message
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(1));
        invalid_request(read_sign(&message.to_string()));

        let results = [
            json!({ "certificate": "MAA=" }),
            json!({ "signature": "MAA=" }),
            json!({ "error": "canceled" }),
        ];
        for result in results {
            assert!(parse_reply(&reply_frame(result.clone())).is_ok());
            invalid_request(parse_reply(&reply_frame(with_field(
                result,
                "extra",
                json!(1),
            ))));
        }
        let mut request: Value =
            serde_json::from_str(&reply_frame(json!({"error":"canceled"}))).unwrap();
        request
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(1));
        invalid_request(parse_request(request.to_string().as_bytes()));
        request.as_object_mut().unwrap().remove("extra");
        request["command"]
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(1));
        invalid_request(parse_request(request.to_string().as_bytes()));
    }

    #[test]
    fn pkcs1_hash_pss_sha1_and_crossed_tags_are_rejected() {
        invalid_request(read_sign(&sign_frame(json!({
            "op": "sign",
            "padding": "pkcs1",
            "hash": "sha256",
            "data": encoded(&digest_info_sha512())
        }))));
        invalid_request(read_sign(&sign_frame(json!({
            "op": "sign",
            "padding": "pss",
            "hash": "sha1",
            "data": encoded(&[0u8; 20])
        }))));
        for op in [
            json!({ "op": "sign" }),
            json!({
                "op": "certificate",
                "padding": "pkcs1",
                "data": encoded(&digest_info_sha512())
            }),
            json!({ "op": "certificate", "hash": "sha256" }),
            json!({
                "op": "sign",
                "padding": "pss",
                "hash": "sha512",
                "data": "MAA="
            }),
        ] {
            invalid_request(read_sign(&sign_frame(op)));
        }
        assert!(
            read_sign(&sign_frame(json!({
                "op": "sign",
                "padding": "pss",
                "hash": "sha256",
                "data": encoded(&[0u8; 32])
            })))
            .is_ok()
        );
    }

    #[test]
    fn encoded_length_limits_accept_exactly_and_reject_over_limit_and_empty() {
        let cert = vec![0x30u8; 16 * 1024];
        let cert_b64 = encoded(&cert);
        assert_eq!(cert_b64.len(), SIGN_CERT_MAX_B64);
        assert!(parse_reply(&reply_frame(json!({ "certificate": cert_b64.clone() }))).is_ok());
        invalid_request(parse_reply(&reply_frame(json!({
            "certificate": format!("{cert_b64}A")
        }))));
        let over_cert = encoded(&vec![0x30u8; 16 * 1024 + 3]);
        assert_eq!(over_cert.len(), 21_852);
        invalid_request(parse_reply(&reply_frame(
            json!({ "certificate": over_cert }),
        )));

        let signature = vec![0x55u8; 512];
        let signature_b64 = encoded(&signature);
        assert_eq!(signature_b64.len(), SIGN_SIGNATURE_MAX_B64);
        assert!(parse_reply(&reply_frame(json!({ "signature": signature_b64.clone() }))).is_ok());
        invalid_request(parse_reply(&reply_frame(json!({
            "signature": format!("{signature_b64}A")
        }))));
        let over_signature = encoded(&vec![0x55u8; 514]);
        assert_eq!(over_signature.len(), 688);
        invalid_request(parse_reply(&reply_frame(
            json!({ "signature": over_signature }),
        )));

        let data_b64 = encoded(&digest_info_sha512());
        assert_eq!(data_b64.len(), SIGN_DATA_MAX_B64);
        assert!(read_sign(&sign_frame(pkcs1_op(&data_b64))).is_ok());
        invalid_request(read_sign(&sign_frame(pkcs1_op(&format!("{data_b64}A")))));
        let over_data = encoded(&[0x30u8; 85]);
        assert_eq!(over_data.len(), 116);
        invalid_request(read_sign(&sign_frame(pkcs1_op(&over_data))));

        invalid_request(parse_reply(&reply_frame(json!({ "certificate": "" }))));
        invalid_request(parse_reply(&reply_frame(json!({ "signature": "" }))));
        invalid_request(read_sign(&sign_frame(pkcs1_op(""))));
    }

    #[test]
    fn non_strict_base64_is_rejected_in_certificate_signature_and_data() {
        for bad in ["MA A=", "MAA=\n", "MAA", "MAA==", "AB=="] {
            invalid_request(parse_reply(&reply_frame(json!({ "certificate": bad }))));
            invalid_request(parse_reply(&reply_frame(json!({ "signature": bad }))));
            invalid_request(read_sign(&sign_frame(pkcs1_op(bad))));
        }
        assert!(parse_reply(&reply_frame(json!({ "certificate": "MAA=" }))).is_ok());
        assert!(parse_reply(&reply_frame(json!({ "signature": "MAA=" }))).is_ok());
        assert!(read_sign(&sign_frame(pkcs1_op(&encoded(&digest_info_sha512())))).is_ok());
    }

    #[test]
    fn data_must_satisfy_padding_accepts() {
        let digest = digest_info_sha512();
        assert!(read_sign(&sign_frame(pkcs1_op(&encoded(&digest)))).is_ok());
        let mut wrong_prefix = digest.clone();
        wrong_prefix[0] = 0x31;
        invalid_request(read_sign(&sign_frame(pkcs1_op(&encoded(&wrong_prefix)))));
        invalid_request(read_sign(&sign_frame(pkcs1_op(&encoded(&digest[..82])))));
        assert!(
            read_sign(&sign_frame(json!({
                "op": "sign",
                "padding": "pss",
                "hash": "sha256",
                "data": encoded(&[0x33u8; 32])
            })))
            .is_ok()
        );
        for len in [31usize, 33] {
            invalid_request(read_sign(&sign_frame(json!({
                "op": "sign",
                "padding": "pss",
                "hash": "sha256",
                "data": encoded(&vec![0x33u8; len])
            }))));
        }
    }

    #[test]
    fn sign_fields_accept_only_json_objects() {
        let pss_data = encoded(&[0x33u8; 32]);
        assert!(read_sign(&sign_frame(json!({ "op": "certificate" }))).is_ok());
        assert!(
            read_sign(&sign_frame(json!({
                "op": "sign", "padding": "pss", "hash": "sha256", "data": pss_data
            })))
            .is_ok()
        );
        for op in [
            json!(["certificate"]),
            json!(["sign", "pss", "sha256", pss_data]),
            json!(null),
            json!("certificate"),
        ] {
            invalid_request(read_sign(&sign_frame(op)));
        }
        assert!(parse_reply(&reply_frame(json!({ "error": "canceled" }))).is_ok());
        assert!(parse_reply(&reply_frame(json!({ "certificate": "MAA=" }))).is_ok());
        for result in [json!(["canceled"]), json!(["MAA="]), json!(null), json!(1)] {
            invalid_request(parse_reply(&reply_frame(result)));
        }
    }

    #[test]
    fn a_repeated_key_inside_op_or_result_is_refused() {
        // json! cannot repeat a key, so the frames are written by hand. Each
        // pair differs only in the repetition, which proves the frame itself
        // is otherwise valid.
        let pss = encoded(&[0x33u8; 32]);
        let other = encoded(&[0x44u8; 32]);
        let op = |inner: &str| {
            format!(
                r#"{{"type":"sign_request","id":7,"profile":"one","generation":1,"epoch":9,"op":{{{inner}}}}}"#
            )
        };
        let single = format!(r#""op":"sign","padding":"pss","hash":"sha256","data":"{pss}""#);
        assert!(read_sign(&op(&single)).is_ok());
        for repeated in [
            format!(r#"{single},"data":"{other}""#),
            format!(r#"{single},"hash":"sha256""#),
            format!(r#"{single},"padding":"pss""#),
            r#""op":"certificate","op":"certificate""#.to_string(),
        ] {
            invalid_request(read_sign(&op(&repeated)));
        }
        let result = |inner: &str| {
            format!(
                r#"{{"id":"req-1","command":{{"type":"sign_reply","id":7,"profile":"one","generation":1,"epoch":9,"result":{{{inner}}}}}}}"#
            )
        };
        assert!(parse_reply(&result(r#""error":"canceled""#)).is_ok());
        assert!(parse_reply(&result(r#""certificate":"MAA=""#)).is_ok());
        for repeated in [
            r#""error":"canceled","error":"unavailable""#,
            r#""certificate":"MAA=","certificate":"MAA=""#,
            r#""signature":"MAA=","signature":"MAA=""#,
        ] {
            invalid_request(parse_reply(&result(repeated)));
        }
    }

    #[test]
    fn pss_hash_names_map_to_their_exact_digest_lengths() {
        for (hash, len) in [("sha256", 32usize), ("sha384", 48), ("sha512", 64)] {
            let data = encoded(&vec![0x33u8; len]);
            assert!(
                read_sign(&sign_frame(json!({
                    "op": "sign", "padding": "pss", "hash": hash, "data": data
                })))
                .is_ok(),
                "{hash}/{len} must be accepted"
            );
            for (other, wrong_len) in [("sha256", 32usize), ("sha384", 48), ("sha512", 64)] {
                if other == hash {
                    continue;
                }
                invalid_request(read_sign(&sign_frame(json!({
                    "op": "sign", "padding": "pss", "hash": hash,
                    "data": encoded(&vec![0x33u8; wrong_len])
                }))));
            }
        }
    }

    #[test]
    fn sign_messages_require_valid_profile_and_nonzero_generation() {
        let op = pkcs1_op(&encoded(&digest_info_sha512()));
        for profile in ["", "bad id", "../etc"] {
            invalid_request(read_sign(&sign_frame_fields(profile, 1, op.clone())));
            invalid_request(parse_reply(&reply_frame_fields(
                profile,
                1,
                json!({ "error": "canceled" }),
            )));
        }
        invalid_request(read_sign(&sign_frame_fields("one", 0, op.clone())));
        invalid_request(parse_reply(&reply_frame_fields(
            "one",
            0,
            json!({ "error": "canceled" }),
        )));
        assert!(read_sign(&sign_frame(op)).is_ok());
        assert!(parse_reply(&reply_frame(json!({ "error": "canceled" }))).is_ok());
    }

    #[test]
    fn debug_never_shows_certificate_signature_or_sign_data() {
        let personal = b"subject=123.456.789-00";
        let personal_b64 = encoded(personal);
        let digest = digest_info_sha512();
        let data_b64 = encoded(&digest);
        let request = Message::SignRequest {
            id: 7,
            profile: "one".into(),
            generation: 1,
            epoch: 9,
            op: SignOperation::Sign(SignFields::Pkcs1(Pkcs1Operation {
                op: SignOperationName::Sign,
                padding: Pkcs1PaddingName::Pkcs1,
                data: WireBase64(data_b64.clone()),
            })),
        };
        let reply = Request {
            id: "req-1".into(),
            command: Command::SignReply {
                id: 7,
                profile: "one".into(),
                generation: 1,
                epoch: 9,
                result: SignReplyResult::Certificate(CertificateReply {
                    certificate: WireBase64(personal_b64.clone()),
                }),
            },
        };
        let request_debug = format!("{request:?}");
        let reply_debug = format!("{reply:?}");
        assert!(!request_debug.contains(&data_b64));
        assert!(!request_debug.contains(&format!("{digest:?}")));
        assert!(!reply_debug.contains(&personal_b64));
        assert!(!reply_debug.contains(&format!("{personal:?}")));
        assert!(request_debug.contains("WireBase64("));
        assert!(reply_debug.contains("WireBase64("));
    }

    #[test]
    fn largest_valid_sign_reply_is_below_64_kib() {
        let der = vec![0x30u8; 16 * 1024];
        let request = Request {
            id: "req-1".into(),
            command: Command::SignReply {
                id: 7,
                profile: "one".into(),
                generation: 1,
                epoch: 9,
                result: SignReplyResult::Certificate(CertificateReply {
                    certificate: WireBase64(encoded(&der)),
                }),
            },
        };
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request).unwrap();
        assert!(bytes.len() < 64 * 1024, "{} bytes", bytes.len());
        assert!(parse_request(&bytes).is_ok());
    }
}
