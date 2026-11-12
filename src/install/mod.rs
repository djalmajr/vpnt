//! Closed installation payloads. Admission alone never grants access or writes
//! to the machine; privileged activation must retain its own controller lock.
#[cfg(target_os = "macos")]
pub mod bundle;
#[cfg(target_os = "macos")]
pub mod engine;
pub mod payload;
pub mod policy;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidManifest,
    UntrustedPath,
    Integrity,
    Incompatible,
    Io,
    PermissionDenied,
    Busy,
    Conflict,
    RecoveryRequired,
    PolicyRejected,
    InvalidRequest,
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
