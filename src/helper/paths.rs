use std::path::{Path, PathBuf};

pub const HELPER: &str = env!("VPNT_HELPER_PATH");
pub const ASKPASS: &str = env!("VPNT_ASKPASS_PATH");
pub const INSTALLER: &str = env!("VPNT_INSTALLER_PATH");
pub const STAGING: &str = env!("VPNT_STAGING_PATH");
pub const PINENTRY: &str = env!("VPNT_PINENTRY_PATH");
pub const PPP_SUPERVISOR: &str = env!("VPNT_PPP_SUPERVISOR_PATH");
/// Private base for per-session OVPN directories created by the helper.
/// The installer does not create this path today (see `install/engine/tree.rs`).
/// Creating and keeping `STATE/ovpn` as root with mode 0700, and removing
/// orphaned sessions, belongs to the controller or installer in VPT-19.
/// `validate_base` uses `canonicalize()`, which refuses a missing base, so the
/// directory must exist before a session starts.
pub fn ovpn_sessions_directory() -> PathBuf {
    Path::new(STATE).join("ovpn")
}
pub const USERS: &str = "/Library/Application Support/vpnt/users";
pub const STATE: &str = "/Library/Application Support/vpnt";

pub fn fence_directory(uid: u32) -> PathBuf {
    Path::new(STATE).join("fences").join(uid.to_string())
}

pub fn runtime_directory() -> PathBuf {
    PathBuf::from(env!("VPNT_RUNTIME_PATH")).join(env!("CARGO_PKG_VERSION"))
}

pub fn user_directory(uid: u32) -> Option<PathBuf> {
    (uid != 0).then(|| PathBuf::from(USERS).join(uid.to_string()))
}

/// Production callers pass the controller's validated STATE directory;
/// fixtures pass their own controller root without touching installed state.
pub(crate) fn charon_log(state: &Path) -> PathBuf {
    state.join("logs").join("charon.log")
}

pub(crate) fn openfortivpn_log(state: &Path) -> PathBuf {
    state.join("logs").join("openfortivpn.log")
}

pub(crate) fn cleanup_log(state: &Path) -> PathBuf {
    state.join("logs").join("cleanup.log")
}
