use std::path::{Path, PathBuf};

pub const HELPER: &str = env!("VPNT_HELPER_PATH");
pub const ASKPASS: &str = env!("VPNT_ASKPASS_PATH");
pub const INSTALLER: &str = env!("VPNT_INSTALLER_PATH");
pub const STAGING: &str = env!("VPNT_STAGING_PATH");
pub const PINENTRY: &str = env!("VPNT_PINENTRY_PATH");
pub const PPP_SUPERVISOR: &str = env!("VPNT_PPP_SUPERVISOR_PATH");
pub const USERS: &str = "/Library/Application Support/vpnt/users";
pub const STATE: &str = "/Library/Application Support/vpnt";

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

pub(crate) fn cleanup_log(state: &Path) -> PathBuf {
    state.join("logs").join("cleanup.log")
}
