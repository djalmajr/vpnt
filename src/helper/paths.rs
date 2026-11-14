use std::path::PathBuf;

pub const HELPER: &str = "/Library/PrivilegedHelperTools/dev.vpnt.helper";
pub const ASKPASS: &str = "/Library/PrivilegedHelperTools/dev.vpnt.askpass";
pub const INSTALLER: &str = "/Library/PrivilegedHelperTools/dev.vpnt.install";
pub const STAGING: &str = "/Library/PrivilegedHelperTools/dev.vpnt.staging";
pub const PINENTRY: &str = "/Library/PrivilegedHelperTools/dev.vpnt.pinentry";
pub const PPP_SUPERVISOR: &str = "/Library/PrivilegedHelperTools/dev.vpnt.pppd";
pub const USERS: &str = "/Library/Application Support/vpnt/users";
pub const STATE: &str = "/Library/Application Support/vpnt";

pub fn runtime_directory() -> PathBuf {
    PathBuf::from("/Library/PrivilegedHelperTools/dev.vpnt.runtime").join(env!("CARGO_PKG_VERSION"))
}

pub fn user_directory(uid: u32) -> Option<PathBuf> {
    (uid != 0).then(|| PathBuf::from(USERS).join(uid.to_string()))
}
