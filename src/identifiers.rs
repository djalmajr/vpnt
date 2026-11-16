//! Immutable build identity. Python and build.rs read native/identifier-channels.conf.
pub const CHANNEL: &str = env!("VPNT_CHANNEL");
pub const BASE: &str = env!("VPNT_BASE");
pub const APP: &str = env!("VPNT_APP_ID");
pub const CREDENTIALS: &str = env!("VPNT_CREDENTIALS_ID");
pub const RUNTIME: &str = env!("VPNT_RUNTIME_ID");
pub const COMPONENT: &str = env!("VPNT_COMPONENT_ID");
pub const POLICY_PREFIX: &str = env!("VPNT_POLICY_PREFIX");
pub const POLICY_ALIAS: &str = env!("VPNT_POLICY_ALIAS");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiled_identity_and_consumers_follow_the_selected_channel() {
        let expected = match CHANNEL {
            "dev" => "dev.djalmajr.vpnt-dev",
            "prd" => "dev.djalmajr.vpnt",
            _ => panic!("unknown build channel"),
        };
        assert_eq!(BASE, expected);
        for id in [APP, CREDENTIALS, RUNTIME, COMPONENT] {
            assert!(id.starts_with(&format!("{BASE}.")));
        }
        for path in [
            crate::helper::paths::HELPER,
            crate::helper::paths::ASKPASS,
            crate::helper::paths::INSTALLER,
            crate::helper::paths::STAGING,
            crate::helper::paths::PINENTRY,
            crate::helper::paths::PPP_SUPERVISOR,
            env!("VPNT_RUNTIME_PATH"),
        ] {
            assert!(path.starts_with(&format!("/Library/PrivilegedHelperTools/{BASE}.")));
        }
        assert_eq!(POLICY_PREFIX, BASE.replace(['.', '-'], "_"));
        assert_eq!(POLICY_ALIAS, POLICY_PREFIX.to_uppercase());
        assert_eq!(
            crate::helper::paths::runtime_directory(),
            std::path::Path::new(env!("VPNT_RUNTIME_PATH")).join(env!("CARGO_PKG_VERSION"))
        );
    }
}
