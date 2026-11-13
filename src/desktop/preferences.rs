//! App-scoped user defaults and login-item effects. Constructed only by the
//! non-demo desktop actor; no effect is applied when saved values are loaded.
use super::login_item;
use crate::preferences::{Preferences, host::*};
use objc2::rc::Retained;
use objc2_foundation::{NSBundle, NSString, NSUserDefaults};

const KEY: &str = "vpnt.native.preferences.v1";
const BUNDLE: &str = "dev.vpnt.app";
struct Native {
    defaults: Retained<NSUserDefaults>,
    login: Option<login_item::Adapter>,
}
pub(super) fn current_bundle() -> Result<Box<dyn Host>, Error> {
    if !NSBundle::mainBundle()
        .bundleIdentifier()
        .is_some_and(|value| value.to_string() == BUNDLE)
    {
        return Err(Error::StartupUnavailable);
    }
    Coordinator::restore(Native {
        defaults: NSUserDefaults::standardUserDefaults(),
        login: login_item::Adapter::current_bundle().ok(),
    })
    .map(|host| Box::new(host) as Box<dyn Host>)
}
fn status(value: login_item::Status) -> StartupStatus {
    match value {
        login_item::Status::Enabled => StartupStatus::Enabled,
        login_item::Status::RequiresApproval => StartupStatus::RequiresApproval,
        login_item::Status::NotRegistered | login_item::Status::NotFound => StartupStatus::Disabled,
    }
}
impl Backend for Native {
    fn load(&mut self) -> Result<Option<Preferences>, Error> {
        // Read the persistent app domain directly: standardUserDefaults search
        // fallbacks (arguments/global/registration) cannot supply opt-in flags.
        let Some(domain) = self
            .defaults
            .persistentDomainForName(&NSString::from_str(BUNDLE))
        else {
            return Ok(None);
        };
        let Some(value) = domain.objectForKey(&NSString::from_str(KEY)) else {
            return Ok(None);
        };
        let value = value.downcast::<NSString>().map_err(|_| Error::Storage)?;
        if value.length() > 1024 {
            return Err(Error::Storage);
        }
        decode(&value.to_string()).map(Some)
    }
    fn save(&mut self, preferences: Preferences) -> Result<(), Error> {
        let value = serde_json::to_string(&preferences).map_err(|_| Error::Storage)?;
        // SAFETY: both arguments are owned Foundation strings. Only the fixed
        // app preference key is written; this contains no profile or secret.
        unsafe {
            self.defaults
                .setObject_forKey(Some(&NSString::from_str(&value)), &NSString::from_str(KEY));
        }
        Ok(())
    }
    fn startup_status(&mut self) -> StartupStatus {
        self.login
            .as_ref()
            .and_then(|login| login.status().ok())
            .map(status)
            .unwrap_or(StartupStatus::Unavailable)
    }
    fn set_startup(&mut self, enabled: bool) -> Result<StartupStatus, StartupFailure> {
        let Some(login) = &self.login else {
            return Err(StartupFailure { observed: None });
        };
        login.set_enabled(enabled).map(status).map_err(|error| {
            let observed = match error {
                login_item::Error::Failed { observed } => observed.map(status),
                login_item::Error::Unavailable => None,
            };
            StartupFailure { observed }
        })
    }
}
fn decode(value: &str) -> Result<Preferences, Error> {
    if value.len() > 1024 {
        return Err(Error::Storage);
    }
    let value: serde_json::Value = serde_json::from_str(value).map_err(|_| Error::Storage)?;
    if !value.is_object() {
        return Err(Error::Storage);
    }
    serde_json::from_value(value).map_err(|_| Error::Storage)
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_unbundled_binary_cannot_open_app_defaults_or_login_item_effects() {
        assert!(super::current_bundle().is_err());
    }
    #[test]
    fn saved_preferences_use_the_closed_object_schema_and_bounded_decoder() {
        let valid = r#"{"interval":30,"notify":false,"reconnect":true,"startup":false}"#;
        assert_eq!(super::decode(valid).unwrap().interval.seconds(), 30);
        for invalid in [
            "[30,false,true,false]",
            "{}",
            r#"{"interval":45,"notify":false,"reconnect":true,"startup":false}"#,
            r#"{"interval":30,"notify":false,"reconnect":true,"startup":false,"path":"foreign"}"#,
        ] {
            assert!(super::decode(invalid).is_err());
        }
        assert!(super::decode(&" ".repeat(1025)).is_err());
    }
}
