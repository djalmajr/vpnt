//! Security.framework access with a fixed service and explicitly selected keychain.
use crate::{
    model::{VpnKind, valid_profile_id},
    secrets::{Credentials, SecretError, SecretStore},
};
use security_framework::{
    item::{ItemClass, ItemSearchOptions},
    os::macos::keychain::SecKeychain,
};
use security_framework_sys::base::{
    errSecAuthFailed as AUTH_FAILED, errSecItemNotFound as ITEM_NOT_FOUND,
};
use zeroize::Zeroizing;

const SERVICE: &str = "dev.vpnt.credentials.v1";
// SecBase.h values absent from the sys crate's exported constants.
const INTERACTION_NOT_ALLOWED: i32 = -25308;
const USER_CANCELED: i32 = -128;

pub struct MacKeychain {
    keychain: SecKeychain,
}

impl MacKeychain {
    pub fn for_current_user() -> Result<Self, SecretError> {
        SecKeychain::default()
            .map(Self::from_keychain)
            .map_err(map_error)
    }

    /// An explicit keychain also lets tests use a disposable database without
    /// replacing the user's default keychain or default search list.
    pub fn from_keychain(keychain: SecKeychain) -> Self {
        Self { keychain }
    }

    fn account(id: &str, kind: VpnKind) -> Result<String, SecretError> {
        if !valid_profile_id(id) {
            return Err(SecretError::InvalidData);
        }
        Ok(format!(
            "{}:{id}",
            match kind {
                VpnKind::Ipsec => "ipsec",
                VpnKind::Ssl => "ssl",
            }
        ))
    }

    fn query(&self, account: &str) -> ItemSearchOptions {
        let mut query = ItemSearchOptions::new();
        query
            .keychains(std::slice::from_ref(&self.keychain))
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(account);
        query
    }
}

impl SecretStore for MacKeychain {
    fn contains(&self, id: &str, kind: VpnKind) -> Result<bool, SecretError> {
        // No load_data/load_refs flags: only test for existence, without reading
        // a password on the background snapshot/polling path.
        match self.query(&Self::account(id, kind)?).search() {
            Ok(_) => Ok(true),
            Err(error) if error.code() == ITEM_NOT_FOUND => Ok(false),
            Err(error) => Err(map_error(error)),
        }
    }

    fn load(&self, id: &str, kind: VpnKind) -> Result<Credentials, SecretError> {
        let (bytes, _item) = self
            .keychain
            .find_generic_password(SERVICE, &Self::account(id, kind)?)
            .map_err(map_error)?;
        if bytes.len() > 16384 {
            return Err(SecretError::InvalidData);
        }
        let credentials: Credentials =
            serde_json::from_slice(bytes.as_ref()).map_err(|_| SecretError::InvalidData)?;
        credentials.validate(kind)?;
        Ok(credentials)
    }

    fn save(&self, id: &str, kind: VpnKind, credentials: &Credentials) -> Result<(), SecretError> {
        credentials.validate(kind)?;
        let account = Self::account(id, kind)?;
        // Both values live in one item, so an interrupted update cannot mix an
        // old PSK with a new password. The temporary serialized buffer is cleared.
        let bytes =
            Zeroizing::new(serde_json::to_vec(credentials).map_err(|_| SecretError::InvalidData)?);
        self.keychain
            .set_generic_password(SERVICE, &account, &bytes)
            .map_err(map_error)
    }

    fn remove(&self, id: &str, kind: VpnKind) -> Result<(), SecretError> {
        // SecKeychainItem::delete discards OSStatus. This query API reports it.
        match self.query(&Self::account(id, kind)?).delete() {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }
}

fn map_error(error: security_framework::base::Error) -> SecretError {
    match error.code() {
        ITEM_NOT_FOUND => SecretError::Missing,
        AUTH_FAILED | INTERACTION_NOT_ALLOWED | USER_CANCELED => SecretError::Denied,
        _ => SecretError::Unavailable,
    }
}
