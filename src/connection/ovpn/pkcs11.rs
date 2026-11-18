//! An RSA key held by a PKCS#11 token and addressed by CKA_ID. Objects are
//! found by class and id only: some modules (SerproID) reject label searches
//! and refuse attribute queries that generic helpers make before signing.
use super::{
    der,
    signing::{Hash, Padding},
};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error, RvError},
    mechanism::{
        Mechanism, MechanismType,
        rsa::{PkcsMgfType, PkcsPssParams},
    },
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::Ulong,
};
use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenError {
    /// The module could not be loaded or initialized.
    Module,
    /// No token holds a certificate and private key with this id.
    NotFound,
    /// The user declined or did not approve in time (CKR_FUNCTION_CANCELED).
    Canceled,
    /// The token wants a PIN; only protected authentication paths are handled.
    PinRequired,
    Failed(RvError),
}

impl From<Error> for TokenError {
    fn from(error: Error) -> Self {
        match error {
            Error::Pkcs11(RvError::FunctionCanceled, _) => Self::Canceled,
            Error::Pkcs11(code, _) => Self::Failed(code),
            _ => Self::Module,
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct CertificateInfo {
    pub id: Vec<u8>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

impl fmt::Debug for CertificateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id: String = self.id.iter().map(|byte| format!("{byte:02x}")).collect();
        f.debug_struct("CertificateInfo")
            .field("id", &id)
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish()
    }
}

/// List certificates whose key object is visible without authenticating.
pub fn list_certificates(module: &Path) -> Result<Vec<CertificateInfo>, TokenError> {
    let pkcs11 = context(module)?;
    let mut certificates = Vec::new();
    let mut seen = HashSet::new();
    for slot in pkcs11.get_slots_with_token()? {
        let session = pkcs11.open_ro_session(slot)?;
        // Finish the find before looking for private keys on the same session.
        let objects = session.find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])?;
        for object in objects {
            let Some(attributes) = object_result(
                session.get_attributes(object, &[AttributeType::Id, AttributeType::Value]),
            )?
            else {
                continue;
            };
            let mut id = None;
            let mut value = None;
            for attribute in attributes {
                match attribute {
                    Attribute::Id(bytes) => id = Some(bytes),
                    Attribute::Value(bytes) => value = Some(bytes),
                    _ => {}
                }
            }
            let (Some(id), Some(value)) = (id, value) else {
                continue;
            };
            if id.is_empty() || seen.contains(&id) {
                continue;
            }
            if !matches!(
                object_result(find(&session, ObjectClass::PRIVATE_KEY, &id))?,
                Some(Some(_))
            ) {
                continue;
            }
            let fields = der::read_certificate(&value);
            seen.insert(id.clone());
            certificates.push(CertificateInfo {
                id,
                subject: fields.subject,
                issuer: fields.issuer,
                not_before: fields.not_before,
                not_after: fields.not_after,
            });
            if certificates.len() == 32 {
                return Ok(certificates);
            }
        }
    }
    Ok(certificates)
}

fn object_result<T>(result: Result<T, Error>) -> Result<Option<T>, TokenError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(
            error @ Error::Pkcs11(
                RvError::SessionHandleInvalid | RvError::SessionClosed | RvError::DeviceRemoved,
                _,
            ),
        ) => Err(error.into()),
        Err(_) => Ok(None),
    }
}

pub struct TokenKey {
    pkcs11: Arc<Pkcs11>,
    slot: Slot,
    id: Vec<u8>,
    /// Kept open: closing a token's last session logs the user out, which
    /// would repeat the approval on every renegotiation.
    session: Option<Session>,
}

impl TokenKey {
    pub fn open(module: &Path, id: &[u8]) -> Result<Self, TokenError> {
        let pkcs11 = context(module)?;
        for slot in pkcs11.get_slots_with_token()? {
            let session = pkcs11.open_ro_session(slot)?;
            if find(&session, ObjectClass::CERTIFICATE, id)?.is_some() {
                return Ok(Self {
                    pkcs11,
                    slot,
                    id: id.to_vec(),
                    session: Some(session),
                });
            }
        }
        Err(TokenError::NotFound)
    }

    pub fn certificate(&mut self) -> Result<Vec<u8>, TokenError> {
        self.with_session(|session, id| {
            let Some(handle) = find(session, ObjectClass::CERTIFICATE, id)? else {
                return Ok(None);
            };
            Ok(session
                .get_attributes(handle, &[AttributeType::Value])?
                .into_iter()
                .find_map(|attribute| match attribute {
                    Attribute::Value(der) => Some(der),
                    _ => None,
                }))
        })?
        .ok_or(TokenError::NotFound)
    }

    /// Blocks while the token waits for the user, which for a cloud token
    /// means an approval on another device.
    pub fn sign(&mut self, padding: Padding, data: &[u8]) -> Result<Vec<u8>, TokenError> {
        let mechanism = mechanism(padding);
        let attempt = |session: &Session, id: &[u8]| -> Result<Option<Vec<u8>>, Error> {
            let Some(key) = find(session, ObjectClass::PRIVATE_KEY, id)? else {
                return Ok(None);
            };
            session.sign(&mechanism, key, data).map(Some)
        };
        // Some tokens hide private objects until login; others refuse to sign.
        match self.with_session(attempt) {
            Ok(Some(signature)) => Ok(signature),
            Ok(None) | Err(Error::Pkcs11(RvError::UserNotLoggedIn, _)) => {
                self.login()?;
                self.with_session(attempt)?.ok_or(TokenError::NotFound)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Only a protected authentication path logs in without a PIN; on other
    /// tokens an empty login could count as a wrong PIN and lock the card.
    fn login(&mut self) -> Result<(), TokenError> {
        if !self
            .pkcs11
            .get_token_info(self.slot)?
            .protected_authentication_path()
        {
            return Err(TokenError::PinRequired);
        }
        self.with_session(|session, _| match session.login(UserType::User, None) {
            Ok(()) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
            Err(error) => Err(error),
        })?;
        Ok(())
    }

    fn with_session<T>(
        &mut self,
        operation: impl Fn(&Session, &[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        match operation(
            session(&self.pkcs11, self.slot, &mut self.session)?,
            &self.id,
        ) {
            Err(Error::Pkcs11(RvError::SessionHandleInvalid | RvError::SessionClosed, _)) => {
                self.session = None;
                operation(
                    session(&self.pkcs11, self.slot, &mut self.session)?,
                    &self.id,
                )
            }
            result => result,
        }
    }
}

/// One initialized context per module for the life of the process. cryptoki
/// never finalizes on drop, and unloading a module that runs its own threads
/// (cloud tokens do) can crash; initializing it again would fail instead.
fn context(module: &Path) -> Result<Arc<Pkcs11>, TokenError> {
    static CONTEXTS: Mutex<Vec<(PathBuf, Arc<Pkcs11>)>> = Mutex::new(Vec::new());
    let mut contexts = CONTEXTS.lock().unwrap_or_else(|error| error.into_inner());
    if let Some((_, pkcs11)) = contexts.iter().find(|(path, _)| path == module) {
        return Ok(Arc::clone(pkcs11));
    }
    let pkcs11 = Pkcs11::new(module).map_err(|_| TokenError::Module)?;
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(_) => return Err(TokenError::Module),
    }
    let pkcs11 = Arc::new(pkcs11);
    contexts.push((module.to_path_buf(), Arc::clone(&pkcs11)));
    Ok(pkcs11)
}

fn session<'a>(
    pkcs11: &Pkcs11,
    slot: Slot,
    cached: &'a mut Option<Session>,
) -> Result<&'a Session, Error> {
    let session = match cached.take() {
        Some(session) => session,
        None => pkcs11.open_ro_session(slot)?,
    };
    Ok(cached.insert(session))
}

fn find(session: &Session, class: ObjectClass, id: &[u8]) -> Result<Option<ObjectHandle>, Error> {
    Ok(session
        .find_objects(&[Attribute::Class(class), Attribute::Id(id.to_vec())])?
        .into_iter()
        .next())
}

fn mechanism(padding: Padding) -> Mechanism<'static> {
    let Padding::Pss(hash) = padding else {
        return Mechanism::RsaPkcs;
    };
    let (hash_alg, mgf) = match hash {
        Hash::Sha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
        Hash::Sha224 => (MechanismType::SHA224, PkcsMgfType::MGF1_SHA224),
        Hash::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
        Hash::Sha384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384),
        Hash::Sha512 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512),
    };
    Mechanism::RsaPkcsPss(PkcsPssParams {
        hash_alg,
        mgf,
        s_len: Ulong::from(hash.digest_len() as u64),
    })
}

#[cfg(test)]
#[path = "pkcs11_tests.rs"]
mod tests;
