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
    /// The module or its directory chain is not trusted.
    UntrustedModule,
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

/// The one directory whose group write admission tolerates, with the gid and
/// the uid it must carry. macOS ships `/Applications` as `root:admin 0775`,
/// and a process in `admin` already holds the user's powers, while the module
/// runs as the user, never as root. Every other target tolerates no directory.
#[cfg(target_os = "macos")]
const GROUP_WRITABLE: Option<(&str, u32, u32)> = Some(("/Applications", 80, 0));
#[cfg(not(target_os = "macos"))]
const GROUP_WRITABLE: Option<(&str, u32, u32)> = None;

fn admit_module(path: &str) -> Result<PathBuf, TokenError> {
    admit_module_with(
        path,
        &[0, unsafe { libc::geteuid() }],
        Path::new("/"),
        GROUP_WRITABLE,
    )
}

/// `group_writable` names the one directory whose group write is tolerated and
/// the gid and uid it must carry; it is compared as a canonical path, like
/// `resolved`.
fn admit_module_with(
    path: &str,
    owners: &[u32],
    stop_at: &Path,
    // Only macOS compiles the exception below; other targets keep the strict rule.
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] group_writable: Option<(
        &str,
        u32,
        u32,
    )>,
) -> Result<PathBuf, TokenError> {
    use std::os::unix::fs::MetadataExt;
    if !crate::model::valid_module_path(path) {
        return Err(TokenError::UntrustedModule);
    }
    let resolved = std::fs::canonicalize(path).map_err(|_| TokenError::Module)?;
    let stop = std::fs::canonicalize(stop_at).map_err(|_| TokenError::UntrustedModule)?;
    if !resolved.starts_with(&stop) || resolved == stop {
        return Err(TokenError::UntrustedModule);
    }
    let metadata = std::fs::metadata(&resolved).map_err(|_| TokenError::UntrustedModule)?;
    if !metadata.is_file() || !owners.contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
        return Err(TokenError::UntrustedModule);
    }
    #[cfg(target_os = "macos")]
    let group_writable = group_writable.and_then(|(tolerated, gid, uid)| {
        std::fs::canonicalize(tolerated)
            .ok()
            .map(|tolerated| (tolerated, gid, uid))
    });
    let mut directory = resolved.parent().ok_or(TokenError::UntrustedModule)?;
    loop {
        let metadata = std::fs::metadata(directory).map_err(|_| TokenError::UntrustedModule)?;
        if !metadata.is_dir() || !owners.contains(&metadata.uid()) {
            return Err(TokenError::UntrustedModule);
        }
        #[cfg(target_os = "macos")]
        let tolerated = tolerates_group_write(
            directory,
            &metadata,
            group_writable
                .as_ref()
                .map(|(tolerated, gid, uid)| (tolerated.as_path(), *gid, *uid)),
        );
        #[cfg(not(target_os = "macos"))]
        let tolerated = false;
        if metadata.mode() & 0o022 != 0 && !tolerated {
            return Err(TokenError::UntrustedModule);
        }
        if directory == stop {
            break;
        }
        directory = directory.parent().ok_or(TokenError::UntrustedModule)?;
    }
    Ok(resolved)
}

/// Whether `directory` is the one directory whose group write admission
/// tolerates: the canonical path, the gid and the uid passed in, and never
/// write for others. Any other directory keeps the strict rule.
#[cfg(target_os = "macos")]
fn tolerates_group_write(
    directory: &Path,
    metadata: &std::fs::Metadata,
    tolerated: Option<(&Path, u32, u32)>,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_dir()
        && metadata.mode() & 0o002 == 0
        && tolerated.is_some_and(|(path, gid, uid)| {
            directory == path && metadata.gid() == gid && metadata.uid() == uid
        })
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
        let Some(session) = open_session(&pkcs11, slot)? else {
            continue;
        };
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

fn open_session(pkcs11: &Pkcs11, slot: Slot) -> Result<Option<Session>, TokenError> {
    match pkcs11.open_ro_session(slot) {
        Ok(session) => Ok(Some(session)),
        // A token may be uninitialized or removed between discovery and opening.
        Err(Error::Pkcs11(RvError::TokenNotRecognized | RvError::TokenNotPresent, _)) => Ok(None),
        Err(error) => Err(error.into()),
    }
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
            let Some(session) = open_session(&pkcs11, slot)? else {
                continue;
            };
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
    with_admitted_module(module, admit_module, |module| {
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
    })
}

fn with_admitted_module<T>(
    module: &Path,
    admit: impl FnOnce(&str) -> Result<PathBuf, TokenError>,
    load: impl FnOnce(&Path) -> Result<T, TokenError>,
) -> Result<T, TokenError> {
    let canonical = admit(module.to_str().ok_or(TokenError::UntrustedModule)?)?;
    load(&canonical)
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
