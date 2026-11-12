use super::*;
use crate::{
    connection::{
        macos::{
            Interfaces,
            egress::Egress,
            ppp::{OwnedPpp, OwnershipError},
            ppp_early_cleanup, probe,
            routing::{InterfaceToken, NativeBackend, Snapshot},
        },
        routes::{Coordinator, Lease, Owner},
        ssl::{SslDriver, SslFailure, StartError},
    },
    helper::{
        controller_lock::ControllerLock,
        protocol::{Message, Request},
        runtime::{Runtime, RuntimeError},
    },
    model::VpnKind,
    storage::ProfileStore,
};
use std::sync::{
    Mutex,
    atomic::Ordering,
    mpsc::{Receiver, SyncSender},
};

type Routes<'a> = Arc<Mutex<Coordinator<NativeBackend<'a>>>>;
struct NativeFactory<'a> {
    routes: Routes<'a>,
}

/// Prepared root-side consumer. Not an installer or an elevation entrypoint.
/// The prepared helper binds uid to its inherited caller and keeps this
/// controller/lock alive through EOF and every outstanding cleanup. Installed
/// execution and the application broker remain unverified.
pub fn run_ssl(
    controller: &ControllerLock,
    uid: u32,
    requests: Receiver<Request>,
    output: SyncSender<Message>,
) -> Result<(), ErrorCode> {
    // SAFETY: queries have no memory preconditions; no process starts on denial.
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        return Err(ErrorCode::PermissionDenied);
    }
    controller
        .validate()
        .map_err(|_| ErrorCode::UntrustedConfiguration)?;
    let profiles = ProfileStore::for_user(uid)
        .and_then(|store| store.load())
        .map_err(|_| ErrorCode::UntrustedConfiguration)?;
    let profiles = profiles
        .into_iter()
        .filter(|profile| profile.kind == VpnKind::Ssl)
        .collect();
    let backend = NativeBackend::new(controller).map_err(|_| ErrorCode::Unavailable)?;
    let routes = Arc::new(Mutex::new(
        Coordinator::new(backend).map_err(|_| ErrorCode::Unavailable)?,
    ));
    engine::run(
        NativeFactory { routes },
        uid,
        profiles,
        requests,
        output,
        Timing::default(),
    )
}
impl<'a> Factory for NativeFactory<'a> {
    type Attempt = NativeAttempt<'a>;
    fn create(
        &self,
        profile: Profile,
        uid: u32,
        generation: u64,
        credentials: Credentials,
        canceled: Arc<AtomicBool>,
    ) -> Self::Attempt {
        NativeAttempt {
            owner: Owner {
                uid,
                profile: profile.id.clone(),
                generation,
            },
            profile,
            credentials: Some(credentials),
            routes: self.routes.clone(),
            canceled,
            before: None,
            before_routes: None,
            client: None,
            link: None,
            token: None,
            lease: None,
            spawn_attempted: false,
            stopped: false,
            uncertain_cleanup: false,
        }
    }
    fn idle(&self) -> bool {
        let Ok(mut routes) = self.routes.lock() else {
            return false;
        };
        routes.retry_cleanup();
        routes.backend_mut().reap_retired().is_ok()
            && !routes.has_resources()
            && !routes.backend_mut().has_resources()
    }
}
struct NativeAttempt<'a> {
    owner: Owner,
    profile: Profile,
    credentials: Option<Credentials>,
    routes: Routes<'a>,
    canceled: Arc<AtomicBool>,
    before: Option<Interfaces>,
    before_routes: Option<Snapshot>,
    client: Option<SslDriver>,
    link: Option<Arc<OwnedPpp>>,
    token: Option<InterfaceToken>,
    lease: Option<Lease>,
    spawn_attempted: bool,
    stopped: bool,
    uncertain_cleanup: bool,
}
impl NativeAttempt<'_> {
    fn client_health(&mut self) -> Result<(), Failure> {
        let update = self
            .client
            .as_mut()
            .ok_or_else(Failure::unavailable)?
            .poll()
            .map_err(|_| Failure::unavailable())?;
        if update.start_error.is_some() {
            return Err(Failure::unavailable());
        }
        if let Some(failure) = update.failure {
            return Err(Failure {
                state: match failure {
                    SslFailure::CredentialsRejected => ConnectionState::CredentialsRejected,
                    SslFailure::GatewayTimeout => ConnectionState::GatewayTimeout,
                },
                error: ErrorCode::BackendFailure,
            });
        }
        if update.exited {
            return Err(Failure::unavailable());
        }
        Ok(())
    }
    fn discover(&mut self) -> Result<bool, Failure> {
        if self.link.is_some() {
            return Ok(true);
        }
        let client = self.client.as_mut().ok_or_else(Failure::unavailable)?;
        let before = self.before.as_ref().ok_or_else(Failure::unavailable)?;
        match OwnedPpp::discover(client, before) {
            Ok(link) => {
                self.link = Some(Arc::new(link));
                Ok(true)
            }
            Err(OwnershipError::NotReady) => Ok(false),
            Err(_) => Err(Failure::unavailable()),
        }
    }
}
impl Attempt for NativeAttempt<'_> {
    fn start(&mut self, canceled: &AtomicBool) -> Result<(), Failure> {
        // Preflight failures have no spawned child. After attempting spawn,
        // uncertainty must survive even if setup returns an error.
        Runtime::installed()
            .and_then(|_| Runtime::verify_pinentry())
            .and_then(|_| Runtime::verify_ppp_supervisor())
            .map_err(|error| Failure {
                state: if error == RuntimeError::Missing {
                    ConnectionState::MissingProgram
                } else {
                    ConnectionState::Dropped
                },
                error: if error == RuntimeError::Missing {
                    ErrorCode::MissingProgram
                } else {
                    ErrorCode::UntrustedConfiguration
                },
            })?;
        let egress = Egress::select(&self.profile, canceled, Duration::from_secs(3))
            .map_err(|_| Failure::unavailable())?;
        self.before = Some(Interfaces::read().map_err(|_| Failure::unavailable())?);
        self.before_routes = Some(Snapshot::read().map_err(|_| Failure::unavailable())?);
        if canceled.load(Ordering::Acquire) {
            return Err(Failure::unavailable());
        }
        let credentials = self.credentials.take().ok_or_else(Failure::unavailable)?;
        self.client = Some(
            SslDriver::start(&self.profile, credentials, &egress, &self.canceled).map_err(
                |error| Failure {
                    state: if error == StartError::MissingProgram {
                        ConnectionState::MissingProgram
                    } else {
                        ConnectionState::Dropped
                    },
                    error: ErrorCode::BackendFailure,
                },
            )?,
        );
        self.spawn_attempted = true;
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        self.client_health()?;
        if !self.discover()? {
            return Ok(false);
        }
        let link = self.link.as_ref().unwrap();
        let mut routes = self.routes.lock().map_err(|_| Failure::unavailable())?;
        if self.token.is_none() {
            let (token, plan) = routes
                .backend_mut()
                .register_ppp(
                    link,
                    self.owner.clone(),
                    &self.profile.networks,
                    &self.canceled,
                )
                .map_err(|_| Failure::unavailable())?;
            self.token = Some(token); // retain before any fallible ADD/lease
            self.lease = Some(
                routes
                    .acquire(self.owner.clone(), &plan)
                    .map_err(|_| Failure::unavailable())?,
            );
        }
        routes
            .validate(self.lease.as_ref().ok_or_else(Failure::unavailable)?)
            .map_err(|_| Failure::unavailable())?;
        Ok(true)
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        self.client_health()?;
        let link = self.link.as_ref().ok_or_else(Failure::unavailable)?;
        if !link.is_current().unwrap_or(false) {
            return Err(Failure::unavailable());
        }
        self.routes
            .lock()
            .map_err(|_| Failure::unavailable())?
            .validate(self.lease.as_ref().ok_or_else(Failure::unavailable)?)
            .map_err(|_| Failure::unavailable())
    }
    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        let link = self.link.as_ref().ok_or_else(Failure::unavailable)?;
        match probe::probe(link, &self.profile, canceled, timeout) {
            probe::Outcome::Responsive(_) => Ok(true),
            probe::Outcome::Unresponsive | probe::Outcome::Canceled => Ok(false),
            _ => Err(Failure::unavailable()),
        }
    }
    fn cleanup(&mut self) -> bool {
        // A canceled connection may have reached PPP before the last poll.
        // Capture proof while its original parent is still alive, if possible.
        if self.link.is_none() && self.client.is_some() && !self.stopped {
            let _ = self.discover();
        }
        if !self.stopped {
            self.stopped = self
                .client
                .as_mut()
                .is_none_or(|client| client.stop().is_ok());
        }
        self.credentials = None;
        if !self.stopped || self.uncertain_cleanup {
            return false;
        }
        if !self.spawn_attempted {
            return true;
        }
        let Some(client) = &mut self.client else {
            return false;
        };
        if !client.children_complete().unwrap_or(false) {
            return false;
        }
        // A birth grant predates configd/address discovery. Process receipts
        // alone cannot prove that implicit network resources were removed.
        let Some(link) = &self.link else {
            if !client.ppp_may_have_run() {
                return true;
            }
            let (Some(before), Some(routes), Some(proof)) =
                (&self.before, &self.before_routes, client.supervised_ppp())
            else {
                return false;
            };
            return ppp_early_cleanup::complete(before, routes, proof.child()).unwrap_or(false);
        };
        let Ok(mut routes) = self.routes.lock() else {
            return false;
        };
        if let Some(lease) = self.lease.take()
            && routes.release(lease).is_err()
        {
            self.uncertain_cleanup = true;
            return false;
        }
        if let Some(token) = &self.token {
            if !routes.backend_mut().begin_cleanup(token).unwrap_or(false) {
                return false;
            }
            routes.retry_cleanup();
            if routes.has_owner(&self.owner) || routes.backend_mut().finish_cleanup(token).is_err()
            {
                return false;
            }
            self.token = None;
        }
        routes.retry_cleanup();
        !routes.has_owner(&self.owner)
            && routes.backend_mut().reap_retired().is_ok()
            && routes
                .backend_mut()
                .ppp_cleanup_complete(link)
                .unwrap_or(false)
    }
}
