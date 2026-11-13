use super::{Config, Error, Observer, Registry, Reservation};
use crate::{connection::routes::Owner, helper::vici::Client};
use crate::{helper::vici::Message, secrets::Credentials};
use std::{
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Instant,
};
mod backend;
mod io;
use io::Call;

/// Implementations must admit the original owned producer and its private
/// socket on every open. UID alone is insufficient. Retirement targets only
/// that producer, is idempotent, and returns true only after its observed exit.
pub trait Peer {
    fn open(
        &mut self,
        owner: &Owner,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<Client, Error>;
    fn retire(&mut self, owner: &Owner) -> Result<bool, Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Prepared,
    Dirty,
    Initiated,
    Released,
}

pub struct Control<N: Observer, P: Peer> {
    registry: Arc<Mutex<Registry<N>>>,
    reservation: Reservation,
    config: Config,
    peer: P,
    phase: Phase,
    version_verified: bool,
    loaded: bool,
    cleanup_sent: bool,
}

impl<N: Observer, P: Peer> Control<N, P> {
    /// A rejected constructor returns the still-owned reservation to its caller.
    pub fn new(
        registry: Arc<Mutex<Registry<N>>>,
        reservation: Reservation,
        config: Config,
        peer: P,
    ) -> Result<Self, (Error, Reservation)> {
        let valid = registry
            .lock()
            .map_err(|_| Error::Unavailable)
            .and_then(|r| r.validate(&reservation));
        if let Err(error) = valid {
            return Err((error, reservation));
        }
        if !config.matches(&reservation) {
            return Err((Error::Changed, reservation));
        }
        Ok(Self {
            registry,
            reservation,
            config,
            peer,
            phase: Phase::Prepared,
            version_verified: false,
            loaded: false,
            cleanup_sent: false,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Initiation is not kernel admission, traffic proof, or Connected.
    /// Any failure consumes this attempt. Cleanup must settle its reservation.
    pub fn start(
        &mut self,
        credentials: Credentials,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::Changed);
        }
        self.phase = Phase::Dirty;
        let call = Call { expires, cancel };
        call.check()?;
        credentials
            .validate(crate::model::VpnKind::Ipsec)
            .map_err(|_| Error::Invalid)?;
        let version = self
            .exchange(&call, "version", Message::new(), &[])?
            .response;
        if version.get_text("daemon") != Some("charon")
            || version.get_text("version") != Some("6.1.0")
        {
            return Err(Error::Incompatible);
        }
        self.version_verified = true;
        // Real constructor evidence before any connection or shared secret is
        // serialized: a stale or foreign backend is refused here.
        let stats = self.exchange(&call, "stats", Message::new(), &[])?.response;
        backend::admit(&stats)?;
        let shared = self.config.shared(credentials)?;
        // Mark uncertainty before sending: a lost reply does not undo a load.
        self.loaded = true;
        self.ack(&call, "load-conn", self.config.connection())?;
        for message in shared {
            self.ack(&call, "load-shared", message)?;
        }
        self.registry
            .lock()
            .map_err(|_| Error::Unavailable)?
            .ensure_initiate_clear(&self.reservation)?;
        let request = self.config.initiate(call.remaining()?)?;
        self.ack(&call, "initiate", request)?;
        self.phase = Phase::Initiated;
        Ok(())
    }

    /// A fresh complete set of daemon candidates, never ownership or traffic.
    pub fn snapshot(
        &mut self,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<Vec<super::Candidate>, Error> {
        if self.phase != Phase::Initiated {
            return Err(Error::Changed);
        }
        let call = Call { expires, cancel };
        let mut request = Message::new();
        request.value("ike", self.config.name().as_bytes());
        let result = self.exchange(&call, "list-sas", request, &["list-sa"])?;
        let candidates = super::snapshot::parse(&self.config, result)?;
        call.check()?;
        self.validate()?;
        Ok(candidates)
    }

    /// Network cleanup is attempted once with a fresh non-canceled budget.
    /// Even if VICI fails, retire the original producer. Only the observer's
    /// stopped + absent proof releases the reservation; Drop never releases it.
    pub fn cleanup(&mut self, expires: Instant) -> Result<bool, Error> {
        if self.phase == Phase::Released {
            return Ok(true);
        }
        let admission = self.validate();
        self.phase = Phase::Dirty;
        if !self.cleanup_sent && admission.is_ok() {
            self.cleanup_sent = true;
            let call = Call {
                expires,
                cancel: Arc::new(AtomicBool::new(false)),
            };
            if self.version_verified && self.loaded {
                if let Ok(request) = call
                    .remaining()
                    .and_then(|timeout| self.config.terminate(timeout))
                {
                    let _ = self.ack(&call, "terminate", request);
                }
                let _ = self.ack(&call, "unload-conn", self.config.unload_connection());
                for message in self.config.unload_shared() {
                    let _ = self.ack(&call, "unload-shared", message);
                }
            }
        }
        let retired = self.peer.retire(self.reservation.owner())?;
        admission?;
        if !retired {
            return Ok(false);
        }
        match self
            .registry
            .lock()
            .map_err(|_| Error::Unavailable)?
            .release(&self.reservation)
        {
            Ok(()) => {
                self.phase = Phase::Released;
                Ok(true)
            }
            Err(Error::Busy) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn validate(&self) -> Result<(), Error> {
        self.registry
            .lock()
            .map_err(|_| Error::Unavailable)?
            .validate(&self.reservation)
    }
}
