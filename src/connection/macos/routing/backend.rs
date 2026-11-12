//! SSL route backend. No per-key delete exists: after both owned processes
//! exit, close only our PPP reference and observe every planned route.
mod registry;
use super::{AddWriter, Error, Key, Route, Snapshot};
use crate::{
    connection::{
        macos::{ppp::OwnedPpp, ppp_attachment::PppAttachment},
        routes::{Backend, Owner, Presence, ppp_networks},
    },
    helper::controller_lock::ControllerLock,
};
use registry::{Attempt, Registry, Scope, Table};
pub use registry::{InterfaceToken, NativeReceipt};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub struct NativeBackend<'a> {
    controller: &'a ControllerLock,
    registry: Registry<NativeScope<'a>, NativeTable<'a>>,
}
impl<'a> NativeBackend<'a> {
    pub fn new(controller: &'a ControllerLock) -> Result<Self, Error> {
        // SAFETY: UID queries have no memory preconditions.
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(Error::Unavailable);
        }
        controller.validate().map_err(|_| Error::Unavailable)?;
        Ok(Self {
            controller,
            registry: Registry::new(NativeTable(controller))?,
        })
    }
    /// Called with the root-stored profile's networks. The caller retains its
    /// Arc even on registration failure so it can still observe PPP shutdown.
    /// Unsupported-family full tunnel requires the forthcoming owned sink;
    /// this method fails instead of silently creating an incomplete full tunnel.
    pub fn register_ppp(
        &mut self,
        ppp: &Arc<OwnedPpp>,
        owner: Owner,
        networks: &[String],
        canceled: &Arc<AtomicBool>,
    ) -> Result<(InterfaceToken, Vec<Route>), Error> {
        self.controller.validate().map_err(|_| Error::Unavailable)?;
        if canceled.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        let index = u16::try_from(ppp.index()).map_err(|_| Error::Invalid)?;
        let ipv4 = ppp.addresses().any(|ip| ip.is_ipv4());
        let ipv6 = ppp.addresses().any(|ip| ip.is_ipv6());
        let plan = ppp_networks(networks, index, ipv4, ipv6, None)?;
        let attachment =
            PppAttachment::retain(ppp, self.controller).map_err(|_| Error::Unavailable)?;
        let scope = NativeScope {
            ppp: ppp.clone(),
            attachment: Some(attachment),
            index,
            writer: AddWriter::open(self.controller)?,
            canceled: canceled.clone(),
        };
        let token = self.registry.register(scope, owner, plan.clone())?;
        Ok((token, plan))
    }
    /// First stops admission. The caller must stop/reap the SSL driver; this
    /// releases our reference only after both kernel process watches report exit.
    /// true means reference released, not that routes have disappeared.
    pub fn begin_cleanup(&mut self, token: &InterfaceToken) -> Result<bool, Error> {
        self.registry.begin_cleanup(token)
    }
    /// Call after retry_cleanup. Checks all planned keys, including borrowed
    /// routes; the scope remains reserved if a route still uses its old index.
    pub fn finish_cleanup(&mut self, token: &InterfaceToken) -> Result<(), Error> {
        self.registry.finish_cleanup(token)
    }
    pub fn has_resources(&self) -> bool {
        !self.registry.is_empty()
    }
}
impl Backend for NativeBackend<'_> {
    type Receipt = NativeReceipt;
    fn authorize(&mut self, owner: &Owner, route: Route) -> Result<(), Error> {
        self.registry.authorize(owner, route)
    }
    fn existing(&mut self, key: Key) -> Result<Option<Route>, Error> {
        self.registry.existing(key)
    }
    fn create(&mut self, route: Route) -> Result<Self::Receipt, Error> {
        self.registry.create(route)
    }
    fn receipt_state(&mut self, receipt: &Self::Receipt) -> Result<Presence, Error> {
        self.registry.receipt_state(receipt)
    }
    fn remove(&mut self, receipt: &Self::Receipt) -> Result<(), Error> {
        self.registry.remove(receipt)
    }
}

struct NativeTable<'a>(&'a ControllerLock);
impl Table for NativeTable<'_> {
    fn exact(&mut self, key: Key) -> Result<Option<Route>, Error> {
        self.0.validate().map_err(|_| Error::Unavailable)?;
        Snapshot::read()?
            .exact(key)?
            .map(|record| record.route())
            .transpose()
    }
}
struct NativeScope<'a> {
    ppp: Arc<OwnedPpp>,
    attachment: Option<PppAttachment<'a>>,
    index: u16,
    writer: AddWriter<'a>,
    canceled: Arc<AtomicBool>,
}
impl Scope for NativeScope<'_> {
    fn index(&self) -> u16 {
        self.index
    }
    fn active(&self) -> Result<(), Error> {
        if self.canceled.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        self.attachment
            .as_ref()
            .ok_or(Error::Unavailable)?
            .validate()
            .map_err(|_| Error::Unavailable)?;
        if !self.ppp.is_current().map_err(|_| Error::Unavailable)? {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn add(&mut self, route: Route) -> Result<Attempt, Error> {
        if route.interface != self.index
            || route.next_hop != crate::connection::routes::NextHop::Interface
        {
            return Err(Error::Invalid);
        }
        let receipt = self.writer.add(
            &self.ppp,
            self.attachment.as_ref().ok_or(Error::Busy)?,
            route.key.network,
            Duration::from_secs(2),
            &self.canceled,
        )?;
        Ok(Attempt {
            confirmation: receipt.confirmation(),
        })
    }
    fn detach_if_stopped(&mut self) -> Result<bool, Error> {
        if !self
            .ppp
            .processes_exited()
            .map_err(|_| Error::Unavailable)?
        {
            return Ok(false);
        }
        // Drop only the FD we created; no PID signal, unit ioctl or route delete.
        drop(self.attachment.take());
        Ok(true)
    }
}
