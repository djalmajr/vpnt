//! SSL route backend. No per-key delete exists: after both owned processes
//! exit, close only our PPP/UTUN references and observe explicit/implicit routes.
mod registry;
mod retirement;
use super::{AddWriter, Error, Key, Route, Snapshot};
use crate::{
    connection::{
        macos::{ppp::OwnedPpp, ppp_attachment::PppAttachment, sink::OwnedSink},
        routes::{Backend, NextHop, Owner, Presence, ppp_networks},
    },
    helper::controller_lock::ControllerLock,
};
use registry::{Attempt, Registry, Scope, Table};
pub use registry::{InterfaceToken, NativeReceipt};
use retirement::Guard;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub struct NativeBackend<'a> {
    controller: &'a ControllerLock,
    registry: Registry<NativeScope<'a>, NativeTable<'a>>,
    retired: retirement::Queue,
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
            retired: Arc::new(Mutex::new(Vec::new())),
        })
    }
    /// Called with the root-stored profile's networks. The caller retains its
    /// Arc even on registration failure so it can still observe PPP shutdown.
    /// A full tunnel with one family creates its own disabled-packet UTUN for
    /// the missing family. Explicit unsupported split networks remain invalid.
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
        self.reap_retired()?;
        // A failed registration has no public token. Its original processes
        // and any partial aliases must retire before admitting another scope.
        retirement::admit(&self.retired)?;
        if self.registry.len() >= 64 {
            return Err(Error::Limit);
        }
        let index = u16::try_from(ppp.index()).map_err(|_| Error::Invalid)?;
        let ipv4 = ppp.addresses().any(|ip| ip.is_ipv4());
        let ipv6 = ppp.addresses().any(|ip| ip.is_ipv6());
        let needs_sink = networks.is_empty() && ipv4 != ipv6;
        // Validate split inputs before native allocation. Full/missing family
        // is planned only after its actual, owned sink index is known.
        let plan = if needs_sink {
            None
        } else {
            Some(ppp_networks(networks, index, ipv4, ipv6, None)?)
        };
        let writer = AddWriter::open(self.controller)?;
        let attachment =
            PppAttachment::retain(ppp, self.controller).map_err(|_| Error::Unavailable)?;
        let mut scope = NativeScope {
            ppp: ppp.clone(),
            attachment: Some(attachment),
            index,
            writer,
            canceled: canceled.clone(),
            sink: None,
            retirement: Guard::new(ppp.clone(), self.retired.clone()),
        };
        if needs_sink {
            match OwnedSink::create(!ipv4, self.controller) {
                Ok(sink) => {
                    scope.retirement.set_sink(Some(sink.identity()));
                    scope.sink = Some(sink);
                }
                Err(failure) => {
                    scope.retirement.set_sink(failure.retired);
                    return Err(failure.error); // Scope Drop preserves retirement
                }
            }
        }
        let plan = match plan {
            Some(plan) => plan,
            None => ppp_networks(
                networks,
                index,
                ipv4,
                ipv6,
                scope.retirement.sink().map(|sink| sink.index),
            )?,
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
        !self.registry.is_empty() || self.retired.lock().map_or(true, |queue| !queue.is_empty())
    }
    /// Also needed when discovery succeeded but registration failed before a
    /// scope was returned. This observes implicit PPP routes without deleting.
    pub fn ppp_cleanup_complete(&self, ppp: &Arc<OwnedPpp>) -> Result<bool, Error> {
        self.controller.validate().map_err(|_| Error::Unavailable)?;
        retirement::Retirement {
            ppp: Some(ppp.clone()),
            sink: None,
        }
        .complete()
    }
    /// Failed registration may have configured an alias before failing. Keep
    /// its passive retirement record until the original processes/ifnets and
    /// implicit routes are gone. This method never mutates machine resources.
    pub fn reap_retired(&mut self) -> Result<(), Error> {
        self.controller.validate().map_err(|_| Error::Unavailable)?;
        retirement::reap(&self.retired)
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
    sink: Option<OwnedSink<'a>>,
    // Last: descriptors above close before pending metadata enters the queue.
    retirement: Guard,
}
impl Scope for NativeScope<'_> {
    fn index(&self) -> u16 {
        self.index
    }
    fn owns(&self, index: u16) -> bool {
        self.index == index
            || self
                .retirement
                .sink()
                .is_some_and(|sink| sink.index == index)
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
        if let Some(sink) = &self.sink {
            sink.validate()?;
        }
        Ok(())
    }
    fn add(&mut self, route: Route) -> Result<Attempt, Error> {
        let receipt = match route.next_hop {
            NextHop::Interface if route.interface == self.index => self.writer.add(
                &self.ppp,
                self.attachment.as_ref().ok_or(Error::Busy)?,
                route.key.network,
                Duration::from_secs(2),
                &self.canceled,
            )?,
            NextHop::Blackhole => {
                let sink = self.sink.as_ref().ok_or(Error::Invalid)?;
                if sink.index() != route.interface {
                    return Err(Error::Invalid);
                }
                self.writer.add_sink(
                    sink,
                    route.key.network,
                    Duration::from_secs(2),
                    &self.canceled,
                )?
            }
            _ => return Err(Error::Invalid),
        };
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
        if let Some(sink) = self.sink.take() {
            self.retirement.set_sink(Some(sink.retire()));
        }
        Ok(true)
    }
    fn cleanup_complete(&mut self) -> Result<bool, Error> {
        if self.attachment.is_some() || self.sink.is_some() {
            return Ok(false);
        }
        self.retirement.complete()
    }
}
