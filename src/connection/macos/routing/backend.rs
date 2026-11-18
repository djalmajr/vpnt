//! Native routes for owned PPP and retained IPsec UTUN scopes, including
//! the scoped default used by a full tunnel’s physical transport.
mod ppp;
mod registry;
mod retained;
pub(crate) mod retirement;
mod utun_absence;
mod utun_retirement;
use super::{AddWriter, Error, Key, Record, Route, Snapshot, TransportDefault, TunnelPlan};
use crate::{
    connection::{
        macos::{ppp::OwnedPpp, ppp_attachment::PppAttachment, sink::OwnedSink},
        routes::{Backend, NextHop, Owner, Presence},
    },
    helper::controller_lock::ControllerLock,
};
use ppp::NativeScope;
use registry::{Attempt, Registry, Scope, Table};
pub use registry::{InterfaceToken, NativeReceipt};
use retained::{UtunQueue, UtunScope};
use retirement::Guard;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use utun_retirement::Lifecycle;

pub struct NativeBackend<'a> {
    controller: &'a ControllerLock,
    registry: Registry<RegisteredScope<'a>, NativeTable<'a>>,
    retired: retirement::Queue,
    utun_retired: UtunQueue<'a>,
}
impl<'a> NativeBackend<'a> {
    #[cfg(test)]
    pub(crate) fn fixture(controller: &'a ControllerLock) -> Result<Self, Error> {
        controller.validate().map_err(|_| Error::Unavailable)?;
        Ok(Self {
            controller,
            registry: Registry::new(NativeTable {
                controller,
                writer: None,
            })?,
            retired: Arc::new(Mutex::new(Vec::new())),
            utun_retired: Lifecycle::new(),
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture_retired(&mut self, owner: Owner) {
        self.retired.lock().unwrap().push(retirement::Retirement {
            owner: Some(owner),
            ppp: None,
            sink: None,
        });
    }
    #[cfg(test)]
    pub(crate) fn fixture_scope(&mut self, owner: Owner, route: Route) {
        self.registry
            .register(
                RegisteredScope::Fixture(route.interface),
                owner,
                vec![route],
            )
            .unwrap();
    }
    #[cfg(test)]
    pub(crate) fn fixture_has_scope(&self, owner: &Owner) -> bool {
        self.registry.owner_scope(owner).is_some()
    }
    pub fn new(controller: &'a ControllerLock) -> Result<Self, Error> {
        // SAFETY: UID queries have no memory preconditions.
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(Error::Unavailable);
        }
        controller.validate().map_err(|_| Error::Unavailable)?;
        Ok(Self {
            controller,
            registry: Registry::new(NativeTable {
                controller,
                writer: None,
            })?,
            retired: Arc::new(Mutex::new(Vec::new())),
            utun_retired: Lifecycle::new(),
        })
    }
    /// Stop route admission first. The PPP caller stops its driver; the UTUN
    /// scope retires its original peer before releasing its pin. `true` means
    /// references released, not that explicit/implicit routes have disappeared.
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
            || self.retired.lock().map_or(true, |queue| !queue.is_empty())
            || self.utun_retired.has_entries().unwrap_or(true)
    }
    /// Also needed when discovery succeeded but registration failed before a
    /// scope was returned. This observes implicit PPP routes without deleting.
    pub fn ppp_cleanup_complete(&self, ppp: &Arc<OwnedPpp>) -> Result<bool, Error> {
        self.controller.validate().map_err(|_| Error::Unavailable)?;
        retirement::Retirement {
            owner: None,
            ppp: Some(ppp.clone()),
            sink: None,
        }
        .complete()
    }
    /// Retry failed registrations: PPP retirement observes passively; UTUN
    /// retirement stops only its original peer and releases only its own pins,
    /// then checks fresh absence. No per-key route mutation is performed.
    pub fn reap_retired(&mut self) -> Result<(), Error> {
        self.controller.validate().map_err(|_| Error::Unavailable)?;
        retirement::reap(&self.retired)?;
        self.utun_retired.reap()
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

enum RegisteredScope<'a> {
    Ppp(NativeScope<'a>),
    Utun(UtunScope<'a>),
    #[cfg(test)]
    Fixture(u16),
}
impl Scope for RegisteredScope<'_> {
    fn index(&self) -> u16 {
        match self {
            Self::Ppp(scope) => scope.index(),
            Self::Utun(scope) => scope.index(),
            #[cfg(test)]
            Self::Fixture(index) => *index,
        }
    }
    fn owns(&self, index: u16) -> bool {
        match self {
            Self::Ppp(scope) => scope.owns(index),
            Self::Utun(scope) => scope.owns(index),
            #[cfg(test)]
            Self::Fixture(value) => *value == index,
        }
    }
    fn transport_default(&self) -> Option<(TransportDefault, &AtomicBool)> {
        match self {
            Self::Ppp(scope) => scope.transport_default(),
            Self::Utun(scope) => scope.transport_default(),
            #[cfg(test)]
            Self::Fixture(_) => None,
        }
    }
    fn active(&self) -> Result<(), Error> {
        match self {
            Self::Ppp(scope) => scope.active(),
            Self::Utun(scope) => scope.active(),
            #[cfg(test)]
            Self::Fixture(_) => Ok(()),
        }
    }
    fn add(&mut self, route: Route) -> Result<Attempt, Error> {
        match self {
            Self::Ppp(scope) => scope.add(route),
            Self::Utun(scope) => scope.add(route),
            #[cfg(test)]
            Self::Fixture(_) => Err(Error::Unavailable),
        }
    }
    fn detach_if_stopped(&mut self) -> Result<bool, Error> {
        match self {
            Self::Ppp(scope) => scope.detach_if_stopped(),
            Self::Utun(scope) => scope.detach_if_stopped(),
            #[cfg(test)]
            Self::Fixture(_) => Ok(false),
        }
    }
    fn cleanup_complete(&mut self) -> Result<bool, Error> {
        match self {
            Self::Ppp(scope) => scope.cleanup_complete(),
            Self::Utun(scope) => scope.cleanup_complete(),
            #[cfg(test)]
            Self::Fixture(_) => Ok(false),
        }
    }
}

struct NativeTable<'a> {
    controller: &'a ControllerLock,
    writer: Option<AddWriter<'a>>,
}
impl<'a> NativeTable<'a> {
    fn writer(&mut self) -> Result<&mut AddWriter<'a>, Error> {
        if self.writer.is_none() {
            self.writer = Some(AddWriter::open(self.controller)?);
        }
        Ok(self.writer.as_mut().expect("writer just initialized"))
    }
}
impl Table for NativeTable<'_> {
    fn exact(&mut self, key: Key) -> Result<Option<Route>, Error> {
        self.controller.validate().map_err(|_| Error::Unavailable)?;
        Snapshot::read()?
            .exact(key)?
            .map(|record| record.route())
            .transpose()
    }
    fn add_default(
        &mut self,
        route: TransportDefault,
        canceled: &AtomicBool,
    ) -> Result<Attempt, Error> {
        self.writer()?
            .add_transport_default(route, canceled)
            .map(|confirmation| Attempt { confirmation })
    }
    fn get_default(&mut self, route: TransportDefault) -> Result<Option<Record>, Error> {
        self.writer()?.get_transport_default(route)
    }
    fn delete_default(&mut self, route: TransportDefault) -> Result<Attempt, Error> {
        self.writer()?
            .delete_transport_default(route)
            .map(|confirmation| Attempt { confirmation })
    }
}
