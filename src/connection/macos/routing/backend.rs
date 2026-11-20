//! Native routes for owned PPP, retained IPsec and observed OpenVPN scopes,
//! including the scoped default used by a full tunnel’s physical transport.
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
        routes::{Backend, Coordinator, NextHop, Owner, Presence},
    },
    helper::controller_lock::ControllerLock,
};
use ppp::NativeScope;
use registry::{Attempt, Registry, Scope, Table};
pub use registry::{InterfaceToken, NativeReceipt};
use retained::UtunQueue;
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
                observe_cleanup_only: false,
                fixture: None,
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
    pub(crate) fn fixture_scope(&mut self, owner: Owner, route: Route) -> InterfaceToken {
        self.registry
            .register(
                RegisteredScope::Fixture(route.interface),
                owner,
                vec![route],
            )
            .unwrap()
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
                observe_cleanup_only: false,
                #[cfg(test)]
                fixture: None,
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
    /// Observe stale receipts without delegating any scoped-default DELETE to
    /// this retry. The coordinator can also hold claims from SSL attempts.
    pub(crate) fn retry_observed_cleanup(routes: &mut Coordinator<Self>) {
        routes
            .backend_mut()
            .registry
            .table_mut()
            .observe_cleanup_only = true;
        routes.retry_cleanup();
        routes
            .backend_mut()
            .registry
            .table_mut()
            .observe_cleanup_only = false;
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

#[allow(
    clippy::large_enum_variant,
    reason = "keep the PPP registry representation unchanged"
)]
enum RegisteredScope<'a> {
    Ppp(NativeScope<'a>),
    Utun(Box<dyn Scope + Send + 'a>),
    #[cfg(test)]
    Fixture(u16),
}
impl Scope for RegisteredScope<'_> {
    fn bind_work(&mut self, owner: &Owner) -> Result<(), Error> {
        match self {
            Self::Utun(scope) => scope.bind_work(owner),
            _ => Ok(()),
        }
    }

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
    observe_cleanup_only: bool,
    #[cfg(test)]
    fixture: Option<Arc<Mutex<FixtureRouteIo>>>,
}
impl<'a> NativeTable<'a> {
    fn check_cleanup_write(&self) -> Result<(), Error> {
        if self.observe_cleanup_only {
            return Err(Error::Busy);
        }
        Ok(())
    }

    fn writer(&mut self) -> Result<&mut AddWriter<'a>, Error> {
        if self.writer.is_none() {
            self.writer = Some(AddWriter::open(self.controller)?);
        }
        Ok(self.writer.as_mut().expect("writer just initialized"))
    }
}
impl Table for NativeTable<'_> {
    fn exact(&mut self, key: Key) -> Result<Option<Route>, Error> {
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            return Ok(fixture.lock().unwrap().rows.get(&key).copied());
        }
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
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            return Ok(fixture.lock().unwrap().add(route.route()));
        }
        self.writer()?
            .add_transport_default(route, canceled)
            .map(|confirmation| Attempt { confirmation })
    }
    fn get_default(&mut self, route: TransportDefault) -> Result<Option<Record>, Error> {
        self.check_cleanup_write()?;
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            let fixture = fixture.lock().unwrap();
            if !fixture.allow_default_delete {
                return Err(Error::Busy);
            }
            let expected = route.route();
            return Ok(fixture.rows.get(&expected.key).map(|row| Record {
                key: row.key,
                interface: row.interface,
                flags: libc::RTF_UP | libc::RTF_GATEWAY | libc::RTF_STATIC | libc::RTF_IFSCOPE,
                gateway: match row.next_hop {
                    NextHop::Gateway(address) => Some(super::Gateway::Address(address)),
                    _ => None,
                },
                source: None,
            }));
        }
        self.writer()?.get_transport_default(route)
    }
    fn delete_default(&mut self, route: TransportDefault) -> Result<Attempt, Error> {
        self.check_cleanup_write()?;
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            let mut fixture = fixture.lock().unwrap();
            fixture.default_deletes += 1;
            fixture.rows.remove(&route.route().key);
            return Ok(Attempt {
                confirmation: Ok(()),
            });
        }
        self.writer()?
            .delete_transport_default(route)
            .map(|confirmation| Attempt { confirmation })
    }
}

#[cfg(test)]
#[derive(Default)]
struct FixtureRouteIo {
    rows: std::collections::BTreeMap<Key, Route>,
    allow_default_delete: bool,
    default_deletes: usize,
}

#[cfg(test)]
impl FixtureRouteIo {
    fn add(&mut self, route: Route) -> Attempt {
        assert!(self.rows.insert(route.key, route).is_none());
        Attempt {
            confirmation: Ok(()),
        }
    }
}

#[cfg(test)]
struct FixtureDefault {
    route: TransportDefault,
    canceled: AtomicBool,
}

#[cfg(test)]
impl Scope for FixtureDefault {
    fn index(&self) -> u16 {
        30
    }

    fn transport_default(&self) -> Option<(TransportDefault, &AtomicBool)> {
        Some((self.route, &self.canceled))
    }

    fn active(&self) -> Result<(), Error> {
        Ok(())
    }

    fn add(&mut self, _: Route) -> Result<Attempt, Error> {
        unreachable!("fixture owns only the transport default")
    }

    fn detach_if_stopped(&mut self) -> Result<bool, Error> {
        Ok(true)
    }

    fn cleanup_complete(&mut self) -> Result<bool, Error> {
        Ok(true)
    }
}

#[cfg(test)]
impl NativeBackend<'_> {
    pub(crate) fn fixture_route_io(&mut self) {
        self.registry.table_mut().fixture = Some(Arc::default());
    }

    pub(crate) fn fixture_default(&mut self, owner: Owner, route: Route) -> InterfaceToken {
        self.registry
            .register(
                RegisteredScope::Utun(Box::new(FixtureDefault {
                    route: TransportDefault::try_from(route).unwrap(),
                    canceled: AtomicBool::new(false),
                })),
                owner,
                vec![route],
            )
            .unwrap()
    }

    pub(crate) fn fixture_remove_route(&mut self, route: Route) {
        assert_eq!(self.fixture_io().rows.remove(&route.key), Some(route));
    }

    pub(crate) fn fixture_allow_default_delete(&mut self) {
        self.fixture_io().allow_default_delete = true;
    }

    pub(crate) fn fixture_default_deletes(&mut self) -> usize {
        self.fixture_io().default_deletes
    }

    fn fixture_io(&mut self) -> std::sync::MutexGuard<'_, FixtureRouteIo> {
        self.registry
            .table_mut()
            .fixture
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
    }
}
