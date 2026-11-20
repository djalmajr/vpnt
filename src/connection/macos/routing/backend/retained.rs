//! Retained configured-UTUN scope, its original-producer adapter and the
//! typed registration entry point. Nothing here fabricates a configured link.
use super::super::resource_fence::RouteWork;
use super::utun_retirement::{Guard, Lifecycle, Pin, Retire, UtunPin};
use super::{AddWriter, Error, NativeBackend, Route, TransportDefault, TunnelPlan, retirement};
use crate::connection::{
    ipsec::{self, NativeContext, NativePeer, Peer},
    macos::{
        sink::{OwnedSink, RetiredSink},
        vip::{ConfiguredUtun, ovpn_link::OvpnUtun},
    },
    routes::{NextHop, Owner},
};
use std::{
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) type UtunQueue<'a> =
    Arc<Lifecycle<UtunPin<'a>, Arc<Mutex<NativePeer<'a>>>, RetiredSink>>;

impl Retire for Arc<Mutex<NativePeer<'_>>> {
    fn retire_peer(&self, owner: &Owner) -> Result<bool, Error> {
        let mut peer = self.try_lock().map_err(|_| Error::Busy)?;
        Peer::retire(&mut *peer, owner).map_err(map_ipsec)
    }
}

struct UtunScope<'a> {
    pin: UtunPin<'a>,
    peer: Arc<Mutex<NativePeer<'a>>>,
    context: Arc<NativeContext<'a>>,
    owner: Owner,
    index: u16,
    writer: AddWriter<'a>,
    canceled: Arc<AtomicBool>,
    sink: Option<OwnedSink<'a>>,
    transport_default: Option<TransportDefault>,
    // Last: descriptors above close before pending metadata enters the queue.
    retirement: Guard<UtunPin<'a>, Arc<Mutex<NativePeer<'a>>>, RetiredSink>,
}

impl super::registry::Scope for UtunScope<'_> {
    fn index(&self) -> u16 {
        self.index
    }
    fn owns(&self, index: u16) -> bool {
        self.index == index || self.sink.as_ref().is_some_and(|sink| sink.index() == index)
    }
    fn transport_default(&self) -> Option<(TransportDefault, &AtomicBool)> {
        self.transport_default
            .map(|route| (route, self.canceled.as_ref()))
    }
    fn active(&self) -> Result<(), Error> {
        // Total budget is fixed before any check and shared by every call.
        let deadline = Instant::now() + Duration::from_secs(2);
        if self.canceled.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        let link = self.pin.link().ok_or(Error::Changed)?;
        link.validate().map_err(map_ipsec)?;
        if let Some(sink) = self.sink.as_ref() {
            sink.validate().map_err(|_| Error::Changed)?;
        }
        let observation = self
            .context
            .observe_interface(&self.owner, deadline, self.canceled.clone())
            .map_err(map_ipsec)?;
        if observation.name() != link.name() || observation.index() != link.index() {
            return Err(Error::Changed);
        }
        // Same original shared peer, caller owner/deadline/cancel; the Client
        // is dropped immediately, no VICI command is sent.
        let mut peer = self.peer.try_lock().map_err(|_| Error::Busy)?;
        let client = Peer::open(&mut *peer, &self.owner, deadline, self.canceled.clone())
            .map_err(map_ipsec)?;
        drop(client);
        Ok(())
    }
    fn add(&mut self, route: Route) -> Result<super::registry::Attempt, Error> {
        let receipt = match route.next_hop {
            NextHop::Interface if route.interface == self.index => {
                let link = self.pin.link().ok_or(Error::Changed)?;
                self.writer.add_utun(
                    link,
                    route.key.network,
                    Duration::from_secs(2),
                    &self.canceled,
                )?
            }
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
        Ok(super::registry::Attempt {
            confirmation: receipt.confirmation(),
        })
    }
    fn detach_if_stopped(&mut self) -> Result<bool, Error> {
        // Confirmed original stop happens first; any failure keeps both pins
        // and the sink, and reports Busy for a bounded retry.
        self.retirement.detach()?;
        self.pin.release();
        if let Some(sink) = self.sink.take() {
            self.retirement.set_sink(Some(sink.retire()));
        }
        Ok(true)
    }
    fn cleanup_complete(&mut self) -> Result<bool, Error> {
        if self.sink.is_some() {
            return Ok(false);
        }
        self.retirement.complete()
    }
}

impl<'a> NativeBackend<'a> {
    /// Register the retained configured UTUN. The controller, owner and plan
    /// are the same ones used by the existing registry; the opaque link is the
    /// only source of index/VIP. The caller keeps its `Arc` on error and drops
    /// it during begin_cleanup after the original stop and before absence.
    pub(crate) fn register_utun(
        &mut self,
        link: &Arc<ConfiguredUtun<'a>>,
        producer: (Arc<NativeContext<'a>>, Arc<Mutex<NativePeer<'a>>>),
        owner: Owner,
        route_plan: TunnelPlan,
        canceled: &Arc<AtomicBool>,
        work: RouteWork,
    ) -> Result<(super::InterfaceToken, Vec<Route>), Error> {
        if work.owner() != &owner {
            return Err(Error::Invalid);
        }
        self.controller.validate().map_err(|_| Error::Unavailable)?;
        if !std::ptr::eq(self.controller, link.controller()) {
            return Err(Error::Invalid);
        }
        if canceled.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        let index = u16::try_from(link.index())
            .ok()
            .filter(|index| *index > 0)
            .ok_or(Error::Invalid)?;
        // Duplicate same owner/index is rejected before any guard or queue
        // entry exists, so it cannot retire the currently active producer.
        if self.registry.has_owner_or_index(&owner, index) {
            return Err(Error::Busy);
        }
        link.validate().map_err(map_ipsec)?;
        self.reap_retired()?;
        retirement::admit(&self.retired)?;
        if self.registry.len() >= 64 {
            return Err(Error::Limit);
        }
        let (context, peer) = producer;
        let deadline = Instant::now() + Duration::from_secs(2);
        let observation = context
            .observe_interface(&owner, deadline, canceled.clone())
            .map_err(map_ipsec)?;
        if observation.name() != link.name() || observation.index() != link.index() {
            return Err(Error::Changed);
        }
        {
            // Same original peer, bounded admission proof; the Client is
            // dropped without sending any VICI command.
            let mut peer = peer.try_lock().map_err(|_| Error::Busy)?;
            Peer::open(&mut *peer, &owner, deadline, canceled.clone()).map_err(map_ipsec)?;
        }
        let pin = UtunPin::new(link, index);
        let conflict = self.registry.has_owner_or_index(&owner, index);
        let mut retirement =
            self.utun_retired
                .open_guard(conflict, owner.clone(), pin.clone(), peer.clone())?;
        retirement.attach_work(work)?;
        let writer = AddWriter::open(self.controller)?;
        let sink = if let Some(sink_ipv4) = route_plan.sink_ipv4() {
            match OwnedSink::create(sink_ipv4, self.controller) {
                Ok(sink) => {
                    retirement.set_sink(Some(sink.identity()));
                    Some(sink)
                }
                Err(failure) => {
                    retirement.set_sink(failure.retired);
                    return Err(failure.error);
                }
            }
        } else {
            None
        };
        let (plan, transport_default) =
            route_plan.bind(index, sink.as_ref().map(|sink| sink.index()))?;
        let scope = UtunScope {
            pin,
            peer,
            context,
            owner: owner.clone(),
            index,
            writer,
            canceled: canceled.clone(),
            sink,
            transport_default,
            retirement,
        };
        let token = self.registry.register(
            super::RegisteredScope::Utun(Box::new(scope)),
            owner,
            plan.clone(),
        )?;
        Ok((token, plan))
    }
}

/// OpenVPN owns this utun's lifetime. The registry only borrows its
/// observed name/index and owns the linear route work.
struct OvpnScope<'a> {
    link: OvpnUtun,
    index: u16,
    address: Ipv4Addr,
    writer: OvpnRouteIo<'a>,
    canceled: Arc<AtomicBool>,
    work: RouteWork,
}

enum OvpnRouteIo<'a> {
    Native(AddWriter<'a>),
    #[cfg(test)]
    Fixture(Arc<std::sync::Mutex<super::FixtureRouteIo>>),
}

impl super::registry::Scope for OvpnScope<'_> {
    fn bind_work(&mut self, owner: &Owner) -> Result<(), Error> {
        self.work.bind(owner)
    }

    fn index(&self) -> u16 {
        self.index
    }

    fn active(&self) -> Result<(), Error> {
        if self.canceled.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        #[cfg(test)]
        if let OvpnRouteIo::Fixture(_) = self.writer {
            return Ok(());
        }
        if !self.link.address_current(self.address) {
            return Err(Error::Changed);
        }
        Ok(())
    }

    fn add(&mut self, route: Route) -> Result<super::registry::Attempt, Error> {
        if route.next_hop != NextHop::Interface || route.interface != self.index {
            return Err(Error::Invalid);
        }
        #[cfg(not(test))]
        let OvpnRouteIo::Native(writer) = &mut self.writer;
        #[cfg(test)]
        let writer = match &mut self.writer {
            OvpnRouteIo::Native(writer) => writer,
            OvpnRouteIo::Fixture(fixture) => return Ok(fixture.lock().unwrap().add(route)),
        };
        let receipt = writer.add_ovpn_utun(
            &self.link,
            self.address,
            route.key.network,
            Duration::from_secs(2),
            &self.canceled,
        )?;
        Ok(super::registry::Attempt {
            confirmation: receipt.confirmation(),
        })
    }

    fn detach_if_stopped(&mut self) -> Result<bool, Error> {
        // No producer or device descriptor is retained by this route scope.
        Ok(true)
    }

    fn cleanup_complete(&mut self) -> Result<bool, Error> {
        // Registry already observed fresh absence for every planned route.
        self.work.complete()?;
        Ok(true)
    }
}

impl<'a> NativeBackend<'a> {
    pub(crate) fn register_ovpn_utun(
        &mut self,
        link: &OvpnUtun,
        address: Ipv4Addr,
        owner: Owner,
        networks: &[String],
        canceled: &Arc<AtomicBool>,
        work: RouteWork,
    ) -> Result<(super::InterfaceToken, Vec<Route>), Error> {
        if work.owner() != &owner || networks.is_empty() {
            return Err(Error::Invalid);
        }
        self.controller.validate().map_err(|_| Error::Unavailable)?;
        let index = u16::try_from(link.index())
            .ok()
            .filter(|&index| index != 0)
            .ok_or(Error::Invalid)?;
        if self.registry.has_owner_or_index(&owner, index) {
            return Err(Error::Busy);
        }
        self.reap_retired()?;
        retirement::admit(&self.retired)?;
        TunnelPlan::prepare(
            networks,
            (true, false),
            || Err(Error::Invalid),
            |prepared| {
                // Up admits split IPv4 routes only. A full tunnel or a sink would
                // change the routing semantics of an empty/invalid push.
                let (plan, default) = prepared.bind(index, None)?;
                if default.is_some() || plan.iter().any(|route| route.key.network.prefix() < 8) {
                    return Err(Error::Invalid);
                }
                let open = || AddWriter::open(self.controller).map(OvpnRouteIo::Native);
                #[cfg(not(test))]
                let writer = open()?;
                #[cfg(test)]
                let writer = self
                    .registry
                    .table_mut()
                    .fixture
                    .clone()
                    .map_or_else(open, |fixture| Ok(OvpnRouteIo::Fixture(fixture)))?;
                let scope = OvpnScope {
                    link: link.clone(),
                    index,
                    address,
                    writer,
                    canceled: canceled.clone(),
                    work,
                };
                let token = self.registry.register(
                    super::RegisteredScope::Utun(Box::new(scope)),
                    owner,
                    plan.clone(),
                )?;
                Ok((token, plan))
            },
        )
    }
}

fn map_ipsec(error: ipsec::Error) -> Error {
    match error {
        ipsec::Error::Invalid | ipsec::Error::Incompatible | ipsec::Error::Rejected => {
            Error::Invalid
        }
        ipsec::Error::Busy => Error::Busy,
        ipsec::Error::Changed => Error::Changed,
        ipsec::Error::Unavailable | ipsec::Error::PermissionDenied | ipsec::Error::Exhausted => {
            Error::Unavailable
        }
        ipsec::Error::Canceled => Error::Canceled,
        ipsec::Error::Timeout => Error::TimedOut,
    }
}

#[cfg(test)]
#[path = "retained/current_tests.rs"]
mod current_tests;
#[cfg(test)]
#[path = "retained/tests.rs"]
mod tests;
