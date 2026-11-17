use super::*;
use crate::connection::macos::egress::prepare_ssl_plan;

impl<'a> NativeBackend<'a> {
    pub(crate) fn retirement_queue(&self) -> retirement::Queue {
        self.retired.clone()
    }
    pub(crate) fn abandonment_sink(
        &self,
        owner: &Owner,
    ) -> Result<Option<crate::connection::fence::Sink>, Error> {
        match self.registry.owner_scope(owner) {
            None => Ok(None),
            Some(RegisteredScope::Ppp(scope)) => {
                Ok(scope
                    .retirement
                    .sink()
                    .map(|sink| crate::connection::fence::Sink {
                        name: sink.name.clone(),
                        index: u32::from(sink.index),
                        source: sink.source,
                    }))
            }
            Some(RegisteredScope::Utun(_)) => Err(Error::Invalid),
            #[cfg(test)]
            Some(RegisteredScope::Fixture(_)) => Ok(None),
        }
    }
    /// The queue is locked before persistence; this is infallible after the
    /// owner scope was validated while holding the coordinator lock.
    pub(crate) fn abandon_owner(
        &mut self,
        owner: &Owner,
        retired: &mut Vec<retirement::Retirement>,
    ) {
        if let Some(scope) = self.registry.take_owner(owner) {
            match scope {
                RegisteredScope::Ppp(mut scope) => scope.retirement.abandon(),
                #[cfg(test)]
                RegisteredScope::Fixture(_) => {}
                _ => unreachable!("owner scope validated before persistence"),
            }
        }
        retirement::detach(retired, owner);
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
        egress: Option<&crate::connection::macos::egress::Egress>,
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
        let index = u16::try_from(ppp.index())
            .ok()
            .filter(|index| *index != 0)
            .ok_or(Error::Invalid)?;
        let ipv4 = ppp.addresses().any(|ip| ip.is_ipv4());
        let ipv6 = ppp.addresses().any(|ip| ip.is_ipv6());
        prepare_ssl_plan(
            networks,
            (ipv4, ipv6),
            egress,
            // ready holds the coordinator lock through registration and acquire.
            Snapshot::read,
            |plan| {
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
                    transport_default: None,
                    retirement: Guard::new(ppp.clone(), owner.clone(), self.retired.clone()),
                };
                if let Some(sink_ipv4) = plan.sink_ipv4() {
                    match OwnedSink::create(sink_ipv4, self.controller) {
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
                let (plan, transport_default) =
                    plan.bind(index, scope.retirement.sink().map(|sink| sink.index))?;
                scope.transport_default = transport_default;
                let token = self.registry.register(
                    super::RegisteredScope::Ppp(scope),
                    owner,
                    plan.clone(),
                )?;
                Ok((token, plan))
            },
        )
    }
}

pub(super) struct NativeScope<'a> {
    ppp: Arc<OwnedPpp>,
    attachment: Option<PppAttachment<'a>>,
    index: u16,
    writer: AddWriter<'a>,
    canceled: Arc<AtomicBool>,
    sink: Option<OwnedSink<'a>>,
    transport_default: Option<TransportDefault>,
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
    fn transport_default(&self) -> Option<(TransportDefault, &AtomicBool)> {
        self.transport_default
            .map(|route| (route, self.canceled.as_ref()))
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
