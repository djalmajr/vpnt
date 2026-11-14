//! One real domain for native IPsec: a verified context, one ledger and its
//! userspace observer registry. It grants no route/VIP/namespace authority by
//! itself; attempts must reserve through the ledger.
use super::*;

#[derive(Clone)]
pub(in crate::connection::controller::native) struct NativeDomain<'a> {
    context: Arc<NativeContext<'a>>,
    ledger: NativeLedger<'a>,
    registry: Arc<Mutex<Registry<UserspaceObserver<'a, NativeLedger<'a>>>>>,
}

impl<'a> NativeDomain<'a> {
    /// Build the single domain from the already-root-checked controller. Any
    /// failure means IPsec is unsupported; it must not prevent SSL.
    pub(in crate::connection::controller::native) fn new(
        controller: &'a ControllerLock,
    ) -> Result<Self, ErrorCode> {
        let context = NativeContext::new(controller).map_err(|_| ErrorCode::MissingProgram)?;
        let ledger = NativeLedger::new(context.clone()).map_err(|_| ErrorCode::MissingProgram)?;
        let observer = context.userspace_observer(ledger.clone());
        Ok(Self {
            context,
            ledger,
            registry: Arc::new(Mutex::new(Registry::new(observer))),
        })
    }

    pub(super) fn context(&self) -> &Arc<NativeContext<'a>> {
        &self.context
    }

    pub(super) fn ledger(&self) -> &NativeLedger<'a> {
        &self.ledger
    }

    pub(super) fn registry(
        &self,
    ) -> &Arc<Mutex<Registry<UserspaceObserver<'a, NativeLedger<'a>>>>> {
        &self.registry
    }

    /// Conservative domain-idle check: stop/fences/serialized records first,
    /// then reservations. Never a false-empty on a lock error.
    pub(in crate::connection::controller::native) fn idle(&self) -> bool {
        if self.ledger.reap().is_err() || self.ledger.has_resources() {
            return false;
        }
        match self.registry.lock() {
            Ok(registry) => !registry.has_reservations(),
            Err(_) => false,
        }
    }
}
