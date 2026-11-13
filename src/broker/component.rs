use super::*;
use crate::{
    install::client::{Error as ComponentError, Kind, Operation, Receipt},
    localization::Locale,
};
type Connector =
    Box<dyn FnMut(Kind, String, Locale, Instant) -> Result<Operation, ComponentError> + Send>;
pub(super) struct Flow {
    connect: Connector,
    current: Option<Pending>,
    completion: Option<(u64, Result<(), &'static str>)>,
    disabled: bool,
    closed: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Admitting,
    Quiescing,
    Running,
    Verifying,
}
struct Pending {
    token: u64,
    kind: Kind,
    client: Operation,
    expires: Instant,
    epoch: u64,
    phase: Phase,
    result: Option<Result<Receipt, ComponentError>>,
    reported: bool,
}
impl Flow {
    pub fn new() -> Self {
        Self {
            connect: Box::new(Operation::start),
            current: None,
            completion: None,
            disabled: false,
            closed: false,
        }
    }
    pub(super) fn busy(&self) -> bool {
        self.current.is_some() || self.completion.is_some()
    }
    pub(super) fn status(&self) -> Option<&'static str> {
        self.current.as_ref().map(|p| {
            if p.reported {
                "settling"
            } else {
                match p.kind {
                    Kind::Install => "installing",
                    Kind::Remove => "removing",
                }
            }
        })
    }
    pub(super) fn blocks_retry(&self) -> bool {
        self.closed
            || self.disabled
            || self
                .current
                .as_ref()
                .is_some_and(|p| p.phase != Phase::Verifying)
    }
    pub(super) fn close(&mut self) {
        self.closed = true;
        if let Some(p) = &mut self.current {
            p.client.close();
        }
    }
}
impl<S: SecretStore> Broker<S> {
    #[cfg(all(test, feature = "desktop"))]
    pub(crate) fn component_fixture(
        client: Client,
        secrets: S,
        connect: impl FnMut(Kind, String, Locale, Instant) -> Result<Operation, ComponentError>
        + Send
        + 'static,
        reconnect: impl FnMut() -> Result<Client, Error> + Send + 'static,
    ) -> Self {
        let mut broker = Self::new(Some(client), secrets);
        broker.component.connect = Box::new(connect);
        broker.retry = Some(retry::Retry::fixture(reconnect));
        broker
    }
    /// Refuse admission in actor tests without opening an installer/remover.
    #[cfg(all(test, feature = "desktop"))]
    pub(crate) fn refuse_components(mut self) -> Self {
        self.component.connect =
            Box::new(|_, _, _, _| Err(ComponentError::Rejected(crate::install::Error::Busy)));
        self
    }
    pub fn begin_component(
        &mut self,
        command: Command,
        locale: Locale,
        expires: Instant,
    ) -> Result<u64, &'static str> {
        self.poll();
        if self.component.closed {
            return Err("backend_unavailable");
        }
        if self.component.busy() || self.administration.busy() {
            return Err("component_busy");
        }
        if Instant::now() >= expires {
            return Err("component_expired");
        }
        let kind = match command {
            Command::InstallHelper {} => Kind::Install,
            Command::RemoveHelper {} => Kind::Remove,
            _ => return Err("invalid_request"),
        };
        let token = self.next.checked_add(1).ok_or("backend_unavailable")?;
        let client = (self.component.connect)(kind, format!("component-{token}"), locale, expires)
            .map_err(map_error)?;
        self.next = token;
        self.component.current = Some(Pending {
            token,
            kind,
            client,
            expires,
            epoch: self.epoch,
            phase: Phase::Admitting,
            result: None,
            reported: false,
        });
        Ok(token)
    }
    pub fn take_component_result(&mut self) -> Option<(u64, Result<Snapshot, &'static str>)> {
        let (token, result) = self.component.completion.take()?;
        Some((token, result.map(|()| self.snapshot())))
    }
    pub fn component_busy(&self) -> bool {
        self.component.busy()
    }
    pub(super) fn poll_component(&mut self) {
        let Some(mut op) = self.component.current.take() else {
            return;
        };
        if op.result.is_none() {
            op.result = op.client.poll();
        }
        if Instant::now() >= op.expires {
            op.client.close();
            if !op.reported {
                self.component.completion = Some((op.token, Err("component_expired")));
                op.reported = true;
            }
        }
        if let Some(Err(error)) = op.result
            && !op.reported
        {
            self.component.completion = Some((op.token, Err(map_error(error))));
            op.reported = true;
        }
        if op.reported {
            if op.client.finished() {
                if op.kind == Kind::Install && matches!(op.phase, Phase::Running | Phase::Verifying)
                {
                    self.component.disabled = false;
                    self.enable_runtime();
                } else if !self.component.disabled {
                    self.wake_runtime();
                }
                return;
            }
        } else {
            if op.phase == Phase::Admitting && op.client.prepared() {
                self.lost(false);
                op.phase = Phase::Quiescing;
            }
            if op.phase == Phase::Quiescing && self.client.as_ref().is_none_or(Client::finished) {
                op.client.proceed();
                op.phase = Phase::Running;
            }
            if op.phase == Phase::Running && op.client.finished() {
                match (&op.kind, &op.result) {
                    (Kind::Install, Some(Ok(Receipt::Installed { .. }))) => {
                        self.component.disabled = false;
                        self.enable_runtime();
                        op.epoch = self.epoch;
                        op.phase = Phase::Verifying;
                    }
                    (Kind::Remove, Some(Ok(Receipt::Removed { .. }))) => {
                        self.component.disabled = true;
                        self.client = None;
                        self.dead = true;
                        self.ready = false;
                        self.helper = "missing";
                        self.component.completion = Some((op.token, Ok(())));
                        return;
                    }
                    (_, Some(Ok(_))) => {
                        self.component.completion = Some((op.token, Err("component_unconfirmed")));
                        self.wake_runtime();
                        return;
                    }
                    _ => {}
                }
            }
            if op.phase == Phase::Verifying && self.ready && self.epoch > op.epoch {
                self.component.completion = Some((op.token, Ok(())));
                return;
            }
        }
        self.component.current = Some(op);
    }
    fn enable_runtime(&mut self) {
        if self.component.closed {
            return;
        }
        if self.retry.is_none() {
            self.retry = Some(retry::Retry::runtime());
        }
        self.wake_runtime();
    }
    fn wake_runtime(&mut self) {
        if let Some(retry) = &mut self.retry {
            retry.wake();
        }
    }
}
fn map_error(error: ComponentError) -> &'static str {
    match error {
        ComponentError::Expired => "component_expired",
        ComponentError::Canceled => "component_canceled",
        ComponentError::Untrusted | ComponentError::Incompatible => "component_incompatible",
        ComponentError::Rejected(crate::install::Error::Busy) => "component_busy",
        _ => "component_unconfirmed",
    }
}
#[cfg(test)]
mod tests;
