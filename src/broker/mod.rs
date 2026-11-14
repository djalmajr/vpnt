//! Normal application state. Only the authenticated helper's current generation
//! may report a connected tunnel; demo schedules never enter this model.
mod admin;
mod automatic;
mod behavior;
mod commands;
mod component;
mod retry;
mod snapshot;
use crate::{
    bridge::Command,
    helper::{
        client::{Client, Error},
        protocol::{self, Message, Request},
    },
    model::{LogEntry, Snapshot, VpnKind, VpnView},
    preferences::Preferences,
    secrets::{Credentials, SecretStore},
    session::ConnectionState as State,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Pending {
    id: String,
    previous: (u64, State),
    accepted: bool,
}
struct Connection {
    view: VpnView,
    generation: u64,
    pending: Option<Pending>,
    failures: u32,
    policy: behavior::Policy,
}
pub struct Broker<S: SecretStore> {
    client: Option<Client>,
    retry: Option<retry::Retry>,
    secrets: S,
    connections: BTreeMap<String, Connection>,
    helper: &'static str,
    ready: bool,
    dead: bool,
    next: u64,
    startup: Instant,
    administration: admin::Flow,
    component: component::Flow,
    epoch: u64,
    preferences: Preferences,
    notifier: Box<dyn crate::notifications::Notifier>,
    locale: crate::localization::Locale,
    automatic: std::collections::VecDeque<automatic::Action>,
    sent_interval: Option<crate::preferences::ProbeInterval>,
    preferences_host: Box<dyn crate::preferences::host::Host>,
}
impl<S: SecretStore> Broker<S> {
    pub fn runtime(secrets: S) -> Self {
        Self::reconnecting(retry::Retry::runtime(), secrets)
    }
    pub fn with_preferences_host(mut self, host: Box<dyn crate::preferences::host::Host>) -> Self {
        self.preferences = host.current();
        self.preferences_host = host;
        self
    }
    fn reconnecting(retry: retry::Retry, secrets: S) -> Self {
        let mut result = Self::new(None, secrets);
        result.retry = Some(retry);
        result.dead = true;
        result.resume();
        result
    }
    fn new(client: Option<Client>, secrets: S) -> Self {
        let mut result = Self {
            client,
            retry: None,
            secrets,
            connections: BTreeMap::new(),
            helper: "missing",
            ready: false,
            dead: false,
            next: 1,
            startup: Instant::now() + Duration::from_secs(5),
            administration: admin::Flow::new(),
            component: component::Flow::new(),
            epoch: 1,
            preferences: Preferences::default(),
            notifier: Box::new(crate::notifications::Noop),
            locale: crate::localization::Locale::default(),
            automatic: automatic::queue(),
            sent_interval: None,
            preferences_host: Box::new(crate::preferences::host::Coordinator::memory()),
        };
        result.begin();
        result
    }
    fn begin(&mut self) {
        if self.client.as_ref().is_some_and(|c| {
            c.send(Request {
                id: "snapshot-1".into(),
                command: protocol::Command::Snapshot {},
            })
            .is_err()
        }) {
            self.lost(false);
        }
    }
    fn resume(&mut self) {
        let attempt = self
            .retry
            .as_mut()
            .and_then(|r| r.attempt(self.client.as_ref()));
        match attempt {
            Some(Ok(client)) => {
                self.epoch = self
                    .epoch
                    .checked_add(1)
                    .expect("helper channel epoch exhausted");
                self.client = Some(client);
                self.dead = false;
                self.ready = false;
                self.startup = Instant::now() + Duration::from_secs(5);
                self.begin();
            }
            Some(Err(error)) => self.lost(error == Error::Incompatible),
            None => {}
        }
    }
    fn lost(&mut self, outdated: bool) {
        if !self.dead
            && let Some(retry) = &mut self.retry
        {
            retry.defer();
        }
        self.dead = true;
        self.ready = false;
        self.sent_interval = None;
        self.automatic.clear();
        self.helper = if outdated { "outdated" } else { "missing" };
        if let Some(client) = &mut self.client {
            client.close();
        }
        for connection in self.connections.values_mut() {
            connection.pending = None;
            set_state(connection, State::HelperMissing);
        }
    }
    pub fn starting(&self) -> bool {
        !self.component.busy() && !self.dead && !self.ready && self.client.is_some()
    }
    pub fn poll(&mut self) {
        if (self.dead || self.client.is_none()) && !self.component.blocks_retry() {
            self.resume();
        }
        if self.dead {
            self.poll_admin();
            self.poll_component();
            return;
        }
        let result = self.client.as_mut().map(Client::poll);
        match result {
            Some(Ok(messages)) => {
                for message in messages {
                    if self.receive(message).is_err() {
                        self.lost(false);
                        break;
                    }
                    if self.dead {
                        break;
                    }
                }
            }
            Some(Err(error)) => self.lost(error == Error::Incompatible),
            None => {}
        }
        if !self.ready && self.client.is_some() && Instant::now() >= self.startup {
            self.lost(self.helper == "outdated");
        }
        self.poll_admin();
        self.poll_component();
        self.reconcile_interval();
    }
    fn receive(&mut self, message: Message) -> Result<(), ()> {
        match message {
            Message::Snapshot {
                id,
                version,
                profiles,
                connections,
                ..
            } => self.receive_snapshot(id, version, profiles, connections)?,
            Message::Changed {
                profile_id,
                generation,
                state,
                failures,
            } => {
                if !self.ready {
                    return Err(());
                }
                let c = self.connections.get_mut(&profile_id).ok_or(())?;
                if generation < c.generation {
                    return Ok(());
                }
                if generation != c.generation {
                    return Err(());
                }
                set_state(c, state);
                c.failures = failures;
                self.refresh_actions();
            }
            Message::Accepted { id } => {
                for c in self.connections.values_mut() {
                    if let Some(p) = &mut c.pending
                        && p.id == id
                    {
                        p.accepted = true;
                    }
                }
            }
            Message::Failed { id, .. } => {
                if self.fail_admin_query(&id) {
                    return Ok(());
                }
                for c in self.connections.values_mut() {
                    if c.pending.as_ref().is_some_and(|p| p.id == id) {
                        let pending = c.pending.take().unwrap();
                        if !pending.accepted {
                            c.generation = pending.previous.0;
                            set_state(c, pending.previous.1);
                        }
                    }
                }
            }
            Message::Fatal { .. } => self.lost(false),
            Message::AdminReady { .. } => return Err(()),
        }
        Ok(())
    }
    pub fn snapshot(&mut self) -> Snapshot {
        self.poll();
        Snapshot {
            version: env!("CARGO_PKG_VERSION"),
            demo: false,
            helper: self.helper,
            component_operation: self.component.status(),
            preferences: self.preferences,
            vpns: self.connections.values().map(|c| c.view.clone()).collect(),
        }
    }
}

fn set_state(c: &mut Connection, state: State) {
    c.policy.state(c.generation, state);
    if state != State::Unresponsive {
        c.failures = 0;
    }
    if c.view.state == state {
        return;
    }
    c.view.state = state;
    c.view.log.push(LogEntry {
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        state,
    });
    if c.view.log.len() > 60 {
        c.view.log.remove(0);
    }
}

#[cfg(test)]
mod preferences_tests;
#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "desktop"))]
impl<S: SecretStore> Broker<S> {
    /// Test-only composition seam with a real transport and injected secrets.
    pub(crate) fn transport_fixture(client: Client, secrets: S) -> Self {
        Self::new(Some(client), secrets)
    }
}
