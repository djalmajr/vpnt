//! Normal application state. Only the authenticated helper's current generation
//! may report a connected tunnel; demo schedules never enter this model.
#[cfg_attr(
    target_os = "linux",
    allow(
        dead_code,
        reason = "the component flow using the admin busy state is macOS-only"
    ),
    allow(
        clippy::large_enum_variant,
        reason = "keep the existing shared admin command representation"
    )
)]
mod admin;
mod automatic;
mod behavior;
mod commands;
#[cfg(target_os = "macos")]
mod component;
#[cfg(target_os = "macos")]
mod diagnostics;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::component;
mod retry;
mod snapshot;
use crate::{
    bridge::Command,
    helper::{
        client::{Client, Error},
        protocol::{self, Message, Request},
    },
    model::{FailureView, LogEntry, Snapshot, VpnKind, VpnView},
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
    /// Generation, state and note restored if the helper rejects the request.
    previous: (u64, State, Option<FailureView>),
    accepted: bool,
}
struct CleanupVerify {
    request: String,
    profile: String,
    observed: BTreeMap<String, u64>,
}
struct Connection {
    view: VpnView,
    generation: u64,
    pending: Option<Pending>,
    failures: u32,
    policy: behavior::Policy,
}

fn needs_credentials(kind: VpnKind) -> bool {
    !cfg!(target_os = "linux") || kind != VpnKind::Ovpn
}

pub struct Broker<S: SecretStore> {
    client: Option<Client>,
    retry: Option<retry::Retry>,
    secrets: S,
    connections: BTreeMap<String, Connection>,
    helper: &'static str,
    expected_build: Option<String>,
    ready: bool,
    dead: bool,
    next: u64,
    startup: Instant,
    waiting_previous: bool,
    administration: admin::Flow,
    component: component::Flow,
    #[cfg(target_os = "linux")]
    netd: Option<linux::NetdProbe>,
    #[cfg(target_os = "macos")]
    diagnostics: diagnostics::Flow,
    epoch: u64,
    preferences: Preferences,
    notifier: Box<dyn crate::notifications::Notifier>,
    #[cfg(any(test, feature = "desktop"))]
    #[cfg_attr(
        target_os = "linux",
        allow(
            dead_code,
            reason = "the Linux desktop actor will consume automatic actions"
        )
    )]
    locale: crate::localization::Locale,
    automatic: std::collections::VecDeque<automatic::Action>,
    sent_interval: Option<crate::preferences::ProbeInterval>,
    cleanup_capable: bool,
    cleanup_probe: Option<BTreeMap<String, u64>>,
    cleanup_verify: Option<CleanupVerify>,
    /// The helper answered `FAILURE_NOTE_PROBE_SNAPSHOT_ID` with its ack.
    failure_capable: bool,
    failure_probe: Option<BTreeMap<String, u64>>,
    preferences_host: Box<dyn crate::preferences::host::Host>,
}
impl<S: SecretStore> Broker<S> {
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn fixture(client: Client, secrets: S) -> Self {
        Self::new(Some(client), secrets)
    }
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
        #[cfg(all(test, target_os = "macos"))]
        let fixture_build = client
            .as_ref()
            .and_then(Client::fixture_build)
            .map(str::to_owned);
        #[cfg(all(not(test), target_os = "macos"))]
        let fixture_build: Option<String> = None;
        #[cfg(target_os = "macos")]
        let expected_build = fixture_build.or_else(|| {
            crate::install::bundle::Component::current()
                .ok()
                .map(|component| component.metadata().build.clone())
        });
        #[cfg(target_os = "linux")]
        let expected_build = crate::helper::client::linux_build_identity();
        let mut result = Self {
            client,
            retry: None,
            secrets,
            connections: BTreeMap::new(),
            helper: "missing",
            expected_build,
            ready: false,
            dead: false,
            next: 1,
            startup: Instant::now() + Duration::from_secs(5),
            waiting_previous: false,
            administration: admin::Flow::new(),
            component: component::Flow::new(),
            #[cfg(all(target_os = "linux", not(test)))]
            netd: Some(linux::NetdProbe::new(
                crate::netd::client::SOCKET_PATH.into(),
            )),
            #[cfg(all(target_os = "linux", test))]
            netd: None,
            #[cfg(target_os = "macos")]
            diagnostics: diagnostics::Flow::new(),
            epoch: 1,
            preferences: Preferences::default(),
            notifier: Box::new(crate::notifications::Noop),
            #[cfg(any(test, feature = "desktop"))]
            locale: crate::localization::Locale::default(),
            automatic: automatic::queue(),
            sent_interval: None,
            cleanup_capable: false,
            cleanup_probe: None,
            cleanup_verify: None,
            failure_capable: false,
            failure_probe: None,
            preferences_host: Box::new(crate::preferences::host::Coordinator::memory()),
        };
        result.begin();
        result
    }
    fn begin(&mut self) {
        if self.client.as_ref().is_some_and(|c| {
            c.send(Request {
                id: protocol::WAIT_CAPABILITY_SNAPSHOT_ID.into(),
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
                #[cfg(all(test, target_os = "macos"))]
                if self.expected_build.is_none() {
                    self.expected_build = client.fixture_build().map(str::to_owned);
                }
                self.epoch = self
                    .epoch
                    .checked_add(1)
                    .expect("helper channel epoch exhausted");
                self.client = Some(client);
                self.dead = false;
                self.ready = false;
                self.waiting_previous = false;
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
        self.cleanup_capable = false;
        self.cleanup_probe = None;
        self.cleanup_verify = None;
        self.failure_capable = false;
        self.failure_probe = None;
        self.automatic.clear();
        #[cfg(target_os = "macos")]
        {
            self.diagnostics.pending = None;
            self.diagnostics.dirty = false;
        }
        self.helper = if outdated {
            "outdated"
        } else if self.waiting_previous {
            "previous_session_finishing"
        } else {
            "missing"
        };
        self.waiting_previous = false;
        if let Some(client) = &mut self.client {
            client.close();
        }
        for connection in self.connections.values_mut() {
            connection.pending = None;
            set_state(connection, State::HelperMissing);
        }
    }
    pub fn starting(&self) -> bool {
        !self.component.busy()
            && !self.dead
            && !self.ready
            && !self.waiting_previous
            && self.client.is_some()
    }
    pub fn poll(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(probe) = self.netd.as_mut() {
            probe.poll(Instant::now());
        }
        #[cfg(target_os = "macos")]
        self.diagnostics.tick();
        if (self.dead || self.client.is_none()) && !self.component.blocks_retry() {
            self.resume();
        }
        if self.dead {
            self.poll_admin();
            #[cfg(target_os = "macos")]
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
            Some(Err(error)) => {
                if !self.ready && error == Error::PreviousSessionFinishing {
                    self.waiting_previous = true;
                }
                self.lost(error == Error::Incompatible);
            }
            None => {}
        }
        if !self.ready && self.client.is_some() && Instant::now() >= self.startup {
            self.lost(self.helper == "outdated");
        }
        self.poll_admin();
        #[cfg(target_os = "macos")]
        self.poll_component();
        self.reconcile_interval();
    }
    fn receive(&mut self, message: Message) -> Result<(), ()> {
        match message {
            Message::PreviousSessionFinishing {
                protocol_version,
                version,
            } => {
                if self.ready || protocol_version != protocol::VERSION {
                    return Err(());
                }
                if version != env!("CARGO_PKG_VERSION") {
                    self.lost(true);
                    return Ok(());
                }
                if !self.waiting_previous {
                    // Longer than the helper's bounded lock retry, including
                    // its bounded protocol write and scheduling margin.
                    self.startup = Instant::now() + Duration::from_secs(45);
                }
                self.waiting_previous = true;
                self.helper = "previous_session_finishing";
            }
            Message::Snapshot {
                id,
                version,
                build,
                profiles,
                connections,
                ..
            } => self.receive_snapshot(id, version, build, profiles, connections)?,
            Message::Changed {
                profile_id,
                generation,
                state,
                failures,
                cleaning,
                failure,
            } => {
                // A note is only valid after the helper acknowledged the probe.
                if !self.ready || (failure.is_some() && !self.failure_capable) {
                    return Err(());
                }
                let c = self.connections.get_mut(&profile_id).ok_or(())?;
                if generation < c.generation {
                    return Ok(());
                }
                if generation != c.generation {
                    return Err(());
                }
                #[cfg(target_os = "macos")]
                let ended = diagnostics::ended(c.view.state, c.view.cleaning, state, cleaning);
                transition(c, state, failure.map(FailureView::from));
                c.failures = failures;
                c.view.cleaning = cleaning;
                self.refresh_actions();
                #[cfg(target_os = "macos")]
                if ended {
                    self.request_diagnostics();
                }
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
            Message::Failed { id, error } => {
                if self.cleanup_probe.is_some()
                    && (id == protocol::CLEANUP_PROBE_SNAPSHOT_ID
                        || id == protocol::CLEANUP_ACK_SNAPSHOT_ID)
                {
                    self.cleanup_probe = None;
                    self.cleanup_capable = false;
                    return Ok(());
                }
                if self.failure_probe.is_some()
                    && (id == protocol::FAILURE_NOTE_PROBE_SNAPSHOT_ID
                        || id == protocol::FAILURE_NOTE_ACK_SNAPSHOT_ID)
                {
                    self.failure_probe = None;
                    self.failure_capable = false;
                    return Ok(());
                }
                if self
                    .cleanup_verify
                    .as_ref()
                    .is_some_and(|pending| pending.request == id)
                {
                    self.cleanup_verify = None;
                    return Ok(());
                }
                #[cfg(target_os = "macos")]
                if self.diagnostics.pending.as_deref() == Some(id.as_str()) {
                    self.diagnostics.pending = None;
                    if std::mem::take(&mut self.diagnostics.dirty) {
                        self.request_diagnostics();
                    }
                    return Ok(());
                }
                if self.fail_admin_query(&id) {
                    return Ok(());
                }
                let mut rejected = false;
                for c in self.connections.values_mut() {
                    if c.pending.as_ref().is_some_and(|p| p.id == id) {
                        let pending = c.pending.take().unwrap();
                        if !pending.accepted {
                            c.generation = pending.previous.0;
                            transition(c, pending.previous.1, pending.previous.2);
                            rejected = true;
                        }
                    }
                }
                if rejected && error == protocol::ErrorCode::ProfileBusy && self.cleanup_capable {
                    self.request_cleanup_snapshot();
                }
            }
            #[cfg(target_os = "macos")]
            Message::Diagnostics { id, status, logs } => {
                if self.diagnostics.pending.as_deref() != Some(id.as_str()) {
                    return Err(());
                }
                self.diagnostics.pending = None;
                self.diagnostics.enqueue(diagnostics::render(status, &logs));
                if std::mem::take(&mut self.diagnostics.dirty) {
                    self.request_diagnostics();
                }
            }
            #[cfg(target_os = "linux")]
            Message::Diagnostics { .. } => return Err(()),
            Message::Fatal { .. } => {
                self.waiting_previous = false;
                self.lost(false);
            }
            Message::AdminReady { .. } => return Err(()),
        }
        Ok(())
    }
    pub fn snapshot(&mut self) -> Snapshot {
        self.poll();
        let verifying = self
            .cleanup_verify
            .as_ref()
            .map(|pending| pending.profile.as_str());
        Snapshot {
            version: env!("CARGO_PKG_VERSION"),
            demo: false,
            #[cfg(target_os = "macos")]
            helper: self.helper,
            #[cfg(target_os = "linux")]
            helper: self
                .netd
                .as_ref()
                .map_or(self.helper, linux::NetdProbe::status),
            component_operation: self.component.status(),
            preferences: self.preferences,
            vpns: self
                .connections
                .values()
                .map(|c| {
                    let mut view = c.view.clone();
                    view.cleanup_verifying = verifying == Some(view.profile.id.as_str());
                    view
                })
                .collect(),
        }
    }
}

/// A state of the app's own (no helper note), which clears any note.
fn set_state(c: &mut Connection, state: State) {
    transition(c, state, None);
}

/// `failure` is the helper's note for `state`; it replaces the card's note and
/// goes into the log entry when the state changes.
fn transition(c: &mut Connection, state: State, failure: Option<FailureView>) {
    c.view.cleaning = false;
    c.view.failure = failure;
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
        failure,
    });
    if c.view.log.len() > 60 {
        c.view.log.remove(0);
    }
}

#[cfg(test)]
mod preferences_tests;
#[cfg(all(test, target_os = "macos"))]
mod tests;

#[cfg(all(test, feature = "desktop", target_os = "macos"))]
impl<S: SecretStore> Broker<S> {
    /// Test-only composition seam with a real transport and injected secrets.
    pub(crate) fn transport_fixture(client: Client, secrets: S) -> Self {
        Self::new(Some(client), secrets)
    }
}
