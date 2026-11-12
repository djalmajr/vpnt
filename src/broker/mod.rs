//! Normal application state. Only the authenticated helper's current generation
//! may report a connected tunnel; demo schedules never enter this model.
mod commands;
use crate::{
    bridge::Command,
    helper::{
        client::{Client, Error},
        protocol::{self, Message, Request},
    },
    model::{LogEntry, Snapshot, VpnKind, VpnView},
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
}
pub struct Broker<S: SecretStore> {
    client: Option<Client>,
    secrets: S,
    connections: BTreeMap<String, Connection>,
    helper: &'static str,
    ready: bool,
    dead: bool,
    next: u64,
    startup: Instant,
}
impl<S: SecretStore> Broker<S> {
    pub fn new(client: Option<Client>, secrets: S) -> Self {
        let mut result = Self {
            client,
            secrets,
            connections: BTreeMap::new(),
            helper: "missing",
            ready: false,
            dead: false,
            next: 1,
            startup: Instant::now() + Duration::from_secs(5),
        };
        if result.client.as_ref().is_some_and(|c| {
            c.send(Request {
                id: "snapshot-1".into(),
                command: protocol::Command::Snapshot {},
            })
            .is_err()
        }) {
            result.lost(false);
        }
        result
    }
    fn lost(&mut self, outdated: bool) {
        self.dead = true;
        self.ready = false;
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
        !self.dead && !self.ready && self.client.is_some()
    }
    pub fn poll(&mut self) {
        if self.dead {
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
    }
    fn receive(&mut self, message: Message) -> Result<(), ()> {
        match message {
            Message::Snapshot {
                id,
                version,
                profiles,
                connections,
                ..
            } => {
                if self.ready || id != "snapshot-1" {
                    return Err(());
                }
                if version != env!("CARGO_PKG_VERSION") {
                    self.lost(true);
                    return Ok(());
                }
                if profiles.len() != connections.len()
                    || connections
                        .iter()
                        .any(|s| s.generation != 0 || s.state != State::Off)
                {
                    return Err(());
                }
                let mut current = BTreeMap::new();
                for profile in profiles {
                    let present = self
                        .secrets
                        .contains(&profile.id, profile.kind)
                        .unwrap_or(false);
                    current.insert(
                        profile.id.clone(),
                        Connection {
                            view: VpnView {
                                has_password: present,
                                has_psk: present && profile.kind == VpnKind::Ipsec,
                                profile,
                                state: if present {
                                    State::Off
                                } else {
                                    State::MissingSecret
                                },
                                log: vec![],
                            },
                            generation: 0,
                            pending: None,
                        },
                    );
                }
                self.connections = current;
                self.ready = true;
                self.helper = "installed";
            }
            Message::Changed {
                profile_id,
                generation,
                state,
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
        }
        Ok(())
    }
    pub fn snapshot(&mut self) -> Snapshot {
        self.poll();
        Snapshot {
            version: env!("CARGO_PKG_VERSION"),
            demo: false,
            helper: self.helper,
            vpns: self.connections.values().map(|c| c.view.clone()).collect(),
        }
    }
}

fn set_state(c: &mut Connection, state: State) {
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
mod tests;
