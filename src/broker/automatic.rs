//! Deferred host work runs only while the desktop actor has no user request.
use super::*;
use crate::{
    localization::Locale,
    notifications::{Notice, Notifier},
    preferences::ProbeInterval,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub(super) enum Action {
    Notify {
        id: String,
        generation: u64,
        current: Arc<AtomicBool>,
    },
    Reconnect {
        id: String,
        generation: u64,
    },
}
impl Action {
    fn key(&self) -> (&str, bool) {
        match self {
            Self::Notify { id, .. } => (id, true),
            Self::Reconnect { id, .. } => (id, false),
        }
    }
}
impl<S: SecretStore> Broker<S> {
    pub fn with_notifier(mut self, notifier: Box<dyn Notifier>) -> Self {
        self.notifier = notifier;
        self
    }
    pub(crate) fn set_locale(&mut self, locale: Locale) {
        self.locale = locale;
    }
    /// A superseding user action abandons pending background reconnects even
    /// when the action itself is later refused or expires. Other profiles keep
    /// their work when the action addresses only one profile.
    pub(crate) fn interrupt_automatic(&mut self, command: &Command) {
        let target = match command {
            Command::Connect { id }
            | Command::Disconnect { id }
            | Command::Toggle { id }
            | Command::Reconnect { id }
            | Command::RemoveProfile { id }
            | Command::SaveSecrets { id, .. } => Some(id.as_str()),
            Command::SaveProfile { profile } => Some(profile.id.as_str()),
            Command::DisconnectAll {}
            | Command::Quit {}
            | Command::InstallHelper {}
            | Command::RemoveHelper {} => None,
            Command::SetPreferences { preferences } if !preferences.reconnect => None,
            _ => return,
        };
        for (id, connection) in &mut self.connections {
            if target.is_none_or(|target| target == id)
                && connection.view.state == State::Unresponsive
            {
                connection.policy.tried(connection.generation);
            }
        }
        self.automatic.retain(|action| match action {
            Action::Reconnect { id, .. } => target.is_some_and(|target| target != id),
            Action::Notify { .. } => true,
        });
    }
    pub(super) fn refresh_actions(&mut self) {
        let mut pending = Vec::new();
        for (id, c) in &mut self.connections {
            let effects =
                c.policy
                    .observe(c.generation, c.view.state, c.failures, self.preferences);
            if let Some(current) = effects.notice {
                pending.push(Action::Notify {
                    id: id.clone(),
                    generation: c.generation,
                    current,
                });
            }
            if effects.reconnect {
                pending.push(Action::Reconnect {
                    id: id.clone(),
                    generation: c.generation,
                });
            }
        }
        for action in pending {
            self.automatic.retain(|old| {
                self.connections.contains_key(old.key().0) && old.key() != action.key()
            });
            self.automatic.push_back(action);
        }
    }
    pub(super) fn reconcile_interval(&mut self) {
        if !self.ready
            || self.component.busy()
            || self.sent_interval == Some(self.preferences.interval)
        {
            return;
        }
        // A fresh protocol-3 helper's production default is already ten seconds.
        if self.sent_interval.is_none() && self.preferences.interval == ProbeInterval::TEN {
            self.sent_interval = Some(ProbeInterval::TEN);
            return;
        }
        let Some(next) = self.next.checked_add(1) else {
            self.lost(false);
            return;
        };
        let request = Request {
            id: format!("preferences-{next}"),
            command: protocol::Command::SetProbeInterval {
                interval: self.preferences.interval,
            },
        };
        if self
            .client
            .as_ref()
            .is_none_or(|client| client.send(request).is_err())
        {
            self.lost(false);
            return;
        }
        self.next = next;
        self.sent_interval = Some(self.preferences.interval);
    }
    pub(crate) fn perform_automatic(&mut self, current: impl Fn() -> bool) {
        self.poll();
        if !current() || !self.ready || self.component.busy() {
            return;
        }
        while let Some(action) = self.automatic.pop_front() {
            match action {
                Action::Notify {
                    id,
                    generation,
                    current: token,
                } => {
                    let Some(c) = self.connections.get(&id) else {
                        continue;
                    };
                    if !self.preferences.notify
                        || c.generation != generation
                        || c.view.state != State::Unresponsive
                        || !token.load(Ordering::Acquire)
                    {
                        continue;
                    }
                    let messages = self.locale.native();
                    self.notifier.send(Notice {
                        id: format!("{id}-{generation}"),
                        title: messages.unresponsive_title,
                        body: messages
                            .unresponsive_body
                            .replace("{profile}", &c.view.profile.name),
                        current: token,
                    });
                    return;
                }
                Action::Reconnect { id, generation } => {
                    let Some(c) = self.connections.get_mut(&id) else {
                        continue;
                    };
                    if c.generation != generation {
                        continue;
                    }
                    if !self.preferences.reconnect
                        || c.view.state != State::Unresponsive
                        || c.failures != 3
                        || !c.view.has_password
                        || (c.view.profile.kind == VpnKind::Ipsec && !c.view.has_psk)
                    {
                        c.policy.unqueue();
                        continue;
                    }
                    if self.editing(&id) {
                        self.automatic
                            .push_back(Action::Reconnect { id, generation });
                        return;
                    }
                    self.connections
                        .get_mut(&id)
                        .unwrap()
                        .policy
                        .tried(generation);
                    let result = self.connect_guarded(
                        &id,
                        true,
                        Instant::now() + Duration::from_secs(9),
                        &current,
                    );
                    if result == Err("operation_canceled") {
                        if let Some(c) = self.connections.get_mut(&id)
                            && c.generation == generation
                        {
                            c.policy.defer(generation);
                        }
                        self.automatic
                            .push_front(Action::Reconnect { id, generation });
                    }
                    return;
                }
            }
        }
    }
}

pub(super) fn queue() -> VecDeque<Action> {
    VecDeque::new()
}
