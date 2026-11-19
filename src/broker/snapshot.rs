use super::*;
use crate::{helper::protocol::TunnelStatus, model::Profile};
impl<S: SecretStore> Broker<S> {
    pub(super) fn request_cleanup_snapshot(&mut self) {
        if self.cleanup_probe.is_some() {
            return;
        }
        if let Some(client) = &self.client {
            let observed = self
                .connections
                .iter()
                .map(|(id, c)| (id.clone(), c.generation))
                .collect();
            self.cleanup_probe = Some(observed);
            if client
                .send(Request {
                    id: protocol::CLEANUP_PROBE_SNAPSHOT_ID.into(),
                    command: protocol::Command::Snapshot {},
                })
                .is_err()
            {
                self.lost(false);
            }
        }
    }
    /// Same probe as cleanup: an older helper echoes the probe ID.
    pub(super) fn request_failure_snapshot(&mut self) {
        if self.failure_probe.is_some() {
            return;
        }
        if let Some(client) = &self.client {
            let observed = self
                .connections
                .iter()
                .map(|(id, c)| (id.clone(), c.generation))
                .collect();
            self.failure_probe = Some(observed);
            if client
                .send(Request {
                    id: protocol::FAILURE_NOTE_PROBE_SNAPSHOT_ID.into(),
                    command: protocol::Command::Snapshot {},
                })
                .is_err()
            {
                self.lost(false);
            }
        }
    }
    pub(super) fn receive_snapshot(
        &mut self,
        id: String,
        version: String,
        build: Option<String>,
        profiles: Vec<Profile>,
        statuses: Vec<TunnelStatus>,
    ) -> Result<(), ()> {
        let initial = !self.ready;
        let probe =
            id == protocol::CLEANUP_PROBE_SNAPSHOT_ID || id == protocol::CLEANUP_ACK_SNAPSHOT_ID;
        let note_probe = id == protocol::FAILURE_NOTE_PROBE_SNAPSHOT_ID
            || id == protocol::FAILURE_NOTE_ACK_SNAPSHOT_ID;
        let verify = self
            .cleanup_verify
            .as_ref()
            .is_some_and(|pending| pending.request == id);
        let observed = if initial {
            if id != protocol::WAIT_CAPABILITY_SNAPSHOT_ID {
                return Err(());
            }
            None
        } else if probe {
            self.cleanup_capable = id == protocol::CLEANUP_ACK_SNAPSHOT_ID;
            Some(self.cleanup_probe.take().ok_or(())?)
        } else if note_probe {
            self.failure_capable = id == protocol::FAILURE_NOTE_ACK_SNAPSHOT_ID;
            Some(self.failure_probe.take().ok_or(())?)
        } else if verify {
            Some(self.cleanup_verify.take().ok_or(())?.observed)
        } else {
            Some(self.admin_query(&id).ok_or(())?)
        };
        if version != env!("CARGO_PKG_VERSION") {
            self.lost(true);
            return Ok(());
        }
        if profiles.len() != statuses.len()
            || (initial
                && statuses
                    .iter()
                    .any(|s| s.generation != 0 || s.state != State::Off))
            || (!self.failure_capable && statuses.iter().any(|s| s.failure.is_some()))
        {
            return Err(());
        }
        let mut statuses: BTreeMap<_, _> =
            statuses.into_iter().map(|s| (s.id.clone(), s)).collect();
        let mut current = BTreeMap::new();
        // Validate the whole reply before taking any cached connection.
        for p in &profiles {
            let s = statuses.get(&p.id).ok_or(())?;
            if !initial
                && !self.connections.contains_key(&p.id)
                && (s.generation != 0
                    || (s.state != State::Off
                        && !(self.cleanup_capable && s.state == State::CleanupUnconfirmed)))
            {
                return Err(());
            }
        }
        if initial {
            self.connections.clear();
        }
        for profile in profiles {
            let requires_credentials = needs_credentials(profile.kind);
            let status = statuses.remove(&profile.id).ok_or(())?;
            let previous = self.connections.remove(&profile.id);
            if let Some(mut c) = previous {
                if observed.as_ref().and_then(|o| o.get(&profile.id)) != Some(&c.generation)
                    || status.generation < c.generation
                {
                    current.insert(profile.id.clone(), c);
                    continue;
                }
                if c.view.profile != profile
                    && (c.view.state.active() || c.view.state == State::Disconnecting)
                {
                    current.insert(c.view.profile.id.clone(), c);
                    continue;
                }
                let changed_kind = c.view.profile.kind != profile.kind;
                if changed_kind {
                    let present = requires_credentials
                        && self
                            .secrets
                            .contains(&profile.id, profile.kind)
                            .unwrap_or(false);
                    c.view.has_password = present;
                    c.view.has_psk = present && profile.kind == VpnKind::Ipsec;
                }
                c.view.profile = profile;
                let same_generation = c.generation == status.generation;
                if !same_generation {
                    c.pending = None;
                }
                c.generation = status.generation;
                let state =
                    if requires_credentials && status.state == State::Off && !c.view.has_password {
                        State::MissingSecret
                    } else {
                        status.state
                    };
                // The macOS app records a local warning when it has no OVPN
                // program. The same generation reporting `Off` carries no new
                // information and must not erase the warning the user can close.
                #[cfg(target_os = "macos")]
                let state = if same_generation
                    && state == State::Off
                    && c.view.state == State::MissingProgram
                    && c.view.profile.kind == VpnKind::Ovpn
                {
                    State::MissingProgram
                } else {
                    state
                };
                transition(&mut c, state, status.failure.map(FailureView::from));
                c.failures = status.failures;
                c.view.cleaning = status.cleaning;
                current.insert(c.view.profile.id.clone(), c);
            } else {
                let present = requires_credentials
                    && self
                        .secrets
                        .contains(&profile.id, profile.kind)
                        .unwrap_or(false);
                current.insert(
                    profile.id.clone(),
                    Connection {
                        view: VpnView {
                            cleaning: status.cleaning,
                            cleanup_verifying: false,
                            has_password: present,
                            has_psk: present && profile.kind == VpnKind::Ipsec,
                            profile,
                            state: if requires_credentials && status.state == State::Off && !present
                            {
                                State::MissingSecret
                            } else {
                                status.state
                            },
                            failure: status.failure.map(FailureView::from),
                            log: vec![],
                        },
                        generation: status.generation,
                        pending: None,
                        failures: status.failures,
                        policy: behavior::Policy::default(),
                    },
                );
            }
        }
        if let Some(observed) = &observed {
            for (id, c) in std::mem::take(&mut self.connections) {
                if observed.get(&id) != Some(&c.generation) {
                    current.insert(id, c);
                }
            }
        }
        self.connections = current;
        self.refresh_actions();
        self.waiting_previous = false;
        self.ready = true;
        self.helper = match (self.expected_build.as_deref(), build.as_deref()) {
            (Some(expected), Some(installed)) if expected == installed => "installed",
            _ => "outdated",
        };
        if initial {
            if let Some(retry) = &mut self.retry {
                retry.ready();
            }
            self.request_cleanup_snapshot();
            self.request_failure_snapshot();
        } else if !probe && !note_probe && !verify {
            self.confirm_admin_snapshot();
        }
        Ok(())
    }
}
