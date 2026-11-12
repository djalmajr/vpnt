use super::*;
use crate::{helper::protocol::TunnelStatus, model::Profile};
impl<S: SecretStore> Broker<S> {
    pub(super) fn receive_snapshot(
        &mut self,
        id: String,
        version: String,
        profiles: Vec<Profile>,
        statuses: Vec<TunnelStatus>,
    ) -> Result<(), ()> {
        let initial = !self.ready;
        let observed = if initial {
            if id != "snapshot-1" {
                return Err(());
            }
            None
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
                && (s.generation != 0 || s.state != State::Off)
            {
                return Err(());
            }
        }
        if initial {
            self.connections.clear();
        }
        for profile in profiles {
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
                    let present = self
                        .secrets
                        .contains(&profile.id, profile.kind)
                        .unwrap_or(false);
                    c.view.has_password = present;
                    c.view.has_psk = present && profile.kind == VpnKind::Ipsec;
                }
                c.view.profile = profile;
                if c.generation != status.generation {
                    c.pending = None;
                }
                c.generation = status.generation;
                let state = if status.state == State::Off && !c.view.has_password {
                    State::MissingSecret
                } else {
                    status.state
                };
                set_state(&mut c, state);
                current.insert(c.view.profile.id.clone(), c);
            } else {
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
                        generation: status.generation,
                        pending: None,
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
        self.ready = true;
        self.helper = "installed";
        if initial {
            if let Some(retry) = &mut self.retry {
                retry.ready();
            }
        } else {
            self.confirm_admin_snapshot();
        }
        Ok(())
    }
}
