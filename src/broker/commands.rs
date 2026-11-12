use super::*;
impl<S: SecretStore> Broker<S> {
    pub fn dispatch(
        &mut self,
        command: Command,
        expires: Instant,
    ) -> Result<Snapshot, &'static str> {
        self.poll();
        if Instant::now() >= expires {
            return Err("backend_unavailable");
        }
        if self.component.busy()
            && !matches!(
                command,
                Command::GetSnapshot {}
                    | Command::Resize { .. }
                    | Command::Hide {}
                    | Command::OpenProject {}
                    | Command::Quit {}
            )
        {
            return Err("component_busy");
        }
        match command {
            Command::GetSnapshot {}
            | Command::Resize { .. }
            | Command::Hide {}
            | Command::OpenProject {} => {}
            Command::Quit {} => {
                self.component.close();
                self.retry = None;
                self.lost(false);
            }
            Command::Toggle { id } => {
                let state = self.connections.get(&id).ok_or("not_found")?.view.state;
                if state.active() {
                    self.disconnect(&id)?;
                } else {
                    self.connect(&id, false, expires)?;
                }
            }
            Command::Reconnect { id } => self.connect(&id, true, expires)?,
            Command::DisconnectAll {} => {
                let ids: Vec<_> = self
                    .connections
                    .iter()
                    .filter(|(_, c)| c.view.state.active())
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in ids {
                    self.disconnect(&id)?;
                }
            }
            Command::Probe { id } => {
                let c = self.connections.get(&id).ok_or("not_found")?;
                if !matches!(
                    c.view.state,
                    State::Connected | State::Verifying | State::Unresponsive
                ) {
                    return Err("unavailable");
                }
                let generation = c.generation;
                self.submit(
                    &id,
                    generation,
                    protocol::Command::Probe {
                        id: id.clone(),
                        generation,
                    },
                    None,
                )?;
            }
            Command::SaveSecrets { id, password, psk } => {
                if self.editing(&id) {
                    return Err("admin_busy");
                }
                let c = self.connections.get_mut(&id).ok_or("not_found")?;
                let credentials = Credentials { password, psk };
                credentials
                    .validate(c.view.profile.kind)
                    .map_err(|_| "invalid_secret")?;
                self.secrets
                    .save(&id, c.view.profile.kind, &credentials)
                    .map_err(|_| "backend_unavailable")?;
                c.view.has_password = true;
                c.view.has_psk = c.view.profile.kind == VpnKind::Ipsec;
                if c.view.state == State::MissingSecret {
                    set_state(c, State::Off);
                }
            }
            Command::SetDemoState { .. } => return Err("invalid_request"),
            Command::SaveProfile { .. }
            | Command::RemoveProfile { .. }
            | Command::InstallHelper {}
            | Command::RemoveHelper {} => return Err("not_implemented"),
        }
        Ok(self.snapshot())
    }
    fn connect(&mut self, id: &str, reconnect: bool, expires: Instant) -> Result<(), &'static str> {
        if !self.ready {
            return Err("backend_unavailable");
        }
        if self.editing(id) {
            return Err("admin_busy");
        }
        let c = self.connections.get_mut(id).ok_or("not_found")?;
        if c.view.profile.kind != VpnKind::Ssl {
            return Err("not_implemented");
        }
        let credentials = match self.secrets.load(id, c.view.profile.kind) {
            Ok(credentials) => credentials,
            Err(crate::secrets::SecretError::Missing) => {
                c.view.has_password = false;
                c.view.has_psk = false;
                set_state(c, State::MissingSecret);
                return Ok(());
            }
            Err(_) => return Err("backend_unavailable"),
        };
        credentials
            .validate(c.view.profile.kind)
            .map_err(|_| "invalid_secret")?;
        if Instant::now() >= expires {
            return Err("backend_unavailable");
        }
        let generation = c.generation.checked_add(1).ok_or("unavailable")?;
        self.submit(
            id,
            generation,
            protocol::Command::Connect {
                id: id.into(),
                generation,
                credentials,
            },
            Some(if reconnect {
                State::Reconnecting
            } else {
                State::Connecting
            }),
        )
    }
    fn disconnect(&mut self, id: &str) -> Result<(), &'static str> {
        let c = self.connections.get(id).ok_or("not_found")?;
        let generation = c.generation.checked_add(1).ok_or("unavailable")?;
        self.submit(
            id,
            generation,
            protocol::Command::Disconnect {
                id: id.into(),
                generation,
            },
            Some(State::Disconnecting),
        )
    }
    fn submit(
        &mut self,
        id: &str,
        generation: u64,
        command: protocol::Command,
        state: Option<State>,
    ) -> Result<(), &'static str> {
        if !self.ready {
            return Err("backend_unavailable");
        }
        let next = self.next.checked_add(1).ok_or("unavailable")?;
        let request = format!("operation-{next}");
        self.client
            .as_ref()
            .ok_or("backend_unavailable")?
            .send(Request {
                id: request.clone(),
                command,
            })
            .map_err(|_| "backend_unavailable")?;
        self.next = next;
        let c = self.connections.get_mut(id).ok_or("not_found")?;
        c.pending = Some(Pending {
            id: request,
            previous: (c.generation, c.view.state),
            accepted: false,
        });
        c.generation = generation;
        if let Some(state) = state {
            set_state(c, state);
        }
        Ok(())
    }
}
