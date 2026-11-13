use crate::{
    bridge::Command,
    model::{LogEntry, Profile, Snapshot, VpnKind, VpnView},
    secrets::Credentials,
    session::{Completion, ConnectionState, Session},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Connection {
    profile: Profile,
    session: Session,
    has_password: bool,
    has_psk: bool,
    log: Vec<LogEntry>,
}

struct Scheduled {
    id: String,
    generation: u64,
    at: Instant,
    completion: Completion,
}

/// Normal operation has no sample profiles. Timed fixtures require explicit demo mode.
#[derive(Default)]
pub struct App {
    demo: bool,
    preferences: crate::preferences::Preferences,
    connections: Vec<Connection>,
    scheduled: Vec<Scheduled>,
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn demo() -> Self {
        let mut app = Self {
            demo: true,
            ..Self::default()
        };
        for (id, name, kind) in [
            ("cluster", "Cluster", VpnKind::Ipsec),
            ("office", "Escritório", VpnKind::Ssl),
        ] {
            app.connections.push(Connection {
                profile: Profile {
                    id: id.into(),
                    name: name.into(),
                    kind,
                    gateway: "vpn.example.com".into(),
                    username: "user.name".into(),
                    networks: if kind == VpnKind::Ipsec {
                        vec!["10.20.0.0/24".into()]
                    } else {
                        vec![]
                    },
                    port: 443,
                    certificate: String::new(),
                    probe_host: "10.20.0.15".into(),
                    probe_port: 8443,
                    probe_method: "ping_tcp".into(),
                },
                session: Session::default(),
                has_password: true,
                has_psk: kind == VpnKind::Ipsec,
                log: vec![],
            });
        }
        app
    }

    pub fn snapshot(&mut self) -> Snapshot {
        self.snapshot_at(Instant::now())
    }

    pub fn snapshot_at(&mut self, now: Instant) -> Snapshot {
        self.tick(now);
        Snapshot {
            version: env!("CARGO_PKG_VERSION"),
            demo: self.demo,
            helper: if self.demo { "installed" } else { "missing" },
            component_operation: None,
            preferences: self.preferences,
            vpns: self
                .connections
                .iter()
                .map(|connection| VpnView {
                    profile: connection.profile.clone(),
                    state: connection.session.state(),
                    has_password: connection.has_password,
                    has_psk: connection.has_psk,
                    log: connection.log.clone(),
                })
                .collect(),
        }
    }

    pub fn dispatch(&mut self, command: Command) -> Result<Snapshot, &'static str> {
        self.dispatch_at(command, Instant::now())
    }

    pub fn dispatch_at(
        &mut self,
        command: Command,
        now: Instant,
    ) -> Result<Snapshot, &'static str> {
        self.tick(now);
        if matches!(
            command,
            Command::GetSnapshot {}
                | Command::Resize { .. }
                | Command::Hide {}
                | Command::OpenProject {}
                | Command::Quit {}
        ) {
            return Ok(self.snapshot_at(now));
        }
        if !self.demo {
            return Err("not_implemented");
        }
        match command {
            Command::Toggle { id } => {
                let connection = self.connection(&id)?;
                if matches!(
                    connection.session.state(),
                    ConnectionState::Offline
                        | ConnectionState::HelperMissing
                        | ConnectionState::MissingProgram
                ) {
                    return Err("unavailable");
                }
                if connection.session.state().active() {
                    self.stop(&id, now)?;
                } else {
                    self.start(&id, false, now)?;
                }
            }
            Command::Reconnect { id } => self.start(&id, true, now)?,
            Command::DisconnectAll {} => {
                let ids: Vec<_> = self
                    .connections
                    .iter()
                    .filter(|connection| connection.session.state().active())
                    .map(|connection| connection.profile.id.clone())
                    .collect();
                for id in ids {
                    self.stop(&id, now)?;
                }
            }
            Command::Probe { id } => {
                let connection = self.connection(&id)?;
                if connection
                    .session
                    .complete(connection.session.generation(), Completion::ProbePassed)
                {
                    Self::log(connection);
                }
            }
            Command::SaveProfile { profile } => {
                profile.validate()?;
                if let Some(connection) = self
                    .connections
                    .iter_mut()
                    .find(|connection| connection.profile.id == profile.id)
                {
                    if connection.session.state().active() {
                        return Err("profile_active");
                    }
                    connection.profile = profile;
                } else {
                    if self.connections.len() >= 64 {
                        return Err("profile_limit");
                    }
                    self.connections.push(Connection {
                        profile,
                        session: Session::with_state(ConnectionState::MissingSecret),
                        has_password: false,
                        has_psk: false,
                        log: vec![],
                    });
                }
            }
            Command::RemoveProfile { id } => {
                self.connection(&id)?;
                self.connections
                    .retain(|connection| connection.profile.id != id);
                self.scheduled.retain(|scheduled| scheduled.id != id);
            }
            Command::SaveSecrets { id, password, psk } => {
                let connection = self.connection(&id)?;
                Credentials { password, psk }
                    .validate(connection.profile.kind)
                    .map_err(|_| "invalid_secret")?;
                connection.has_password = true;
                connection.has_psk = connection.profile.kind == VpnKind::Ipsec;
                if connection.session.state() == ConnectionState::MissingSecret {
                    connection.session = Session::default();
                }
            }
            Command::SetDemoState { id, state } => {
                self.connection(&id)?.session = Session::with_state(state);
                self.scheduled.retain(|scheduled| scheduled.id != id);
            }
            Command::SetPreferences { preferences } => self.preferences = preferences,
            Command::InstallHelper {} | Command::RemoveHelper {} => return Err("not_implemented"),
            Command::GetSnapshot {}
            | Command::Quit {}
            | Command::Hide {}
            | Command::OpenProject {}
            | Command::Resize { .. } => {}
        }
        Ok(self.snapshot_at(now))
    }

    fn connection(&mut self, id: &str) -> Result<&mut Connection, &'static str> {
        self.connections
            .iter_mut()
            .find(|connection| connection.profile.id == id)
            .ok_or("not_found")
    }

    fn start(&mut self, id: &str, reconnect: bool, now: Instant) -> Result<(), &'static str> {
        let connection = self.connection(id)?;
        if !connection.has_password
            || (connection.profile.kind == VpnKind::Ipsec && !connection.has_psk)
        {
            connection.session = Session::with_state(ConnectionState::MissingSecret);
            return Ok(());
        }
        let generation = if reconnect {
            connection.session.reconnect()
        } else {
            connection.session.connect()
        };
        Self::log(connection);
        self.scheduled.push(Scheduled {
            id: id.into(),
            generation,
            at: now + Duration::from_millis(700),
            completion: Completion::TunnelReady,
        });
        self.scheduled.push(Scheduled {
            id: id.into(),
            generation,
            at: now + Duration::from_millis(1100),
            completion: Completion::ProbePassed,
        });
        Ok(())
    }

    fn stop(&mut self, id: &str, now: Instant) -> Result<(), &'static str> {
        let connection = self.connection(id)?;
        let generation = connection.session.disconnect();
        Self::log(connection);
        self.scheduled.push(Scheduled {
            id: id.into(),
            generation,
            at: now + Duration::from_millis(200),
            completion: Completion::Stopped,
        });
        Ok(())
    }

    fn tick(&mut self, now: Instant) {
        let (mut due, future): (Vec<_>, Vec<_>) = self
            .scheduled
            .drain(..)
            .partition(|scheduled| scheduled.at <= now);
        self.scheduled = future;
        due.sort_by_key(|scheduled| scheduled.at);
        for scheduled in due {
            if let Ok(connection) = self.connection(&scheduled.id)
                && connection
                    .session
                    .complete(scheduled.generation, scheduled.completion)
            {
                Self::log(connection);
            }
        }
    }

    fn log(connection: &mut Connection) {
        connection.log.push(LogEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            state: connection.session.state(),
        });
        if connection.log.len() > 60 {
            connection.log.remove(0);
        }
    }
}
