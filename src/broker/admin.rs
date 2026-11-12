use super::*;
use crate::{
    helper::{
        admin_client::{Admin, Error as AdminError},
        protocol::{AdminCommand, AdminRequest, ErrorCode},
    },
    localization::Locale,
    model::Profile,
};
type Connector = Box<dyn FnMut(AdminRequest, Locale, Instant) -> Result<Admin, AdminError> + Send>;
pub(super) struct Flow {
    connect: Connector,
    current: Option<Operation>,
    completion: Option<(u64, Result<(), &'static str>)>,
}
pub(super) struct Operation {
    token: u64,
    change: Change,
    client: Admin,
    expires: Instant,
    epoch: u64,
    receipt: Option<Result<(), AdminError>>,
    reported: bool,
    failed_session: bool,
    pub(super) query: Option<Query>,
    pub(super) confirmed: Option<bool>,
}
pub(super) struct Query {
    pub id: String,
    pub epoch: u64,
    pub observed: BTreeMap<String, u64>,
}
enum Change {
    Save(Profile),
    Remove { id: String, kind: VpnKind },
}
impl Change {
    fn id(&self) -> &str {
        match self {
            Self::Save(p) => &p.id,
            Self::Remove { id, .. } => id,
        }
    }
}
impl Flow {
    pub(super) fn busy(&self) -> bool {
        self.current.is_some() || self.completion.is_some()
    }
    pub(super) fn new() -> Self {
        Self {
            connect: Box::new(Admin::start),
            current: None,
            completion: None,
        }
    }
}
impl<S: SecretStore> Broker<S> {
    #[cfg(all(test, feature = "desktop"))]
    pub(crate) fn administrative_fixture(
        client: Client,
        secrets: S,
        connect: impl FnMut(AdminRequest, Locale, Instant) -> Result<Admin, AdminError> + Send + 'static,
    ) -> Self {
        let mut broker = Self::new(Some(client), secrets);
        broker.administration.connect = Box::new(connect);
        broker
    }
    pub fn begin_admin(
        &mut self,
        command: Command,
        locale: Locale,
        expires: Instant,
    ) -> Result<u64, &'static str> {
        self.poll();
        if self.component.busy() {
            return Err("component_busy");
        }
        if !self.ready || Instant::now() >= expires {
            return Err("backend_unavailable");
        }
        if self.administration.current.is_some() || self.administration.completion.is_some() {
            return Err("admin_busy");
        }
        let (change, command) = match command {
            Command::SaveProfile { profile } => {
                profile.validate()?;
                (
                    Change::Save(profile.clone()),
                    AdminCommand::SaveProfile { profile },
                )
            }
            Command::RemoveProfile { id } => {
                let kind = self
                    .connections
                    .get(&id)
                    .ok_or("not_found")?
                    .view
                    .profile
                    .kind;
                (
                    Change::Remove {
                        id: id.clone(),
                        kind,
                    },
                    AdminCommand::RemoveProfile { id },
                )
            }
            _ => return Err("invalid_request"),
        };
        if self
            .connections
            .get(change.id())
            .is_some_and(|c| c.view.state.active() || c.view.state == State::Disconnecting)
        {
            return Err("profile_busy");
        }
        let token = self.next.checked_add(1).ok_or("backend_unavailable")?;
        let client = (self.administration.connect)(
            AdminRequest {
                id: format!("admin-{token}"),
                command,
            },
            locale,
            expires,
        )
        .map_err(map_error)?;
        self.next = token;
        self.administration.current = Some(Operation {
            token,
            change,
            client,
            expires,
            epoch: self.epoch,
            receipt: None,
            reported: false,
            failed_session: false,
            query: None,
            confirmed: None,
        });
        Ok(token)
    }
    pub fn take_admin_result(&mut self) -> Option<(u64, Result<Snapshot, &'static str>)> {
        let (token, result) = self.administration.completion.take()?;
        Some((token, result.map(|()| self.snapshot())))
    }
    pub(super) fn editing(&self, id: &str) -> bool {
        self.administration
            .current
            .as_ref()
            .is_some_and(|p| p.change.id() == id)
    }
    pub(super) fn poll_admin(&mut self) {
        let Some(mut op) = self.administration.current.take() else {
            return;
        };
        if op.receipt.is_none() {
            op.receipt = op.client.poll();
        }
        if !self.ready || op.epoch != self.epoch {
            op.client.close();
            op.failed_session = true;
            if op.query.as_ref().is_some_and(|q| q.epoch != self.epoch) || !self.ready {
                op.query = None;
            }
        }
        if Instant::now() >= op.expires {
            op.client.close();
        }
        let failure = if op.failed_session {
            Some("backend_unavailable")
        } else if Instant::now() >= op.expires {
            Some("admin_expired")
        } else {
            op.receipt.and_then(|r| r.err()).map(map_error)
        };
        if !op.reported
            && let Some(error) = failure
        {
            self.administration.completion = Some((op.token, Err(error)));
            op.reported = true;
        }
        if op.client.finished()
            && op.receipt.is_some()
            && self.ready
            && op.query.is_none()
            && op.confirmed.is_none()
        {
            let Some(next) = self.next.checked_add(1) else {
                self.administration.current = Some(op);
                return;
            };
            let id = format!("refresh-{next}");
            if self.client.as_ref().is_some_and(|c| {
                c.send(Request {
                    id: id.clone(),
                    command: protocol::Command::Snapshot {},
                })
                .is_ok()
            }) {
                self.next = next;
                op.query = Some(Query {
                    id,
                    epoch: self.epoch,
                    observed: self
                        .connections
                        .iter()
                        .map(|(id, c)| (id.clone(), c.generation))
                        .collect(),
                });
            }
        }
        if op.client.finished()
            && let Some(confirmed) = op.confirmed
        {
            if !op.reported {
                let mut result = if confirmed
                    && op.receipt == Some(Ok(()))
                    && !op.failed_session
                    && Instant::now() < op.expires
                {
                    Ok(())
                } else {
                    Err("admin_unconfirmed")
                };
                if result.is_ok()
                    && let Change::Remove { id, kind } = &op.change
                    && self.secrets.remove(id, *kind).is_err()
                {
                    result = Err("secret_cleanup_failed");
                }
                self.administration.completion = Some((op.token, result));
            }
            return;
        }
        self.administration.current = Some(op);
    }
    pub(super) fn admin_query(&self, id: &str) -> Option<BTreeMap<String, u64>> {
        self.administration
            .current
            .as_ref()?
            .query
            .as_ref()
            .filter(|q| q.id == id && q.epoch == self.epoch)
            .map(|q| q.observed.clone())
    }
    pub(super) fn confirm_admin_snapshot(&mut self) {
        if let Some(op) = &mut self.administration.current {
            let confirmed = match &op.change {
                Change::Save(p) => self.connections.get(&p.id).is_some_and(|c| {
                    c.view.profile == *p
                        && !c.view.state.active()
                        && c.view.state != State::Disconnecting
                }),
                Change::Remove { id, .. } => !self.connections.contains_key(id),
            };
            op.confirmed = Some(confirmed);
        }
    }
    pub(super) fn fail_admin_query(&mut self, id: &str) -> bool {
        if let Some(op) = &mut self.administration.current
            && op.query.as_ref().is_some_and(|q| q.id == id)
        {
            op.confirmed = Some(false);
            return true;
        }
        false
    }
}
fn map_error(error: AdminError) -> &'static str {
    match error {
        AdminError::Expired => "admin_expired",
        AdminError::Canceled => "admin_canceled",
        AdminError::Rejected(ErrorCode::ProfileBusy) => "profile_busy",
        AdminError::Incompatible => "admin_incompatible",
        _ => "admin_unconfirmed",
    }
}
#[cfg(test)]
mod tests;
