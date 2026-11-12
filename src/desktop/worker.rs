use crate::{
    app::App,
    bridge::{Reply, Request},
    broker::Broker,
    keychain::MacKeychain,
    model::VpnKind,
    secrets::{Credentials, SecretError, SecretStore},
};
use std::{
    sync::mpsc::{self, SyncSender},
    time::{Duration, Instant},
};

struct Keychain(Result<MacKeychain, SecretError>);
impl Keychain {
    fn store(&self) -> Result<&MacKeychain, SecretError> {
        self.0.as_ref().map_err(|e| *e)
    }
}
impl SecretStore for Keychain {
    fn contains(&self, id: &str, kind: VpnKind) -> Result<bool, SecretError> {
        self.store()?.contains(id, kind)
    }
    fn load(&self, id: &str, kind: VpnKind) -> Result<Credentials, SecretError> {
        self.store()?.load(id, kind)
    }
    fn save(&self, id: &str, kind: VpnKind, value: &Credentials) -> Result<(), SecretError> {
        self.store()?.save(id, kind, value)
    }
    fn remove(&self, id: &str, kind: VpnKind) -> Result<(), SecretError> {
        self.store()?.remove(id, kind)
    }
}
struct Work {
    request: Request,
    expires: Instant,
}
pub(super) struct Worker {
    input: SyncSender<Work>,
}
impl Worker {
    pub fn new(demo: bool, reply: impl Fn(Reply) + Send + 'static) -> Result<Self, std::io::Error> {
        Self::spawn(
            move || {
                let demo = demo.then(App::demo);
                let normal = demo
                    .is_none()
                    .then(|| Broker::runtime(Keychain(MacKeychain::for_current_user())));
                (demo, normal)
            },
            reply,
        )
    }
    fn spawn(
        init: impl FnOnce() -> (Option<App>, Option<Broker<Keychain>>) + Send + 'static,
        reply: impl Fn(Reply) + Send + 'static,
    ) -> Result<Self, std::io::Error> {
        let (input, requests) = mpsc::sync_channel::<Work>(32);
        std::thread::Builder::new()
            .name("vpnt-application".into())
            .spawn(move || {
                let (mut demo, mut normal) = init();
                let mut administrative = std::collections::BTreeMap::new();
                loop {
                    if let Some(normal) = &mut normal {
                        normal.poll();
                        if let Some((token, result)) = normal.take_admin_result()
                            && let Some(id) = administrative.remove(&token)
                        {
                            reply(response(id, result));
                        }
                    }
                    match requests.recv_timeout(Duration::from_millis(20)) {
                        Ok(work) => {
                            if matches!(
                                work.request.command,
                                crate::bridge::Command::GetSnapshot {}
                            ) && let Some(normal) = &mut normal
                            {
                                while normal.starting() && Instant::now() < work.expires {
                                    normal.poll();
                                    std::thread::sleep(Duration::from_millis(5));
                                }
                            }
                            let result = if Instant::now() >= work.expires {
                                Err("backend_unavailable")
                            } else if let Some(demo) = &mut demo {
                                demo.dispatch(work.request.command)
                            } else {
                                if matches!(
                                    work.request.command,
                                    crate::bridge::Command::SaveProfile { .. }
                                        | crate::bridge::Command::RemoveProfile { .. }
                                ) {
                                    match normal.as_mut().unwrap().begin_admin(
                                        work.request.command,
                                        work.request.locale.unwrap_or_default(),
                                        work.expires,
                                    ) {
                                        Ok(token) => {
                                            administrative.insert(token, work.request.id);
                                        }
                                        Err(error) => reply(response(work.request.id, Err(error))),
                                    }
                                    continue;
                                }
                                normal
                                    .as_mut()
                                    .unwrap()
                                    .dispatch(work.request.command, work.expires)
                            };
                            reply(response(work.request.id, result));
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            })?;
        Ok(Self { input })
    }
    pub fn send(&self, request: Request, received: Instant) -> Result<(), ()> {
        let seconds = if matches!(
            request.command,
            crate::bridge::Command::Toggle { .. }
                | crate::bridge::Command::Reconnect { .. }
                | crate::bridge::Command::SaveSecrets { .. }
                | crate::bridge::Command::SaveProfile { .. }
                | crate::bridge::Command::RemoveProfile { .. }
                | crate::bridge::Command::InstallHelper {}
                | crate::bridge::Command::RemoveHelper {}
        ) {
            119
        } else {
            9
        };
        self.input
            .try_send(Work {
                request,
                expires: received + Duration::from_secs(seconds),
            })
            .map_err(|_| ())
    }
}
fn response(id: String, result: Result<crate::model::Snapshot, &'static str>) -> Reply {
    match result {
        Ok(snapshot) => Reply {
            id,
            snapshot: Some(snapshot),
            error: None,
        },
        Err(error) => Reply {
            id,
            snapshot: None,
            error: Some(error.into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod administration;
    #[test]
    fn expired_native_requests_cannot_start_a_demo_or_replay_after_a_ui_timeout() {
        let (send, receive) = mpsc::sync_channel(8);
        let worker = Worker::new(true, move |reply| send.send(reply).unwrap()).unwrap();
        worker
            .send(
                Request {
                    id: "expired".into(),
                    locale: None,
                    command: crate::bridge::Command::Toggle {
                        id: "office".into(),
                    },
                },
                Instant::now() - Duration::from_secs(130),
            )
            .unwrap();
        let reply = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(reply.error.as_deref(), Some("backend_unavailable"));
        worker
            .send(
                Request {
                    id: "fresh".into(),
                    locale: None,
                    command: crate::bridge::Command::GetSnapshot {},
                },
                Instant::now(),
            )
            .unwrap();
        let reply = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        let s = reply.snapshot.unwrap();
        assert!(s.demo);
        assert!(
            s.vpns
                .iter()
                .all(|v| v.state == crate::session::ConnectionState::Off)
        );
    }
}
