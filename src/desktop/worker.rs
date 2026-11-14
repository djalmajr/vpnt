use crate::{
    app::App,
    bridge::{Reply, Request},
    broker::Broker,
    keychain::MacKeychain,
    model::VpnKind,
    secrets::{Credentials, SecretError, SecretStore},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender},
    },
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
    intent: Arc<AtomicU64>,
    #[cfg(test)]
    idle_cycles: Arc<AtomicU64>,
}
impl Worker {
    pub fn new(demo: bool, reply: impl Fn(Reply) + Send + 'static) -> Result<Self, std::io::Error> {
        Self::spawn(
            move || {
                let demo = demo.then(App::demo);
                let normal = demo.is_none().then(|| {
                    let broker = Broker::runtime(Keychain(MacKeychain::for_current_user()));
                    let broker =
                        if let Some(notifier) = super::notifications::Adapter::current_bundle() {
                            broker.with_notifier(Box::new(notifier))
                        } else {
                            broker
                        };
                    match super::preferences::current_bundle() {
                        Ok(host) => broker.with_preferences_host(host),
                        Err(crate::preferences::host::Error::Storage) => broker
                            .with_preferences_host(Box::new(
                                crate::preferences::host::Unavailable::new(
                                    crate::preferences::host::Error::Storage,
                                ),
                            )),
                        Err(_) => broker,
                    }
                });
                (demo, normal)
            },
            reply,
        )
    }
    fn spawn<S: SecretStore + 'static>(
        init: impl FnOnce() -> (Option<App>, Option<Broker<S>>) + Send + 'static,
        reply: impl Fn(Reply) + Send + 'static,
    ) -> Result<Self, std::io::Error> {
        let (input, requests) = mpsc::sync_channel::<Work>(32);
        let intent = Arc::new(AtomicU64::new(1));
        let actor_intent = intent.clone();
        #[cfg(test)]
        let idle_cycles = Arc::new(AtomicU64::new(0));
        #[cfg(test)]
        let actor_idle_cycles = idle_cycles.clone();
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
                        if let Some((token, result)) = normal.take_component_result()
                            && let Some(id) = administrative.remove(&token)
                        {
                            reply(response(id, result));
                        }
                    }
                    let observed_intent = actor_intent.load(Ordering::Acquire);
                    match requests.recv_timeout(Duration::from_millis(20)) {
                        Ok(work) => {
                            if let Some(normal) = &mut normal {
                                normal.interrupt_automatic(&work.request.command);
                                if let Some(locale) = work.request.locale {
                                    normal.set_locale(locale);
                                }
                            }
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
                                        | crate::bridge::Command::InstallHelper {}
                                        | crate::bridge::Command::RemoveHelper {}
                                ) {
                                    let component = matches!(
                                        &work.request.command,
                                        crate::bridge::Command::InstallHelper {}
                                            | crate::bridge::Command::RemoveHelper {}
                                    );
                                    let normal = normal.as_mut().unwrap();
                                    let locale = work.request.locale.unwrap_or_default();
                                    let started = if component {
                                        normal.begin_component(
                                            work.request.command,
                                            locale,
                                            work.expires,
                                        )
                                    } else {
                                        normal.begin_admin(
                                            work.request.command,
                                            locale,
                                            work.expires,
                                        )
                                    };
                                    match started {
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
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if let Some(normal) = &mut normal {
                                normal.perform_automatic(|| {
                                    actor_intent.load(Ordering::Acquire) == observed_intent
                                });
                            }
                            #[cfg(test)]
                            actor_idle_cycles.fetch_add(1, Ordering::Release);
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            })?;
        Ok(Self {
            input,
            intent,
            #[cfg(test)]
            idle_cycles,
        })
    }
    pub fn send(&self, request: Request, received: Instant) -> Result<(), ()> {
        // A queued manual action interrupts background reconnect before it can
        // submit credentials after a blocking keychain read. The actor processes
        // that action before retrying any still-current background work.
        if matches!(
            &request.command,
            crate::bridge::Command::Connect { .. }
                | crate::bridge::Command::Disconnect { .. }
                | crate::bridge::Command::Toggle { .. }
                | crate::bridge::Command::Reconnect { .. }
                | crate::bridge::Command::DisconnectAll {}
                | crate::bridge::Command::SaveProfile { .. }
                | crate::bridge::Command::RemoveProfile { .. }
                | crate::bridge::Command::SaveSecrets { .. }
                | crate::bridge::Command::InstallHelper {}
                | crate::bridge::Command::RemoveHelper {}
                | crate::bridge::Command::Quit {}
        ) || matches!(&request.command, crate::bridge::Command::SetPreferences { preferences } if !preferences.reconnect)
        {
            self.intent.fetch_add(1, Ordering::AcqRel);
        }
        let seconds = if matches!(
            request.command,
            crate::bridge::Command::Connect { .. }
                | crate::bridge::Command::Disconnect { .. }
                | crate::bridge::Command::Toggle { .. }
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
    mod automatic;
    mod automatic_component;
    mod automatic_deadline;
    mod automatic_support;
    mod component;
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
