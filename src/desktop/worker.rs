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
            crate::bridge::Command::InstallHelper {} | crate::bridge::Command::RemoveHelper {}
        ) {
            599
        } else if matches!(
            request.command,
            crate::bridge::Command::Connect { .. }
                | crate::bridge::Command::Disconnect { .. }
                | crate::bridge::Command::Toggle { .. }
                | crate::bridge::Command::Reconnect { .. }
                | crate::bridge::Command::SaveSecrets { .. }
                | crate::bridge::Command::SaveProfile { .. }
                | crate::bridge::Command::RemoveProfile { .. }
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
    Reply::from_result(id, result)
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
    fn component_deadlines_are_extended_without_changing_other_commands() {
        let (send, receive) = mpsc::sync_channel(1);
        let worker = Worker {
            input: send,
            intent: Arc::new(AtomicU64::new(1)),
            idle_cycles: Arc::new(AtomicU64::new(0)),
        };
        let profile = serde_json::json!({"id":"one","name":"Fixture","kind":"ssl","gateway":"vpn.example.test","username":"fixture","networks":[],"port":443,"certificate":"","probeHost":"192.0.2.1","probePort":8443,"probeMethod":"tcp"});
        let cases = [
            (serde_json::json!({"type":"install_helper"}), 599),
            (serde_json::json!({"type":"remove_helper"}), 599),
            (serde_json::json!({"type":"connect","id":"one"}), 119),
            (serde_json::json!({"type":"disconnect","id":"one"}), 119),
            (serde_json::json!({"type":"toggle","id":"one"}), 119),
            (serde_json::json!({"type":"reconnect","id":"one"}), 119),
            (
                serde_json::json!({"type":"save_secrets","id":"one","password":"fictional","psk":""}),
                119,
            ),
            (
                serde_json::json!({"type":"save_profile","profile":profile}),
                119,
            ),
            (serde_json::json!({"type":"remove_profile","id":"one"}), 119),
            (serde_json::json!({"type":"get_snapshot"}), 9),
            (serde_json::json!({"type":"disconnect_all"}), 9),
            (serde_json::json!({"type":"probe","id":"one"}), 9),
            (serde_json::json!({"type":"hide"}), 9),
            (serde_json::json!({"type":"open_project"}), 9),
            (serde_json::json!({"type":"quit"}), 9),
            (serde_json::json!({"type":"resize","height":320}), 9),
            (
                serde_json::json!({"type":"set_demo_state","id":"one","state":"off"}),
                9,
            ),
            (
                serde_json::json!({"type":"set_preferences","preferences":{"interval":10,"notify":true,"reconnect":false,"startup":false}}),
                9,
            ),
        ];
        for (command, seconds) in cases {
            let name = command["type"].as_str().unwrap().to_owned();
            let body = serde_json::json!({"id":"fixture", "command":command}).to_string();
            let request = crate::bridge::parse_request(&body).unwrap();
            let received = Instant::now();
            worker.send(request, received).unwrap();
            let work = receive.try_recv().unwrap();
            assert_eq!(
                work.expires.duration_since(received),
                Duration::from_secs(seconds),
                "{name}"
            );
        }
    }
    #[test]
    fn profile_admin_exports_only_the_original_119_second_deadline() {
        use crate::helper::{
            admin_client::Admin,
            protocol::{AdminCommand, AdminRequest},
        };
        let (send, receive) = mpsc::sync_channel(1);
        let worker = Worker {
            input: send,
            intent: Arc::new(AtomicU64::new(1)),
            idle_cycles: Arc::new(AtomicU64::new(0)),
        };
        let profile = serde_json::json!({"id":"one","name":"Fixture","kind":"ssl","gateway":"vpn.example.test","username":"fixture","networks":[],"port":443,"certificate":"","probeHost":"192.0.2.1","probePort":8443,"probeMethod":"tcp"});
        let body = serde_json::json!({"id":"fixture", "command":{"type":"save_profile", "profile":profile}}).to_string();
        let received = Instant::now();
        worker
            .send(crate::bridge::parse_request(&body).unwrap(), received)
            .unwrap();
        let work = receive.try_recv().unwrap();
        assert_eq!(
            work.expires.duration_since(received),
            Duration::from_secs(119)
        );
        let crate::bridge::Command::SaveProfile { profile, .. } = work.request.command else {
            panic!("wrong command");
        };
        let request = AdminRequest {
            id: "fixture".into(),
            command: AdminCommand::SaveProfile {
                profile,
                ovpn_config: None,
            },
        };
        struct Marker(std::path::PathBuf);
        impl Drop for Marker {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let marker = Marker(
            std::env::temp_dir().join(format!("vpnt-admin-deadline-{}", std::process::id())),
        );
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker.0)
            .unwrap();
        let source = r#"import json,os,pathlib,socket,sys,time
p=pathlib.Path(sys.argv[2])
try:
 remaining=int(os.environ['VPNT_AUTH_UNTIL_NS'])-time.clock_gettime_ns(time.CLOCK_MONOTONIC)
 p.write_text('remaining='+str(remaining))
 if not 0 < remaining <= 119000000000: raise ValueError('deadline outside 119 seconds')
 s=socket.socket(fileno=0)
 s.sendall((json.dumps({'type':'admin_ready','protocol_version':3,'version':sys.argv[1]})+'\n').encode())
 request=json.loads(s.makefile('rb').read())
 s.sendall((json.dumps({'type':'accepted','id':request['id']})+'\n').encode())
 s.shutdown(socket.SHUT_WR);s.close()
except Exception as exc:
 p.write_text(type(exc).__name__+': '+str(exc));raise
"#;
        let mut command = std::process::Command::new("/usr/bin/python3");
        command
            .arg("-c")
            .arg(source)
            .arg(env!("CARGO_PKG_VERSION"))
            .arg(&marker.0);
        let mut admin = Admin::fixture(
            command,
            request,
            crate::localization::Locale::EnUs,
            work.expires,
        )
        .unwrap();
        let until = Instant::now() + Duration::from_secs(4);
        while !admin.finished() {
            assert!(Instant::now() < until, "admin fixture must exit");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            admin.poll(),
            Some(Ok(())),
            "fixture result: {}",
            std::fs::read_to_string(&marker.0).unwrap()
        );
    }
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

#[cfg(test)]
mod previous_wait_actor_tests {
    use super::*;
    use crate::helper::client::Client;

    #[test]
    fn actor_returns_waiting_snapshot_without_admitting_actions() {
        let script = format!(
            r#"import socket,json
s=socket.socket(fileno=0)
data=b''
while not data.endswith(b'\n'):
    part=s.recv(4096)
    if not part: break
    data+=part
s.sendall((json.dumps(dict(type='previous_session_finishing',protocol_version=3,version='{}'))+'\n').encode())
while s.recv(4096): pass
s.close()
"#,
            env!("CARGO_PKG_VERSION")
        );
        let mut command = std::process::Command::new("/usr/bin/python3");
        command.args(["-c", &script]);
        let client = Client::fixture(command).unwrap();
        let finished = client.fixture_finished();
        let verify_finished = finished.clone();
        struct ActorGuard<F: Fn() -> bool> {
            worker: Option<Worker>,
            finished: F,
        }
        impl<F: Fn() -> bool> Drop for ActorGuard<F> {
            fn drop(&mut self) {
                drop(self.worker.take());
                let until = Instant::now() + Duration::from_secs(4);
                while !(self.finished)() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        let (ready, wait) = mpsc::sync_channel(1);
        let (replies, receive) = mpsc::sync_channel(2);
        let worker = Worker::spawn(
            move || {
                let mut broker =
                    Broker::transport_fixture(client, Keychain(Err(SecretError::Unavailable)));
                let until = Instant::now() + Duration::from_secs(3);
                while broker.snapshot().helper != "previous_session_finishing" {
                    assert!(Instant::now() < until);
                    std::thread::sleep(Duration::from_millis(5));
                }
                ready.send(()).unwrap();
                (None, Some(broker))
            },
            move |reply| {
                let _ = replies.send(reply);
            },
        )
        .unwrap();
        let guard = ActorGuard {
            worker: Some(worker),
            finished,
        };
        wait.recv_timeout(Duration::from_secs(4)).unwrap();
        let start = Instant::now();
        guard
            .worker
            .as_ref()
            .unwrap()
            .send(
                Request {
                    id: "waiting".into(),
                    command: crate::bridge::Command::GetSnapshot {},
                    locale: None,
                },
                start,
            )
            .unwrap();
        let reply = receive.recv_timeout(Duration::from_secs(11)).unwrap();
        assert_eq!(reply.error, None);
        assert_eq!(reply.snapshot.unwrap().helper, "previous_session_finishing");
        guard
            .worker
            .as_ref()
            .unwrap()
            .send(
                Request {
                    id: "blocked".into(),
                    command: crate::bridge::Command::Connect {
                        id: "fixture".into(),
                    },
                    locale: None,
                },
                Instant::now(),
            )
            .unwrap();
        assert!(
            receive
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .error
                .is_some()
        );
        guard
            .worker
            .as_ref()
            .unwrap()
            .send(
                Request {
                    id: "component-blocked".into(),
                    command: crate::bridge::Command::InstallHelper {},
                    locale: None,
                },
                Instant::now(),
            )
            .unwrap();
        assert_eq!(
            receive
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .error
                .as_deref(),
            Some("previous_session_finishing")
        );
        drop(guard);
        assert!(verify_finished(), "fixture child must exit and be reaped");
    }
}
