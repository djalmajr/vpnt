use crate::{
    app::App,
    bridge::{Command, Reply, Request},
    broker::Broker,
    localization::Locale,
    model::Snapshot,
    secrets::SecretStore,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender},
    },
    time::{Duration, Instant},
};

type ResultSnapshot = Result<Snapshot, &'static str>;

fn list_certificates(id: String, module: String) -> Reply {
    if !crate::model::valid_module_path(&module) {
        return Reply::error(id, "invalid_module");
    }
    match crate::connection::ovpn::pkcs11::list_certificates(std::path::Path::new(&module)) {
        Ok(certificates) => Reply {
            id,
            certificates: Some(
                certificates
                    .into_iter()
                    .map(|certificate| crate::bridge::CertificateView {
                        id: certificate
                            .id
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect(),
                        subject: certificate.subject,
                        issuer: certificate.issuer,
                        not_before: certificate.not_before,
                        not_after: certificate.not_after,
                    })
                    .collect(),
            ),
            ..Reply::default()
        },
        Err(crate::connection::ovpn::pkcs11::TokenError::UntrustedModule) => {
            Reply::error(id, "untrusted_module")
        }
        Err(_) => Reply::error(id, "token_unavailable"),
    }
}

trait Runtime {
    fn poll(&mut self);
    fn take_admin_result(&mut self) -> Option<(u64, ResultSnapshot)>;
    fn take_component_result(&mut self) -> Option<(u64, ResultSnapshot)>;
    fn observe_request(&mut self, request: &Request);
    fn starting(&self) -> bool;
    fn begin_change(
        &mut self,
        command: Command,
        locale: Locale,
        expires: Instant,
    ) -> Result<u64, &'static str>;
    fn dispatch(&mut self, command: Command, expires: Instant) -> ResultSnapshot;
    fn perform_automatic(&mut self, current: impl Fn() -> bool);
}

pub(crate) struct Work {
    pub(crate) request: Request,
    pub(crate) expires: Instant,
    #[cfg(target_os = "linux")]
    received: Instant,
}

pub(crate) struct Actor {
    pub(crate) input: SyncSender<Work>,
    pub(crate) intent: Arc<AtomicU64>,
    #[cfg(test)]
    pub(crate) idle_cycles: Arc<AtomicU64>,
}

impl<S: SecretStore> Runtime for Broker<S> {
    fn poll(&mut self) {
        Broker::poll(self);
    }

    fn take_admin_result(&mut self) -> Option<(u64, ResultSnapshot)> {
        Broker::take_admin_result(self)
    }

    fn take_component_result(&mut self) -> Option<(u64, ResultSnapshot)> {
        #[cfg(target_os = "macos")]
        {
            Broker::take_component_result(self)
        }
        #[cfg(target_os = "linux")]
        {
            None
        }
    }

    fn observe_request(&mut self, request: &Request) {
        self.interrupt_automatic(&request.command);
        if let Some(locale) = request.locale {
            self.set_locale(locale);
        }
    }

    fn starting(&self) -> bool {
        Broker::starting(self)
    }

    fn begin_change(
        &mut self,
        command: Command,
        locale: Locale,
        expires: Instant,
    ) -> Result<u64, &'static str> {
        if matches!(
            &command,
            Command::InstallHelper {} | Command::RemoveHelper {}
        ) {
            #[cfg(target_os = "macos")]
            return self.begin_component(command, locale, expires);
            #[cfg(target_os = "linux")]
            return Err("unsupported");
        }
        self.begin_admin(command, locale, expires)
    }

    fn dispatch(&mut self, command: Command, expires: Instant) -> ResultSnapshot {
        Broker::dispatch(self, command, expires)
    }

    fn perform_automatic(&mut self, current: impl Fn() -> bool) {
        Broker::perform_automatic(self, current);
    }
}

impl Actor {
    pub(crate) fn spawn<S: SecretStore + 'static>(
        init: impl FnOnce() -> (Option<App>, Option<Broker<S>>) + Send + 'static,
        reply: impl Fn(Reply) + Send + 'static,
    ) -> std::io::Result<Self> {
        Self::spawn_with(init, reply)
    }

    fn spawn_with<B: Runtime + 'static>(
        init: impl FnOnce() -> (Option<App>, Option<B>) + Send + 'static,
        reply: impl Fn(Reply) + Send + 'static,
    ) -> std::io::Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return Self::spawn_with_listing(init, reply, list_certificates);
    }

    fn spawn_with_listing<B: Runtime + 'static>(
        init: impl FnOnce() -> (Option<App>, Option<B>) + Send + 'static,
        reply: impl Fn(Reply) + Send + 'static,
        list: impl Fn(String, String) -> Reply + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        let (input, requests) = mpsc::sync_channel::<Work>(32);
        let intent = Arc::new(AtomicU64::new(1));
        let actor_intent = intent.clone();
        #[cfg(test)]
        let idle_cycles = Arc::new(AtomicU64::new(0));
        #[cfg(test)]
        let actor_idle_cycles = idle_cycles.clone();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let list = Arc::new(list);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = list;
        std::thread::Builder::new()
            .name("vpnt-application".into())
            .spawn(move || {
                let (mut demo, mut normal) = init();
                let mut administrative = std::collections::BTreeMap::new();
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                let mut listing: Option<(
                    String,
                    mpsc::Receiver<Reply>,
                    Instant,
                    bool,
                )> = None;
                loop {
                    // A token module may wait on a native call: the listing
                    // runs on its own thread so this loop keeps answering.
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    if let Some((id, receiver, expires, reported)) = &mut listing {
                        match receiver.try_recv() {
                            Ok(value) => {
                                if !*reported {
                                    reply(value);
                                }
                                listing = None;
                            }
                            Err(mpsc::TryRecvError::Disconnected) => {
                                if !*reported {
                                    reply(Reply::error(id.clone(), "token_unavailable"));
                                }
                                listing = None;
                            }
                            Err(mpsc::TryRecvError::Empty)
                                if !*reported && Instant::now() >= *expires =>
                            {
                                reply(Reply::error(id.clone(), "token_unavailable"));
                                *reported = true;
                            }
                            Err(mpsc::TryRecvError::Empty) => {}
                        }
                    }
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
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            if let Command::ListCertificates { module } = &work.request.command {
                                let id = work.request.id.clone();
                                if listing.is_some() {
                                    reply(Reply::error(id, "token_unavailable"));
                                    continue;
                                }
                                let module = module.clone();
                                let list = list.clone();
                                let (send, recv) = mpsc::channel();
                                let worker_id = id.clone();
                                if std::thread::Builder::new()
                                    .name("vpnt-certificate-reply".into())
                                    .spawn(move || {
                                        let _ = send.send(list(worker_id, module));
                                    })
                                    .is_err()
                                {
                                    reply(Reply::error(id, "token_unavailable"));
                                } else {
                                    listing = Some((
                                        id,
                                        recv,
                                        Instant::now() + Duration::from_secs(30),
                                        false,
                                    ));
                                }
                                continue;
                            }
                            #[cfg(target_os = "linux")]
                            if let Some(metadata) =
                                crate::bridge::ovpn::reply(&work.request.id, &work.request.command)
                            {
                                reply(metadata);
                                continue;
                            }
                            if let Some(normal) = &mut normal {
                                normal.observe_request(&work.request);
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
                                #[cfg(target_os = "macos")]
                                let result = demo.dispatch(work.request.command);
                                #[cfg(target_os = "linux")]
                                let result = demo.dispatch_at(work.request.command, work.received);
                                result
                            } else {
                                if matches!(
                                    work.request.command,
                                    crate::bridge::Command::SaveProfile { .. }
                                        | crate::bridge::Command::RemoveProfile { .. }
                                        | crate::bridge::Command::InstallHelper {}
                                        | crate::bridge::Command::RemoveHelper {}
                                ) {
                                    let normal = normal.as_mut().unwrap();
                                    let locale = work.request.locale.unwrap_or_default();
                                    let started = normal.begin_change(
                                        work.request.command,
                                        locale,
                                        work.expires,
                                    );
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
    pub(crate) fn send(&self, request: Request, received: Instant) -> Result<(), ()> {
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
                #[cfg(target_os = "linux")]
                received,
            })
            .map_err(|_| ())
    }
}
fn response(id: String, result: Result<crate::model::Snapshot, &'static str>) -> Reply {
    Reply::from_result(id, result)
}

#[cfg(test)]
#[path = "desktop_actor_tests.rs"]
mod tests;
