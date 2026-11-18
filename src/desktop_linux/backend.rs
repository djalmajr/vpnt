use crate::{
    app::App,
    bridge::{Reply, Request},
};
use std::{
    sync::mpsc::{self, SyncSender},
    time::Instant,
};

struct Work {
    request: Request,
    received: Instant,
}

pub(super) struct Backend {
    input: SyncSender<Work>,
}

impl Backend {
    pub(super) fn new(demo: bool, reply: impl Fn(Reply) + Send + 'static) -> std::io::Result<Self> {
        let (input, requests) = mpsc::sync_channel::<Work>(32);
        std::thread::Builder::new()
            .name("vpnt-desktop-backend".into())
            .spawn(move || {
                let mut app = if demo { App::demo() } else { App::new() };
                while let Ok(work) = requests.recv() {
                    let id = work.request.id;
                    let response = crate::bridge::ovpn::reply(&id, &work.request.command)
                        .unwrap_or_else(|| {
                            Reply::from_result(
                                id,
                                app.dispatch_at(work.request.command, work.received),
                            )
                        });
                    reply(response);
                }
            })?;
        Ok(Self { input })
    }

    pub(super) fn send(&self, request: Request, received: Instant) -> Result<(), ()> {
        self.input
            .try_send(Work { request, received })
            .map_err(|_| ())
    }
}
