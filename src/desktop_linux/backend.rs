use crate::{
    app::App,
    bridge::{Reply, Request},
    broker::Broker,
    desktop_actor::Actor,
    preferences::host::{Error, Unavailable},
    secret_service::LinuxSecretService,
};
use std::time::Instant;

pub(super) struct Backend(Actor);

impl Backend {
    pub(super) fn new(demo: bool, reply: impl Fn(Reply) + Send + 'static) -> std::io::Result<Self> {
        Actor::spawn(
            move || {
                if demo {
                    (Some(App::demo()), None)
                } else {
                    (None, Some(real_broker()))
                }
            },
            reply,
        )
        .map(Self)
    }

    pub(super) fn send(&self, request: Request, received: Instant) -> Result<(), ()> {
        self.0.send(request, received)
    }
}

fn real_broker() -> Broker<LinuxSecretService> {
    let broker = Broker::runtime(LinuxSecretService::new());
    match super::preferences::current() {
        Ok(host) => broker.with_preferences_host(host),
        Err(Error::Storage) => {
            broker.with_preferences_host(Box::new(Unavailable::new(Error::Storage)))
        }
        Err(_) => broker,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::parse_request;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn backend_intercepts_ovpn_metadata_before_demo_dispatch() {
        let (send, receive) = mpsc::channel();
        let backend = Backend::new(true, move |reply| {
            let _ = send.send(reply);
        })
        .unwrap();
        let request = parse_request(&serde_json::json!({
            "id":"inspection",
            "command":{"type":"inspect_ovpn","content":"remote fixture.example.test 1194\n<ca>\nSYNTHETIC\n</ca>\n"}
        }).to_string()).unwrap();
        backend.send(request, Instant::now()).unwrap();
        let reply = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(reply.id, "inspection");
        assert_eq!(reply.ovpn.unwrap().gateway, "fixture.example.test");
    }
}
