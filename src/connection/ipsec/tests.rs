use super::*;
use crate::{
    connection::routes::Owner,
    helper::vici::{self, Message, Packet},
    model::{Profile, VpnKind},
    secrets::Credentials,
};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};
mod control;
mod control_peer;
mod identity;
mod namespace;
#[cfg(target_os = "macos")]
mod sdk;
#[derive(Default)]
struct Kernel {
    occupied: BTreeSet<u32>,
    stopped: bool,
    fail: bool,
}
#[derive(Clone, Default)]
struct Observation(Arc<Mutex<Kernel>>);
impl Observer for Observation {
    fn occupied(&mut self) -> Result<BTreeSet<u32>, Error> {
        let k = self.0.lock().unwrap();
        if k.fail {
            Err(Error::Unavailable)
        } else {
            Ok(k.occupied.clone())
        }
    }
    fn producer_stopped(&mut self, _: &Owner) -> Result<bool, Error> {
        let k = self.0.lock().unwrap();
        if k.fail {
            Err(Error::Unavailable)
        } else {
            Ok(k.stopped)
        }
    }
}
fn owner(id: &str, generation: u64) -> Owner {
    Owner {
        uid: 502,
        profile: id.into(),
        generation,
    }
}
fn profile() -> Profile {
    Profile {
        id: "Case".into(),
        name: "Fixture VPN".into(),
        kind: VpnKind::Ipsec,
        gateway: "vpn.example.com".into(),
        username: "fixture@example.com".into(),
        networks: vec!["10.20.0.9/24".into()],
        port: 500,
        certificate: String::new(),
        probe_host: "10.20.0.15".into(),
        probe_port: 8443,
        probe_method: "tcp".into(),
    }
}
fn creds() -> Credentials {
    Credentials {
        password: "fictional-eap-password".into(),
        psk: "fictional-gateway-key".into(),
    }
}
fn config(
    registry: &Registry<Observation>,
    reservation: &Reservation,
    p: &Profile,
) -> Result<Config, Error> {
    Config::new(
        registry,
        reservation,
        p,
        "192.0.2.2".parse().unwrap(),
        "198.51.100.3".parse().unwrap(),
    )
}
fn wire(command: &str, body: Message) -> Message {
    let mut bytes = Vec::new();
    vici::write_packet(&mut bytes, &Packet::Request(command.into(), body)).unwrap();
    let Packet::Request(got, body) = vici::read_packet(&mut bytes.as_slice()).unwrap() else {
        panic!("request frame expected")
    };
    assert_eq!(got, command);
    body
}

#[test]
fn private_ike_configuration_has_fixed_scope_and_only_shared_messages_carry_credentials() {
    let mut registry = Registry::new(Observation::default());
    let reservation = registry
        .reserve(owner("Case", 7))
        .expect("a free kernel namespace must be reservable");
    let c = config(&registry, &reservation, &profile()).unwrap();
    assert_eq!(c.name(), "vpnt-502-43617365-7");
    assert_eq!(c.child_name(), "vpnt-502-43617365-7-child");
    let root = wire("load-conn", c.connection());
    let conn = root.get_section(c.name()).unwrap();
    for (key, value) in [
        ("version", "2"),
        ("mobike", "no"),
        ("remote_port", "500"),
        ("local_port", "0"),
    ] {
        assert_eq!(conn.get_text(key), Some(value));
    }
    assert_eq!(
        conn.get_section("local").unwrap().get_text("auth"),
        Some("eap-mschapv2")
    );
    assert_eq!(
        conn.get_section("remote").unwrap().get_text("auth"),
        Some("psk")
    );
    assert_eq!(
        conn.get_section("remote").unwrap().get_text("id"),
        Some("vpn.example.com")
    );
    let child = conn
        .get_section("children")
        .unwrap()
        .get_section(c.child_name())
        .unwrap();
    assert_eq!(
        child.get_text("reqid"),
        Some(reservation.reqid().to_string().as_str())
    );
    assert_eq!(child.get_text("start_action"), Some("none"));
    assert_eq!(child.get_text("dpd_action"), Some("clear"));
    assert_eq!(
        child.get_list("remote_ts").unwrap()[0].as_slice(),
        b"10.20.0.0/24"
    );
    let mut raw = Vec::new();
    vici::write_packet(
        &mut raw,
        &Packet::Request("load-conn".into(), c.connection()),
    )
    .unwrap();
    for secret in ["fictional-eap-password", "fictional-gateway-key"] {
        assert!(!raw.windows(secret.len()).any(|v| v == secret.as_bytes()));
    }
    let [eap, psk] = c.shared(creds()).unwrap();
    for (body, kind, secret, identity) in [
        (
            eap,
            "EAP",
            "fictional-eap-password",
            "keyid:#66697874757265406578616d706c652e636f6d",
        ),
        (psk, "IKE", "fictional-gateway-key", "vpn.example.com"),
    ] {
        let body = wire("load-shared", body);
        assert_eq!(body.get_text("type"), Some(kind));
        assert!(body.get_value("data") == Some(secret.as_bytes()));
        assert_eq!(body.get_list("owners").unwrap().len(), 1);
        assert!(body.get_list("owners").unwrap()[0].as_slice() == identity.as_bytes());
        assert!(!format!("{body:?}").contains(secret));
    }
    let initiate = wire("initiate", c.initiate(Duration::from_micros(1)).unwrap());
    assert_eq!(initiate.get_text("ike"), Some(c.name()));
    assert_eq!(initiate.get_text("child"), Some(c.child_name()));
    assert_eq!(initiate.get_text("timeout"), Some("1"));
    assert_eq!(initiate.get_text("loglevel"), Some("-1"));
    let terminate = wire("terminate", c.terminate(Duration::from_secs(2)).unwrap());
    assert_eq!(terminate.get_text("ike"), Some(c.name()));
    assert_eq!(terminate.get_text("timeout"), Some("2000"));
    assert_eq!(
        wire("unload-conn", c.unload_connection()).get_text("name"),
        Some(c.name())
    );
    let shared = c.unload_shared();
    assert_ne!(shared[0].get_text("id"), shared[1].get_text("id"));
    assert!(
        shared
            .iter()
            .all(|m| m.get_text("id").unwrap().starts_with(c.name()))
    );
}

#[test]
fn configuration_cannot_cross_a_profile_or_reservation_or_use_an_invalid_endpoint_or_deadline() {
    let mut registry = Registry::new(Observation::default());
    let reservation = registry.reserve(owner("Case", 1)).unwrap();
    let p = profile();
    let mut wrong = p.clone();
    wrong.id = "case".into();
    assert!(matches!(
        config(&registry, &reservation, &wrong),
        Err(Error::Invalid)
    ));
    wrong = p.clone();
    wrong.kind = VpnKind::Ssl;
    assert!(matches!(
        config(&registry, &reservation, &wrong),
        Err(Error::Invalid)
    ));
    wrong = p.clone();
    wrong.username.clear();
    assert!(matches!(
        config(&registry, &reservation, &wrong),
        Err(Error::Invalid)
    ));
    for (local, remote) in [
        ("0.0.0.0", "198.51.100.3"),
        ("192.0.2.2", "224.0.0.1"),
        ("192.0.2.2", "::1"),
    ] {
        assert!(
            Config::new(
                &registry,
                &reservation,
                &p,
                local.parse().unwrap(),
                remote.parse().unwrap()
            )
            .is_err()
        );
    }
    let c = config(&registry, &reservation, &p).unwrap();
    for duration in [Duration::ZERO, Duration::from_secs(121)] {
        assert!(c.initiate(duration).is_err());
        assert!(c.terminate(duration).is_err());
    }
    let mut secret = creds();
    secret.psk = "".into();
    assert!(c.shared(secret).is_err());
    let foreign = Registry::new(Observation::default());
    assert!(matches!(
        config(&foreign, &reservation, &p),
        Err(Error::Changed)
    ));
}
