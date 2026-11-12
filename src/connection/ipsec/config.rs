use super::{Error, Observer, Registry, Reservation};
use crate::{
    connection::routes::Network,
    helper::vici::Message,
    model::{Profile, VpnKind},
    secrets::Credentials,
};
use std::{collections::BTreeSet, fmt::Write, net::IpAddr, time::Duration};
/// Request metadata only. Every transport operation must revalidate its
/// reservation; a built config is neither a live lease nor tunnel evidence.
pub struct Config {
    name: String,
    child: String,
    reqid: u16,
    gateway: String,
    identity: String,
    port: u16,
    local: IpAddr,
    remote: IpAddr,
    networks: Vec<String>,
}
impl Config {
    pub fn new<N: Observer>(
        registry: &Registry<N>,
        reservation: &Reservation,
        profile: &Profile,
        local: IpAddr,
        remote: IpAddr,
    ) -> Result<Self, Error> {
        registry.validate(reservation)?;
        profile.validate().map_err(|_| Error::Invalid)?;
        if profile.kind != VpnKind::Ipsec
            || profile.id != reservation.owner().profile
            || profile.username.is_empty()
            || !endpoint(local)
            || !endpoint(remote)
            || local.is_ipv4() != remote.is_ipv4()
            || profile
                .gateway
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_unspecified())
        {
            return Err(Error::Invalid);
        }
        let encoded = hex(&profile.id)?;
        let owner = reservation.owner();
        let name = format!("vpnt-{}-{}-{}", owner.uid, encoded, owner.generation);
        let networks = if profile.networks.is_empty() {
            vec!["0.0.0.0/0".into(), "::/0".into()]
        } else {
            profile
                .networks
                .iter()
                .map(|n| {
                    let n: Network = n.parse().map_err(|_| Error::Invalid)?;
                    Ok(format!("{}/{}", n.address(), n.prefix()))
                })
                .collect::<Result<BTreeSet<_>, Error>>()?
                .into_iter()
                .collect()
        };
        Ok(Self {
            child: format!("{name}-child"),
            name,
            reqid: reservation.reqid(),
            gateway: profile.gateway.clone(),
            identity: format!("keyid:#{}", hex(&profile.username)?),
            port: profile.port,
            local,
            remote,
            networks,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn child_name(&self) -> &str {
        &self.child
    }
    pub fn connection(&self) -> Message {
        let mut local = Message::new();
        local
            .value("auth", b"eap-mschapv2")
            .value("id", self.identity.as_bytes())
            .value("eap_id", self.identity.as_bytes());
        let mut remote = Message::new();
        remote
            .value("auth", b"psk")
            .value("id", self.gateway.as_bytes());
        let mut child = Message::new();
        child
            .value("mode", b"tunnel")
            .value("reqid", self.reqid.to_string().as_bytes())
            .value("start_action", b"none")
            .value("dpd_action", b"clear")
            .value("close_action", b"none");
        child
            .list("local_ts", [b"dynamic".as_slice()])
            .list("remote_ts", self.networks.iter().map(|n| n.as_bytes()));
        let mut children = Message::new();
        children.section(&self.child, child);
        let mut connection = Message::new();
        connection
            .value("version", b"2")
            .value("mobike", b"no")
            .value("local_port", b"0")
            .value("remote_port", self.port.to_string().as_bytes());
        connection
            .list("local_addrs", [self.local.to_string().as_bytes()])
            .list("remote_addrs", [self.remote.to_string().as_bytes()])
            .list("vips", [b"0.0.0.0".as_slice(), b"::"]);
        connection
            .section("local", local)
            .section("remote", remote)
            .section("children", children);
        let mut root = Message::new();
        root.section(&self.name, connection);
        root
    }
    pub fn shared(&self, credentials: Credentials) -> Result<[Message; 2], Error> {
        credentials
            .validate(VpnKind::Ipsec)
            .map_err(|_| Error::Invalid)?;
        let mut eap = Message::new();
        eap.value("id", format!("{}-eap", self.name).as_bytes())
            .value("type", b"EAP")
            .value("data", credentials.password.expose().as_bytes())
            .list("owners", [self.identity.as_bytes()]);
        let mut psk = Message::new();
        psk.value("id", format!("{}-psk", self.name).as_bytes())
            .value("type", b"IKE")
            .value("data", credentials.psk.expose().as_bytes())
            .list("owners", [self.gateway.as_bytes()]);
        Ok([eap, psk])
    }
    pub fn initiate(&self, timeout: Duration) -> Result<Message, Error> {
        let mut message = self.lifecycle(timeout)?;
        message.value("child", self.child.as_bytes());
        Ok(message)
    }
    pub fn terminate(&self, timeout: Duration) -> Result<Message, Error> {
        self.lifecycle(timeout)
    }
    pub fn unload_connection(&self) -> Message {
        let mut message = Message::new();
        message.value("name", self.name.as_bytes());
        message
    }
    pub fn unload_shared(&self) -> [Message; 2] {
        ["eap", "psk"].map(|kind| {
            let mut message = Message::new();
            message.value("id", format!("{}-{kind}", self.name).as_bytes());
            message
        })
    }
    fn lifecycle(&self, timeout: Duration) -> Result<Message, Error> {
        if timeout.is_zero() || timeout > Duration::from_secs(120) {
            return Err(Error::Invalid);
        }
        let milliseconds = timeout.as_nanos().div_ceil(1_000_000);
        let mut message = Message::new();
        message
            .value("ike", self.name.as_bytes())
            .value("timeout", milliseconds.to_string().as_bytes())
            .value("loglevel", b"-1");
        Ok(message)
    }
}
fn endpoint(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        && !matches!(ip,IpAddr::V6(ip) if ip.is_unicast_link_local())
}

fn hex(value: &str) -> Result<String, Error> {
    let mut encoded = String::new();
    for byte in value.bytes() {
        write!(&mut encoded, "{byte:02x}").map_err(|_| Error::Invalid)?;
    }
    Ok(encoded)
}
