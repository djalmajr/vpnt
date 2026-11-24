use super::{Error, Observer, Registry, Reservation};
use crate::{
    connection::routes::Network,
    helper::vici::Message,
    model::{Profile, VpnKind},
    secrets::Credentials,
};
use std::{collections::BTreeSet, fmt::Write, net::IpAddr, time::Duration};

#[cfg(target_os = "linux")]
#[path = "control/backend.rs"]
mod linux_backend;
mod selection;
/// Request metadata only. Every transport operation must revalidate its
/// reservation; a built config is neither a live lease nor tunnel evidence.
#[derive(Clone)]
pub struct Config {
    binding: Option<super::namespace::Binding>,
    #[cfg(target_os = "linux")]
    linux_child: Option<(u32, Vec<String>)>,
    name: String,
    child: String,
    pub(super) reqid: u16,
    gateway: String,
    identity: String,
    port: u16,
    pub(super) local: IpAddr,
    pub(super) remote: IpAddr,
    pub(super) networks: Vec<String>,
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
            || !text_identity_username(&profile.username)
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
            binding: Some(reservation.binding()),
            #[cfg(target_os = "linux")]
            linux_child: None,
            child: format!("{name}-child"),
            name,
            reqid: reservation.reqid(),
            gateway: profile.gateway.clone(),
            identity: text_identity(&profile.username)?,
            port: profile.port,
            local,
            remote,
            networks,
        })
    }
    /// The one rule for a literal IKE peer identity on Linux: a typed `fqdn:`,
    /// `email:` or `ipv4:` value that VICI carries unchanged. Policy admission
    /// and the instance's VICI adaptation must both use it.
    #[cfg(target_os = "linux")]
    pub(crate) fn literal_peer_identity(identity: &str) -> bool {
        let Some((kind, text)) = identity.split_once(':') else {
            return false;
        };
        identity.len() <= 253
            && match kind {
                "ipv4" => text
                    .parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|ip| endpoint(ip.into())),
                "fqdn" | "email" => {
                    text_identity_username(text) && text.bytes().all(|b| (0x20..0x7f).contains(&b))
                }
                _ => false,
            }
    }
    /// The Linux writer already owns the attempt and the reqid reservation.
    /// This config is usable only with the instance's private VICI adapter.
    #[cfg(target_os = "linux")]
    pub(crate) fn linux(
        remote: std::net::SocketAddrV4,
        peer_identity: &str,
        username: &str,
        if_id: u32,
        reqid: u16,
        local_ts: Vec<String>,
        remote_ts: Vec<String>,
    ) -> Result<Self, Error> {
        if !Self::literal_peer_identity(peer_identity)
            || username.len() > 200
            || !text_identity_username(username)
        {
            return Err(Error::Invalid);
        }
        let name = format!("vpnt-{reqid}");
        Ok(Self {
            binding: None,
            linux_child: Some((if_id, local_ts)),
            child: format!("{name}-child"),
            name,
            reqid,
            gateway: peer_identity.into(),
            identity: text_identity(username)?,
            port: remote.port(),
            local: std::net::Ipv4Addr::UNSPECIFIED.into(),
            remote: (*remote.ip()).into(),
            networks: remote_ts,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn admit_linux(version: &Message, stats: &Message) -> Result<(), Error> {
        let mut parts = version.get_text("version").unwrap_or_default().split('.');
        if version.get_text("daemon") != Some("charon")
            || parts.next() != Some("6")
            || parts.next() != Some("1")
            || !parts.next().is_some_and(|patch| {
                !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit())
            })
            || parts.next().is_some()
        {
            return Err(Error::Incompatible);
        }
        linux_backend::admit(stats)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub(super) fn matches(&self, reservation: &Reservation) -> bool {
        self.binding
            .as_ref()
            .is_some_and(|binding| binding.matches(reservation))
            && self.reqid == reservation.reqid()
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
            .list(
                "esp_proposals",
                [
                    b"aes256-sha256-ecp384".as_slice(),
                    b"aes256-sha1-ecp384",
                    b"aes256-sha256",
                    b"aes256-sha1",
                ],
            )
            .list("remote_ts", self.networks.iter().map(|n| n.as_bytes()));
        #[cfg(target_os = "linux")]
        let linux_child = self.linux_child.as_ref();
        #[cfg(not(target_os = "linux"))]
        let linux_child: Option<&(u32, Vec<String>)> = None;

        if let Some((if_id, local_ts)) = linux_child {
            let if_id = if_id.to_string();
            child
                .value("if_id_in", if_id.as_bytes())
                .value("if_id_out", if_id.as_bytes())
                .list(
                    "local_ts",
                    local_ts.iter().map(|selector| selector.as_bytes()),
                );
        } else {
            child.list("local_ts", [b"dynamic".as_slice()]);
        }
        let mut children = Message::new();
        children.section(&self.child, child);
        let mut connection = Message::new();
        connection
            .value("version", b"2")
            .value("mobike", b"no")
            .value("dpd_delay", b"30s")
            .value("local_port", b"0")
            .value("remote_port", self.port.to_string().as_bytes());
        if linux_child.is_none() {
            connection.list("local_addrs", [self.local.to_string().as_bytes()]);
        }
        connection
            .list("remote_addrs", [self.remote.to_string().as_bytes()])
            .list("vips", [b"0.0.0.0".as_slice()])
            .list(
                "proposals",
                [
                    b"aes256-sha256-ecp384".as_slice(),
                    b"aes256-sha256-modp2048",
                    b"aes256-sha256-modp1536",
                    b"aes128-sha1-modp1536",
                ],
            );
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
// VICI refuses values with bytes outside printable ASCII (chunk_printable), so
// any other username keeps its text type and travels as '#'-prefixed hex,
// which strongSwan decodes without changing the identity type.
fn text_identity(username: &str) -> Result<String, Error> {
    let kind = if username.contains('@') {
        "email"
    } else {
        "fqdn"
    };
    if username.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        Ok(format!("{kind}:{username}"))
    } else {
        Ok(format!("{kind}:#{}", hex(username)?))
    }
}
fn text_identity_username(username: &str) -> bool {
    // strongSwan's typed identities still decode a leading '#' and recognize
    // '^...$' as regex; '*' also makes FQDN/email secret owners wildcarded.
    !username.is_empty()
        && !username.starts_with('#')
        && !(username.starts_with('^') && username.ends_with('$'))
        && !username.contains('*')
        && !username.chars().any(char::is_control)
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
