//! Start half of the native IPsec attempt: reserve, prepare, capture the
//! original typed interface and start Control without consuming credentials
//! before the guarded operation.
use super::*;
use crate::connection::ipsec::{Observer, Peer};

impl NativeIpsecAttempt<'_> {
    pub(super) fn start_driver(
        &mut self,
        canceled: &AtomicBool,
        expires: Instant,
    ) -> Result<(), Failure> {
        if self.profile.kind != VpnKind::Ipsec {
            return Err(missing_program());
        }
        check(expires, canceled, Step::Profile)?;
        self.expires = Some(expires);
        let profile_use = self
            .profiles
            .begin(&self.profile, self.owner.generation)
            .map_err(profile_failure)?;
        self.profile_use = Some(profile_use);
        let egress = IpsecEgress::select(
            &self.profile,
            canceled,
            bounded(expires, canceled, Step::Egress)?,
        )
        .map_err(|_| Failure::at(Step::Egress))?;
        let egress = Arc::new(egress);
        self.egress = Some(egress.clone());
        // Reservation, admission, opening the producer and Control's start up
        // to `initiate` are the IPsec equivalent of the SSL client start. The
        // interface capture and IKE (`initiate`) belong to the tunnel.
        let unavailable = || Failure::at(Step::Spawn);
        let domain = self.domain.clone();
        let ledger = domain.ledger().clone();
        let mut registry =
            lock_until(domain.registry(), expires, canceled).map_err(|()| unavailable())?;
        let reservation = registry
            .reserve(self.owner.clone())
            .map_err(|_| unavailable())?;
        self.reservation = Some(reservation);
        let prepared = ledger.prepare(
            &registry,
            self.reservation.as_ref().ok_or_else(unavailable)?,
            &self.profile,
            egress,
            (expires, self.canceled.clone()),
        );
        let (config, admission) = keep_for_control(&mut self.reservation, prepared)?;
        drop(registry);
        self.admission = Some(admission.clone());
        let mut admission = admission;
        // The original Admission peer must be opened before capture/start.
        let client = admission
            .open(&self.owner, expires, self.canceled.clone())
            .map_err(|_| unavailable())?;
        drop(client);
        admission
            .capture_interface(expires, self.canceled.clone())
            .map_err(|_| Failure::at(Step::Tunnel))?;
        let reservation = self.reservation.take().ok_or_else(unavailable)?;
        let control = match Control::new(
            domain.registry().clone(),
            reservation,
            config,
            admission.clone(),
        ) {
            Ok(control) => control,
            Err((_error, reservation)) => {
                self.reservation = Some(reservation);
                return Err(unavailable());
            }
        };
        self.control = Some(control);
        let credentials = self.credentials.take().ok_or_else(unavailable)?;
        let control = self.control.as_mut().ok_or_else(unavailable)?;
        control
            .start(credentials, expires, self.canceled.clone())
            .map_err(|_| control_failure(control))
    }
}

/// A failed `Control::start` before `initiate` is the client start; from
/// `initiate` on (IKE negotiation) it is the tunnel.
fn control_failure<N: Observer, P: Peer>(control: &Control<N, P>) -> Failure {
    Failure::at(if control.initiate_sent() {
        Step::Tunnel
    } else {
        Step::Spawn
    })
}

#[cfg(test)]
mod tests {
    //! `Control::start` against an in-process VICI peer that refuses one
    //! command. Both refusals are `Rejected`; only their origin differs.
    use super::*;
    use crate::{
        connection::ipsec::{Config, Error, Registry},
        helper::vici::{self, Client, Message, Packet},
    };
    use std::{collections::BTreeSet, os::unix::net::UnixStream};

    struct Clear;
    impl Observer for Clear {
        fn occupied(&mut self) -> Result<BTreeSet<u32>, Error> {
            Ok(BTreeSet::new())
        }
        fn producer_stopped(&mut self, _: &Owner) -> Result<bool, Error> {
            Ok(false)
        }
    }
    /// Serves one command per open, like charon, and refuses `refuse`.
    struct Refusing {
        refuse: &'static str,
        audit: Arc<Mutex<Vec<String>>>,
    }
    impl Peer for Refusing {
        fn open(
            &mut self,
            _: &Owner,
            expires: Instant,
            cancel: Arc<AtomicBool>,
        ) -> Result<Client, Error> {
            let (client, mut server) = UnixStream::pair().map_err(|_| Error::Unavailable)?;
            let (refuse, audit) = (self.refuse, self.audit.clone());
            thread::spawn(move || {
                let Ok(Packet::Request(command, _)) = vici::read_packet(&mut server) else {
                    return;
                };
                let mut response = Message::new();
                match command.as_str() {
                    "version" => {
                        response
                            .value("daemon", b"charon")
                            .value("version", b"6.1.0");
                    }
                    "stats" => {
                        response.list(
                            "plugins",
                            [
                                "kernel-libipsec",
                                "kernel-pfroute",
                                "socket-default",
                                "vici",
                            ]
                            .map(str::as_bytes),
                        );
                    }
                    name => {
                        let success: &[u8] = if name == refuse { b"no" } else { b"yes" };
                        response.value("success", success);
                    }
                }
                audit.lock().unwrap().push(command);
                let _ = vici::write_packet(&mut server, &Packet::Response(response));
            });
            // SAFETY: geteuid has no memory preconditions.
            Client::from_stream_until(client, unsafe { libc::geteuid() }, expires, cancel)
                .map_err(|_| Error::Unavailable)
        }
        fn retire(&mut self, _: &Owner) -> Result<bool, Error> {
            Ok(true)
        }
    }

    fn start_refusing(refuse: &'static str) -> (Result<(), Failure>, Vec<String>) {
        let mut registry = Registry::new(Clear);
        let reservation = registry
            .reserve(Owner {
                uid: 502,
                profile: "example".into(),
                generation: 1,
            })
            .unwrap();
        let profile = Profile {
            dns_domains: Vec::new(),
            id: "example".into(),
            name: "example".into(),
            kind: VpnKind::Ipsec,
            gateway: "vpn.example.test".into(),
            username: "fictional@example.test".into(),
            networks: vec!["10.20.0.0/24".into()],
            port: 500,
            certificate: String::new(),
            probe_host: "10.20.0.15".into(),
            probe_port: 8443,
            probe_method: "tcp".into(),
        };
        let config = Config::new(
            &registry,
            &reservation,
            &profile,
            "192.0.2.2".parse().unwrap(),
            "198.51.100.3".parse().unwrap(),
        )
        .unwrap();
        let audit = Arc::new(Mutex::new(Vec::new()));
        let peer = Refusing {
            refuse,
            audit: audit.clone(),
        };
        let Ok(mut control) =
            Control::new(Arc::new(Mutex::new(registry)), reservation, config, peer)
        else {
            panic!("fixture configuration must match its reservation");
        };
        let result = control
            .start(
                Credentials {
                    password: "fictional-password".into(),
                    psk: "fictional-key".into(),
                },
                Instant::now() + Duration::from_secs(3),
                Arc::new(AtomicBool::new(false)),
            )
            .map_err(|_| control_failure(&control));
        let audit = audit.lock().unwrap().clone();
        (result, audit)
    }

    #[test]
    fn refused_initiate_is_the_tunnel_and_an_earlier_refusal_the_client_start() {
        let (result, audit) = start_refusing("load-conn");
        assert_eq!(audit, ["version", "stats", "load-conn"]);
        assert_eq!(result.unwrap_err().step, Step::Spawn);

        let (result, audit) = start_refusing("initiate");
        assert_eq!(
            audit,
            [
                "version",
                "stats",
                "load-conn",
                "load-shared",
                "load-shared",
                "initiate"
            ]
        );
        let failure = result.unwrap_err();
        assert_eq!(failure.step, Step::Tunnel);
        assert_eq!(failure.state, ConnectionState::Dropped);
        assert_eq!(failure.error, ErrorCode::BackendFailure);

        // Control: the same peer refusing nothing lets the start complete.
        let (result, audit) = start_refusing("none");
        assert!(result.is_ok());
        assert_eq!(audit.last().map(String::as_str), Some("initiate"));
    }
}
