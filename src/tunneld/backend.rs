//! Admission, authenticated instance control, and lease recovery.
use super::{
    attest::SystemdAttestor,
    cleanup::{Reservation, Store},
    fortinet_instance::{self, Event},
    fortinet_network::{self, FortinetNetwork},
    handshake::{
        AuthenticatedChannel, Backend, CONTROL_SOCKET_NAME, RECORD_NAME, UnitAttestor,
        UnitIdentity, Writer,
    },
    instance_protocol::{Order, Reply, Start, encode_credentials},
    network::{Network, Receipt, SetupCancellation, parse_cidr, valid_generation},
    policy::{Entry, MAX_IPSEC_ROUTES},
    protocol::{
        self, CidrV4, Credentials, ErrorCode, FortinetRequest, Prepare, ProbeBinding, State,
    },
};
use crate::{
    helper::local_socket::Budget,
    netd::{iproute::Backend as NetworkBackend, server::ovpn_present},
    netlease::{NetworkGuard, NetworkLock},
};
use serde::Deserialize;
use std::{
    ffi::OsStr,
    fs::{self, DirBuilder, File},
    io,
    net::Ipv4Addr,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

/// Runtime directory shared with the network writers.
pub(super) const RUNTIME_DIRECTORY: &str = "/run/vpnt";
/// Per-generation private directories live in `<runtime>/tunneld/<generation>`.
/// The unit templates bind that directory read-only into the instance.
pub(super) const INSTANCE_DIRECTORY: &str = "tunneld";
/// The instance units run as root with group 0.
pub(super) const INSTANCE_GID: libc::gid_t = 0;

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const LOCK_DEADLINE: Duration = Duration::from_secs(4);
const START_DEADLINE: Duration = Duration::from_secs(5);
const STOP_DEADLINE: Duration = Duration::from_secs(30);
const ESTABLISHED_TIMEOUT: Duration = Duration::from_secs(35);
// Allow for the instance's bounded VICI cleanup and child termination.
const STOPPED_TIMEOUT: Duration = Duration::from_secs(8);

/// Admit a session and return its running handle.
pub(super) trait Launch: Send + Sync {
    fn launch<'a>(
        &'a self,
        offer: &Prepare,
        grant: &Entry,
        credentials: Credentials,
        authorization: File,
        cancel: &Arc<SetupCancellation>,
    ) -> Result<Box<dyn Running + 'a>, ErrorCode>;

    fn launch_v2<'a>(
        &'a self,
        offer: &Prepare,
        grant: &Entry,
        credentials: Credentials,
        authorization: File,
        cancel: &Arc<SetupCancellation>,
        reservation: &mut Reservation<'_>,
    ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
        let _ = (
            offer,
            grant,
            credentials,
            authorization,
            cancel,
            reservation,
        );
        Err(ErrorCode::Backend)
    }
}

/// One admitted session. Dropping it stops it.
pub(super) trait Running: Send {
    fn state(&self) -> State;
    fn probe_binding(&self, _: Instant) -> io::Result<ProbeBinding> {
        Err(io::Error::other("unconfirmed probe binding"))
    }
    fn peer(&self) -> Option<BorrowedFd<'_>> {
        None
    }
    fn channel_fd(&self) -> Option<BorrowedFd<'_>> {
        None
    }
    /// Stop and clean up. A `CleanupPending` result may be retried.
    fn stop(&mut self) -> State;
}

pub(super) fn retry_cleanup(mut attempt: impl FnMut() -> bool) -> bool {
    const ATTEMPTS: usize = 3;
    for count in 0..ATTEMPTS {
        if count != 0 {
            thread::sleep(Duration::from_millis(100));
        }
        if attempt() {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub lock: Duration,
    pub start: Duration,
    pub stop: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            lock: LOCK_DEADLINE,
            start: START_DEADLINE,
            stop: STOP_DEADLINE,
        }
    }
}

type AcquireLock = Box<dyn Fn(Instant) -> io::Result<NetworkGuard> + Send + Sync>;

pub(super) struct Launcher<N, A> {
    runtime: PathBuf,
    systemctl: PathBuf,
    network: N,
    attestor: A,
    xfrm: Network,
    fortinet: FortinetNetwork,
    lock: AcquireLock,
    limits: Limits,
}

impl<N: NetworkBackend> Launcher<N, SystemdAttestor> {
    pub(super) fn system(network: N) -> Self {
        Self {
            runtime: PathBuf::from(RUNTIME_DIRECTORY),
            systemctl: PathBuf::from(SYSTEMCTL),
            network,
            attestor: SystemdAttestor,
            xfrm: Network::default(),
            fortinet: FortinetNetwork::default(),
            lock: Box::new(NetworkLock::acquire),
            limits: Limits::default(),
        }
    }
}

/// What this attempt has already done, so teardown reverses exactly that.
struct Attempt {
    backend: Backend,
    generation: String,
    unit: String,
    registered: bool,
    directory: bool,
    started: bool,
    /// A runtime `IPAddressAllow` was requested for the unit: a failed call
    /// may still have written the drop-in, so teardown always reverts it.
    allowed: bool,
    credentials_sent: bool,
    managed_cleanup: bool,
    receipt: Option<Receipt>,
    fortinet: Option<fortinet_network::Receipt>,
}

impl Attempt {
    fn new(backend: Backend, generation: String) -> Self {
        let kind = match backend {
            Backend::Ipsec => "ipsec",
            Backend::Fortinet => "fortinet",
        };
        let unit = format!("vpnt-tunneld-{kind}@{generation}.service");
        Self {
            backend,
            generation,
            unit,
            registered: false,
            directory: false,
            started: false,
            allowed: false,
            credentials_sent: false,
            managed_cleanup: false,
            receipt: None,
            fortinet: None,
        }
    }
}

struct Failure {
    code: ErrorCode,
    cause: String,
}

impl Failure {
    fn new(code: ErrorCode, cause: impl std::fmt::Display) -> Self {
        Self {
            code,
            cause: cause.to_string(),
        }
    }

    fn io(step: &str, error: &io::Error) -> Self {
        let code = if error.kind() == io::ErrorKind::TimedOut {
            ErrorCode::Timeout
        } else {
            ErrorCode::Backend
        };
        Self::new(code, format_args!("{step}: {error}"))
    }
}

// Projection of the canonical policy entry. The offer only supplies a username.
#[derive(Deserialize)]
struct IpsecGrant {
    hostname: String,
    peer_identity: String,
    transport_ipv4: Vec<Ipv4Addr>,
    port: u16,
    route_cidrs: Vec<String>,
}

struct IpsecStart {
    order: Start,
    approved: Vec<Ipv4Addr>,
    credentials: zeroize::Zeroizing<Vec<u8>>,
}

/// Everything the writer needs to admit a Fortinet attempt, from the policy
/// entry and the user's password. The user's request supplied only the username.
struct FortinetStart {
    host: String,
    port: u16,
    username: String,
    certificate_sha256: String,
    remote: Ipv4Addr,
    grant: fortinet_network::Grant,
    credentials: zeroize::Zeroizing<Vec<u8>>,
}

enum Setup {
    Ipsec(IpsecStart),
    Fortinet(FortinetStart),
}

/// What an attempt ended with, in the codes the writer's clients know.
fn fatal_code(fatal: &fortinet_network::Fatal) -> ErrorCode {
    use fortinet_instance::Failure as Reported;
    use fortinet_network::Fatal;
    match fatal {
        Fatal::Failure(Reported::CredentialsRejected) => ErrorCode::PermissionDenied,
        Fatal::Failure(Reported::GatewayTimeout) => ErrorCode::Timeout,
        Fatal::Failure(Reported::LocalAddressDenied) => ErrorCode::FortinetLocalAddressDenied,
        Fatal::InterfaceMismatch | Fatal::Exited | Fatal::Invalid => ErrorCode::Backend,
    }
}

struct CapturePeer<'a, A> {
    attestor: &'a A,
    cancel: &'a SetupCancellation,
    peer: std::cell::RefCell<Option<OwnedFd>>,
}

impl<A: UnitAttestor> UnitAttestor for CapturePeer<'_, A> {
    fn attest(&self, fd: BorrowedFd<'_>) -> io::Result<UnitIdentity> {
        self.attest_until(fd, Instant::now() + START_DEADLINE)
    }

    fn attest_until(&self, fd: BorrowedFd<'_>, deadline: Instant) -> io::Result<UnitIdentity> {
        self.cancel.check()?;
        let identity = self.attestor.attest_until(fd, deadline)?;
        self.cancel.check()?;
        self.peer.replace(Some(fd.try_clone_to_owned()?));
        Ok(identity)
    }
}

impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Launcher<N, A> {
    fn bring_up(
        &self,
        attempt: &mut Attempt,
        setup: Option<Setup>,
        entry: Option<&Entry>,
        authorization: Option<File>,
        channel: &mut Option<AuthenticatedChannel>,
        cancel: &SetupCancellation,
        reservation: Option<&mut Reservation<'_>>,
    ) -> Result<OwnedFd, Failure> {
        cancel.check().map_err(|e| Failure::io("admission", &e))?;
        let guard = (self.lock)(Instant::now() + self.limits.lock).map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut {
                Failure::new(ErrorCode::Busy, "network write lock is contended")
            } else {
                Failure::io("network write lock", &error)
            }
        })?;
        if ovpn_present(&self.network).map_err(|e| Failure::io("network inventory", &e))? {
            return Err(Failure::new(ErrorCode::Busy, "an OVPN tunnel is present"));
        }
        if guard
            .tunnels_present()
            .map_err(|e| Failure::io("lease registry", &e))?
        {
            return Err(Failure::new(ErrorCode::Busy, "a tunnel lease is present"));
        }
        cancel
            .check()
            .map_err(|e| Failure::io("generation setup", &e))?;
        let directory = self
            .create_directory(&attempt.generation)
            .map_err(|e| Failure::io("generation directory", &e))?;
        attempt.directory = true;
        match setup.as_ref() {
            Some(Setup::Ipsec(setup)) => {
                let receipt = self
                    .xfrm
                    .plan(
                        &guard,
                        &attempt.generation,
                        setup.order.remote_ipv4,
                        &setup.approved,
                        setup.order.remote_ts.clone(),
                    )
                    .map_err(|e| Failure::io("network admission", &e))?;
                cancel.check().map_err(|e| Failure::io("lease setup", &e))?;
                receipt
                    .save(&directory, &guard)
                    .map_err(|e| Failure::io("network receipt", &e))?;
                // Ensure the generation directory entry itself is durable before spawn.
                File::open(self.runtime.join(INSTANCE_DIRECTORY))
                    .and_then(|dir| dir.sync_all())
                    .map_err(|e| Failure::io("generation directory sync", &e))?;
                attempt.receipt = Some(receipt);
            }
            Some(Setup::Fortinet(setup)) => {
                let receipt = self
                    .fortinet
                    .plan(&guard, &attempt.generation, setup.remote, &setup.grant)
                    .map_err(|e| Failure::io("network admission", &e))?;
                cancel.check().map_err(|e| Failure::io("lease setup", &e))?;
                receipt
                    .save(&directory, &guard)
                    .map_err(|e| Failure::io("network receipt", &e))?;
                File::open(self.runtime.join(INSTANCE_DIRECTORY))
                    .and_then(|dir| dir.sync_all())
                    .map_err(|e| Failure::io("generation directory sync", &e))?;
                attempt.fortinet = Some(receipt);
            }
            None => {}
        }
        // A dead writer releases the flock. Only a durable, generation-scoped
        // network receipt and an armed cleanup record may precede a lease.
        if let Some(record) = reservation {
            record
                .arm()
                .map_err(|e| Failure::io("arm cleanup receipt", &e))?;
        }
        // A sync error after creation can still leave the marker.
        attempt.registered = true;
        guard
            .register(&attempt.generation)
            .map_err(|e| Failure::io("lease registration", &e))?;
        // The lease now excludes other network writers. Keep the policy
        // lock until the manager has accepted the unit start request.
        drop(guard);

        let writer = Writer::publish(
            &directory,
            OsStr::new(CONTROL_SOCKET_NAME),
            &attempt.generation,
            attempt.backend,
            INSTANCE_GID,
        )
        .map_err(|e| Failure::io("handshake publication", &e))?;
        // Writer creates the file exclusively in this private directory. Its
        // current API fixes the initial basename; the unit binds RECORD_NAME.
        fs::rename(
            directory.join(&attempt.generation),
            directory.join(RECORD_NAME),
        )
        .map_err(|e| Failure::io("handshake record basename", &e))?;

        // The units deny every address. Open only the frozen transport IPv4 of
        // this generation (the one the Start order carries), at runtime, and
        // before the unit exists as a process.
        if let Some(transport) = match setup.as_ref() {
            Some(Setup::Ipsec(setup)) => Some(setup.order.remote_ipv4),
            Some(Setup::Fortinet(setup)) => Some(setup.remote),
            None => None,
        } {
            let allow = format!("IPAddressAllow={transport}/32");
            let allow_deadline = Instant::now() + self.limits.start;
            let child = cancel
                .start(|| {
                    attempt.allowed = true; // A failed call may still have written the drop-in.
                    spawn_systemctl(
                        &self.systemctl,
                        &["set-property", "--runtime", &attempt.unit, &allow],
                    )
                })
                .map_err(|e| Failure::io("systemctl set-property", &e))?;
            wait_systemctl(child, allow_deadline)
                .map_err(|e| Failure::io("systemctl set-property", &e))?;
        }
        let start_deadline = Instant::now() + self.limits.start;
        let child = cancel
            .start(|| {
                attempt.started = true; // A failed call may still have queued the job.
                spawn_systemctl(
                    &self.systemctl,
                    &["start", "--no-block", "--", &attempt.unit],
                )
            })
            .map_err(|e| Failure::io("systemctl start", &e))?;
        wait_systemctl(child, start_deadline).map_err(|e| Failure::io("systemctl start", &e))?;
        drop(authorization);
        cancel
            .check()
            .map_err(|e| Failure::io("handshake setup", &e))?;
        let attestor = CapturePeer {
            attestor: &self.attestor,
            cancel,
            peer: Default::default(),
        };
        let authenticated = channel.insert(
            writer
                .authenticate(&attestor)
                .map_err(|e| Failure::io("instance authentication", &e))?,
        );
        match setup {
            Some(Setup::Ipsec(setup)) => {
                self.establish(attempt, setup, authenticated, &directory, cancel)?;
            }
            Some(Setup::Fortinet(setup)) => {
                let entry = entry.expect("a Fortinet setup comes with its policy entry");
                self.establish_fortinet(attempt, setup, entry, authenticated, &directory, cancel)?;
            }
            None => {}
        }
        cancel
            .check()
            .map_err(|e| Failure::io("session publication", &e))?;
        let peer = attestor
            .peer
            .into_inner()
            .ok_or_else(|| Failure::new(ErrorCode::Backend, "missing attested peer"))?;
        let mut pollfd = libc::pollfd {
            fd: peer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll updates one initialized entry for a live descriptor.
        match unsafe { libc::poll(&mut pollfd, 1, 0) } {
            0 => Ok(peer),
            -1 => Err(Failure::io(
                "instance liveness check",
                &io::Error::last_os_error(),
            )),
            _ => Err(Failure::new(
                ErrorCode::Backend,
                "instance exited before publication",
            )),
        }
    }

    fn establish(
        &self,
        attempt: &mut Attempt,
        mut setup: IpsecStart,
        channel: &mut AuthenticatedChannel,
        directory: &Path,
        cancel: &SetupCancellation,
    ) -> Result<(), Failure> {
        let receipt = attempt
            .receipt
            .as_mut()
            .expect("IPsec receipt precedes start");
        setup.order.if_id = receipt.if_id;
        setup.order.reqid = receipt.reqid;
        let start = serde_json::to_vec(&Order::Start(setup.order))
            .map_err(|_| Failure::new(ErrorCode::Backend, "invalid Start order"))?;
        cancel
            .start(|| channel.send(&start))
            .map_err(|e| Failure::io("instance Start", &e))?;
        let sent = cancel.start(|| channel.send(&setup.credentials));
        zeroize::Zeroize::zeroize(&mut setup.credentials);
        sent.map_err(|e| Failure::io("instance credentials", &e))?;
        attempt.credentials_sent = true;
        let reply = wait_setup_reply(channel, cancel)
            .map_err(|e| Failure::io("instance setup reply", &e))?;
        let vip = match reply {
            Reply::Established {
                if_id,
                reqid,
                virtual_ipv4,
                remote_ts,
            } if if_id == receipt.if_id && reqid == receipt.reqid => {
                receipt
                    .select_routes(remote_ts)
                    .map_err(|e| Failure::io("negotiated routes", &e))?;
                virtual_ipv4
            }
            Reply::Failed { code } => return Err(Failure::new(code, "instance failed setup")),
            _ => {
                return Err(Failure::new(
                    ErrorCode::Backend,
                    "unexpected instance setup reply",
                ));
            }
        };
        let guard = (self.lock)(Instant::now() + self.limits.lock)
            .map_err(|e| Failure::io("network write lock", &e))?;
        self.xfrm
            .install_checked(&guard, directory, receipt, vip, &setup.approved, cancel)
            .map_err(|e| Failure::io("configure XFRM network", &e))
    }

    /// Start the instance, wait until it observes the PPP link with the routes
    /// and DNS the gateway delivered, then apply what policy accepts.
    fn establish_fortinet(
        &self,
        attempt: &mut Attempt,
        mut setup: FortinetStart,
        entry: &Entry,
        channel: &mut AuthenticatedChannel,
        directory: &Path,
        cancel: &SetupCancellation,
    ) -> Result<(), Failure> {
        let receipt = attempt
            .fortinet
            .as_mut()
            .expect("Fortinet receipt precedes start");
        let (interface, index, gateway) = receipt.binding();
        let deadline = protocol::FortinetDeadline::new()
            .map_err(|e| Failure::io("instance establishment clock", &e))?;
        let start = fortinet_instance::Start {
            host: setup.host.clone(),
            port: setup.port,
            username: setup.username.clone(),
            certificate_sha256: setup.certificate_sha256.clone(),
            fortinet_local_cidr: setup.grant.fortinet_local_cidr,
            interface: interface.to_owned(),
            index,
            gateway,
            ppp_ifname: receipt.ifname.clone(),
            establishment_deadline_ms: deadline.monotonic_ms,
        };
        let start = serde_json::to_vec(&start)
            .map_err(|_| Failure::new(ErrorCode::Backend, "invalid Start order"))?;
        // Each send begins under the cancellation lock, like the IPsec ones.
        cancel
            .start(|| channel.send(&start))
            .map_err(|e| Failure::io("instance Start", &e))?;
        let sent = cancel.start(|| {
            super::network::check_deadline(Some(deadline.instant))?;
            channel.send(&setup.credentials)
        });
        zeroize::Zeroize::zeroize(&mut setup.credentials);
        sent.map_err(|e| Failure::io("instance credentials", &e))?;
        attempt.credentials_sent = true;

        let deadline = deadline.instant;
        let mut delivered = fortinet_network::Delivered::default();
        loop {
            let event = wait_event(channel, cancel, deadline)
                .map_err(|e| Failure::io("instance setup event", &e))?;
            delivered.absorb(event);
            if let Some(fatal) = delivered.fatal() {
                return Err(Failure::new(
                    fatal_code(&fatal),
                    format_args!("instance reported {fatal:?}"),
                ));
            }
            if delivered.ready() {
                break;
            }
        }
        // Whatever is already queued behind the last event counts too: a late
        // `interface_mismatch` must stop the attempt before anything is applied.
        while channel
            .wait_control(Duration::ZERO)
            .map_err(|e| Failure::io("instance setup event", &e))?
        {
            let event = wait_event(channel, cancel, deadline)
                .map_err(|e| Failure::io("instance setup event", &e))?;
            delivered.absorb(event);
        }
        if let Some(fatal) = delivered.fatal() {
            return Err(Failure::new(
                fatal_code(&fatal),
                format_args!("instance reported {fatal:?}"),
            ));
        }
        cancel
            .check()
            .map_err(|e| Failure::io("configure PPP network", &e))?;
        let guard = (self.lock)(Instant::now() + self.limits.lock)
            .map_err(|e| Failure::io("network write lock", &e))?;
        let scope = fortinet_network::Scope {
            entry,
            grant: &setup.grant,
        };
        self.fortinet
            .apply(&guard, directory, receipt, &delivered, &scope, cancel)
            .map_err(|e| Failure::io("configure PPP network", &e))?;
        if attempt.managed_cleanup {
            self.fortinet
                .mark_probe_link(&guard, directory, receipt, cancel)
                .map_err(|e| Failure::io("mark PPP probe link", &e))?;
        }
        let report = receipt.report();
        // Counts only: nothing the gateway printed is logged.
        eprintln!(
            "vpnt-tunneld: fortinet network ready: routes accepted {} refused {}, \
             DNS servers {} refused {}",
            report.accepted_routes, report.refused_routes, report.dns_servers, report.refused_dns
        );
        Ok(())
    }

    fn create_directory(&self, generation: &str) -> io::Result<PathBuf> {
        let parent = self.runtime.join(INSTANCE_DIRECTORY);
        match DirBuilder::new().mode(0o700).create(&parent) {
            Ok(()) => {
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
                File::open(&self.runtime)?.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        require_private(&parent)?;
        let directory = parent.join(generation);
        // Exclusive: a generation is never reused.
        DirBuilder::new().mode(0o700).create(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        require_private(&directory)?;
        Ok(directory)
    }

    #[cfg(test)]
    pub(super) fn recover(&self) -> io::Result<()> {
        self.recover_with(None)
    }

    fn recovery_lease_present(&self, guard: &NetworkGuard, generation: &str) -> io::Result<bool> {
        // Validate the registry under the writer lock before inspecting the
        // matching entry. A different writer's lease proves nothing here.
        if !guard.tunnels_present()? {
            return Ok(false);
        }
        match fs::symlink_metadata(self.runtime.join("tunnel-leases").join(generation)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn recover_with(&self, cleanup: Option<&Store>) -> io::Result<()> {
        let guard = (self.lock)(Instant::now() + self.limits.lock)?;
        let parent = self.runtime.join(INSTANCE_DIRECTORY);
        let entries = match require_private(&parent) {
            Ok(()) => Some(fs::read_dir(parent)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        for entry in entries.into_iter().flatten() {
            let entry = entry?;
            let filename = entry.file_name();
            let Some(generation) = filename.to_str().filter(|name| valid_generation(name)) else {
                continue;
            };
            let directory = entry.path();
            require_private(&directory)?;
            let ipsec = absent_receipt(Receipt::load(&directory, &guard))?;
            let fortinet = absent_receipt(fortinet_network::Receipt::load(&directory, &guard))?;
            // An unreadable cleanup record cannot establish a staged plan.
            // Still clean a valid network receipt and surface the read error
            // when publishing the cleanup result.
            let staged = (ipsec.is_some() || fortinet.is_some())
                && cleanup
                    .is_some_and(|store| store.preparing_network(generation).unwrap_or(false))
                && !self.recovery_lease_present(&guard, generation)?;
            match (ipsec, fortinet) {
                (Some(mut receipt), None) => {
                    if !receipt.complete {
                        if !staged {
                            let mut attempt = Attempt::new(Backend::Ipsec, generation.to_owned());
                            // The dead writer may have left the runtime drop-in.
                            attempt.allowed = true;
                            self.stop_unit(&attempt)?;
                            self.revert_unit(&mut attempt)?;
                            self.xfrm.clean(&guard, &directory, &receipt)?;
                        }
                        receipt.complete = true;
                        receipt.save(&directory, &guard)?;
                    }
                }
                (None, Some(mut receipt)) => {
                    if !receipt.complete {
                        if !staged {
                            let mut attempt =
                                Attempt::new(Backend::Fortinet, generation.to_owned());
                            attempt.allowed = true;
                            self.stop_unit(&attempt)?;
                            self.revert_unit(&mut attempt)?;
                            self.fortinet.clean(&guard, &directory, &receipt)?;
                        }
                        receipt.complete = true;
                        receipt.save(&directory, &guard)?;
                    }
                }
                (None, None) => continue,
                (Some(_), Some(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ambiguous network recovery receipt",
                    ));
                }
            }
            guard.withdraw(generation)?;
            if let Some(cleanup) = cleanup {
                cleanup.recovered(generation)?;
            }
        }
        if let Some(cleanup) = cleanup {
            cleanup.finish_recovery(|id| self.recovery_lease_present(&guard, id.as_str()))?;
        }
        Ok(())
    }

    fn stop_unit(&self, attempt: &Attempt) -> io::Result<()> {
        run_systemctl(
            &self.systemctl,
            &["stop", "--", &attempt.unit],
            self.limits.stop,
        )
    }

    /// Remove the runtime drop-in that opened the transport address. Only after
    /// the unit is stopped; a failure leaves `allowed` set so a retry repeats it.
    fn revert_unit(&self, attempt: &mut Attempt) -> io::Result<()> {
        if attempt.allowed {
            run_systemctl(
                &self.systemctl,
                &["revert", "--", &attempt.unit],
                self.limits.stop,
            )?;
            attempt.allowed = false;
        }
        Ok(())
    }

    fn teardown(&self, attempt: &mut Attempt, channel: Option<AuthenticatedChannel>) -> bool {
        let result = if attempt.receipt.is_some() {
            self.teardown_ipsec(attempt, channel)
        } else if attempt.fortinet.is_some() {
            self.teardown_fortinet(attempt, channel)
        } else {
            drop(channel);
            self.teardown_before_ipsec(attempt)
        };
        if let Err(error) = result {
            eprintln!("vpnt-tunneld: cleanup is unproven: {error}");
            return false;
        }
        true
    }

    fn teardown_ipsec(
        &self,
        attempt: &mut Attempt,
        channel: Option<AuthenticatedChannel>,
    ) -> io::Result<()> {
        let directory = self
            .runtime
            .join(INSTANCE_DIRECTORY)
            .join(&attempt.generation);
        // The lease remains registered while the supervisor settles. Send
        // Stop before waiting for the network writer lock.
        let stopped = match channel.filter(|_| attempt.credentials_sent) {
            Some(mut channel) => {
                let stopped = stop_instance(&mut channel);
                if !matches!(stopped, Ok(Reply::Stopped {})) {
                    eprintln!("vpnt-tunneld: instance did not confirm Stop: {stopped:?}");
                }
                matches!(stopped, Ok(Reply::Stopped {}))
            }
            None => false,
        };
        let guard = (self.lock)(Instant::now() + self.limits.lock)?;
        if attempt.started && !stopped {
            self.stop_unit(attempt)?;
            attempt.started = false;
        }
        let receipt = attempt
            .receipt
            .as_mut()
            .expect("IPsec cleanup has a receipt");
        let clean = if receipt.complete {
            Ok(())
        } else {
            self.xfrm.clean(&guard, &directory, receipt)
        };
        // Even when a network read or delete failed, stop the producer.
        if attempt.started {
            self.stop_unit(attempt)?;
            attempt.started = false;
        }
        let reverted = self.revert_unit(attempt);
        clean?;
        reverted?;
        let receipt = attempt
            .receipt
            .as_mut()
            .expect("IPsec cleanup has a receipt");
        if !receipt.complete {
            self.xfrm.verify_xfrm_clear(receipt)?;
            receipt.complete = true;
            if let Err(error) = receipt.save(&directory, &guard) {
                receipt.complete = false;
                return Err(error);
            }
        }
        guard.withdraw(&attempt.generation)
    }

    /// Stop the instance (it stops the client and reports `exited`), stop the
    /// unit whatever it answered, remove what the receipt says was attempted,
    /// prove it is gone, and only then withdraw the lease.
    fn teardown_fortinet(
        &self,
        attempt: &mut Attempt,
        channel: Option<AuthenticatedChannel>,
    ) -> io::Result<()> {
        let directory = self
            .runtime
            .join(INSTANCE_DIRECTORY)
            .join(&attempt.generation);
        // The lease remains registered while the instance settles. Send Stop
        // before waiting for the network writer lock, and only when the
        // credential was sent: before that the instance only waits for it.
        if let Some(mut channel) = channel.filter(|_| attempt.credentials_sent) {
            let stopped = channel
                .send(&[fortinet_instance::MESSAGE_STOP])
                .and_then(|()| wait_exited(&mut channel, Instant::now() + STOPPED_TIMEOUT));
            if let Err(error) = stopped {
                eprintln!("vpnt-tunneld: instance did not confirm Stop: {error}");
            }
        }
        let guard = (self.lock)(Instant::now() + self.limits.lock)?;
        // The unit is stopped even when the instance confirmed: that is what
        // proves no client or pppd outlives the attempt.
        if attempt.started {
            self.stop_unit(attempt)?;
            attempt.started = false;
        }
        let reverted = self.revert_unit(attempt);
        let receipt = attempt
            .fortinet
            .as_mut()
            .expect("Fortinet cleanup has a receipt");
        let clean = if receipt.complete {
            Ok(())
        } else {
            self.fortinet.clean(&guard, &directory, receipt)
        };
        clean?;
        reverted?;
        let receipt = attempt
            .fortinet
            .as_mut()
            .expect("Fortinet cleanup has a receipt");
        if !receipt.complete {
            receipt.complete = true;
            if let Err(error) = receipt.save(&directory, &guard) {
                receipt.complete = false;
                return Err(error);
            }
        }
        guard.withdraw(&attempt.generation)
    }

    fn teardown_before_ipsec(&self, attempt: &mut Attempt) -> io::Result<()> {
        if attempt.started {
            self.stop_unit(attempt)?;
            attempt.started = false;
        }
        self.revert_unit(attempt)?;
        let removed = if attempt.directory {
            match fs::remove_dir_all(
                self.runtime
                    .join(INSTANCE_DIRECTORY)
                    .join(&attempt.generation),
            ) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                result => result,
            }
        } else {
            Ok(())
        };
        if attempt.registered {
            let guard = (self.lock)(Instant::now() + self.limits.lock)?;
            guard.withdraw(&attempt.generation)?;
        }
        removed
    }

    fn launch_backend<'a>(
        &'a self,
        backend: Backend,
        setup: Option<Setup>,
        entry: Option<&Entry>,
        authorization: Option<File>,
        cancel: &SetupCancellation,
        reservation: Option<&mut Reservation<'_>>,
    ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
        let generation = match reservation.as_ref() {
            Some(record) => record.generation().as_str().to_owned(),
            None => generation().map_err(|error| {
                eprintln!("vpnt-tunneld: could not draw a generation: {error}");
                ErrorCode::Backend
            })?,
        };
        let managed_cleanup = reservation.is_some();
        let mut attempt = Attempt::new(backend, generation);
        attempt.managed_cleanup = managed_cleanup;
        let mut channel = None;
        let state = if setup.is_some() {
            State::NetworkReady
        } else {
            State::Starting
        };
        match self.bring_up(
            &mut attempt,
            setup,
            entry,
            authorization,
            &mut channel,
            cancel,
            reservation,
        ) {
            Ok(peer) => Ok(Box::new(Session {
                launcher: self,
                attempt,
                channel,
                peer: Some(peer),
                state,
            })),
            Err(failure) => {
                eprintln!("vpnt-tunneld: admission ended: {}", failure.cause);
                if cancel.is_cancelled() {
                    let mut session = Session {
                        launcher: self,
                        attempt,
                        channel,
                        peer: None,
                        state,
                    };
                    if !managed_cleanup {
                        session.stop();
                    }
                    return Ok(Box::new(session));
                }
                let stopped = if managed_cleanup {
                    retry_cleanup(|| self.teardown(&mut attempt, channel.take()))
                } else {
                    self.teardown(&mut attempt, channel)
                };
                Err(if stopped {
                    failure.code
                } else {
                    ErrorCode::CleanupPending
                })
            }
        }
    }
}

fn absent_receipt<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(receipt) => Ok(Some(receipt)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn receive_event(channel: &mut AuthenticatedChannel, deadline: Instant) -> io::Result<Event> {
    let bytes = channel.receive_until(deadline)?;
    if bytes.first() != Some(&b'{') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected instance event object",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid instance event"))
}

/// Read events until the instance says it exited.
fn wait_exited(channel: &mut AuthenticatedChannel, deadline: Instant) -> io::Result<()> {
    loop {
        if matches!(receive_event(channel, deadline)?, Event::Exited { .. }) {
            return Ok(());
        }
    }
}

/// Wait for one event, polling so that a client cancellation is seen within a
/// poll interval, as `wait_setup_reply` does for the IPsec reply.
fn wait_event(
    channel: &mut AuthenticatedChannel,
    cancel: &SetupCancellation,
    deadline: Instant,
) -> io::Result<Event> {
    let budget = Budget::until(deadline, Some(cancel.flag()))?;
    loop {
        let wait = budget.poll_timeout()?;
        if channel.wait_control(Duration::from_millis(wait as u64))? {
            cancel.check()?;
            return receive_event(channel, deadline);
        }
    }
}

fn wait_setup_reply(
    channel: &mut AuthenticatedChannel,
    cancel: &SetupCancellation,
) -> io::Result<Reply> {
    let deadline = Instant::now() + ESTABLISHED_TIMEOUT;
    let budget = Budget::until(deadline, Some(cancel.flag()))?;
    loop {
        let wait = budget.poll_timeout()?;
        if channel.wait_control(Duration::from_millis(wait as u64))? {
            cancel.check()?;
            return receive_reply(channel, deadline);
        }
    }
}

fn stop_instance(channel: &mut AuthenticatedChannel) -> io::Result<Reply> {
    channel.send(br#"{"op":"stop"}"#)?;
    let deadline = Instant::now() + STOPPED_TIMEOUT;
    match receive_reply(channel, deadline)? {
        // The supervisor can establish just as Stop overtakes it.
        Reply::Established { .. } => receive_reply(channel, deadline),
        reply => Ok(reply),
    }
}

fn receive_reply(channel: &mut AuthenticatedChannel, deadline: Instant) -> io::Result<Reply> {
    let bytes = channel.receive_until(deadline)?;
    if bytes.first() != Some(&b'{') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected instance reply object",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid instance reply"))
}

impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Launch for Launcher<N, A> {
    fn launch<'a>(
        &'a self,
        offer: &Prepare,
        grant: &Entry,
        credentials: Credentials,
        authorization: File,
        cancel: &Arc<SetupCancellation>,
    ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
        self.launch_for(offer, grant, credentials, authorization, cancel, None)
    }

    fn launch_v2<'a>(
        &'a self,
        offer: &Prepare,
        grant: &Entry,
        credentials: Credentials,
        authorization: File,
        cancel: &Arc<SetupCancellation>,
        reservation: &mut Reservation<'_>,
    ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
        self.launch_for(
            offer,
            grant,
            credentials,
            authorization,
            cancel,
            Some(reservation),
        )
    }
}

impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Launcher<N, A> {
    fn launch_for<'a>(
        &'a self,
        offer: &Prepare,
        grant: &Entry,
        credentials: Credentials,
        authorization: File,
        cancel: &SetupCancellation,
        reservation: Option<&mut Reservation<'_>>,
    ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
        let request = match offer {
            Prepare::Ipsec(request) => request,
            Prepare::Fortinet(request) => {
                return self.launch_fortinet(
                    request,
                    grant,
                    &credentials,
                    authorization,
                    cancel,
                    reservation,
                );
            }
        };
        let grant: IpsecGrant = serde_json::to_value(grant)
            .and_then(serde_json::from_value)
            .map_err(|_| ErrorCode::Backend)?;
        let remote_ts: Vec<CidrV4> = grant
            .route_cidrs
            .iter()
            .map(|r| parse_cidr(r))
            .collect::<io::Result<_>>()
            .map_err(|_| ErrorCode::PermissionDenied)?;
        if !(1..=MAX_IPSEC_ROUTES).contains(&remote_ts.len()) || grant.port != 500 {
            return Err(ErrorCode::PermissionDenied);
        }
        cancel.check().map_err(|_| ErrorCode::Backend)?;
        let remote_ipv4 = self
            .xfrm
            .resolve(&grant.hostname, &grant.transport_ipv4)
            .map_err(|error| {
                eprintln!("vpnt-tunneld: policy transport selection failed: {error}");
                ErrorCode::Backend
            })?;
        cancel.check().map_err(|_| ErrorCode::Backend)?;
        let frame = encode_credentials(&credentials)?;
        drop(credentials);
        let setup = IpsecStart {
            order: Start {
                remote_ipv4,
                port: grant.port,
                peer_identity: grant.peer_identity,
                username: request.username().into(),
                if_id: 0,
                reqid: 0,
                local_ts: vec!["dynamic".into()],
                remote_ts,
            },
            approved: grant.transport_ipv4,
            credentials: frame,
        };
        self.launch_backend(
            Backend::Ipsec,
            Some(Setup::Ipsec(setup)),
            None,
            Some(authorization),
            cancel,
            reservation,
        )
    }

    fn launch_fortinet<'a>(
        &'a self,
        request: &FortinetRequest,
        grant: &Entry,
        credentials: &Credentials,
        authorization: File,
        cancel: &SetupCancellation,
        reservation: Option<&mut Reservation<'_>>,
    ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
        if credentials.backend() != protocol::Backend::Fortinet {
            return Err(ErrorCode::BadRequest);
        }
        if grant.fortinet_local_cidr().is_none() {
            return Err(ErrorCode::PolicyReapprovalRequired);
        }
        let projection =
            fortinet_network::Grant::from_entry(grant).map_err(|_| ErrorCode::Backend)?;
        // The pin and the endpoint come from the policy entry, which the offer
        // matched exactly; the offer supplies only the username.
        cancel.check().map_err(|_| ErrorCode::Backend)?;
        let remote = self
            .xfrm
            .resolve(&projection.hostname, &projection.transport_ipv4)
            .map_err(|error| {
                eprintln!("vpnt-tunneld: policy transport selection failed: {error}");
                ErrorCode::Backend
            })?;
        cancel.check().map_err(|_| ErrorCode::Backend)?;
        let credentials = fortinet_instance::credential_frame(credentials.password())
            .map_err(|_| ErrorCode::BadRequest)?;
        let setup = FortinetStart {
            host: projection.hostname.clone(),
            port: projection.port,
            username: request.username().into(),
            certificate_sha256: projection.certificate_sha256.clone(),
            remote,
            grant: projection,
            credentials,
        };
        self.launch_backend(
            Backend::Fortinet,
            Some(Setup::Fortinet(setup)),
            Some(grant),
            Some(authorization),
            cancel,
            reservation,
        )
    }
}

struct Session<'a, N: NetworkBackend, A: UnitAttestor + Send + Sync> {
    launcher: &'a Launcher<N, A>,
    attempt: Attempt,
    channel: Option<AuthenticatedChannel>,
    peer: Option<OwnedFd>,
    state: State,
}

impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Running for Session<'_, N, A> {
    fn state(&self) -> State {
        self.state
    }

    fn probe_binding(&self, deadline: Instant) -> io::Result<ProbeBinding> {
        if self.state != State::NetworkReady {
            return Err(io::Error::other("network is not ready for probing"));
        }
        super::network::check_deadline(Some(deadline))?;
        let guard = (self.launcher.lock)(deadline.min(Instant::now() + self.launcher.limits.lock))?;
        let binding = match (
            self.attempt.backend,
            &self.attempt.receipt,
            &self.attempt.fortinet,
        ) {
            (Backend::Ipsec, Some(receipt), None) => {
                self.launcher.xfrm.probe_binding(&guard, receipt, deadline)
            }
            (Backend::Fortinet, None, Some(receipt)) => {
                self.launcher
                    .fortinet
                    .probe_binding(&guard, receipt, Some(deadline))
            }
            _ => Err(io::Error::other("probe receipt is unproven")),
        }?;
        // Keep the network observation and final backend liveness check
        // under the same guard. Socket writes use their own frame budget.
        super::network::check_deadline(Some(deadline))?;
        if super::server::probe_session_ended(self, deadline)? {
            return Err(io::ErrorKind::NotConnected.into());
        }
        super::network::check_deadline(Some(deadline))?;
        Ok(binding)
    }

    fn peer(&self) -> Option<BorrowedFd<'_>> {
        self.peer.as_ref().map(AsFd::as_fd)
    }

    fn channel_fd(&self) -> Option<BorrowedFd<'_>> {
        self.channel
            .as_ref()
            .and_then(AuthenticatedChannel::poll_fd)
    }

    fn stop(&mut self) -> State {
        if self.state == State::Stopped {
            return self.state;
        }
        self.state = State::Stopping;
        self.peer.take();
        self.state = if self
            .launcher
            .teardown(&mut self.attempt, self.channel.take())
        {
            State::Stopped
        } else {
            State::CleanupPending
        };
        self.state
    }
}

impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Drop for Session<'_, N, A> {
    fn drop(&mut self) {
        if !self.attempt.managed_cleanup || self.state != State::CleanupPending {
            Running::stop(self);
        }
    }
}

fn require_private(path: &Path) -> io::Result<()> {
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = File::metadata(&directory)?;
    // SAFETY: geteuid has no preconditions.
    let owner = unsafe { libc::geteuid() };
    if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

/// 32 lowercase hex characters from the kernel, new for every session.
pub(super) fn generation() -> io::Result<String> {
    use std::fmt::Write as _;

    let mut bytes = [0_u8; 16];
    let mut filled = 0;
    while filled < bytes.len() {
        // SAFETY: the remaining slice is writable for the supplied length.
        let count = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        match usize::try_from(count) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => filled += count,
            Err(_) => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
    let mut generation = String::with_capacity(32);
    for byte in bytes {
        write!(generation, "{byte:02x}").expect("writing to a String");
    }
    Ok(generation)
}

struct Reaper(Child);

impl Drop for Reaper {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Run the fixed systemctl with a clean environment and an absolute deadline.
fn run_systemctl(path: &Path, args: &[&str], timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    wait_systemctl(spawn_systemctl(path, args)?, deadline)
}

fn spawn_systemctl(path: &Path, args: &[&str]) -> io::Result<Reaper> {
    Command::new(path)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(Reaper)
}

fn wait_systemctl(mut child: Reaper, deadline: Instant) -> io::Result<()> {
    loop {
        if let Some(status) = child.0.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("systemctl exited with {status}")))
            };
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Launcher<N, A> {
    fn launch(&self, backend: Backend) -> Result<Box<dyn Running + '_>, ErrorCode> {
        self.launch_backend(
            backend,
            None,
            None,
            None,
            &SetupCancellation::default(),
            None,
        )
    }

    fn with_fortinet(mut self, network: FortinetNetwork, xfrm: Network) -> Self {
        self.fortinet = network;
        self.xfrm = xfrm;
        self
    }

    fn for_test(
        runtime: PathBuf,
        systemctl: PathBuf,
        network: N,
        attestor: A,
        lock: AcquireLock,
        limits: Limits,
    ) -> Self {
        Self {
            runtime,
            systemctl,
            network,
            attestor,
            xfrm: Network::default(),
            fortinet: FortinetNetwork::default(),
            lock,
            limits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        netd::{
            iproute::Existing,
            protocol::{Config, TunName},
        },
        tunneld::handshake::connect_instance,
    };
    use std::{
        process::Command,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread::JoinHandle,
    };

    const NAMESPACE: &str = "VPNT_ADMISSION_NAMESPACE";
    const INVOCATION: &str = "fedcba9876543210fedcba9876543210";

    /// The handshake accepts only a root peer and a root-owned directory, so
    /// each case re-runs itself as root of a private user and mount namespace.
    /// Returns true inside that namespace, where the case body must run.
    fn namespaced(name: &str) -> bool {
        namespaced_in(name, "tests")
    }

    fn namespaced_in(name: &str, module: &str) -> bool {
        if std::env::var_os(NAMESPACE).is_some() {
            return true;
        }
        let unshare = || {
            let mut command = Command::new("/usr/bin/unshare");
            command.args(["--user", "--map-root-user", "--mount", "--"]);
            command
        };
        let probe = unshare()
            .arg("/bin/true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !probe.as_ref().is_ok_and(|status| status.success()) {
            // CI sets VPNT_REQUIRE_USERNS=1 where the namespaces are enabled.
            assert!(
                std::env::var_os("VPNT_REQUIRE_USERNS").is_none(),
                "unprivileged user and mount namespaces are required here: {probe:?}"
            );
            eprintln!("skipped: unprivileged user namespaces are unavailable here: {probe:?}");
            return false;
        }
        let output = unshare()
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", &format!("tunneld::backend::{module}::{name}")])
            .arg("--nocapture")
            .env_clear()
            .env(NAMESPACE, "1")
            .env("TMPDIR", std::env::temp_dir())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{name} failed:\n{stdout}\n{stderr}"
        );
        assert!(stdout.contains("1 passed"), "{name} did not run:\n{stdout}");
        false
    }

    #[derive(Default)]
    struct FakeNetwork {
        ovpn: Arc<AtomicBool>,
        inventories: Arc<AtomicUsize>,
    }

    impl NetworkBackend for FakeNetwork {
        fn create_tun(&self, _: &TunName, _: u32) -> io::Result<()> {
            Err(io::Error::other("inventory fixture"))
        }
        fn configure(&self, _: &Config) -> io::Result<()> {
            Err(io::Error::other("inventory fixture"))
        }
        fn delete_tun(&self, _: &TunName) -> io::Result<()> {
            Err(io::Error::other("inventory fixture"))
        }
        fn existing(&self) -> io::Result<Vec<Existing>> {
            self.inventories.fetch_add(1, Ordering::SeqCst);
            Ok(if self.ovpn.load(Ordering::SeqCst) {
                vec![Existing {
                    name: TunName::parse("vpnt0").unwrap(),
                    owned: true,
                    ifindex: std::num::NonZeroU32::new(7).unwrap(),
                    is_tun: true,
                }]
            } else {
                Vec::new()
            })
        }
    }

    /// Attests the unit that the fake systemctl was asked to start.
    struct FakeAttestor {
        log: PathBuf,
        fail: bool,
    }

    impl UnitAttestor for FakeAttestor {
        fn attest(&self, fd: BorrowedFd<'_>) -> io::Result<UnitIdentity> {
            if self.fail {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(UnitIdentity {
                name: started_unit(&self.log).ok_or(io::ErrorKind::NotFound)?,
                invocation: INVOCATION.to_owned(),
                main_pid: fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?
                    .lines()
                    .find_map(|line| line.strip_prefix("Pid:")?.trim().parse().ok())
                    .ok_or(io::ErrorKind::InvalidData)?,
            })
        }
    }

    fn started_unit(log: &Path) -> Option<String> {
        fs::read_to_string(log)
            .ok()?
            .lines()
            .filter_map(|line| line.strip_prefix("start --no-block -- "))
            .next_back()
            .map(str::to_owned)
    }

    fn generation_of(unit: &str) -> String {
        let (_, rest) = unit.split_once('@').unwrap();
        rest.strip_suffix(".service").unwrap().to_owned()
    }

    struct Harness {
        root: PathBuf,
        runtime: PathBuf,
        log: PathBuf,
        stop: Arc<AtomicBool>,
        instance: Option<JoinHandle<Option<AuthenticatedChannel>>>,
    }

    impl Harness {
        fn new() -> Self {
            // Unix socket paths are short: keep the fixture root brief.
            let root = std::env::temp_dir().join(format!("va-{}", &generation().unwrap()[..8]));
            DirBuilder::new().mode(0o700).create(&root).unwrap();
            let runtime = root.join("run");
            DirBuilder::new().mode(0o700).create(&runtime).unwrap();
            let log = root.join("systemctl.log");
            let script = format!(
                "#!/bin/sh\necho \"$*\" >> '{log}'\n\
                 [ \"$1\" = start ] && [ -e '{root}/fail-start' ] && exit 1\n\
                 [ \"$1\" = stop ] && [ -e '{root}/fail-stop' ] && exit 1\n\
                 [ \"$1\" = set-property ] && [ -e '{root}/fail-set-property' ] && exit 1\n\
                 if [ \"$1\" = revert ] && [ -e '{root}/slow-revert-once' ]; then
                     : > '{root}/revert-entered'
                     /usr/bin/sleep 1.4
                     /usr/bin/rm -- '{root}/slow-revert-once'
                     exit 1
                 fi
                 [ \"$1\" = revert ] && [ -e '{root}/fail-revert' ] && exit 1\n\
                 exit 0\n",
                log = log.display(),
                root = root.display(),
            );
            let systemctl = root.join("systemctl");
            fs::write(&systemctl, script).unwrap();
            fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                root,
                runtime,
                log,
                stop: Arc::default(),
                instance: None,
            }
        }

        fn flag(&self, name: &str, on: bool) {
            let path = self.root.join(name);
            if on {
                fs::write(path, b"").unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }
        }

        fn lock(&self) -> AcquireLock {
            let runtime = self.runtime.clone();
            Box::new(move |deadline| NetworkLock::acquire_test(&runtime, deadline))
        }

        fn launcher(&self, fail_attest: bool) -> Launcher<FakeNetwork, FakeAttestor> {
            self.launcher_with(
                FakeNetwork::default(),
                fail_attest,
                self.lock(),
                Limits::default(),
            )
        }

        fn launcher_with(
            &self,
            network: FakeNetwork,
            fail: bool,
            lock: AcquireLock,
            limits: Limits,
        ) -> Launcher<FakeNetwork, FakeAttestor> {
            Launcher::for_test(
                self.runtime.clone(),
                self.root.join("systemctl"),
                network,
                FakeAttestor {
                    log: self.log.clone(),
                    fail,
                },
                lock,
                limits,
            )
        }

        /// A fake instance that runs the real handshake once its unit is started.
        fn instance(&mut self, backend: Backend) {
            let (log, runtime, stop) = (self.log.clone(), self.runtime.clone(), self.stop.clone());
            self.instance = Some(thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(20);
                let unit = loop {
                    if stop.load(Ordering::SeqCst) || Instant::now() > deadline {
                        return None;
                    }
                    if let Some(unit) = started_unit(&log) {
                        break unit;
                    }
                    thread::sleep(Duration::from_millis(5));
                };
                let generation = generation_of(&unit);
                let directory = runtime.join(INSTANCE_DIRECTORY).join(&generation);
                connect_instance(
                    &directory.join(CONTROL_SOCKET_NAME),
                    &directory.join(RECORD_NAME),
                    &generation,
                    backend,
                    INVOCATION,
                    INSTANCE_GID,
                )
                .ok()
            }));
        }

        fn log(&self) -> Vec<String> {
            fs::read_to_string(&self.log)
                .map(|log| log.lines().map(str::to_owned).collect())
                .unwrap_or_default()
        }

        fn leases(&self) -> Vec<String> {
            let mut leases: Vec<String> = fs::read_dir(self.runtime.join("tunnel-leases"))
                .map(|entries| {
                    entries
                        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                        .collect()
                })
                .unwrap_or_default();
            leases.sort();
            leases
        }

        fn directory(&self, generation: &str) -> PathBuf {
            self.runtime.join(INSTANCE_DIRECTORY).join(generation)
        }

        /// Nothing was started, created or registered.
        fn assert_no_effect(&self, leases: &[&str]) {
            assert!(self.log().is_empty(), "systemctl ran: {:?}", self.log());
            assert!(!self.runtime.join(INSTANCE_DIRECTORY).exists());
            assert_eq!(self.leases(), leases);
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            drop(self.instance.take().map(|instance| instance.join()));
            let removed = fs::remove_dir_all(&self.root);
            if !thread::panicking() {
                removed.expect("remove only this test's fixture");
            }
        }
    }

    fn admitted<'a>(result: Result<Box<dyn Running + 'a>, ErrorCode>) -> Box<dyn Running + 'a> {
        match result {
            Ok(session) => session,
            Err(code) => panic!("admission refused: {code:?}"),
        }
    }

    fn refused(result: Result<Box<dyn Running + '_>, ErrorCode>) -> ErrorCode {
        match result {
            Err(code) => code,
            Ok(session) => panic!("admitted in state {:?}", session.state()),
        }
    }

    fn admit_and_stop(name: &str, backend: Backend, kind: &str) {
        if !namespaced(name) {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(backend);
        let launcher = harness.launcher(false);
        let mut running = admitted(launcher.launch(backend));
        assert_eq!(running.state(), State::Starting);

        let unit = started_unit(&harness.log).unwrap();
        let generation = generation_of(&unit);
        assert_eq!(unit, format!("vpnt-tunneld-{kind}@{generation}.service"));
        assert_eq!(generation.len(), 32);
        assert_eq!(harness.log(), [format!("start --no-block -- {unit}")]);
        assert_eq!(harness.leases(), [generation.as_str()]);
        let directory = harness.directory(&generation);
        assert!(
            directory
                .join(super::super::handshake::RECORD_NAME)
                .is_file(),
            "fixed handshake record"
        );
        assert!(
            !directory.join(CONTROL_SOCKET_NAME).exists(),
            "listener consumed"
        );

        assert_eq!(running.stop(), State::Stopped);
        assert_eq!(running.state(), State::Stopped);
        assert_eq!(
            harness.log(),
            [
                format!("start --no-block -- {unit}"),
                format!("stop -- {unit}")
            ]
        );
        assert!(!directory.exists());
        assert!(harness.leases().is_empty());
        // A repeated stop does not repeat the mutation.
        assert_eq!(running.stop(), State::Stopped);
        assert_eq!(harness.log().len(), 2);
    }

    #[test]
    fn admits_an_ipsec_instance_and_stops_it() {
        admit_and_stop(
            "admits_an_ipsec_instance_and_stops_it",
            Backend::Ipsec,
            "ipsec",
        );
    }

    #[test]
    fn admits_a_fortinet_instance_under_its_own_unit() {
        admit_and_stop(
            "admits_a_fortinet_instance_under_its_own_unit",
            Backend::Fortinet,
            "fortinet",
        );
    }

    #[test]
    fn dropping_a_running_session_stops_it() {
        if !namespaced("dropping_a_running_session_stops_it") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(false);
        let running = admitted(launcher.launch(Backend::Ipsec));
        let unit = started_unit(&harness.log).unwrap();
        drop(running);
        assert_eq!(harness.log().last().unwrap(), &format!("stop -- {unit}"));
        assert!(harness.leases().is_empty());
        assert!(!harness.directory(&generation_of(&unit)).exists());
    }

    #[test]
    fn ovpn_present_refuses_without_effect() {
        if !namespaced("ovpn_present_refuses_without_effect") {
            return;
        }
        let harness = Harness::new();
        let network = FakeNetwork::default();
        network.ovpn.store(true, Ordering::SeqCst);
        let inventories = network.inventories.clone();
        let launcher = harness.launcher_with(network, false, harness.lock(), Limits::default());
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Busy);
        assert_eq!(inventories.load(Ordering::SeqCst), 1);
        harness.assert_no_effect(&[]);
    }

    #[test]
    fn a_present_lease_refuses_without_effect() {
        if !namespaced("a_present_lease_refuses_without_effect") {
            return;
        }
        let harness = Harness::new();
        NetworkLock::acquire_test(&harness.runtime, Instant::now() + Duration::from_secs(2))
            .unwrap()
            .register("other-tunnel")
            .unwrap();
        let launcher = harness.launcher(false);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Busy);
        harness.assert_no_effect(&["other-tunnel"]);
    }

    #[test]
    fn a_contended_lock_refuses_without_effect() {
        if !namespaced("a_contended_lock_refuses_without_effect") {
            return;
        }
        let harness = Harness::new();
        let held =
            NetworkLock::acquire_test(&harness.runtime, Instant::now() + Duration::from_secs(2))
                .unwrap();
        let limits = Limits {
            lock: Duration::from_millis(100),
            ..Limits::default()
        };
        let network = FakeNetwork::default();
        let inventories = network.inventories.clone();
        let launcher = harness.launcher_with(network, false, harness.lock(), limits);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Busy);
        // The inventory is read only under the lock.
        assert_eq!(inventories.load(Ordering::SeqCst), 0);
        harness.assert_no_effect(&[]);
        drop(held);
    }

    #[test]
    fn checks_and_registration_share_one_lock_acquisition() {
        if !namespaced("checks_and_registration_share_one_lock_acquisition") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let acquisitions = Arc::new(AtomicUsize::new(0));
        let armed = Arc::new(AtomicBool::new(true));
        let lock: AcquireLock = {
            let (runtime, acquisitions, armed) =
                (harness.runtime.clone(), acquisitions.clone(), armed.clone());
            Box::new(move |deadline| {
                // A second acquisition by the same admission opens a window
                // between its checks and its registration: a competing
                // admission fits in it, passes its own checks and registers.
                if acquisitions.fetch_add(1, Ordering::SeqCst) >= 1 && armed.load(Ordering::SeqCst)
                {
                    let guard = NetworkLock::acquire_test(&runtime, deadline)?;
                    if !guard.tunnels_present()? {
                        guard.register("competitor")?;
                    }
                }
                NetworkLock::acquire_test(&runtime, deadline)
            })
        };
        let launcher =
            harness.launcher_with(FakeNetwork::default(), false, lock, Limits::default());
        let mut running = admitted(launcher.launch(Backend::Ipsec));
        let generation = generation_of(&started_unit(&harness.log).unwrap());
        assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
        assert_eq!(harness.leases(), [generation.as_str()]);
        armed.store(false, Ordering::SeqCst);
        assert_eq!(running.stop(), State::Stopped);
    }

    #[test]
    fn systemctl_start_failure_cleans_up() {
        if !namespaced("systemctl_start_failure_cleans_up") {
            return;
        }
        let mut harness = Harness::new();
        harness.flag("fail-start", true);
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(false);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Backend);
        let unit = started_unit(&harness.log).unwrap();
        assert_eq!(
            harness.log(),
            [
                format!("start --no-block -- {unit}"),
                format!("stop -- {unit}")
            ]
        );
        assert!(!harness.directory(&generation_of(&unit)).exists());
        assert!(harness.leases().is_empty());
    }

    #[test]
    fn attestation_failure_cleans_up() {
        if !namespaced("attestation_failure_cleans_up") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(true);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Backend);
        let unit = started_unit(&harness.log).unwrap();
        assert_eq!(harness.log().last().unwrap(), &format!("stop -- {unit}"));
        assert!(!harness.directory(&generation_of(&unit)).exists());
        assert!(harness.leases().is_empty());
    }

    #[test]
    fn unproven_unit_stop_keeps_the_lease_and_a_retry_converges() {
        if !namespaced("unproven_unit_stop_keeps_the_lease_and_a_retry_converges") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(false);
        let mut running = admitted(launcher.launch(Backend::Ipsec));
        let unit = started_unit(&harness.log).unwrap();
        let generation = generation_of(&unit);

        harness.flag("fail-stop", true);
        assert_eq!(running.stop(), State::CleanupPending);
        // The instance may still run, so its directory and lease stay.
        assert!(harness.directory(&generation).exists());
        assert_eq!(harness.leases(), [generation.as_str()]);
        assert_eq!(running.state(), State::CleanupPending);

        harness.flag("fail-stop", false);
        assert_eq!(running.stop(), State::Stopped);
        assert!(!harness.directory(&generation).exists());
        assert!(harness.leases().is_empty());
    }

    #[test]
    fn failed_admission_with_unproven_stop_reports_cleanup_pending_and_blocks_the_next() {
        if !namespaced(
            "failed_admission_with_unproven_stop_reports_cleanup_pending_and_blocks_the_next",
        ) {
            return;
        }
        let harness = Harness::new();
        harness.flag("fail-start", true);
        harness.flag("fail-stop", true);
        let launcher = harness.launcher(false);
        assert_eq!(
            refused(launcher.launch(Backend::Ipsec)),
            ErrorCode::CleanupPending
        );
        let generation = generation_of(&started_unit(&harness.log).unwrap());
        assert_eq!(harness.leases(), [generation.as_str()]);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Busy);
    }

    #[test]
    fn failed_directory_removal_reports_cleanup_pending_and_a_retry_converges() {
        if !namespaced("failed_directory_removal_reports_cleanup_pending_and_a_retry_converges") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(false);
        let mut running = admitted(launcher.launch(Backend::Ipsec));
        let generation = generation_of(&started_unit(&harness.log).unwrap());
        let directory = harness.directory(&generation);

        // A mount point cannot be removed (EBUSY): a real removal failure.
        let (source, target) = (harness.root.join("pin-source"), directory.join("pin"));
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        let cpath = |path: &Path| std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: both paths are NUL-terminated and the other arguments are null.
        let mounted = unsafe {
            libc::mount(
                cpath(&source).as_ptr(),
                cpath(&target).as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if mounted != 0 {
            let error = io::Error::last_os_error();
            assert!(
                std::env::var_os("VPNT_REQUIRE_USERNS").is_none(),
                "bind mounts are required here: {error}"
            );
            eprintln!("skipped: bind mounts are unavailable here: {error}");
            assert_eq!(running.stop(), State::Stopped);
            return;
        }

        assert_eq!(running.stop(), State::CleanupPending);
        assert!(directory.exists());
        // The unit stop was proven, so the network reservation is released.
        assert!(harness.leases().is_empty());

        // SAFETY: target is a NUL-terminated mount point created above.
        assert_eq!(unsafe { libc::umount2(cpath(&target).as_ptr(), 0) }, 0);
        assert_eq!(running.stop(), State::Stopped);
        assert!(!directory.exists());
    }

    #[test]
    fn generations_are_32_lowercase_hex_and_new_each_time() {
        let first = generation().unwrap();
        let second = generation().unwrap();
        assert_eq!(first.len(), 32);
        assert!(
            first
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        );
        assert_ne!(first, second);
    }

    #[test]
    fn systemctl_runs_with_a_clean_environment_and_a_deadline() {
        struct Root(PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let removed = fs::remove_dir_all(&self.0);
                if !thread::panicking() {
                    removed.expect("remove only this test's fixture");
                }
            }
        }
        let root = std::env::temp_dir().join(format!("vs-{}", &generation().unwrap()[..8]));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let root = Root(root);
        let script = |name: &str, body: &str| {
            let path = root.0.join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        };
        let env = script("env", "[ -z \"$HOME$USER$LANG$TMPDIR\" ]");
        let slow = script("slow", "exec /bin/sleep 5");
        let failing = script("fail", "exit 3");
        // A fork in a sibling test can hold a script's write descriptor for an
        // instant, which makes its exec fail with ETXTBSY. Only the fixture retries.
        let run = |path: &Path, timeout: Duration| loop {
            match run_systemctl(path, &[], timeout) {
                Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                    thread::sleep(Duration::from_millis(10));
                }
                result => break result,
            }
        };
        run(&env, Duration::from_secs(5)).unwrap();
        // Control: the script does detect an inherited environment.
        if std::env::var_os("HOME").is_some() {
            let inherited = loop {
                match Command::new(&env).status() {
                    Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {}
                    status => break status.unwrap(),
                }
            };
            assert!(!inherited.success());
        }
        assert!(run(&failing, Duration::from_secs(5)).is_err());
        let started = Instant::now();
        let error = run(&slow, Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    mod fortinet_tests {
        use super::*;
        use crate::tunneld::{
            fortinet_instance::Failure as Reported,
            fortinet_network::fixture::{self, Kernel},
            protocol::{Endpoint, FortinetRequest},
        };
        use std::sync::Mutex;

        const PIN: [u8; 32] = [0xab; 32];
        const PASSWORD: &str = "fixture-password";

        /// What the fake openfortivpn does once it has the order and password.
        #[derive(Clone)]
        enum Script {
            /// The link comes up with these events, then it waits for Stop.
            Ready(Vec<Event>),
            /// Same, but the link outlives the instance after Stop.
            ReadyAndLeaveTheLink(Vec<Event>),
            Report(Vec<Event>),
        }

        #[derive(Default)]
        struct Seen {
            start: Option<fortinet_instance::Start>,
            password: Option<String>,
            stop_frames: usize,
        }

        fn event_bytes(event: &Event) -> Vec<u8> {
            serde_json::to_vec(event).unwrap()
        }

        fn standard_events() -> Vec<Event> {
            vec![
                Event::Started,
                Event::Interface {
                    name: "vpntp1".into(),
                },
                Event::SplitRoute {
                    network: Ipv4Addr::new(10, 20, 0, 0),
                    prefix: 16,
                },
                Event::SplitRoute {
                    network: Ipv4Addr::new(172, 16, 0, 0),
                    prefix: 12,
                },
                Event::SplitRoutes { count: 2 },
                Event::DnsServer {
                    address: Ipv4Addr::new(10, 20, 1, 53),
                },
                Event::DnsServer {
                    address: Ipv4Addr::new(8, 8, 8, 8),
                },
                Event::DnsCount {
                    servers: 2,
                    domains: 0,
                },
            ]
        }

        struct Rig {
            harness: Harness,
            kernel: Arc<Mutex<Kernel>>,
            seen: Arc<Mutex<Seen>>,
            instance: Mutex<Option<JoinHandle<()>>>,
        }

        impl Rig {
            fn new() -> Self {
                Self {
                    harness: Harness::new(),
                    kernel: Arc::default(),
                    seen: Arc::default(),
                    instance: Mutex::new(None),
                }
            }

            fn launcher(&self, ovpn: bool) -> Launcher<FakeNetwork, FakeAttestor> {
                let network = FakeNetwork::default();
                network.ovpn.store(ovpn, Ordering::SeqCst);
                self.harness
                    .launcher_with(network, false, self.harness.lock(), Limits::default())
                    .with_fortinet(
                        fixture::network(self.kernel.clone(), Some(self.harness.runtime.clone())),
                        Network::fake(|program, args| {
                            assert_eq!(program, "/usr/bin/busctl");
                            assert!(args.contains(&"vpn.example"));
                            Ok(br#"{"type":"a(iiay)st","data":[[[2,2,[192,0,2,20]]],"vpn.example",1]}"#.to_vec())
                        }),
                    )
            }

            /// The fake instance runs the real handshake once its unit is started.
            fn instance(&self, script: Script) {
                let (log, runtime, stop) = (
                    self.harness.log.clone(),
                    self.harness.runtime.clone(),
                    self.harness.stop.clone(),
                );
                let (kernel, seen) = (self.kernel.clone(), self.seen.clone());
                *self.instance.lock().unwrap() = Some(thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(20);
                    let unit = loop {
                        if stop.load(Ordering::SeqCst) || Instant::now() > deadline {
                            return;
                        }
                        if let Some(unit) = started_unit(&log) {
                            break unit;
                        }
                        thread::sleep(Duration::from_millis(5));
                    };
                    let generation = generation_of(&unit);
                    let directory = runtime.join(INSTANCE_DIRECTORY).join(&generation);
                    let Ok(mut channel) = connect_instance(
                        &directory.join(CONTROL_SOCKET_NAME),
                        &directory.join(RECORD_NAME),
                        &generation,
                        Backend::Fortinet,
                        INVOCATION,
                        INSTANCE_GID,
                    ) else {
                        return;
                    };
                    let start: fortinet_instance::Start =
                        serde_json::from_slice(&channel.receive().unwrap()).unwrap();
                    let frame = channel.receive().unwrap();
                    let length = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
                    assert_eq!((frame[0], frame.len()), (1, 3 + length));
                    {
                        let mut seen = seen.lock().unwrap();
                        seen.password = Some(String::from_utf8(frame[3..].to_vec()).unwrap());
                        seen.start = Some(start);
                    }
                    let (events, leave_link) = match script {
                        Script::Ready(events) | Script::Report(events) => (events, false),
                        Script::ReadyAndLeaveTheLink(events) => (events, true),
                    };
                    // Events that report the link up make pppd's interface appear.
                    if events
                        .iter()
                        .any(|event| matches!(event, Event::Interface { .. }))
                    {
                        kernel.lock().unwrap().ppp = true;
                    }
                    for event in &events {
                        channel.send(&event_bytes(event)).unwrap();
                    }
                    loop {
                        if stop.load(Ordering::SeqCst) {
                            return;
                        }
                        match channel.wait_control(Duration::from_millis(50)) {
                            Ok(false) => continue,
                            Ok(true) => {}
                            Err(_) => return,
                        }
                        let frame = channel.receive().unwrap();
                        if *frame == [fortinet_instance::MESSAGE_STOP] {
                            seen.lock().unwrap().stop_frames += 1;
                            if !leave_link {
                                // pppd removes its link, and the kernel and the
                                // resolver forget what hung on it.
                                let mut k = kernel.lock().unwrap();
                                k.ppp = false;
                                k.ifalias = None;
                                k.routes.clear();
                                k.dns.clear();
                                k.domains.clear();
                            }
                            let _ = channel.send(&event_bytes(&Event::Exited {
                                code: None,
                                signal: Some(15),
                            }));
                            return;
                        }
                    }
                }));
            }

            fn launch<'a>(
                &self,
                launcher: &'a Launcher<FakeNetwork, FakeAttestor>,
                entry: &Entry,
            ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
                self.launch_with(launcher, entry, &Arc::default())
            }

            fn launch_with<'a>(
                &self,
                launcher: &'a Launcher<FakeNetwork, FakeAttestor>,
                entry: &Entry,
                cancel: &Arc<SetupCancellation>,
            ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
                let offer = Prepare::Fortinet(
                    FortinetRequest::new(
                        Endpoint::new("vpn.example".into(), 443).unwrap(),
                        "alice".into(),
                        PIN,
                    )
                    .unwrap(),
                );
                Launch::launch(
                    launcher,
                    &offer,
                    entry,
                    Credentials::fortinet(PASSWORD).unwrap(),
                    File::open("/dev/null").unwrap(),
                    cancel,
                )
            }

            fn routes(&self) -> Vec<String> {
                self.kernel.lock().unwrap().routes.clone()
            }

            fn dns(&self) -> Vec<String> {
                self.kernel.lock().unwrap().dns.clone()
            }

            fn receipt(&self, generation: &str) -> serde_json::Value {
                serde_json::from_slice(
                    &fs::read(
                        self.harness
                            .directory(generation)
                            .join(fortinet_network::RECEIPT),
                    )
                    .unwrap(),
                )
                .unwrap()
            }
        }

        impl Drop for Rig {
            fn drop(&mut self) {
                self.harness.stop.store(true, Ordering::SeqCst);
                drop(self.instance.lock().unwrap().take().map(JoinHandle::join));
            }
        }

        /// Everything that stopped the unit also reverted its runtime drop-in
        /// right after, and nothing came after that.
        fn assert_reverted_after_stop(rig: &Rig, unit: &str) {
            let log = rig.harness.log();
            let stop = log
                .iter()
                .position(|l| *l == format!("stop -- {unit}"))
                .unwrap();
            let revert = log
                .iter()
                .position(|l| *l == format!("revert -- {unit}"))
                .unwrap();
            assert!(stop < revert, "{log:?}");
            assert_eq!(log.last(), Some(&format!("revert -- {unit}")), "{log:?}");
        }

        fn policy(dns_servers: &[&str]) -> Entry {
            fixture::entry(&["10.20.0.0/15"], dns_servers, &["corp.example"])
        }

        #[test]
        fn v2_fortinet_uses_the_prepared_generation_through_cleanup() {
            use crate::tunneld::{
                admin::PolicyFixture, client::Client, policy::canonical_snapshot,
                protocol::CleanupState, server::serve_cleanup_fixture,
            };
            use std::os::unix::net::UnixListener;
            if !namespaced_in(
                "v2_fortinet_uses_the_prepared_generation_through_cleanup",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            let launcher = rig.launcher(false);
            let policy_file = PolicyFixture::new();
            policy_file.install();
            let snapshot = serde_json::json!({"version": 1, "entries": [policy(&[])]});
            fs::write(
                policy_file.path(),
                canonical_snapshot(snapshot.to_string().as_bytes()).unwrap(),
            )
            .unwrap();
            rig.instance(Script::Ready(standard_events()));
            let cleanup = Store::open(&rig.harness.runtime).unwrap();
            let path = rig.harness.root.join("client.sock");
            let listener = UnixListener::bind(&path).unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    let (stream, _) = listener.accept().unwrap();
                    serve_cleanup_fixture(stream, 1000, &policy_file.store, &launcher, &cleanup)
                });
                let deadline = || Instant::now() + Duration::from_secs(1);
                let mut client = Client::connect_v2(&path, deadline()).unwrap();
                let offer = Prepare::Fortinet(
                    FortinetRequest::new(
                        Endpoint::new("vpn.example".into(), 443).unwrap(),
                        "alice".into(),
                        PIN,
                    )
                    .unwrap(),
                );
                let id = client.prepare(offer, deadline()).unwrap().unwrap();
                assert!(rig.harness.log().is_empty());
                client
                    .send_credentials(Credentials::fortinet(PASSWORD).unwrap(), deadline())
                    .unwrap();
                let ready_by = Instant::now() + Duration::from_secs(8);
                loop {
                    match client.status_with_binding(deadline()).unwrap() {
                        (State::NetworkReady, Some(binding)) => {
                            assert_eq!(binding.generation(), &id);
                            assert_eq!(binding.ifindex().get(), 9);
                            assert!(binding.allows("10.20.0.5".parse().unwrap()));
                            assert!(!binding.allows("172.16.0.5".parse().unwrap()));
                            break;
                        }
                        (State::Starting, None) if Instant::now() < ready_by => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        state => panic!("unexpected v2 status: {state:?}"),
                    }
                }
                assert_eq!(rig.routes(), ["10.20.0.0/16"]);
                assert_eq!(rig.dns(), ["10.20.1.53"]);
                let unit = started_unit(&rig.harness.log).unwrap();
                assert_eq!(generation_of(&unit), id.as_str());
                assert_eq!(client.stop(deadline()).unwrap(), State::Stopping);
                worker.join().unwrap().unwrap();
                let observer = scope.spawn(|| {
                    let (stream, _) = listener.accept().unwrap();
                    serve_cleanup_fixture(stream, 1000, &policy_file.store, &launcher, &cleanup)
                });
                let observer_client = Client::connect_v2(&path, deadline()).unwrap();
                assert_eq!(
                    observer_client.cleanup_status(&id, deadline()).unwrap(),
                    CleanupState::Stopped
                );
                observer.join().unwrap().unwrap();
                assert!(
                    rig.routes().is_empty()
                        && rig.dns().is_empty()
                        && rig.harness.leases().is_empty()
                );
                assert_reverted_after_stop(&rig, &unit);
            });
        }

        #[test]
        fn a_fortinet_attempt_reaches_network_ready_with_the_accepted_network_and_stops_clean() {
            if !namespaced_in(
                "a_fortinet_attempt_reaches_network_ready_with_the_accepted_network_and_stops_clean",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            rig.instance(Script::Ready(standard_events()));
            let launcher = rig.launcher(false);
            let mut running = rig.launch(&launcher, &policy(&[])).unwrap();
            assert_eq!(running.state(), State::NetworkReady);

            // The order carries the policy's endpoint and pin and the planned
            // egress; the password arrived on the instance channel only.
            let seen = rig.seen.lock().unwrap();
            let start = seen.start.as_ref().unwrap();
            assert_eq!(
                (
                    start.host.as_str(),
                    start.port,
                    start.username.as_str(),
                    start.certificate_sha256.as_str(),
                    start.interface.as_str(),
                    start.index,
                    start.gateway,
                    start.ppp_ifname.as_str()
                ),
                (
                    "vpn.example",
                    443,
                    "alice",
                    "ab".repeat(32).as_str(),
                    "eth-fixture",
                    2,
                    Ipv4Addr::new(192, 0, 2, 20),
                    "vpntp1"
                )
            );
            assert_eq!(seen.password.as_deref(), Some(PASSWORD));
            drop(seen);
            assert!(
                !serde_json::to_string(&start_json(&rig))
                    .unwrap()
                    .contains(PASSWORD)
            );

            // Inside the ceiling only; the rest refused and counted.
            assert_eq!(rig.routes(), ["10.20.0.0/16"]);
            assert_eq!(rig.dns(), ["10.20.1.53"]);
            let unit = started_unit(&rig.harness.log).unwrap();
            let generation = generation_of(&unit);
            let receipt = rig.receipt(&generation);
            assert_eq!(receipt["refused_routes"], 1);
            assert_eq!(receipt["refused_dns"], 1);
            assert_eq!(receipt["confirmed"], true);
            assert_eq!(rig.harness.leases(), [generation.as_str()]);
            // The frozen transport address, and only it, is opened before the start.
            let allow = format!("set-property --runtime {unit} IPAddressAllow=192.0.2.20/32");
            assert_eq!(
                rig.harness.log(),
                [allow.clone(), format!("start --no-block -- {unit}")]
            );

            assert_eq!(running.stop(), State::Stopped);
            assert_eq!(rig.seen.lock().unwrap().stop_frames, 1);
            assert_eq!(
                rig.harness.log(),
                [
                    allow,
                    format!("start --no-block -- {unit}"),
                    format!("stop -- {unit}"),
                    format!("revert -- {unit}")
                ]
            );
            assert!(rig.routes().is_empty() && rig.dns().is_empty());
            assert!(rig.harness.leases().is_empty());
            assert_eq!(rig.receipt(&generation)["complete"], true);
            // A repeated stop does not repeat any mutation.
            let ops = rig.kernel.lock().unwrap().ops.len();
            assert_eq!(running.stop(), State::Stopped);
            assert_eq!(rig.harness.log().len(), 4);
            assert_eq!(rig.kernel.lock().unwrap().ops.len(), ops);
        }

        fn start_json(rig: &Rig) -> serde_json::Value {
            serde_json::to_value(rig.seen.lock().unwrap().start.as_ref().unwrap()).unwrap()
        }

        #[test]
        fn a_policy_that_fixes_the_dns_servers_prevails_over_the_gateway() {
            if !namespaced_in(
                "a_policy_that_fixes_the_dns_servers_prevails_over_the_gateway",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            rig.instance(Script::Ready(standard_events()));
            let launcher = rig.launcher(false);
            let mut running = rig.launch(&launcher, &policy(&["10.20.9.9"])).unwrap();
            assert_eq!(running.state(), State::NetworkReady);
            assert_eq!(rig.dns(), ["10.20.9.9"]);
            assert_eq!(running.stop(), State::Stopped);
        }

        #[test]
        fn fortinet_without_reachable_policy_dns_never_reaches_network_ready() {
            if !namespaced_in(
                "fortinet_without_reachable_policy_dns_never_reaches_network_ready",
                "tests::fortinet_tests",
            ) {
                return;
            }
            for fixed in [false, true] {
                let rig = Rig::new();
                let mut events = standard_events();
                let servers: &[&str] = if fixed {
                    // Offers from the standard fixture include a reachable server.
                    &["10.21.0.53"]
                } else {
                    events.retain(|event| {
                        !matches!(event, Event::DnsServer { .. } | Event::DnsCount { .. })
                    });
                    events.push(Event::DnsCount {
                        servers: 0,
                        domains: 0,
                    });
                    &[]
                };
                rig.instance(Script::Ready(events));
                let launcher = rig.launcher(false);
                assert_eq!(
                    rig.launch(&launcher, &policy(servers)).err(),
                    Some(ErrorCode::Backend)
                );

                let unit = started_unit(&rig.harness.log).unwrap();
                let saved = rig.receipt(&generation_of(&unit));
                assert_eq!(saved["routes_intended"], 0);
                assert_eq!(saved["dns_intended"], false);
                assert_eq!(saved["confirmed"], false);
                assert_eq!(saved["complete"], true);
                assert_reverted_after_stop(&rig, &unit);
                assert!(rig.harness.leases().is_empty());
                let kernel = rig.kernel.lock().unwrap();
                assert_eq!(kernel.adds, 0);
                assert!(!kernel.ppp);
                assert!(
                    kernel.routes.is_empty() && kernel.dns.is_empty() && kernel.domains.is_empty()
                );
                assert!(
                    !kernel
                        .ops
                        .iter()
                        .any(|op| op.starts_with("/usr/bin/resolvectl "))
                );
            }
        }

        #[test]
        fn an_interface_mismatch_is_fatal_and_leaves_nothing_behind() {
            if !namespaced_in(
                "an_interface_mismatch_is_fatal_and_leaves_nothing_behind",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            let mut events = standard_events();
            events.push(Event::InterfaceMismatch);
            rig.instance(Script::ReadyAndLeaveTheLink(events));
            let launcher = rig.launcher(false);
            assert_eq!(
                rig.launch(&launcher, &policy(&[])).err(),
                Some(ErrorCode::Backend)
            );
            // Nothing was applied, the unit was stopped, the lease is gone.
            assert!(rig.routes().is_empty() && rig.dns().is_empty());
            let unit = started_unit(&rig.harness.log).unwrap();
            assert!(rig.harness.log().contains(&format!("stop -- {unit}")));
            assert_reverted_after_stop(&rig, &unit);
            assert!(rig.harness.leases().is_empty());
            assert_eq!(rig.receipt(&generation_of(&unit))["complete"], true);
        }

        #[test]
        fn a_reported_fortinet_failure_ends_the_attempt_with_its_code() {
            if !namespaced_in(
                "a_reported_fortinet_failure_ends_the_attempt_with_its_code",
                "tests::fortinet_tests",
            ) {
                return;
            }
            for (kind, code) in [
                (Reported::CredentialsRejected, ErrorCode::PermissionDenied),
                (Reported::GatewayTimeout, ErrorCode::Timeout),
                (
                    Reported::LocalAddressDenied,
                    ErrorCode::FortinetLocalAddressDenied,
                ),
            ] {
                let rig = Rig::new();
                rig.instance(Script::Report(vec![
                    Event::Started,
                    Event::Failure { kind },
                ]));
                let launcher = rig.launcher(false);
                assert_eq!(rig.launch(&launcher, &policy(&[])).err(), Some(code));
                assert!(rig.harness.leases().is_empty());
                assert!(rig.routes().is_empty());
                let unit = started_unit(&rig.harness.log).unwrap();
                assert!(rig.harness.log().contains(&format!("stop -- {unit}")));
                assert_reverted_after_stop(&rig, &unit);
            }
        }

        #[test]
        fn legacy_fortinet_grant_requires_reapproval_before_launch() {
            let rig = Rig::new();
            let launcher = rig.launcher(false);
            let mut value = serde_json::to_value(policy(&[])).unwrap();
            value.as_object_mut().unwrap().remove("fortinet_local_cidr");
            let entry = serde_json::from_value(value).unwrap();
            assert_eq!(
                rig.launch(&launcher, &entry).err(),
                Some(ErrorCode::PolicyReapprovalRequired)
            );
            assert!(rig.harness.log().is_empty());
            assert!(rig.kernel.lock().unwrap().ops.is_empty());
        }

        #[test]
        fn the_death_of_the_instance_is_cleaned_by_the_receipt() {
            if !namespaced_in(
                "the_death_of_the_instance_is_cleaned_by_the_receipt",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            // Ready, then the instance vanishes without cleaning: the link, the
            // routes and the DNS it left are the writer's to remove.
            let mut events = standard_events();
            events.push(Event::Started);
            rig.instance(Script::ReadyAndLeaveTheLink(events));
            let launcher = rig.launcher(false);
            let mut running = rig.launch(&launcher, &policy(&[])).unwrap();
            assert_eq!(rig.routes(), ["10.20.0.0/16"]);
            assert_eq!(rig.dns(), ["10.20.1.53"]);
            // The instance process exits; the server's reaction is a stop.
            rig.harness.stop.store(true, Ordering::SeqCst);
            drop(rig.instance.lock().unwrap().take().map(JoinHandle::join));
            assert_eq!(running.stop(), State::Stopped);
            assert!(rig.routes().is_empty() && rig.dns().is_empty());
            let unit = started_unit(&rig.harness.log).unwrap();
            assert!(rig.harness.log().contains(&format!("stop -- {unit}")));
            assert_reverted_after_stop(&rig, &unit);
            assert!(rig.harness.leases().is_empty());
            assert_eq!(rig.receipt(&generation_of(&unit))["complete"], true);
        }

        #[test]
        fn a_stop_that_cannot_be_proven_keeps_the_lease_and_a_retry_converges() {
            if !namespaced_in(
                "a_stop_that_cannot_be_proven_keeps_the_lease_and_a_retry_converges",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            rig.instance(Script::ReadyAndLeaveTheLink(standard_events()));
            let launcher = rig.launcher(false);
            let mut running = rig.launch(&launcher, &policy(&[])).unwrap();
            let unit = started_unit(&rig.harness.log).unwrap();
            let generation = generation_of(&unit);
            rig.kernel.lock().unwrap().refuse_delete = true;
            assert_eq!(running.stop(), State::CleanupPending);
            assert_eq!(rig.harness.leases(), [generation.as_str()]);
            assert_eq!(rig.receipt(&generation)["complete"], false);
            // The network cleanup failed, but the unit was stopped and its
            // drop-in reverted all the same.
            assert_reverted_after_stop(&rig, &unit);
            rig.kernel.lock().unwrap().refuse_delete = false;
            assert_eq!(running.stop(), State::Stopped);
            assert!(rig.routes().is_empty() && rig.dns().is_empty());
            assert!(rig.harness.leases().is_empty());
            assert_eq!(rig.receipt(&generation)["complete"], true);
        }

        #[test]
        fn exclusion_v1_refuses_a_fortinet_attempt_while_an_ovpn_tunnel_is_present() {
            if !namespaced_in(
                "exclusion_v1_refuses_a_fortinet_attempt_while_an_ovpn_tunnel_is_present",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            let launcher = rig.launcher(true);
            assert_eq!(
                rig.launch(&launcher, &policy(&[])).err(),
                Some(ErrorCode::Busy)
            );
            rig.harness.assert_no_effect(&[]);
            assert!(rig.kernel.lock().unwrap().ops.is_empty());
        }

        #[test]
        fn a_present_lease_blocks_a_fortinet_attempt_before_any_effect() {
            if !namespaced_in(
                "a_present_lease_blocks_a_fortinet_attempt_before_any_effect",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            NetworkLock::acquire_test(
                &rig.harness.runtime,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap()
            .register("0123456789abcdef0123456789abcdef")
            .unwrap();
            let launcher = rig.launcher(false);
            assert_eq!(
                rig.launch(&launcher, &policy(&[])).err(),
                Some(ErrorCode::Busy)
            );
            assert!(rig.harness.log().is_empty());
            assert_eq!(rig.harness.leases(), ["0123456789abcdef0123456789abcdef"]);
            assert!(rig.kernel.lock().unwrap().ops.is_empty());
        }

        #[test]
        fn a_failed_property_call_aborts_without_start_and_reverts() {
            if !namespaced_in(
                "a_failed_property_call_aborts_without_start_and_reverts",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            rig.harness.flag("fail-set-property", true);
            let launcher = rig.launcher(false);
            assert_eq!(
                rig.launch(&launcher, &policy(&[])).err(),
                Some(ErrorCode::Backend)
            );
            let log = rig.harness.log();
            let unit = log[0].rsplit(' ').nth(1).unwrap().to_owned();
            assert_eq!(
                log,
                [
                    format!("set-property --runtime {unit} IPAddressAllow=192.0.2.20/32"),
                    format!("revert -- {unit}")
                ],
                "no start, and the possibly written drop-in is reverted"
            );
            assert!(rig.harness.leases().is_empty());
            assert!(rig.seen.lock().unwrap().start.is_none(), "no instance ran");
            // Nothing was written to the network: only the planning reads ran.
            assert!(
                rig.kernel
                    .lock()
                    .unwrap()
                    .ops
                    .iter()
                    .all(|op| !op.contains(" add ") && !op.contains(RESOLVECTL_PREFIX))
            );
            assert_eq!(rig.receipt(&generation_of(&unit))["complete"], true);
        }

        const RESOLVECTL_PREFIX: &str = "resolvectl";

        #[test]
        fn a_failed_revert_is_cleanup_pending_and_a_retry_converges() {
            if !namespaced_in(
                "a_failed_revert_is_cleanup_pending_and_a_retry_converges",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            rig.instance(Script::Ready(standard_events()));
            let launcher = rig.launcher(false);
            let mut running = rig.launch(&launcher, &policy(&[])).unwrap();
            let unit = started_unit(&rig.harness.log).unwrap();
            let generation = generation_of(&unit);
            rig.harness.flag("fail-revert", true);
            assert_eq!(running.stop(), State::CleanupPending);
            // The lease stays: the drop-in that opened the address may remain.
            assert_eq!(rig.harness.leases(), [generation.as_str()]);
            assert_eq!(rig.receipt(&generation)["complete"], false);
            rig.harness.flag("fail-revert", false);
            assert_eq!(running.stop(), State::Stopped);
            let log = rig.harness.log();
            let count = |line: String| log.iter().filter(|l| **l == line).count();
            assert_eq!(count(format!("stop -- {unit}")), 1, "{log:?}");
            assert_eq!(count(format!("revert -- {unit}")), 2, "{log:?}");
            assert!(rig.harness.leases().is_empty());
            assert_eq!(rig.receipt(&generation)["complete"], true);
        }

        #[test]
        fn a_cancelled_attempt_is_stopped_and_its_drop_in_reverted() {
            if !namespaced_in(
                "a_cancelled_attempt_is_stopped_and_its_drop_in_reverted",
                "tests::fortinet_tests",
            ) {
                return;
            }
            // The instance takes the order and the password and then reports
            // nothing: the attempt waits for the link until the client cancels.
            let rig = Rig::new();
            rig.instance(Script::Report(vec![Event::Started]));
            let launcher = rig.launcher(false);
            let cancel = Arc::new(SetupCancellation::default());
            thread::scope(|scope| {
                let attempt = scope.spawn(|| rig.launch_with(&launcher, &policy(&[]), &cancel));
                let deadline = Instant::now() + Duration::from_secs(10);
                while rig.seen.lock().unwrap().password.is_none() {
                    assert!(Instant::now() < deadline, "the password never arrived");
                    thread::sleep(Duration::from_millis(5));
                }
                cancel.cancel();
                let mut session = attempt
                    .join()
                    .unwrap()
                    .expect("a cancelled setup is stopped");
                assert_eq!(session.state(), State::Stopped);
                assert_eq!(session.stop(), State::Stopped);
            });
            let unit = started_unit(&rig.harness.log).unwrap();
            assert_reverted_after_stop(&rig, &unit);
            assert!(rig.routes().is_empty() && rig.dns().is_empty());
            assert!(rig.harness.leases().is_empty());
            assert_eq!(rig.receipt(&generation_of(&unit))["complete"], true);
        }

        #[test]
        fn recovery_cleans_a_fortinet_generation_left_by_a_dead_writer() {
            if !namespaced_in(
                "recovery_cleans_a_fortinet_generation_left_by_a_dead_writer",
                "tests::fortinet_tests",
            ) {
                return;
            }
            let rig = Rig::new();
            rig.instance(Script::ReadyAndLeaveTheLink(standard_events()));
            let launcher = rig.launcher(false);
            let running = rig.launch(&launcher, &policy(&[])).unwrap();
            let unit = started_unit(&rig.harness.log).unwrap();
            let generation = generation_of(&unit);
            assert_eq!(rig.routes(), ["10.20.0.0/16"]);
            // The writer dies: nothing of the session's teardown runs.
            std::mem::forget(running);
            launcher.recover().unwrap();
            assert!(rig.harness.log().contains(&format!("stop -- {unit}")));
            assert_reverted_after_stop(&rig, &unit);
            assert!(rig.routes().is_empty() && rig.dns().is_empty());
            assert!(rig.harness.leases().is_empty());
            assert_eq!(rig.receipt(&generation)["complete"], true);
            // A second recovery finds a complete receipt and does nothing.
            let ops = rig.kernel.lock().unwrap().ops.len();
            let log = rig.harness.log().len();
            launcher.recover().unwrap();
            assert_eq!(rig.kernel.lock().unwrap().ops.len(), ops);
            assert_eq!(rig.harness.log().len(), log);
        }
    }

    mod xfrm_tests {
        use super::*;
        use crate::tunneld::{
            admin::PolicyFixture,
            protocol::{Generation, Response, decode_response, read_control, timed},
            server::serve_fixture,
        };
        use std::{
            io::Write,
            os::unix::net::UnixStream,
            sync::{Mutex, mpsc},
        };

        const CHILD: &str = "VPNT_XFRM_FIXTURE_CHILD";

        #[derive(Default)]
        struct Kernel {
            ops: Vec<String>,
            link: bool,
            alias: Option<String>,
            address: bool,
            up: bool,
            routes: Vec<String>,
            ignore_delete: bool,
            refuse_delete: bool,
            leftover_policy: bool,
            before_install: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
        }

        fn fake_network(runtime: PathBuf, kernel: Arc<Mutex<Kernel>>) -> Network {
            Network::fake(move |program, args| {
                if program == "/usr/bin/busctl" {
                    assert!(args.contains(&"vpn.example"));
                    return Ok(br#"{"type":"a(iiay)st","data":[[[2,2,[192,0,2,99]],[2,2,[192,0,2,20]]],"vpn.example",1]}"#.to_vec());
                }
                assert_eq!(program, "/usr/bin/ip");
                assert_eq!(
                    NetworkLock::acquire_test(&runtime, Instant::now() + Duration::from_millis(12))
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::TimedOut,
                    "network operation outside the writer lock: {args:?}",
                );
                let mut k = kernel.lock().unwrap();
                k.ops.push(args.join(" "));
                let json = match args {
                ["-4", "-j", "rule", "show"] => serde_json::json!([
                    {"priority": 0, "src":"all","table":"local"},
                    {"priority":32766,"src":"all","table":"main"},
                    {"priority":32767,"src":"all","table":"default"}
                ]),
                ["-4", "-j", "route", "get", "192.0.2.20"] => serde_json::json!([
                    {"dev":"eth-fixture","prefsrc":"192.0.2.2","gateway":"192.0.2.1"}
                ]),
                ["-j", "-d", "link", "show"] => {
                    // Plan and install each read egress and then inventory.
                    let link_reads = k.ops.iter().filter(|op| op.as_str() == "-j -d link show").count();
                    if link_reads == 4 && let Some((entered, resume)) = k.before_install.take() {
                        entered.send(()).unwrap();
                        resume.recv_timeout(Duration::from_secs(4)).unwrap();
                    }
                    let mut links = vec![serde_json::json!({"ifname":"eth-fixture","ifindex":2,"flags":["UP"]})];
                    if k.link {
                        links.push(serde_json::json!({
                            "ifname":"vpnti1","ifindex":7,"flags":if k.up { vec!["UP"] } else { vec![] },
                            "link":"eth-fixture","ifalias":k.alias,
                            "linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"0x1"}}
                        }));
                    }
                    serde_json::json!(links)
                }
                ["-4", "-j", "-d", "route", "show", "table", "all"] => serde_json::json!(
                    k.routes.iter().map(|dst| serde_json::json!({
                        "dst":dst,"dev":"vpnti1","type":"unicast","table":"main","protocol":"boot","scope":"link"
                    })).collect::<Vec<_>>()
                ),
                ["-6", "-j", "-d", "route", "show", "table", "all"] => serde_json::json!([]),
                ["-j", "addr", "show", "dev", "vpnti1"] => serde_json::json!([{
                    "ifindex":7,"addr_info":if k.address {
                        vec![serde_json::json!({"family":"inet","local":"10.99.0.2","prefixlen":32})]
                    } else { vec![] }
                }]),
                ["xfrm", "state", "list", "nokeys"] => return Ok(vec![]),
                ["xfrm", "policy", "list"] if k.leftover_policy => return Ok(
                    b"src 10.99.0.2/32 dst 10.20.0.0/15\n\tdir out priority 1\n\tif_id 0x1\n".to_vec()
                ),
                ["xfrm", "policy", "list"] => return Ok(vec![]),
                ["link", "add", "name", "vpnti1", "type", "xfrm", "dev", "eth-fixture", "if_id", "1"] => {
                    let receipt = fs::read_dir(runtime.join(INSTANCE_DIRECTORY)).unwrap().next().unwrap().unwrap()
                        .path().join(crate::tunneld::network::RECEIPT);
                    let bytes = fs::read(receipt).unwrap();
                    let intent: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(intent["creating"], true);
                    assert_eq!(intent["vip"], "10.99.0.2");
                    if runtime.join("../negotiated-route").is_file() {
                        let routes: Vec<CidrV4> = serde_json::from_value(intent["routes"].clone()).unwrap();
                        assert_eq!(routes, [parse_cidr("10.20.0.0/16").unwrap()]);
                    }
                    k.link = true;
                    return Ok(vec![]);
                }
                ["link", "set", "dev", "vpnti1", "alias", alias] => { k.alias = Some((*alias).into()); return Ok(vec![]); }
                ["link", "set", "dev", "vpnti1", "addrgenmode", "none"] => return Ok(vec![]),
                ["link", "set", "dev", "vpnti1", "up"] => { k.up = true; return Ok(vec![]); }
                ["-4", "addr", "add", "10.99.0.2/32", "dev", "vpnti1", "noprefixroute"] => { k.address = true; return Ok(vec![]); }
                ["-4", "route", "add", dst, "dev", "vpnti1", "table", "main", "proto", "boot", "scope", "link"] => {
                    assert!(["10.20.0.0/15", "10.20.0.0/16", "172.16.0.0/12"].contains(dst), "unapproved network command: {args:?}");
                    k.routes.push((*dst).into());
                        return Ok(vec![]);
                }
                ["-4", "route", "del", dst, "dev", "vpnti1", "table", "main", "proto", "boot", "scope", "link"] => {
                    if k.refuse_delete {
                        return Err(io::Error::other("fixture refused delete"));
                    }
                    assert_eq!(k.routes.pop().as_deref(), Some(*dst));
                        return Ok(vec![]);
                }
                ["-4", "addr", "del", "10.99.0.2/32", "dev", "vpnti1"] => {
                        k.address = false;
                        return Ok(vec![]);
                    }
                ["link", "del", "dev", "vpnti1"] => {
                    assert!(k.routes.is_empty() && !k.address, "delete order");
                    if !k.ignore_delete {
                        k.link = false;
                    }
                    return Ok(vec![]);
                }
                _ => panic!("unexpected network operation: {args:?}"),
            };
                Ok(serde_json::to_vec(&json).unwrap())
            })
        }

        #[test]
        fn fixture_supervisor() {
            let Some(root) = std::env::var_os(CHILD).map(PathBuf::from) else {
                return;
            };
            let deadline = Instant::now() + Duration::from_secs(10);
            let unit = loop {
                if let Some(unit) = started_unit(&root.join("systemctl.log")) {
                    break unit;
                }
                assert!(Instant::now() < deadline, "instance unit never queued");
                thread::sleep(Duration::from_millis(5));
            };
            let generation = generation_of(&unit);
            let directory = root.join("run").join(INSTANCE_DIRECTORY).join(&generation);
            let mut channel = connect_instance(
                &directory.join(CONTROL_SOCKET_NAME),
                &directory.join(RECORD_NAME),
                &generation,
                Backend::Ipsec,
                INVOCATION,
                INSTANCE_GID,
            )
            .unwrap();
            let Order::Start(start) = serde_json::from_slice(&channel.receive().unwrap()).unwrap()
            else {
                panic!("expected Start");
            };
            assert_eq!(start.local_ts, ["dynamic"]);
            assert_eq!(start.port, 500);
            assert_eq!(start.peer_identity, "fqdn:vpn.example");
            assert_eq!(start.username, "fixture");
            assert_eq!(start.remote_ipv4, Ipv4Addr::new(192, 0, 2, 20));
            assert_eq!(
                start
                    .remote_ts
                    .iter()
                    .map(crate::tunneld::network::cidr_text)
                    .collect::<Vec<_>>(),
                ["10.20.0.0/15", "172.16.0.0/12"]
            );
            let mut frame = channel.receive().unwrap();
            let credentials =
                crate::tunneld::instance_protocol::decode_credentials(&mut frame).unwrap();
            assert!(credentials.password.expose() == "fixture-password");
            assert!(credentials.psk.expose() == "fixture-psk");
            drop(credentials);
            if root.join("pause-before-established").is_file() {
                fs::write(root.join("received-start"), b"").unwrap();
                wait_for_file(&root.join("allow-established"));
            }
            if root.join("cancel-negotiation").is_file() {
                fs::write(root.join("negotiation-started"), b"").unwrap();
                let bytes = channel
                    .receive_until(Instant::now() + Duration::from_secs(3))
                    .unwrap();
                assert!(matches!(
                    serde_json::from_slice::<Order>(&bytes).unwrap(),
                    Order::Stop {}
                ));
                fs::write(root.join("instance-stopped"), b"").unwrap();
                channel.send(br#"{"op":"stopped"}"#).unwrap();
                return;
            }
            let delay = fs::read_to_string(root.join("setup-delay"))
                .ok()
                .map(|text| text.parse::<u64>().unwrap());
            if let Some(seconds) = delay {
                thread::sleep(Duration::from_secs(seconds));
            }
            let established = channel.send(
                &serde_json::to_vec(&Reply::Established {
                    if_id: start.if_id,
                    reqid: start.reqid,
                    virtual_ipv4: Ipv4Addr::new(10, 99, 0, 2),
                    remote_ts: vec![
                        parse_cidr(if root.join("outside-selector").is_file() {
                            "10.22.0.0/16"
                        } else {
                            "10.20.0.0/16"
                        })
                        .unwrap(),
                    ],
                })
                .unwrap(),
            );
            if root.join("expect-setup-timeout").is_file() && established.is_err() {
                return;
            }
            established.unwrap();
            if root.join("close-channel-after-setup").is_file() {
                wait_for_file_until(&root.join("close-now"), Duration::from_secs(12));
                drop(channel);
                fs::write(root.join("channel-closed"), b"").unwrap();
                wait_for_file_until(&root.join("exit-now"), Duration::from_secs(15));
                return;
            }
            if root.join("exit-after-setup").exists() {
                while !root.join("exit-now").exists() {
                    assert!(
                        Instant::now() < deadline,
                        "fixture never allowed supervisor exit"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                return;
            }
            assert!(matches!(
                serde_json::from_slice::<Order>(&channel.receive().unwrap()).unwrap(),
                Order::Stop {}
            ));
            fs::write(root.join("instance-stopped"), b"").unwrap();
            channel.send(br#"{"op":"stopped"}"#).unwrap();
        }

        fn response(socket: &UnixStream) -> Response {
            response_with_timeout(socket, Duration::from_secs(8))
        }

        fn response_with_timeout(socket: &UnixStream, timeout: Duration) -> Response {
            let mut socket = timed(socket, Instant::now() + timeout).unwrap();
            read_control(&mut socket, decode_response).unwrap()
        }

        fn client_prepare(client: &mut UnixStream) {
            client
                .write_all(b"{\"op\":\"hello\",\"version\":1}\n")
                .unwrap();
            assert!(matches!(response(client), Response::Version { .. }));
            client.write_all(b"{\"op\":\"prepare_ipsec\",\"endpoint\":{\"host\":\"vpn.example\",\"port\":500},\"username\":\"fixture\",\"networks\":[{\"network\":\"10.20.1.0\",\"prefix\":24}]}\n").unwrap();
            assert!(matches!(
                response(client),
                Response::Prepared { generation: None }
            ));
        }

        fn v2_prepare(client: &mut UnixStream) -> Generation {
            v2_hello(client);
            client.write_all(b"{\"op\":\"prepare_ipsec\",\"endpoint\":{\"host\":\"vpn.example\",\"port\":500},\"username\":\"fixture\",\"networks\":[{\"network\":\"10.20.1.0\",\"prefix\":24}]}\n").unwrap();
            match response(client) {
                Response::Prepared {
                    generation: Some(generation),
                } => generation,
                reply => panic!("expected v2 preparation, got {reply:?}"),
            }
        }

        fn v2_hello(client: &mut UnixStream) {
            client
                .write_all(b"{\"op\":\"hello\",\"version\":2}\n")
                .unwrap();
            assert!(matches!(response(client), Response::Version { version: 2 }));
        }

        fn v2_query(
            uid: u32,
            policy: &PolicyFixture,
            launcher: &dyn Launch,
            cleanup: &Store,
            generation: &Generation,
        ) -> protocol::CleanupState {
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    super::super::super::server::serve_cleanup_fixture(
                        stream,
                        uid,
                        &policy.store,
                        launcher,
                        cleanup,
                    )
                });
                v2_hello(&mut client);
                protocol::write_control(
                    &mut client,
                    &protocol::Request::CleanupStatus {
                        generation: generation.clone(),
                    },
                )
                .unwrap();
                let Response::CleanupStatus { state } =
                    response_with_timeout(&client, Duration::from_secs(1))
                else {
                    panic!("expected cleanup receipt status");
                };
                worker.join().unwrap().unwrap();
                state
            })
        }

        fn v2_ready(client: &mut UnixStream) {
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                client.write_all(b"{\"op\":\"status\"}\n").unwrap();
                match response_with_timeout(client, Duration::from_secs(1)) {
                    Response::NetworkReady { .. } => return,
                    Response::Status {
                        state: State::Starting,
                    } if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    reply => panic!("unexpected v2 status: {reply:?}"),
                }
            }
        }

        #[test]
        fn v2_stop_and_eof_converge_after_slow_transient_revert() {
            use crate::tunneld::{
                client::{Client, Confirmation},
                protocol::CleanupState,
                server::serve_cleanup_fixture,
            };
            use std::os::unix::net::UnixListener;
            if !namespaced_in(
                "v2_stop_and_eof_converge_after_slow_transient_revert",
                "tests::xfrm_tests",
            ) {
                return;
            }
            for explicit in [true, false] {
                let harness = Harness::new();
                let policy = PolicyFixture::new();
                policy.install();
                harness.flag("negotiated-route", true);
                harness.flag("slow-revert-once", true);
                let mut process = supervisor(&harness);
                let kernel = Arc::new(Mutex::new(Kernel::default()));
                let mut launcher = harness.launcher(false);
                launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
                let cleanup = Store::open(&harness.runtime).unwrap();
                let path = harness.root.join("client.sock");
                let listener = UnixListener::bind(&path).unwrap();
                thread::scope(|scope| {
                    let worker = scope.spawn(|| {
                        let (stream, _) = listener.accept().unwrap();
                        serve_cleanup_fixture(stream, 1000, &policy.store, &launcher, &cleanup)
                    });
                    let deadline = || Instant::now() + Duration::from_secs(1);
                    let mut client = Client::connect_v2(&path, deadline()).unwrap();
                    let offer = Prepare::Ipsec(
                        protocol::IpsecRequest::new(
                            protocol::Endpoint::new("vpn.example".into(), 500).unwrap(),
                            "fixture".into(),
                            vec![parse_cidr("10.20.1.0/24").unwrap()],
                        )
                        .unwrap(),
                    );
                    let id = client.prepare(offer, deadline()).unwrap().unwrap();
                    assert!(harness.log().is_empty() && harness.leases().is_empty());
                    client
                        .send_credentials(
                            Credentials::ipsec("fixture-password", "fixture-psk").unwrap(),
                            deadline(),
                        )
                        .unwrap();
                    let ready_by = Instant::now() + Duration::from_secs(8);
                    let original_binding = loop {
                        match client.status_with_binding(deadline()).unwrap() {
                            (State::NetworkReady, Some(binding)) => {
                                assert_eq!(binding.generation(), &id);
                                assert_eq!(binding.ifindex().get(), 7);
                                assert!(binding.allows("10.20.0.5".parse().unwrap()));
                                assert!(!binding.allows("10.21.0.5".parse().unwrap()));
                                break binding;
                            }
                            (State::Starting, None) if Instant::now() < ready_by => {
                                thread::sleep(Duration::from_millis(10))
                            }
                            state => panic!("unexpected v2 status: {state:?}"),
                        }
                    };
                    assert_eq!(
                        generation_of(&started_unit(&harness.log).unwrap()),
                        id.as_str()
                    );
                    assert_eq!(kernel.lock().unwrap().routes, ["10.20.0.0/16"]);
                    if explicit {
                        let guard =
                            NetworkLock::acquire_test(&harness.runtime, deadline()).unwrap();
                        let started = Instant::now();
                        assert!(matches!(
                            client.confirm(started + Duration::from_millis(80)).unwrap(),
                            Confirmation::Unavailable
                        ));
                        assert!(started.elapsed() < Duration::from_millis(400));
                        if client.confirmation_pending() {
                            assert!(matches!(
                                client.confirm(deadline()).unwrap(),
                                Confirmation::Late(None)
                            ));
                        }
                        assert!(!client.confirmation_pending());
                        drop(guard);
                        assert!(matches!(
                            client.confirm(deadline()).unwrap(),
                            Confirmation::Fresh(binding) if binding == original_binding
                        ));
                        assert_eq!(client.stop(deadline()).unwrap(), State::Stopping);
                    }
                    drop(client);
                    wait_for_file(&harness.root.join("revert-entered"));
                    assert_eq!(harness.leases(), [id.as_str()]);
                    assert_eq!(
                        v2_query(1000, &policy, &launcher, &cleanup, &id),
                        CleanupState::Pending
                    );
                    assert_eq!(
                        v2_query(1001, &policy, &launcher, &cleanup, &id),
                        CleanupState::Unknown
                    );
                    let result = worker.join().unwrap();
                    if explicit {
                        result.unwrap();
                    }
                    assert_eq!(
                        v2_query(1000, &policy, &launcher, &cleanup, &id),
                        CleanupState::Stopped
                    );
                    assert!(harness.leases().is_empty());
                    assert_eq!(
                        harness
                            .log()
                            .iter()
                            .filter(|line| line.starts_with("revert --"))
                            .count(),
                        2
                    );
                    let kernel = kernel.lock().unwrap();
                    assert!(kernel.routes.is_empty() && !kernel.link && !kernel.address);
                });
                assert!(process.0.wait().unwrap().success());
            }
        }

        #[test]
        fn v2_persistent_cleanup_stays_pending_until_recovery_proves_removal() {
            use crate::tunneld::{protocol::CleanupState, server::serve_cleanup_fixture};
            if !namespaced_in(
                "v2_persistent_cleanup_stays_pending_until_recovery_proves_removal",
                "tests::xfrm_tests",
            ) {
                return;
            }
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            harness.flag("negotiated-route", true);
            harness.flag("fail-revert", true);
            let mut process = supervisor(&harness);
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
            let cleanup = Store::open(&harness.runtime).unwrap();
            let (mut client, stream) = UnixStream::pair().unwrap();
            let generation = thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    serve_cleanup_fixture(stream, 1000, &policy.store, &launcher, &cleanup)
                });
                let id = v2_prepare(&mut client);
                client_credentials(&mut client);
                v2_ready(&mut client);
                command(&mut client, b"{\"op\":\"stop\"}\n", State::Stopping);
                drop(client);
                worker.join().unwrap().unwrap();
                id
            });
            assert_eq!(harness.leases(), [generation.as_str()]);
            assert_eq!(
                harness
                    .log()
                    .iter()
                    .filter(|line| line.starts_with("revert --"))
                    .count(),
                3
            );
            assert_eq!(
                v2_query(1000, &policy, &launcher, &cleanup, &generation),
                CleanupState::Pending
            );
            drop(cleanup);
            harness.flag("fail-revert", false);
            let reopened = Store::open(&harness.runtime).unwrap();
            launcher.recover_with(Some(&reopened)).unwrap();
            assert!(harness.leases().is_empty());
            assert_eq!(
                v2_query(1000, &policy, &launcher, &reopened, &generation),
                CleanupState::Stopped
            );
            let kernel = kernel.lock().unwrap();
            assert!(kernel.routes.is_empty() && !kernel.link && !kernel.address);
            assert!(process.0.wait().unwrap().success());
        }

        struct LaunchSnapshot {
            policy: PolicyFixture,
            id: Generation,
            phase: Vec<u8>,
            plan: Option<Vec<u8>>,
        }

        fn network_receipt_name(backend: Backend) -> &'static str {
            match backend {
                Backend::Ipsec => super::super::super::network::RECEIPT,
                Backend::Fortinet => fortinet_network::RECEIPT,
            }
        }

        fn snapshot_launch(backend: Backend, before_lock: bool) -> LaunchSnapshot {
            use crate::tunneld::{
                fortinet_network::fixture, policy::Policy, server::serve_cleanup_fixture,
            };
            use serde_json::{Value, json};

            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            let bytes = fs::read(policy.path()).unwrap();
            let mut grants = Policy::from_disk(&bytes).unwrap();
            let mut other: Value = serde_json::from_slice(&bytes).unwrap();
            other["entries"][0]["uid"] = json!(1001);
            grants
                .apply(Policy::snapshot(other.to_string().as_bytes()).unwrap())
                .unwrap();
            grants
                .apply(fixture::entry(&["10.20.0.0/15"], &[], &[]))
                .unwrap();
            fs::write(policy.path(), grants.bytes().unwrap()).unwrap();

            let captured = Arc::new(Mutex::new(None));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), Arc::default());
            launcher.fortinet = fixture::network(Arc::default(), Some(harness.runtime.clone()));
            harness.flag("fail-set-property", true);
            let runtime = harness.runtime.clone();
            let captured_by_launcher = captured.clone();
            launcher.lock = Box::new(move |deadline| {
                let snapshot_phase = || {
                    let receipts = runtime.join("tunneld-cleanup");
                    let entry = fs::read_dir(receipts).unwrap().next().unwrap().unwrap();
                    (entry.file_name(), fs::read(entry.path()).unwrap())
                };
                if before_lock {
                    let (_, phase) = snapshot_phase();
                    *captured_by_launcher.lock().unwrap() = Some((phase, None));
                    return Err(io::ErrorKind::TimedOut.into());
                }
                let guard = NetworkLock::acquire_test(&runtime, deadline)?;
                if guard.tunnels_present()? {
                    // At the first cleanup lock, the lease and its plan must
                    // already exist even when unit setup could not begin.
                    let (name, phase) = snapshot_phase();
                    let plan = fs::read(
                        runtime
                            .join(INSTANCE_DIRECTORY)
                            .join(&name)
                            .join(network_receipt_name(backend)),
                    )
                    .unwrap();
                    assert!(runtime.join("tunnel-leases").join(name).is_file());
                    *captured_by_launcher.lock().unwrap() = Some((phase, Some(plan)));
                }
                Ok(guard)
            });
            let cleanup = Store::open(&harness.runtime).unwrap();
            let (mut client, stream) = UnixStream::pair().unwrap();
            let id = thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    serve_cleanup_fixture(stream, 1000, &policy.store, &launcher, &cleanup)
                });
                let id = match backend {
                    Backend::Ipsec => {
                        let id = v2_prepare(&mut client);
                        client_credentials(&mut client);
                        id
                    }
                    Backend::Fortinet => {
                        v2_hello(&mut client);
                        let offer = Prepare::Fortinet(
                            protocol::FortinetRequest::new(
                                protocol::Endpoint::new("vpn.example".into(), 443).unwrap(),
                                "alice".into(),
                                [0xab; 32],
                            )
                            .unwrap(),
                        );
                        protocol::write_control(&mut client, &protocol::Request::from(offer))
                            .unwrap();
                        let Response::Prepared {
                            generation: Some(id),
                        } = response(&client)
                        else {
                            panic!("Fortinet preparation failed");
                        };
                        Credentials::fortinet("fixture-password")
                            .unwrap()
                            .write(&mut client)
                            .unwrap();
                        id
                    }
                };
                let expected = if before_lock {
                    ErrorCode::Busy
                } else {
                    ErrorCode::Backend
                };
                let reply = response(&client);
                assert!(
                    matches!(reply, Response::Error { code } if code == expected),
                    "{reply:?}"
                );
                worker.join().unwrap().unwrap();
                id
            });
            assert!(harness.leases().is_empty());
            if before_lock {
                assert!(harness.log().is_empty());
            }
            let (phase, plan) = captured.lock().unwrap().take().unwrap();
            LaunchSnapshot {
                policy,
                id,
                phase,
                plan,
            }
        }

        fn restore_receipt(path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        #[test]
        fn v2_launch_persists_recovery_phase_before_taking_the_network_lock() {
            use crate::tunneld::{protocol::CleanupState, server::serve_recovery_fixture};

            for backend in [Backend::Ipsec, Backend::Fortinet] {
                let LaunchSnapshot {
                    policy,
                    id,
                    phase: bytes,
                    ..
                } = snapshot_launch(backend, true);
                let receipt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(receipt["phase"], "preparing_network", "{backend:?}");

                // Restore the snapshot without the original writer's teardown.
                let restarted = Harness::new();
                let reopened = Store::open(&restarted.runtime).unwrap();
                restore_receipt(
                    &restarted.runtime.join("tunneld-cleanup").join(id.as_str()),
                    &bytes,
                );
                let launcher = restarted.launcher(false);
                for version in [1, 2] {
                    let (mut client, stream) = UnixStream::pair().unwrap();
                    thread::scope(|scope| {
                        let worker = scope.spawn(|| {
                            serve_recovery_fixture(
                                stream,
                                1001,
                                &policy.store,
                                &launcher,
                                &reopened,
                            )
                        });
                        if version == 1 {
                            client_prepare(&mut client);
                        } else {
                            v2_prepare(&mut client);
                        }
                        drop(client);
                        assert!(worker.join().unwrap().is_err());
                    });
                }
                assert_eq!(reopened.status(1000, &id), CleanupState::Stopped);
                assert_eq!(reopened.status(1001, &id), CleanupState::Unknown);
                assert!(restarted.log().is_empty() && restarted.leases().is_empty());
            }
        }

        #[test]
        fn v2_recovery_requires_proof_after_publishing_the_network_lease() {
            use crate::tunneld::{fortinet_network::fixture, protocol::CleanupState};

            for backend in [Backend::Ipsec, Backend::Fortinet] {
                let LaunchSnapshot {
                    id,
                    phase: bytes,
                    plan,
                    ..
                } = snapshot_launch(backend, false);
                let receipt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(receipt["phase"], "pending", "{backend:?}");
                let restarted = Harness::new();
                let reopened = Store::open(&restarted.runtime).unwrap();
                restore_receipt(
                    &restarted.runtime.join("tunneld-cleanup").join(id.as_str()),
                    &bytes,
                );
                let mut launcher = restarted.launcher(false);
                launcher.xfrm = fake_network(restarted.runtime.clone(), Arc::default());
                launcher.fortinet =
                    fixture::network(Arc::default(), Some(restarted.runtime.clone()));
                let guard = (launcher.lock)(Instant::now() + Duration::from_secs(1)).unwrap();
                guard.register(id.as_str()).unwrap();
                drop(guard);

                let error = launcher.recover_with(Some(&reopened)).unwrap_err();
                assert_eq!(error.to_string(), "cleanup lacks proof for a generation");
                assert_eq!(reopened.status(1000, &id), CleanupState::Pending);
                assert_eq!(restarted.leases(), [id.as_str()]);
                assert!(restarted.log().is_empty());

                let directory = launcher.create_directory(id.as_str()).unwrap();
                let receipt_name = network_receipt_name(backend);
                restore_receipt(&directory.join(receipt_name), &plan.unwrap());
                launcher.recover_with(Some(&reopened)).unwrap();
                assert_eq!(reopened.status(1000, &id), CleanupState::Stopped);
                assert!(restarted.leases().is_empty());
                assert!(
                    restarted
                        .log()
                        .iter()
                        .any(|line| line.starts_with("stop -- "))
                );
            }
        }

        #[test]
        fn v2_recovery_can_retire_a_staged_plan_without_network_cleanup() {
            use crate::tunneld::{fortinet_network::fixture, protocol::CleanupState};

            for backend in [Backend::Ipsec, Backend::Fortinet] {
                let LaunchSnapshot {
                    id,
                    phase: bytes,
                    plan,
                    ..
                } = snapshot_launch(backend, false);
                let mut receipt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                receipt["phase"] = serde_json::json!("preparing_network");
                let restarted = Harness::new();
                let reopened = Store::open(&restarted.runtime).unwrap();
                let mut launcher = restarted.launcher(false);
                launcher.xfrm = fake_network(restarted.runtime.clone(), Arc::default());
                launcher.fortinet =
                    fixture::network(Arc::default(), Some(restarted.runtime.clone()));
                restore_receipt(
                    &restarted.runtime.join("tunneld-cleanup").join(id.as_str()),
                    &serde_json::to_vec(&receipt).unwrap(),
                );
                let directory = launcher.create_directory(id.as_str()).unwrap();
                let receipt_name = network_receipt_name(backend);
                restore_receipt(&directory.join(receipt_name), &plan.unwrap());
                let guard = (launcher.lock)(Instant::now() + Duration::from_secs(1)).unwrap();
                guard.register("unrelated").unwrap();
                drop(guard);

                launcher.recover_with(Some(&reopened)).unwrap();
                assert_eq!(reopened.status(1000, &id), CleanupState::Stopped);
                assert!(restarted.log().is_empty());
                assert_eq!(restarted.leases(), ["unrelated"]);
                let bytes = fs::read(directory.join(receipt_name)).unwrap();
                let plan: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(plan["complete"], true);
            }
        }

        #[test]
        fn recovery_only_confirms_an_empty_preparation_not_an_orphaned_pending() {
            use crate::tunneld::protocol::CleanupState;
            let harness = Harness::new();
            let launcher = harness.launcher(false);
            let store = Store::open(&harness.runtime).unwrap();
            let fresh = store.reserve(1000).unwrap();
            let mut started = store.reserve(1000).unwrap();
            started.begin_network().unwrap();
            started.arm().unwrap();
            let started_id = started.generation().clone();
            drop(started);
            assert!(launcher.recover_with(Some(&store)).is_err());
            assert_eq!(
                store.status(1000, fresh.generation()),
                CleanupState::Stopped
            );
            assert_eq!(store.status(1000, &started_id), CleanupState::Pending);
            assert!(harness.log().is_empty());
            assert!(harness.leases().is_empty());
        }

        #[test]
        fn malformed_network_receipts_never_confirm_their_generations() {
            use crate::tunneld::protocol::CleanupState;
            for receipt_name in [
                super::super::super::network::RECEIPT,
                fortinet_network::RECEIPT,
            ] {
                let harness = Harness::new();
                let launcher = harness.launcher(false);
                let store = Store::open(&harness.runtime).unwrap();
                let mut record = store.reserve(1000).unwrap();
                record.begin_network().unwrap();
                record.arm().unwrap();
                let generation = record.generation().as_str();
                let directory = launcher.create_directory(generation).unwrap();
                let path = directory.join(receipt_name);
                fs::write(&path, b"{").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                assert!(launcher.recover_with(Some(&store)).is_err());
                assert_eq!(
                    store.status(1000, record.generation()),
                    CleanupState::Pending
                );
                assert!(harness.log().is_empty());
                assert!(harness.leases().is_empty());
            }
        }

        #[test]
        fn v2_precredential_eof_and_failed_property_rollback_produce_read_only_proof() {
            use crate::tunneld::{protocol::CleanupState, server::serve_cleanup_fixture};
            if !namespaced_in(
                "v2_precredential_eof_and_failed_property_rollback_produce_read_only_proof",
                "tests::xfrm_tests",
            ) {
                return;
            }
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(
                harness.runtime.clone(),
                Arc::new(Mutex::new(Kernel::default())),
            );
            let cleanup = Store::open(&harness.runtime).unwrap();
            for send in [false, true] {
                if send {
                    harness.flag("fail-set-property", true);
                }
                let (mut client, stream) = UnixStream::pair().unwrap();
                thread::scope(|scope| {
                    let worker = scope.spawn(|| {
                        serve_cleanup_fixture(stream, 1000, &policy.store, &launcher, &cleanup)
                    });
                    let id = v2_prepare(&mut client);
                    assert_eq!(
                        v2_query(1000, &policy, &launcher, &cleanup, &id),
                        CleanupState::Pending
                    );
                    assert_eq!(
                        v2_query(1001, &policy, &launcher, &cleanup, &id),
                        CleanupState::Unknown
                    );
                    if send {
                        client_credentials(&mut client);
                        assert!(matches!(
                            response(&client),
                            Response::Error {
                                code: ErrorCode::Backend
                            }
                        ));
                    }
                    drop(client);
                    let result = worker.join().unwrap();
                    if send {
                        result.unwrap();
                    }
                    let log = harness.log();
                    assert_eq!(
                        v2_query(1000, &policy, &launcher, &cleanup, &id),
                        CleanupState::Stopped
                    );
                    assert_eq!(harness.log(), log, "query has no backend effects");
                    assert!(harness.leases().is_empty());
                    if send {
                        assert_eq!(log.len(), 2);
                        assert!(log[0].starts_with("set-property --runtime "));
                        assert_eq!(
                            log[1],
                            format!("revert -- vpnt-tunneld-ipsec@{}.service", id.as_str())
                        );
                    } else {
                        assert!(log.is_empty());
                    }
                });
            }
        }

        fn client_credentials(client: &mut UnixStream) {
            Credentials::ipsec("fixture-password", "fixture-psk")
                .unwrap()
                .write(client)
                .unwrap();
        }

        fn command(client: &mut UnixStream, command: &[u8], expected: State) {
            client.write_all(command).unwrap();
            let reply = response(client);
            assert!(
                matches!(reply, Response::Status { state } if state == expected),
                "{reply:?}"
            );
        }

        fn supervisor(harness: &Harness) -> Reaper {
            Reaper(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "tunneld::backend::tests::xfrm_tests::fixture_supervisor",
                        "--nocapture",
                    ])
                    .env_clear()
                    .env(CHILD, &harness.root)
                    .spawn()
                    .unwrap(),
            )
        }

        fn wait_for_file(path: &Path) {
            wait_for_file_until(path, Duration::from_secs(4));
        }

        fn wait_for_file_until(path: &Path, timeout: Duration) {
            let deadline = Instant::now() + timeout;
            while !path.is_file() {
                assert!(
                    Instant::now() < deadline,
                    "fixture barrier not reached: {path:?}"
                );
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn exercise(name: &str, exit: bool, unproven: bool) {
            if !namespaced_in(name, "tests::xfrm_tests") {
                return;
            }
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            harness.flag("negotiated-route", true);
            if exit {
                fs::write(harness.root.join("exit-after-setup"), b"").unwrap();
            }
            let mut process = supervisor(&harness);
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| serve_fixture(stream, &policy.store, &launcher));
                client_prepare(&mut client);
                client_credentials(&mut client);
                command(&mut client, b"{\"op\":\"status\"}\n", State::NetworkReady);
                {
                    let k = kernel.lock().unwrap();
                    assert_eq!(k.routes, ["10.20.0.0/16"]);
                    assert!(k.link && k.up && k.address);
                }
                if exit && unproven {
                    kernel.lock().unwrap().refuse_delete = true;
                    fs::write(harness.root.join("exit-now"), b"").unwrap();
                    assert!(process.0.wait().unwrap().success());
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !harness
                        .log()
                        .iter()
                        .any(|line| line.starts_with("stop -- "))
                    {
                        assert!(
                            Instant::now() < deadline,
                            "idle client did not trigger unit stop"
                        );
                        thread::sleep(Duration::from_millis(10));
                    }
                    command(&mut client, b"{\"op\":\"status\"}\n", State::CleanupPending);
                    assert_eq!(harness.leases().len(), 1);
                    kernel.lock().unwrap().refuse_delete = false;
                    command(&mut client, b"{\"op\":\"stop\"}\n", State::Stopped);
                } else if exit {
                    fs::write(harness.root.join("exit-now"), b"").unwrap();
                    assert!(process.0.wait().unwrap().success());
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !harness.leases().is_empty() {
                        assert!(
                            Instant::now() < deadline,
                            "idle client retained lease after instance death"
                        );
                        thread::sleep(Duration::from_millis(10));
                    }
                    command(&mut client, b"{\"op\":\"status\"}\n", State::Stopped);
                } else if unproven {
                    kernel.lock().unwrap().refuse_delete = true;
                    command(&mut client, b"{\"op\":\"stop\"}\n", State::CleanupPending);
                    assert_eq!(harness.leases().len(), 1);
                    // The network cleanup failed, but the unit was stopped and its
                    // drop-in reverted all the same, in that order.
                    let log = harness.log();
                    let stop = log.iter().position(|l| l.starts_with("stop -- ")).unwrap();
                    let revert = log
                        .iter()
                        .position(|l| l.starts_with("revert -- "))
                        .unwrap();
                    assert!(stop < revert, "{log:?}");
                    {
                        let mut k = kernel.lock().unwrap();
                        k.refuse_delete = false;
                        k.ignore_delete = true;
                    }
                    command(&mut client, b"{\"op\":\"stop\"}\n", State::CleanupPending);
                    assert_eq!(harness.leases().len(), 1);
                    {
                        let mut k = kernel.lock().unwrap();
                        k.ignore_delete = false;
                        k.leftover_policy = true;
                    }
                    command(&mut client, b"{\"op\":\"stop\"}\n", State::CleanupPending);
                    assert_eq!(harness.leases().len(), 1);
                    kernel.lock().unwrap().leftover_policy = false;
                    command(&mut client, b"{\"op\":\"stop\"}\n", State::Stopped);
                } else {
                    command(&mut client, b"{\"op\":\"stop\"}\n", State::Stopped);
                    assert!(harness.root.join("instance-stopped").is_file());
                }
                drop(client);
                assert!(worker.join().is_ok());
            });
            assert!(process.0.wait().unwrap().success());
            let k = kernel.lock().unwrap();
            assert!(!k.link && !k.address && k.routes.is_empty());
            assert!(harness.leases().is_empty());
            assert_systemctl_order(&harness);
        }

        /// The transport address is opened once, before the start, and the
        /// runtime drop-in is reverted last, after the unit was stopped.
        fn assert_systemctl_order(harness: &Harness) {
            let log = harness.log();
            let unit = started_unit(&harness.log).unwrap();
            let position = |line: String| {
                log.iter()
                    .position(|entry| *entry == line)
                    .unwrap_or_else(|| panic!("{line} is not in {log:?}"))
            };
            let allow = position(format!(
                "set-property --runtime {unit} IPAddressAllow=192.0.2.20/32"
            ));
            let start = position(format!("start --no-block -- {unit}"));
            let stop = position(format!("stop -- {unit}"));
            let revert = position(format!("revert -- {unit}"));
            assert!(allow < start && start < stop && stop < revert, "{log:?}");
            assert_eq!(
                log.iter()
                    .filter(|entry| entry.starts_with("set-property "))
                    .count(),
                1
            );
            assert_eq!(log.last(), Some(&format!("revert -- {unit}")), "{log:?}");
        }

        #[test]
        fn an_ipsec_property_failure_aborts_before_start_and_reverts() {
            let name = "an_ipsec_property_failure_aborts_before_start_and_reverts";
            if !namespaced_in(name, "tests::xfrm_tests") {
                return;
            }
            let harness = Harness::new();
            harness.flag("fail-set-property", true);
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
            let remote = Ipv4Addr::new(192, 0, 2, 20);
            let setup = IpsecStart {
                order: Start {
                    remote_ipv4: remote,
                    port: 500,
                    peer_identity: "fqdn:vpn.example".into(),
                    username: "fixture".into(),
                    if_id: 0,
                    reqid: 0,
                    local_ts: vec!["dynamic".into()],
                    remote_ts: vec![parse_cidr("10.20.0.0/15").unwrap()],
                },
                approved: vec![remote],
                credentials: zeroize::Zeroizing::new(Vec::new()),
            };
            let result = launcher.launch_backend(
                Backend::Ipsec,
                Some(Setup::Ipsec(setup)),
                None,
                None,
                &SetupCancellation::default(),
                None,
            );
            assert_eq!(result.err(), Some(ErrorCode::Backend));
            let log = harness.log();
            let unit = log[0].rsplit(' ').nth(1).unwrap().to_owned();
            assert_eq!(
                log,
                [
                    format!("set-property --runtime {unit} IPAddressAllow=192.0.2.20/32"),
                    format!("revert -- {unit}")
                ],
                "no start, and the possibly written drop-in is reverted"
            );
            assert!(harness.leases().is_empty());
            assert!(!kernel.lock().unwrap().link);
        }

        fn exercise_cancel_negotiation(name: &str, eof: bool) {
            if !namespaced_in(name, "tests::xfrm_tests") {
                return;
            }
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            harness.flag("cancel-negotiation", true);
            let mut process = supervisor(&harness);
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| serve_fixture(stream, &policy.store, &launcher));
                client_prepare(&mut client);
                client_credentials(&mut client);
                wait_for_file(&harness.root.join("negotiation-started"));
                if !eof {
                    command(&mut client, b"{\"op\":\"stop\"}\n", State::Stopped);
                }
                drop(client);
                worker.join().unwrap().ok();
            });
            assert!(process.0.wait().unwrap().success());
            assert!(harness.root.join("instance-stopped").is_file());
            assert!(harness.leases().is_empty());
            assert_no_install(&kernel.lock().unwrap());
        }

        struct ObservedLaunch<'a> {
            launcher: &'a dyn Launch,
            cancel: mpsc::Sender<Arc<SetupCancellation>>,
        }

        impl Launch for ObservedLaunch<'_> {
            fn launch<'a>(
                &'a self,
                offer: &Prepare,
                grant: &Entry,
                credentials: Credentials,
                authorization: File,
                cancel: &Arc<SetupCancellation>,
            ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
                self.cancel.send(Arc::clone(cancel)).unwrap();
                self.launcher
                    .launch(offer, grant, credentials, authorization, cancel)
            }
        }

        fn exercise_cancel_before_install(name: &str, eof: bool) {
            if !namespaced_in(name, "tests::xfrm_tests") {
                return;
            }
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            let mut process = supervisor(&harness);
            let (entered, at_install) = mpsc::channel();
            let (resume, release) = mpsc::channel();
            let kernel = Arc::new(Mutex::new(Kernel {
                before_install: Some((entered, release)),
                ..Kernel::default()
            }));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
            let (observer, token) = mpsc::channel();
            let launch = ObservedLaunch {
                launcher: &launcher,
                cancel: observer,
            };
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| serve_fixture(stream, &policy.store, &launch));
                client_prepare(&mut client);
                client_credentials(&mut client);
                let cancel = token.recv_timeout(Duration::from_secs(3)).unwrap();
                at_install.recv_timeout(Duration::from_secs(3)).unwrap();
                if eof {
                    client.shutdown(std::net::Shutdown::Both).unwrap();
                } else {
                    client.write_all(b"{\"op\":\"stop\"}\n").unwrap();
                }
                let deadline = Instant::now() + Duration::from_secs(3);
                while !cancel.is_cancelled() {
                    assert!(
                        Instant::now() < deadline,
                        "public cancel was not observed during the install preflight"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                resume.send(()).unwrap();
                if !eof {
                    assert!(matches!(
                        response(&client),
                        Response::Status {
                            state: State::Stopped
                        }
                    ));
                }
                drop(client);
                worker.join().unwrap().ok();
            });
            assert!(process.0.wait().unwrap().success());
            assert!(harness.root.join("instance-stopped").is_file());
            assert!(harness.leases().is_empty());
            assert_no_install(&kernel.lock().unwrap());
        }

        #[test]
        fn public_stop_after_established_prevents_network_install() {
            exercise_cancel_before_install(
                "public_stop_after_established_prevents_network_install",
                false,
            );
        }

        #[test]
        fn public_eof_after_established_prevents_network_install() {
            exercise_cancel_before_install(
                "public_eof_after_established_prevents_network_install",
                true,
            );
        }

        fn assert_no_install(kernel: &Kernel) {
            assert!(!kernel.link && !kernel.address && kernel.routes.is_empty());
            assert!(
                !kernel
                    .ops
                    .iter()
                    .any(|operation| operation.starts_with("link add ")),
                "{:?}",
                kernel.ops
            );
        }

        #[test]
        fn public_stop_cancels_negotiation() {
            exercise_cancel_negotiation("public_stop_cancels_negotiation", false);
        }

        #[test]
        fn public_eof_cancels_negotiation() {
            exercise_cancel_negotiation("public_eof_cancels_negotiation", true);
        }

        #[test]
        fn negotiated_selector_outside_policy_is_rejected_and_cleaned() {
            let name = "negotiated_selector_outside_policy_is_rejected_and_cleaned";
            if !namespaced_in(name, "tests::xfrm_tests") {
                return;
            }
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            harness.flag("outside-selector", true);
            let mut process = supervisor(&harness);
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| serve_fixture(stream, &policy.store, &launcher));
                client_prepare(&mut client);
                client_credentials(&mut client);
                assert!(matches!(
                    response(&client),
                    Response::Error {
                        code: ErrorCode::Backend
                    }
                ));
                worker.join().unwrap().unwrap();
            });
            assert!(process.0.wait().unwrap().success());
            assert!(harness.root.join("instance-stopped").is_file());
            assert!(harness.leases().is_empty());
            assert_no_install(&kernel.lock().unwrap());
        }

        #[test]
        fn policy_routes_reach_network_ready_and_stop() {
            exercise("policy_routes_reach_network_ready_and_stop", false, false);
        }

        #[test]
        fn cleanup_pending_until_absence_is_proven() {
            exercise("cleanup_pending_until_absence_is_proven", false, true);
        }

        #[test]
        fn instance_death_cleans_while_client_is_idle() {
            exercise("instance_death_cleans_while_client_is_idle", true, false);
        }

        #[test]
        fn instance_death_preserves_lease_when_cleanup_is_unproven() {
            exercise(
                "instance_death_preserves_lease_when_cleanup_is_unproven",
                true,
                true,
            );
        }

        #[test]
        fn oversized_ipsec_grant_on_disk_is_refused_before_backend_setup() {
            use crate::tunneld::{admin::IPSEC_SNAPSHOT, policy::canonical_snapshot};

            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            let mut snapshot: serde_json::Value = serde_json::from_slice(IPSEC_SNAPSHOT).unwrap();
            let mut routes: Vec<_> = (0..64).map(|i| format!("10.25.0.{i}/32")).collect();
            routes.push("10.20.0.0/15".into());
            snapshot["entries"][0]["route_cidrs"] = serde_json::json!(routes);
            let bytes = canonical_snapshot(snapshot.to_string().as_bytes()).unwrap();
            fs::write(policy.path(), &bytes).unwrap();

            let mut launcher = harness.launcher(false);
            launcher.xfrm =
                Network::fake(|_, args| panic!("oversized grant reached backend setup: {args:?}"));
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| serve_fixture(stream, &policy.store, &launcher));
                client_prepare(&mut client);
                client_credentials(&mut client);
                assert!(matches!(
                    response(&client),
                    Response::Error {
                        code: ErrorCode::PermissionDenied
                    }
                ));
                worker.join().unwrap().unwrap();
            });
            harness.assert_no_effect(&[]);
            assert_eq!(fs::read(policy.path()).unwrap(), bytes);
        }

        #[test]
        fn revocation_before_commit_prevents_lease_and_unit_request() {
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            let mut launcher = harness.launcher(false);
            launcher.xfrm =
                Network::fake(|_, args| panic!("network operation after revoke: {args:?}"));
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| serve_fixture(stream, &policy.store, &launcher));
                client_prepare(&mut client);
                policy.revoke();
                client_credentials(&mut client);
                let reply = response(&client);
                assert!(
                    matches!(
                        reply,
                        Response::Error {
                            code: ErrorCode::PermissionDenied
                        }
                    ),
                    "{reply:?}"
                );
                drop(client);
                assert!(worker.join().unwrap().is_ok());
            });
            harness.assert_no_effect(&[]);
        }

        #[test]
        fn policy_lock_orders_revocation_after_unit_request() {
            if !namespaced_in(
                "policy_lock_orders_revocation_after_unit_request",
                "tests::xfrm_tests",
            ) {
                return;
            }
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            let script = format!(
                r#"#!/bin/sh
if [ "$1" = start ]; then
  : > '{root}/start-entered'
  while [ ! -f '{root}/allow-start' ]; do /usr/bin/sleep 0.01; done
fi
printf '%s\n' "$*" >> '{log}'
"#,
                root = harness.root.display(),
                log = harness.log.display(),
            );
            fs::write(harness.root.join("systemctl"), script).unwrap();
            fs::write(harness.root.join("pause-before-established"), b"").unwrap();

            let mut process = supervisor(&harness);
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel);
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| serve_fixture(stream, &policy.store, &launcher));
                client_prepare(&mut client);
                client_credentials(&mut client);
                wait_for_file(&harness.root.join("start-entered"));
                assert_eq!(harness.leases().len(), 1);
                // Only the property call preceded the start the manager has not accepted.
                let log = harness.log();
                assert!(
                    log.len() == 1 && log[0].starts_with("set-property --runtime "),
                    "the fake manager has not accepted the request: {log:?}"
                );

                let contender = File::open(policy.lock_path()).unwrap();
                // SAFETY: the descriptor exclusively belongs to this contender.
                let locked =
                    unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                let lock_result = io::Error::last_os_error().kind();
                drop(contender);
                // Unblock the fixture even if the assertion below fails.
                fs::write(harness.root.join("allow-start"), b"").unwrap();
                assert_eq!(
                    locked, -1,
                    "revocation could commit before unit start was accepted"
                );
                assert_eq!(lock_result, io::ErrorKind::WouldBlock);
                wait_for_file(&harness.root.join("received-start"));
                policy.revoke();
                assert_eq!(harness.leases().len(), 1);
                fs::write(harness.root.join("allow-established"), b"").unwrap();
                command(&mut client, b"{\"op\":\"status\"}\n", State::NetworkReady);
                command(&mut client, b"{\"op\":\"stop\"}\n", State::Stopped);
                drop(client);
                assert!(worker.join().is_ok());
            });
            assert!(process.0.wait().unwrap().success());
            assert!(harness.leases().is_empty());
        }

        fn exercise_setup_deadline(name: &str, seconds: u64, expect_timeout: bool) {
            if !namespaced_in(name, "tests::xfrm_tests") {
                return;
            }
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            fs::write(harness.root.join("setup-delay"), seconds.to_string()).unwrap();
            if expect_timeout {
                harness.flag("expect-setup-timeout", true);
            }
            let mut process = supervisor(&harness);
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
            let cleanup = Store::open(&harness.runtime).unwrap();
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    if expect_timeout {
                        super::super::super::server::serve_cleanup_fixture(
                            stream,
                            1000,
                            &policy.store,
                            &launcher,
                            &cleanup,
                        )
                    } else {
                        serve_fixture(stream, &policy.store, &launcher)
                    }
                });
                let generation = if expect_timeout {
                    Some(v2_prepare(&mut client))
                } else {
                    client_prepare(&mut client);
                    None
                };
                let start = Instant::now();
                client_credentials(&mut client);
                let deadline = start + Duration::from_secs(45);
                let reply = loop {
                    client
                        .write_all(b"{\"op\":\"status\"}\n")
                        .or_else(|error| {
                            // The server may have already sent the typed rejection.
                            if expect_timeout && error.kind() == io::ErrorKind::BrokenPipe {
                                Ok(())
                            } else {
                                Err(error)
                            }
                        })
                        .unwrap();
                    let reply =
                        read_control(&mut timed(&client, deadline).unwrap(), decode_response)
                            .unwrap();
                    if expect_timeout
                        && matches!(
                            reply,
                            Response::Status {
                                state: State::Starting
                            }
                        )
                    {
                        thread::sleep(Duration::from_millis(100));
                    } else {
                        break reply;
                    }
                };
                if expect_timeout {
                    assert!(
                        matches!(
                            reply,
                            Response::Error {
                                code: ErrorCode::Timeout
                            }
                        ),
                        "{reply:?}"
                    );
                    assert!(
                        start.elapsed() >= Duration::from_secs(35),
                        "setup timed out at {:?}",
                        start.elapsed()
                    );
                    assert!(harness.leases().is_empty(), "timeout retained lease");
                    assert!(
                        harness
                            .log()
                            .iter()
                            .any(|entry| entry.starts_with("stop -- "))
                    );
                    assert!(!kernel.lock().unwrap().link);
                    assert_eq!(
                        v2_query(
                            1000,
                            &policy,
                            &launcher,
                            &cleanup,
                            generation.as_ref().unwrap()
                        ),
                        protocol::CleanupState::Stopped
                    );
                } else {
                    assert!(
                        matches!(
                            reply,
                            Response::Status {
                                state: State::NetworkReady
                            }
                        ),
                        "{reply:?}"
                    );
                    assert!(start.elapsed() >= Duration::from_secs(seconds));
                    command(&mut client, b"{\"op\":\"stop\"}\n", State::Stopped);
                }
                drop(client);
                assert!(worker.join().is_ok());
            });
            assert!(process.0.wait().unwrap().success());
        }

        #[test]
        fn ten_second_negotiation_reaches_network_ready() {
            exercise_setup_deadline("ten_second_negotiation_reaches_network_ready", 10, false);
        }

        #[test]
        fn negotiation_past_thirty_five_seconds_times_out_and_cleans() {
            exercise_setup_deadline(
                "negotiation_past_thirty_five_seconds_times_out_and_cleans",
                38,
                true,
            );
        }

        #[test]
        fn internal_channel_eof_cleans_while_client_and_supervisor_live() {
            if !namespaced_in(
                "internal_channel_eof_cleans_while_client_and_supervisor_live",
                "tests::xfrm_tests",
            ) {
                return;
            }
            let harness = Harness::new();
            let policy = PolicyFixture::new();
            policy.install();
            harness.flag("close-channel-after-setup", true);
            let mut process = supervisor(&harness);
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            let mut launcher = harness.launcher(false);
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
            let (mut client, stream) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let worker = scope.spawn(|| serve_fixture(stream, &policy.store, &launcher));
                client_prepare(&mut client);
                client_credentials(&mut client);
                command(&mut client, b"{\"op\":\"status\"}\n", State::NetworkReady);
                harness.flag("close-now", true);
                wait_for_file(&harness.root.join("channel-closed"));
                let limit = Instant::now() + Duration::from_secs(5);
                while !harness.leases().is_empty() {
                    assert!(
                        process.0.try_wait().unwrap().is_none(),
                        "supervisor exited before EOF cleanup"
                    );
                    assert!(
                        Instant::now() < limit,
                        "internal EOF retained the lease with both peers alive"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                assert!(process.0.try_wait().unwrap().is_none());
                assert!(!kernel.lock().unwrap().link);
                command(&mut client, b"{\"op\":\"status\"}\n", State::Stopped);
                harness.flag("exit-now", true);
                drop(client);
                assert!(worker.join().is_ok());
            });
            assert!(process.0.wait().unwrap().success());
        }

        #[test]
        fn orphan_is_reconciled_before_admission() {
            let harness = Harness::new();
            let mut launcher = harness.launcher(false);
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            launcher.xfrm = fake_network(harness.runtime.clone(), kernel.clone());
            let generation = generation().unwrap();
            let directory = launcher.create_directory(&generation).unwrap();
            {
                let guard = NetworkLock::acquire_test(
                    &harness.runtime,
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap();
                let remote = Ipv4Addr::new(192, 0, 2, 20);
                let routes = ["10.20.0.0/15", "172.16.0.0/12"]
                    .into_iter()
                    .map(parse_cidr)
                    .collect::<io::Result<_>>()
                    .unwrap();
                let mut receipt = launcher
                    .xfrm
                    .plan(&guard, &generation, remote, &[remote], routes)
                    .unwrap();
                receipt.save(&directory, &guard).unwrap();
                guard.register(&generation).unwrap();
                launcher
                    .xfrm
                    .install(
                        &guard,
                        &directory,
                        &mut receipt,
                        Ipv4Addr::new(10, 99, 0, 2),
                        &[remote],
                    )
                    .unwrap();
            }
            assert_eq!(harness.leases(), [generation.as_str()]);
            launcher.recover().unwrap();
            assert!(harness.leases().is_empty());
            assert!(!kernel.lock().unwrap().link);
            // The dead writer may have left the runtime drop-in: recovery reverts it
            // after the stop.
            assert_eq!(
                harness.log(),
                [
                    format!("stop -- vpnt-tunneld-ipsec@{generation}.service"),
                    format!("revert -- vpnt-tunneld-ipsec@{generation}.service")
                ]
            );
            launcher.recover().unwrap();
            assert_eq!(harness.log().len(), 2);
        }
    }
}
