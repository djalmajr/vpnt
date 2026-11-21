use super::*;
use crate::{
    connection::ovpn::{session::SignError, signing::Padding},
    storage::ProfileStore,
};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        use std::sync::atomic::AtomicUsize;
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::current_dir().unwrap().join(format!(
            "vpnt-native-ovpn-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn profile() -> Profile {
    serde_json::from_value(serde_json::json!({
        "id": "ovpn", "name": "OVPN", "kind": "ovpn", "gateway": "vpn.example.test",
        "username": "", "networks": [], "port": 1194, "certificate": "",
        "probeHost": "10.0.0.42", "probePort": 443, "probeMethod": "tcp",
        "ovpn": {"module": "/example/libtoken.dylib", "certificateId": "00"}
    }))
    .unwrap()
}

struct FixtureSigner;
impl Signer for FixtureSigner {
    fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
        Err(SignError::Unavailable)
    }

    fn sign(&mut self, _: Padding, _: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError::Unavailable)
    }
}

#[derive(Default)]
struct Signers(Mutex<Vec<(String, u64)>>);
impl OvpnSigners for Signers {
    fn signer(&self, profile: &str, generation: u64) -> Box<dyn Signer> {
        self.0.lock().unwrap().push((profile.into(), generation));
        Box::new(FixtureSigner)
    }
}

#[test]
fn factory_requests_one_signer_per_injected_attempt() {
    let root = Root::new();
    let uid = unsafe { libc::geteuid() };
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.0.join(".controller.lock"))
        .unwrap();
    let controller = ControllerLock::fixture(&root.0, uid).unwrap();
    let routes = Arc::new(Mutex::new(
        Coordinator::new(NativeBackend::fixture(&controller).unwrap()).unwrap(),
    ));
    let open = || ProfileStore::open(&root.0, uid).unwrap();
    let store = open();
    store.save(profile()).unwrap();
    let profile_text = concat!(
        "client\r\ndev tun\r\nremote vpn.example.test 1194\r\n",
        "persist-tun\r\n \t--persist-tun # comment\r\n",
        "persist-key\r\n# persist-tun stays in comments\r\n",
        "<ca>\r\n  persist-tun\r\n</ca>\r\n",
    );
    let expected_text = concat!(
        "client\ndev tun\nremote vpn.example.test 1194\n",
        "persist-key\n# persist-tun stays in comments\n",
        "<ca>\n  persist-tun\n</ca>\n",
    );
    store.save_ovpn_config("ovpn", profile_text).unwrap();
    let factory = NativeFactory::new(routes, Arc::new(Profiles::fixture(store)), None, uid);
    fn create<'a>(
        factory: &NativeFactory<'a>,
        uid: u32,
        generation: u64,
    ) -> super::super::factory::AttemptKind<'a> {
        let credentials =
            serde_json::from_value(serde_json::json!({"password": "", "psk": ""})).unwrap();
        factory.create(
            profile(),
            uid,
            generation,
            credentials,
            Arc::new(AtomicBool::new(false)),
        )
    }
    assert!(!factory.supports(VpnKind::Ovpn));
    let mut denied = create(&factory, uid, 1);
    assert!(matches!(
        denied,
        super::super::factory::AttemptKind::Denied(_)
    ));
    let failure = denied
        .start(
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
    assert_eq!(
        (failure.state, failure.error, failure.step),
        (
            ConnectionState::MissingProgram,
            ErrorCode::MissingProgram,
            Step::Runtime
        )
    );
    let signers = Arc::new(Signers::default());
    let factory = factory
        .with_ovpn_signers(signers.clone())
        .fixture_fence_root(root.0.clone(), uid);
    assert!(factory.supports(VpnKind::Ovpn));
    let super::super::factory::AttemptKind::Ovpn(mut attempt) = create(&factory, uid, 2) else {
        panic!("injected OVPN was denied");
    };
    assert_eq!(attempt.cycle.network.journal.root, root.0);
    assert_eq!(attempt.cycle.network.journal.owner, uid);
    assert!(
        attempt
            .read_config()
            .is_err_and(|failure| failure.step == Step::Profile)
    );
    attempt.profile_use = Some(attempt.profiles.begin(&attempt.profile, 2).unwrap());
    let (config, signatures) = attempt.read_config().unwrap();
    let ConfigSource::Private(bytes) = config else {
        panic!("config was not private")
    };
    assert!(
        bytes == expected_text.as_bytes(),
        "unexpected private launch configuration"
    );
    assert_eq!(signatures, Signatures::Pkcs1Only);
    attempt.profile_use.take().unwrap().complete().unwrap();
    open().save_ovpn_config("ovpn", "up /path").unwrap();
    attempt.profile_use = Some(attempt.profiles.begin(&attempt.profile, 2).unwrap());
    assert!(
        attempt
            .read_config()
            .is_err_and(|failure| failure.step == Step::Profile)
    );
    attempt.profile_use.take().unwrap().complete().unwrap();
    create(&factory, uid, 3);
    assert_eq!(
        *signers.0.lock().unwrap(),
        [("ovpn".into(), 2), ("ovpn".into(), 3)]
    );
}

const LAUNCH_CONFIG: &str = concat!(
    "client\ndev tun\nremote vpn.example.test 1194\n",
    "<ca>\nexample\n</ca>\npersist-tun\n",
);

fn with_launch_fixture(text: &str, run: impl FnOnce(&mut NativeOvpnAttempt<'_>, &ProfileStore)) {
    let root = Root::new();
    // SAFETY: UID query has no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.0.join(".controller.lock"))
        .unwrap();
    let controller = ControllerLock::fixture(&root.0, uid).unwrap();
    let routes = Arc::new(Mutex::new(
        Coordinator::new(NativeBackend::fixture(&controller).unwrap()).unwrap(),
    ));
    let store = ProfileStore::open(&root.0, uid).unwrap();
    let profile = profile();
    store.save(profile.clone()).unwrap();
    store.save_ovpn_config(&profile.id, text).unwrap();
    let profiles = Arc::new(Profiles::fixture(ProfileStore::open(&root.0, uid).unwrap()));
    let owner = Owner {
        uid,
        profile: profile.id.clone(),
        generation: 1,
    };
    let mut attempt = NativeOvpnAttempt::new(
        profile,
        profiles,
        Box::new(FixtureSigner),
        owner,
        routes,
        Arc::new(AtomicBool::new(false)),
        (root.0.clone(), uid),
    );
    run(&mut attempt, &store);
    assert!(attempt.cleanup());
}

#[test]
fn start_rejects_user_group_and_chroot_before_launch() {
    for directive in ["user nobody", "group nobody", "chroot /tmp"] {
        with_launch_fixture(&format!("{LAUNCH_CONFIG}{directive}\n"), |attempt, _| {
            let mut launched = false;
            let result = attempt.start_using(
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(5),
                |_, _, _| {
                    launched = true;
                    Ok(())
                },
            );
            assert!(!launched, "{directive} reached launch");
            let failure = result.expect_err("privilege directive must fail admission");
            assert_eq!(
                (failure.state, failure.error, failure.step),
                (
                    ConnectionState::Dropped,
                    ErrorCode::UntrustedConfiguration,
                    Step::Profile
                ),
                "{directive}"
            );
        });
    }
}

#[test]
fn start_strips_persist_tun_from_launch_copy_and_preserves_stored_bytes() {
    with_launch_fixture(LAUNCH_CONFIG, |attempt, store| {
        let mut launched = false;
        attempt
            .start_using(
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(5),
                |_, config, _| {
                    let ConfigSource::Private(bytes) = config else {
                        panic!("launch config was not private");
                    };
                    assert_eq!(
                        bytes,
                        LAUNCH_CONFIG
                            .strip_suffix("persist-tun\n")
                            .unwrap()
                            .as_bytes()
                    );
                    launched = true;
                    Ok(())
                },
            )
            .unwrap();
        assert!(launched);
        assert_eq!(
            store.read_ovpn_config("ovpn").unwrap().as_deref(),
            Some(LAUNCH_CONFIG.as_bytes())
        );
    });
}

use crate::connection::{
    macos::vip::ovpn_link::fixture_interfaces,
    ovpn::management::{Phase, State},
};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};

#[derive(Clone, Debug, Eq, PartialEq)]
enum Effect {
    Address(u32, Ipv4Addr, u8),
    Mtu(u32, u16),
    Routes(u32, usize),
    Dns(ServiceId, Vec<Ipv4Addr>, Vec<String>),
    CloseDns,
    JournalCleanup,
    JournalWithdrawn,
    Withdraw,
    WaitForWithdrawal,
    Release(u64),
    Stop,
    Reap,
    ForceStop,
    Finish,
    Probe(u32),
}

type Effects = Rc<RefCell<Vec<Effect>>>;

#[derive(Default)]
struct FakeTunnel {
    effects: Effects,
    events: VecDeque<Progress>,
    on_up: Option<Box<dyn FnOnce()>>,
    pending: bool,
    hold_expired: bool,
    exit: Rc<Cell<Option<Option<OvpnReason>>>>,
    absent: bool,
    stop_error: Option<io::ErrorKind>,
}
impl Tunnel for FakeTunnel {
    fn next(&mut self) -> Option<Progress> {
        let event = self.events.pop_front();
        if matches!(event, Some(Progress::Up(_)))
            && let Some(action) = self.on_up.take()
        {
            action();
        }
        event
    }

    fn approval_pending(&self) -> bool {
        self.pending
    }

    fn exited(&self) -> Option<Option<OvpnReason>> {
        self.exit.get()
    }

    fn restart_hold_expired(&self) -> bool {
        self.hold_expired
    }

    fn release_restart_hold(&mut self, epoch: u64) {
        self.effects.borrow_mut().push(Effect::Release(epoch));
    }

    fn has_session(&self) -> bool {
        true
    }

    fn stop(&mut self) -> io::Result<()> {
        self.effects.borrow_mut().push(Effect::Stop);
        self.stop_error.map_or(Ok(()), |kind| Err(kind.into()))
    }

    fn reap(&mut self) {
        self.effects.borrow_mut().push(Effect::Reap);
    }

    fn force_stop(&mut self) {
        self.effects.borrow_mut().push(Effect::ForceStop);
    }

    fn confirm_absent(&self) -> bool {
        self.absent
    }
}

struct FakeNetwork {
    effects: Effects,
    current: Interfaces,
    now: Instant,
    following_snapshots: VecDeque<Interfaces>,
    snapshot_errors: usize,
    on_wait: Option<Box<dyn FnOnce()>>,
    on_withdraw: Option<Box<dyn FnOnce()>>,
    canceled: Rc<AtomicBool>,
    pending_withdrawals: usize,
    fail: Option<Effect>,
}
impl FakeNetwork {
    fn record(&self, effect: Effect, step: Step) -> Result<(), Failure> {
        let fail = self.fail.as_ref() == Some(&effect);
        self.effects.borrow_mut().push(effect);
        if fail { Err(Failure::at(step)) } else { Ok(()) }
    }
}
impl Network for FakeNetwork {
    fn canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    fn interfaces(&mut self) -> std::io::Result<Interfaces> {
        if self.snapshot_errors > 0 {
            self.snapshot_errors -= 1;
            return Err(std::io::ErrorKind::NotFound.into());
        }
        Ok(self.current.clone())
    }

    fn address(
        &mut self,
        link: &OvpnUtun,
        config: &NetworkConfig,
        _: Instant,
    ) -> Result<(), Failure> {
        self.record(
            Effect::Address(link.index(), config.address, config.prefix),
            Step::Routes,
        )
    }

    fn mtu(&mut self, link: &OvpnUtun, mtu: u16, _: Instant) -> Result<(), Failure> {
        self.record(Effect::Mtu(link.index(), mtu), Step::Routes)
    }

    fn routes(
        &mut self,
        link: &OvpnUtun,
        config: &NetworkConfig,
        _: Instant,
    ) -> Result<(), Failure> {
        self.record(
            Effect::Routes(link.index(), config.routes.len()),
            Step::Routes,
        )
    }

    fn publish_dns(
        &mut self,
        service: &ServiceId,
        servers: &[Ipv4Addr],
        domains: &[String],
    ) -> Result<(), Failure> {
        self.record(
            Effect::Dns(service.clone(), servers.to_vec(), domains.to_vec()),
            Step::Dns,
        )
    }

    fn close_dns(&mut self) -> Result<(), Failure> {
        self.record(Effect::CloseDns, Step::Dns)
    }

    fn withdraw_routes(&mut self) -> Result<bool, Failure> {
        self.record(Effect::Withdraw, Step::Routes)?;
        if let Some(action) = self.on_withdraw.take() {
            action();
        }
        if self.pending_withdrawals > 0 {
            self.pending_withdrawals -= 1;
            return Ok(false);
        }
        Ok(true)
    }

    fn journal_cleanup(&mut self) -> Result<(), Failure> {
        if self.fail == Some(Effect::JournalCleanup) {
            return Err(Failure::at(Step::Routes));
        }
        Ok(())
    }

    fn journal_withdrawn(&mut self) -> Result<(), Failure> {
        if self.fail == Some(Effect::JournalWithdrawn) {
            return Err(Failure::at(Step::Routes));
        }
        Ok(())
    }

    fn now(&self) -> Instant {
        self.now
    }

    fn pause(&mut self, expires: Instant) {
        self.effects.borrow_mut().push(Effect::WaitForWithdrawal);
        self.now = (self.now + Duration::from_secs(1)).min(expires);
        if let Some(next) = self.following_snapshots.pop_front() {
            self.current = next;
        }
        if let Some(action) = self.on_wait.take() {
            action();
        }
    }

    fn finish(&mut self) -> Result<(), Failure> {
        self.record(Effect::Finish, Step::Routes)
    }

    fn validate_routes(&mut self) -> Result<(), Failure> {
        Ok(())
    }

    fn probe(
        &mut self,
        link: &OvpnUtun,
        _: Ipv4Addr,
        _: &Profile,
        _: &AtomicBool,
        _: Duration,
    ) -> Result<bool, Failure> {
        self.record(Effect::Probe(link.index()), Step::Health)?;
        Ok(true)
    }
}

fn fixture() -> Cycle<FakeTunnel, FakeNetwork> {
    let session = FakeTunnel::default();
    let network = FakeNetwork {
        effects: session.effects.clone(),
        current: fixture_interfaces(&[("utun40", 40), ("en0", 2), ("utun7", 7)]),
        now: Instant::now(),
        following_snapshots: VecDeque::new(),
        snapshot_errors: 0,
        on_wait: None,
        on_withdraw: None,
        canceled: Rc::new(AtomicBool::new(false)),
        pending_withdrawals: 0,
        fail: None,
    };
    let mut cycle = Cycle::new(session, network);
    cycle.before = fixture_interfaces(&[("utun7", 3)]);
    cycle
}

fn up(device: Option<&str>) -> NetworkConfig {
    NetworkConfig {
        address: "10.90.0.8".parse().unwrap(),
        prefix: 24,
        mtu: None,
        routes: vec![crate::connection::ovpn::network::Route {
            network: "10.80.0.0".parse().unwrap(),
            prefix: 16,
        }],
        dns_servers: vec!["10.90.0.53".parse().unwrap()],
        dns_domains: vec!["pushed.example.test".into()],
        server: None,
        device: device.map(str::to_owned),
    }
}

fn restart(epoch: u64, reason: Option<OvpnReason>) -> Progress {
    Progress::Restarting {
        epoch,
        state: State {
            phase: Phase::Reconnecting,
            reason,
            tunnel_ipv4: None,
        },
    }
}

impl Cycle<FakeTunnel, FakeNetwork> {
    fn push(&mut self, event: Progress) {
        self.session.events.push_back(event);
    }

    fn open(&mut self) {
        self.push(Progress::Up(up(Some("utun40"))));
        assert!(self.ready(&profile()).unwrap());
    }

    fn take_effects(&self) -> Vec<Effect> {
        self.session.effects.take()
    }
}

#[test]
fn up_binds_the_address_mtu_routes_and_profile_dns_in_order() {
    let mut cycle = fixture();
    let mut profile = profile();
    profile.dns_domains = vec!["local.example.test".into()];
    let mut config = up(Some("utun40"));
    config.mtu = Some(1420);
    cycle.push(Progress::Up(config.clone()));
    assert!(cycle.ready(&profile).unwrap());
    let effects = cycle.take_effects();
    assert_eq!(
        &effects[..3],
        &[
            Effect::Address(40, config.address, 24),
            Effect::Mtu(40, 1420),
            Effect::Routes(40, 1),
        ]
    );
    assert!(matches!(&effects[3..], [Effect::Dns(_, servers, domains)]
        if servers == &config.dns_servers && domains == &profile.dns_domains));
}

#[test]
fn up_without_a_device_is_rejected_before_network_effects() {
    let mut cycle = fixture();
    cycle.push(Progress::Up(up(None)));
    assert_eq!(cycle.ready(&profile()).unwrap_err().step, Step::Tunnel);
    assert!(cycle.take_effects().is_empty());
}

#[test]
fn up_cannot_claim_a_name_seen_before_spawn_even_at_a_new_index() {
    let mut cycle = fixture();
    cycle.push(Progress::Up(up(Some("utun7"))));
    assert_eq!(cycle.ready(&profile()).unwrap_err().step, Step::Tunnel);
    assert!(cycle.take_effects().is_empty());
}

#[test]
fn up_cannot_claim_a_non_utun_that_appeared_after_spawn() {
    let mut cycle = fixture();
    cycle.push(Progress::Up(up(Some("en0"))));
    assert_eq!(cycle.ready(&profile()).unwrap_err().step, Step::Tunnel);
    assert!(cycle.take_effects().is_empty());
}

#[test]
fn up_rejects_absent_link_and_health_rejects_changed_index() {
    let mut absent = fixture();
    absent.push(Progress::Up(up(Some("utun99"))));
    assert_eq!(absent.ready(&profile()).unwrap_err().step, Step::Tunnel);
    assert!(absent.take_effects().is_empty());

    let mut cycle = fixture();
    cycle.open();
    cycle.network.current = fixture_interfaces(&[("utun40", 41)]);
    cycle.poll(&profile()).unwrap();
    assert_eq!(cycle.validate_network().unwrap_err().step, Step::Health);
}

#[test]
fn failed_address_or_mtu_never_promotes_ready_or_reaches_routes() {
    let config = up(Some("utun40"));
    for failure in [
        Effect::Address(40, config.address, 24),
        Effect::Mtu(40, 1500),
    ] {
        let mut cycle = fixture();
        cycle.network.fail = Some(failure.clone());
        cycle.push(Progress::Up(config.clone()));
        assert_eq!(cycle.ready(&profile()).unwrap_err().step, Step::Routes);
        assert!(!cycle.network_active);
        assert_eq!(cycle.take_effects().last(), Some(&failure));
    }
}

#[test]
fn dns_requires_nonempty_servers_and_domains() {
    for no_server in [false, true] {
        let mut cycle = fixture();
        let mut config = up(Some("utun40"));
        if no_server {
            config.dns_servers.clear();
        } else {
            config.dns_domains.clear();
        }
        cycle.push(Progress::Up(config));
        assert!(cycle.ready(&profile()).unwrap());
        assert_eq!(cycle.take_effects().len(), 3);
    }
}

#[test]
fn dns_uses_distinct_service_ids_across_attempts_and_pushed_domains() {
    let dns = |cycle: &mut Cycle<FakeTunnel, FakeNetwork>| {
        cycle.open();
        match cycle.take_effects().pop() {
            Some(Effect::Dns(service, servers, domains)) => {
                assert_eq!(servers, up(None).dns_servers);
                assert_eq!(domains, ["pushed.example.test"]);
                service
            }
            _ => panic!("missing DNS publication"),
        }
    };
    assert_ne!(dns(&mut fixture()), dns(&mut fixture()));
}

#[test]
fn restart_releases_its_hold_only_after_routes_and_dns_are_withdrawn() {
    let mut cycle = fixture();
    cycle.open();
    cycle.take_effects();
    cycle.network.current = Interfaces::default();
    cycle.push(restart(8, None));
    assert!(!cycle.ready(&profile()).unwrap());
    assert_eq!(cycle.phase(), Some(ConnectionState::Reconnecting));
    assert_eq!(cycle.restart_epoch, 8);
    assert_eq!(
        cycle.take_effects(),
        [Effect::CloseDns, Effect::Withdraw, Effect::Release(8)]
    );

    for (effect, step, expected) in [
        (Effect::CloseDns, Step::Dns, vec![Effect::CloseDns]),
        (
            Effect::Withdraw,
            Step::Routes,
            vec![Effect::CloseDns, Effect::Withdraw],
        ),
    ] {
        let mut cycle = fixture();
        cycle.open();
        cycle.take_effects();
        cycle.network.fail = Some(effect);
        cycle.network.current = Interfaces::default();
        cycle.push(restart(8, None));
        assert_eq!(cycle.ready(&profile()).unwrap_err().step, step);
        assert_eq!(cycle.take_effects(), expected);
    }
}

#[test]
fn restart_waits_for_absent_name_index_and_backend_before_releasing_hold() {
    let mut cycle = fixture();
    cycle.open();
    cycle.take_effects();
    cycle.network.following_snapshots.extend([
        fixture_interfaces(&[("utun40", 41)]),
        fixture_interfaces(&[("utun41", 40)]),
        Interfaces::default(),
    ]);
    cycle.network.pending_withdrawals = 1;
    cycle.push(Progress::Down);
    cycle.push(restart(11, None));
    assert!(!cycle.ready(&profile()).unwrap());
    assert_eq!(
        cycle.take_effects(),
        [
            Effect::CloseDns,
            Effect::WaitForWithdrawal,
            Effect::WaitForWithdrawal,
            Effect::WaitForWithdrawal,
            Effect::Withdraw,
            Effect::WaitForWithdrawal,
            Effect::Withdraw,
            Effect::Release(11),
        ]
    );
}

#[test]
fn restart_timeout_keeps_hold_closed_and_cleanup_stops_the_session() {
    for utun_persists in [true, false] {
        let mut cycle = fixture();
        cycle.open();
        cycle.take_effects();
        let started = cycle.network.now;
        if !utun_persists {
            cycle.network.current = Interfaces::default();
            cycle.network.pending_withdrawals = usize::MAX;
        }
        cycle.push(restart(11, None));
        assert_eq!(cycle.ready(&profile()).unwrap_err().step, Step::Routes);
        assert_eq!(cycle.network.now - started, Duration::from_secs(5));
        let effects = cycle.take_effects();
        assert_eq!(effects.first(), Some(&Effect::CloseDns));
        assert!(
            !effects
                .iter()
                .any(|event| matches!(event, Effect::Release(_)))
        );
        assert_eq!(
            effects
                .iter()
                .filter(|&event| *event == Effect::Withdraw)
                .count(),
            if utun_persists { 0 } else { 5 }
        );

        cycle.session.exit.set(Some(None));
        cycle.session.absent = true;
        assert!(cycle.cleanup());
        assert_eq!(
            cycle.take_effects(),
            [Effect::CloseDns, Effect::Stop, Effect::Reap, Effect::Finish]
        );
    }
}

#[test]
fn withdrawal_rechecks_cancellation_and_exit_after_waiting() {
    for exit in [false, true] {
        let mut cycle = fixture();
        cycle.open();
        cycle.take_effects();
        cycle
            .network
            .following_snapshots
            .push_back(Interfaces::default());
        let canceled = cycle.network.canceled.clone();
        let observed = cycle.session.exit.clone();
        cycle.network.on_wait = Some(Box::new(move || {
            if exit {
                observed.set(Some(None));
            } else {
                canceled.store(true, Ordering::Release);
            }
        }));
        cycle.push(restart(15, None));
        cycle.push(Progress::Up(up(Some("utun40"))));
        let result = cycle.ready(&profile());
        if exit {
            assert_eq!(result.unwrap_err().step, Step::Tunnel);
        } else {
            assert!(!result.unwrap());
        }
        assert_eq!(
            cycle.take_effects(),
            [Effect::CloseDns, Effect::WaitForWithdrawal]
        );
    }
}

#[test]
fn restart_rechecks_cancellation_and_exit_after_routes_are_absent() {
    for exit in [false, true] {
        let mut cycle = fixture();
        cycle.open();
        cycle.take_effects();
        cycle.network.current = Interfaces::default();
        let canceled = cycle.network.canceled.clone();
        let observed = cycle.session.exit.clone();
        cycle.network.on_withdraw = Some(Box::new(move || {
            if exit {
                observed.set(Some(None));
            } else {
                canceled.store(true, Ordering::Release);
            }
        }));
        cycle.push(restart(15, None));
        let result = cycle.ready(&profile());
        if exit {
            assert_eq!(result.unwrap_err().step, Step::Tunnel);
        } else {
            assert!(!result.unwrap());
        }
        assert_eq!(cycle.take_effects(), [Effect::CloseDns, Effect::Withdraw]);
    }
}

#[test]
fn pending_up_rechecks_cancellation_and_exit_before_network_effects() {
    for exit in [false, true] {
        let mut cycle = fixture();
        let canceled = cycle.network.canceled.clone();
        let observed = cycle.session.exit.clone();
        cycle.session.on_up = Some(Box::new(move || {
            if exit {
                observed.set(Some(None));
            } else {
                canceled.store(true, Ordering::Release);
            }
        }));
        cycle.push(Progress::Up(up(Some("utun40"))));
        let result = cycle.ready(&profile());
        if exit {
            assert_eq!(result.unwrap_err().step, Step::Tunnel);
        } else {
            assert!(!result.unwrap());
        }
        assert!(cycle.take_effects().is_empty());
    }
}

#[test]
fn withdrawal_retries_an_incomplete_interface_snapshot_within_its_budget() {
    for (errors, completed) in [(1, true), (10, false)] {
        let mut cycle = fixture();
        cycle.open();
        cycle.take_effects();
        cycle.network.current = Interfaces::default();
        cycle.network.snapshot_errors = errors;
        let started = cycle.network.now;
        cycle.push(restart(15, None));
        let result = cycle.ready(&profile());
        let effects = cycle.take_effects();
        if completed {
            assert!(!result.unwrap());
            assert_eq!(
                effects,
                [
                    Effect::CloseDns,
                    Effect::WaitForWithdrawal,
                    Effect::Withdraw,
                    Effect::Release(15)
                ]
            );
        } else {
            assert_eq!(result.unwrap_err().step, Step::Routes);
            assert_eq!(cycle.network.now - started, RESTART_WITHDRAWAL_TIMEOUT);
            assert!(
                effects[1..]
                    .iter()
                    .all(|effect| *effect == Effect::WaitForWithdrawal)
            );
        }
    }
}

#[test]
fn probes_do_not_touch_the_network_while_routes_are_withdrawn() {
    let mut cycle = fixture();
    cycle.open();
    let canceled = AtomicBool::new(false);
    let probe = |cycle: &mut Cycle<_, _>| {
        cycle
            .probe(&profile(), &canceled, Duration::from_secs(1))
            .unwrap()
    };
    assert!(probe(&mut cycle));
    assert_eq!(cycle.take_effects().last(), Some(&Effect::Probe(40)));
    cycle.push(Progress::Down);
    cycle.poll(&profile()).unwrap();
    assert!(!probe(&mut cycle));
    assert!(cycle.take_effects().is_empty());
    cycle.network.current = Interfaces::default();
    cycle.push(restart(2, None));
    cycle.poll(&profile()).unwrap();
    cycle.take_effects();
    assert!(!probe(&mut cycle));
    assert!(cycle.take_effects().is_empty());
}

#[test]
fn up_after_restart_reproves_and_reapplies_on_same_or_recreated_utun() {
    for index in [41, 40] {
        let mut cycle = fixture();
        cycle.open();
        cycle.take_effects();
        cycle.network.current = Interfaces::default();
        cycle.push(restart(9, None));
        cycle.poll(&profile()).unwrap();
        cycle.take_effects();
        cycle.network.current = fixture_interfaces(&[("utun40", index)]);
        let mut replacement = up(Some("utun40"));
        replacement.address = Ipv4Addr::new(10, 90, 0, 9);
        replacement.mtu = Some(1400);
        cycle.push(Progress::Up(replacement.clone()));
        assert!(
            matches!(cycle.ready(&profile()), Ok(true)),
            "UP on utun40 with index {index} must reprove and reapply the network"
        );
        assert_eq!(cycle.phase(), None);
        assert!(matches!(&cycle.take_effects()[..], [
            Effect::Address(found, address, 24), Effect::Mtu(mtu_index, mtu), Effect::Routes(route_index, 1), Effect::Dns(_, _, _)
        ] if *found == index && *address == replacement.address && *mtu_index == index
            && *mtu == replacement.mtu.unwrap_or(1500) && *route_index == index));
    }
}

#[test]
fn phase_and_tunnel_failures_preserve_approval_and_authentication() {
    let mut cycle = fixture();
    cycle.session.pending = true;
    assert_eq!(cycle.phase(), Some(ConnectionState::AwaitingApproval));
    cycle.session.pending = false;
    cycle.push(Progress::AwaitingApproval);
    assert!(!cycle.ready(&profile()).unwrap());
    assert_eq!(cycle.phase(), Some(ConnectionState::AwaitingApproval));

    for event in [
        Progress::Refused(SignError::Canceled),
        restart(8, Some(OvpnReason::AuthFailure)),
        Progress::State(State {
            phase: Phase::Exiting,
            reason: Some(OvpnReason::AuthFailure),
            tunnel_ipv4: None,
        }),
    ] {
        let mut cycle = fixture();
        cycle.push(event);
        let failure = cycle.ready(&profile()).unwrap_err();
        assert_eq!(
            (failure.state, failure.error, failure.step),
            (
                ConnectionState::CredentialsRejected,
                ErrorCode::InvalidSecret,
                Step::Tunnel
            )
        );
        assert!(cycle.take_effects().is_empty());
    }

    let mut cycle = fixture();
    cycle.push(Progress::Refused(SignError::Unavailable));
    let failure = cycle.ready(&profile()).unwrap_err();
    assert_eq!(
        (failure.state, failure.error, failure.step),
        (
            ConnectionState::Dropped,
            ErrorCode::BackendFailure,
            Step::Tunnel
        )
    );
    cycle.session.exit.set(Some(None));
    cycle.push(Progress::Up(up(Some("utun40"))));
    assert_eq!(cycle.ready(&profile()).unwrap_err().step, Step::Tunnel);
    assert!(cycle.take_effects().is_empty());
}

#[test]
fn cleanup_reaps_before_network_release_and_retries_without_second_stop() {
    let mut cycle = fixture();
    cycle.open();
    cycle.take_effects();
    cycle.session.exit.set(Some(None));
    assert!(!cycle.cleanup());
    assert_eq!(
        cycle.take_effects(),
        [Effect::CloseDns, Effect::Stop, Effect::Reap]
    );
    cycle.session.absent = true;
    cycle.network.fail = Some(Effect::Finish);
    assert!(!cycle.cleanup());
    assert_eq!(cycle.take_effects(), [Effect::CloseDns, Effect::Finish]);
    cycle.network.fail = None;
    assert!(cycle.cleanup());
    assert_eq!(cycle.take_effects(), [Effect::CloseDns, Effect::Finish]);
}

#[test]
fn restart_withdraws_resources_and_keeps_hold_closed_when_journal_write_fails() {
    for failure in [Effect::JournalCleanup, Effect::JournalWithdrawn] {
        let mut cycle = fixture();
        cycle.open();
        cycle.take_effects();
        cycle.network.current = Interfaces::default();
        cycle.network.fail = Some(failure);
        cycle.push(restart(8, None));
        assert_eq!(cycle.ready(&profile()).unwrap_err().step, Step::Routes);
        assert_eq!(cycle.take_effects(), [Effect::CloseDns, Effect::Withdraw]);

        cycle.session.exit.set(Some(None));
        cycle.session.absent = true;
        assert!(cycle.cleanup());
        assert_eq!(
            cycle.take_effects(),
            [Effect::CloseDns, Effect::Stop, Effect::Reap, Effect::Finish]
        );
    }
}

#[test]
fn cleanup_forces_a_live_child_within_the_stop_budget() {
    for stop_error in [Some(io::ErrorKind::TimedOut), None] {
        let mut cycle = fixture();
        cycle.session.stop_error = stop_error;
        cycle.session.absent = true;
        let started = cycle.network.now;
        assert!(cycle.cleanup());
        let effects = cycle.take_effects();
        assert_eq!(&effects[..2], &[Effect::CloseDns, Effect::Stop]);
        assert_eq!(
            &effects[effects.len() - 2..],
            &[Effect::ForceStop, Effect::Finish]
        );
        let expected_wait = if stop_error.is_some() {
            Duration::ZERO
        } else {
            STOP_WAIT
        };
        assert_eq!(cycle.network.now - started, expected_wait);
    }
}

#[test]
fn cleanup_uses_the_fallback_as_soon_as_stop_fails() {
    let mut cycle = fixture();
    cycle.session.stop_error = Some(io::ErrorKind::BrokenPipe);
    cycle.session.exit.set(Some(None));
    cycle.session.absent = true;

    assert!(cycle.cleanup());
    assert_eq!(
        cycle.take_effects(),
        [
            Effect::CloseDns,
            Effect::Stop,
            Effect::ForceStop,
            Effect::Finish
        ]
    );
}

#[test]
fn reap_receipt_confirms_absence_when_a_pid_is_reused_without_identity() {
    use std::os::unix::fs::PermissionsExt;

    let root = Root::new();
    let executable = root.0.join("openvpn");
    fs::write(
        &executable,
        r#"#!/usr/bin/python3
import socket, sys
if '--version' in sys.argv:
    print('OpenVPN 2.6.19')
    sys.exit(0)
with socket.socket(socket.AF_UNIX) as management:
    management.settimeout(5)
    management.connect(sys.argv[sys.argv.index('--management') + 1])
    with management.makefile('rb') as commands:
        for line in commands:
            if line == b'signal SIGTERM\n':
                break
"#,
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let session = Session::start_with(
        Launch {
            openvpn: executable,
            config: ConfigSource::private(b"dev tun\n"),
            dev: None,
            signatures: Signatures::Any,
            extra: vec![],
            env: vec![],
        },
        FixtureSigner,
        &std::env::temp_dir(),
        RestartPolicy::CallerOrStop,
    )
    .unwrap();
    let mut tunnel = RealTunnel {
        pid: session.pid(),
        session: Some(session),
        ..RealTunnel::default()
    };
    assert!(!tunnel.confirm_absent());
    tunnel.stop().unwrap();
    tunnel.reap();

    // Use a live process to model the reused PID without depending on kernel allocation.
    tunnel.pid = Some(std::process::id());
    let without_receipt = RealTunnel {
        pid: tunnel.pid,
        ..RealTunnel::default()
    };
    assert!(!without_receipt.confirm_absent());
    assert!(tunnel.confirm_absent());
}

#[test]
fn expired_management_hold_fails_even_if_the_child_ignores_terminate() {
    let mut cycle = fixture();
    cycle.open();
    cycle.take_effects();
    cycle.session.hold_expired = true;
    assert_eq!(cycle.poll(&profile()).unwrap_err().step, Step::Tunnel);
    assert!(cycle.take_effects().is_empty());

    let started = cycle.network.now;
    assert!(!cycle.cleanup());
    assert_eq!(cycle.network.now - started, STOP_WAIT);
    assert_eq!(cycle.take_effects().last(), Some(&Effect::ForceStop));
    cycle.session.absent = true;
    assert!(cycle.cleanup());
    assert_eq!(cycle.take_effects(), [Effect::CloseDns, Effect::Finish]);
}

fn with_native_network(check_network: impl FnOnce(&mut NativeNetwork<'_>, &OvpnUtun)) {
    with_owned_native_network(|mut network, link| check_network(&mut network, link));
}

fn with_owned_native_network(check_network: impl FnOnce(NativeNetwork<'_>, &OvpnUtun)) {
    let root = Root::new();
    let uid = unsafe { libc::geteuid() };
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.0.join(".controller.lock"))
        .unwrap();
    let controller = ControllerLock::fixture(&root.0, uid).unwrap();
    let mut backend = NativeBackend::fixture(&controller).unwrap();
    backend.fixture_route_io();
    let network = NativeNetwork {
        owner: Owner {
            uid: 501,
            profile: "ovpn".into(),
            generation: 1,
        },
        routes: Arc::new(Mutex::new(Coordinator::new(backend).unwrap())),
        canceled: Arc::new(AtomicBool::new(false)),
        address: None,
        token: None,
        lease: None,
        fence: None,
        dns: None,
        journal: Journal::new((root.0.clone(), uid)),
    };
    let link = OvpnUtun::prove(
        "utun40",
        &Interfaces::default(),
        &fixture_interfaces(&[("utun40", 40)]),
    )
    .unwrap();
    check_network(network, &link);
}

fn fixture_process() -> Process {
    Process {
        identity: crate::connection::macos::process::Identity {
            pid: 321,
            start: (123, 456),
        },
        parent: 111,
        uid: 0,
        real_uid: 0,
        running: true,
        executable: "/fixture/runtime/bin/openvpn".into(),
    }
}

#[test]
fn native_ovpn_journals_spawn_and_interface_before_the_address_attempt() {
    with_native_network(|network, _| {
        let directory = paths::ovpn_sessions_directory().join("vpnt-ovpn-111-a-0");
        network
            .journal_spawn(&directory, &fixture_process())
            .unwrap();
        let read = |network: &NativeNetwork<'_>| {
            fence::read(
                &network.journal.root,
                network.journal.owner,
                network.owner.uid,
                &network.owner.profile,
                1,
            )
            .unwrap()
            .expect("journal must exist")
        };
        let initial = read(network);
        assert_eq!(initial.session_dir.as_deref(), directory.to_str());
        assert_eq!(initial.processes[0].pid, 321);
        assert_eq!(initial.processes[0].start_usec, 456);
        assert!(initial.incomplete && initial.interface.is_none());
        let device = "utun4294967295";
        let absent_link = OvpnUtun::prove(
            device,
            &Interfaces::default(),
            &fixture_interfaces(&[(device, 65534)]),
        )
        .unwrap();
        // No real link can match this synthetic snapshot. The write must
        // precede even an address operation that returns an error.
        let result = network.address(
            &absent_link,
            &up(Some(device)),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(result.is_err());
        let addressed = read(network);
        assert_eq!(
            addressed.interface,
            Some(Interface {
                name: device.into(),
                index: 65534
            })
        );
        network.journal_cleanup().unwrap();
        assert!(!read(network).incomplete);
    });
}

#[test]
fn native_ovpn_propagates_initial_journal_failure_before_network() {
    with_native_network(|network, _| {
        let directory = paths::ovpn_sessions_directory().join("vpnt-ovpn-111-a-0");
        network.journal.owner ^= 1;
        assert!(
            network
                .journal_spawn(&directory, &fixture_process())
                .is_err_and(|failure| failure.step == Step::Spawn)
        );
        assert!(network.journal.record.is_none());
        assert!(network.address.is_none());
    });
}

#[test]
fn native_ovpn_cleanup_stops_child_and_preserves_fence_when_journal_write_fails() {
    with_owned_native_network(|mut network, _| {
        let directory = paths::ovpn_sessions_directory().join("vpnt-ovpn-111-a-0");
        network
            .journal_spawn(&directory, &fixture_process())
            .unwrap();
        let original_owner = network.journal.owner;
        let path = network.journal.root.join("fences/501/ovpn-1.json");
        let original = fs::read(&path).unwrap();
        let tunnel = FakeTunnel::default();
        let effects = tunnel.effects.clone();
        tunnel.exit.set(Some(None));
        let mut cycle = Cycle::new(tunnel, network);
        cycle.network.journal.owner ^= 1;

        assert!(!cycle.cleanup(), "child absence has not been confirmed");
        assert_eq!(*effects.borrow(), [Effect::Stop, Effect::Reap]);
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(cycle.network.journal.record.as_ref().unwrap().incomplete);

        cycle.session.absent = true;
        cycle.network.journal.owner = original_owner;
        assert!(cycle.cleanup());
        cycle.network.journal.remove().unwrap();
        assert!(!path.exists());
    });
}

#[test]
fn session_directory_reports_the_actual_private_child() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Root::new();
    let executable = fixture.0.join("fake-openvpn");
    fs::write(
        &executable,
        concat!(
            "#!/usr/bin/env python3\n",
            "import sys, socket\n",
            "if '--version' in sys.argv:\n",
            "  print('OpenVPN 2.6.19'); sys.exit(0)\n",
            "with socket.socket(socket.AF_UNIX) as stream:\n",
            "  stream.connect(sys.argv[sys.argv.index('--management') + 1])\n",
            "  for line in stream.makefile('rb'):\n",
            "    if line.startswith(b'signal SIGTERM'): break\n",
        ),
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let temp = std::env::temp_dir();
    let base = ('A'..='Z')
        .find_map(|letter| {
            let path = temp.join(letter.to_string());
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => Some(Root(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(error) => panic!("fixture base: {error}"),
            }
        })
        .expect("no short base available");
    let session = Session::start_with(
        Launch {
            openvpn: executable,
            config: ConfigSource::private(b"directory-fixture"),
            dev: None,
            signatures: Signatures::Any,
            extra: vec![],
            env: vec![],
        },
        FixtureSigner,
        &base.0,
        RestartPolicy::CallerOrStop,
    )
    .unwrap();
    let directory = session.directory().to_path_buf();
    assert_eq!(directory.parent().unwrap(), base.0.canonicalize().unwrap());
    assert!(fence::is_ovpn_session_name(
        directory.file_name().unwrap().to_str().unwrap()
    ));
    assert_eq!(
        fs::read(directory.join("config")).unwrap(),
        b"directory-fixture"
    );
    drop(session);
    assert!(!directory.exists());
}

#[test]
fn native_mtu_delivers_the_requested_value_to_the_write_boundary() {
    use crate::connection::macos::vip::ovpn_link::capture_mtu_writes;

    with_native_network(|network, link| {
        let values = capture_mtu_writes(|| {
            let deadline = Instant::now() + Duration::from_secs(1);
            network.mtu(link, 1420, deadline).unwrap();
            network.mtu(link, 1500, deadline).unwrap();
        });
        assert_eq!(values, [1420, 1500]);
    });
}

#[test]
fn native_ovpn_withdrawal_retries_its_lease_without_deleting_the_ssl_default() {
    use crate::connection::routes::{Address, Key, NextHop, Route};

    with_native_network(|network, link| {
        let ssl_owner = Owner {
            profile: "ssl".into(),
            ..network.owner.clone()
        };
        let default = Route {
            key: Key {
                network: "0.0.0.0/0".parse().unwrap(),
                scope: 7,
            },
            interface: 7,
            next_hop: NextHop::Gateway(Address::unscoped("192.0.2.1".parse().unwrap())),
        };
        let routes = network.routes.clone();
        let ssl_scope;
        {
            let mut routes = routes.lock().unwrap();
            ssl_scope = routes
                .backend_mut()
                .fixture_default(ssl_owner.clone(), default);
            let lease = routes.acquire(ssl_owner.clone(), &[default]).unwrap();
            assert!(routes.backend_mut().begin_cleanup(&ssl_scope).unwrap());
            assert_eq!(routes.release(lease).unwrap().pending, 1);
            routes.backend_mut().fixture_allow_default_delete();
        }

        let directory = paths::ovpn_sessions_directory().join("vpnt-ovpn-111-a-0");
        network
            .journal_spawn(&directory, &fixture_process())
            .unwrap();
        network
            .routes(
                link,
                &up(Some("utun40")),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let on_disk = fence::read(
            &network.journal.root,
            network.journal.owner,
            network.owner.uid,
            &network.owner.profile,
            1,
        )
        .unwrap()
        .unwrap();
        assert!(on_disk.incomplete);
        assert_eq!(
            on_disk.routes,
            routes.lock().unwrap().inventory(&network.owner)
        );
        assert_eq!(on_disk.routes.len(), 1);
        assert!(on_disk.routes[0].created);
        network.journal_cleanup().unwrap();
        let fence = network.fence.as_ref().unwrap().clone();
        assert!(!network.withdraw_routes().unwrap());
        assert!(network.lease.is_none());
        assert!(network.token.is_some());
        assert!(!fence.is_complete());
        {
            let mut routes = routes.lock().unwrap();
            let inventory = routes.inventory(&network.owner);
            assert_eq!(inventory.len(), 1);
            assert_eq!(inventory[0].route.interface, 40);
            assert!(routes.has_owner(&ssl_owner));
            assert_eq!(routes.backend_mut().fixture_default_deletes(), 0);
            routes
                .backend_mut()
                .fixture_remove_route(inventory[0].route);
        }

        assert!(network.withdraw_routes().unwrap());
        assert!(network.token.is_none());
        assert!(fence.is_complete());
        let mut routes = routes.lock().unwrap();
        assert!(!routes.has_owner(&network.owner));
        assert!(!routes.backend_mut().fixture_has_scope(&network.owner));
        assert!(routes.has_owner(&ssl_owner));
        assert_eq!(routes.backend_mut().fixture_default_deletes(), 0);
        assert_eq!(routes.retry_cleanup().removed, 1);
        assert_eq!(routes.backend_mut().fixture_default_deletes(), 1);
        routes.backend_mut().finish_cleanup(&ssl_scope).unwrap();
    });
}
