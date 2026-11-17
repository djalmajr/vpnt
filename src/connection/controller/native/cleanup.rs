use super::*;
use crate::helper::runtime::cleanup::{self as diagnostic, Reason};

fn persist_claims<B: crate::connection::routes::Backend>(
    routes: &mut Coordinator<B>,
    owner: &Owner,
    record: &mut crate::connection::fence::Fence,
    persist: impl FnOnce(&crate::connection::fence::Fence) -> Result<(), AbandonError>,
    detach: impl FnOnce(&mut B),
) -> Result<(), AbandonError> {
    routes.try_abandon(owner, |inventory| {
        record.routes = inventory.to_vec();
        persist(record)
    })?;
    detach(routes.backend_mut());
    Ok(())
}

impl NativeAttempt<'_> {
    pub(super) fn abandon_ssl(&mut self, reason: Reason) -> Result<(), AbandonError> {
        use crate::connection::{fence, macos::routing::retirement};
        use std::time::{SystemTime, UNIX_EPOCH};

        // Only the retained driver may signal its own children.
        if let Some(client) = &mut self.client {
            let _ = client.stop();
        }
        let (service_id, processes) = match &self.client {
            Some(client) => {
                let (service, processes) = client
                    .recorded_processes()
                    .map_err(|_| AbandonError::Unsupported)?;
                (Some(service), processes)
            }
            None => (None, Vec::new()),
        };
        let written_unix_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| AbandonError::Unsupported)?
                .as_millis(),
        )
        .map_err(|_| AbandonError::Unsupported)?;
        let interface = self.link.as_ref().map(|link| fence::Interface {
            name: link.name().to_owned(),
            index: link.index(),
        });
        let incomplete = self.uncertain_cleanup
            || (self.spawn_attempted
                && (self.client.is_none()
                    || processes.is_empty()
                    || (self
                        .client
                        .as_ref()
                        .is_some_and(|client| client.ppp_may_have_run())
                        && interface.is_none())));
        let mut record = fence::Fence {
            version: 1,
            uid: self.owner.uid,
            profile: self.owner.profile.clone(),
            generation: self.owner.generation,
            kind: fence::Kind::Ssl,
            reason: reason.id().to_owned(),
            incomplete,
            written_unix_ms,
            service_id,
            dns_key: self.dns.as_ref().map(|dns| dns.key()),
            processes,
            interface,
            sink: None,
            retired: Vec::new(),
            routes: Vec::new(),
        };
        let mut commit = || {
            let mut routes = self
                .routes
                .try_lock()
                .map_err(|_| AbandonError::Unsupported)?;
            let queue = routes.backend_mut().retirement_queue();
            let mut retired = queue.try_lock().map_err(|_| AbandonError::Unsupported)?;
            record.sink = routes
                .backend_mut()
                .abandonment_sink(&self.owner)
                .map_err(|_| AbandonError::Unsupported)?;
            record.retired = retirement::inventory(&retired, &self.owner);
            persist_claims(
                &mut routes,
                &self.owner,
                &mut record,
                |record| {
                    fence::write(&self.fence_root, self.fence_owner, record)
                        .map_err(|_| AbandonError::Persist)
                },
                |backend| backend.abandon_owner(&self.owner, &mut retired),
            )
        };
        match &self.profile_use {
            Some(profile) => profile.abandon_after(|| AbandonError::Unsupported, commit)?,
            None => commit()?,
        }
        self.lease = None;
        self.token = None;
        self.link = None;
        self.client = None;
        self.dns = None;
        self.credentials = None;
        self.profile_use = None;
        Ok(())
    }
    pub(super) fn cleanup_network(&mut self) -> bool {
        if let Some(dns) = &mut self.dns {
            if !dns.close_and_observe().unwrap_or(false) {
                return diagnostic::refuse(Reason::UncertainCleanup);
            }
            self.dns = None;
        }
        // A canceled connection may have reached PPP before the last poll.
        // Capture proof while its original parent is still alive, if possible.
        if self.link.is_none() && self.client.is_some() && !self.stopped {
            let _ = self.discover();
        }
        if !self.stopped {
            self.stopped = self
                .client
                .as_mut()
                .is_none_or(|client| client.stop().is_ok());
        }
        self.credentials = None;
        if self.uncertain_cleanup {
            return diagnostic::refuse(Reason::UncertainCleanup);
        }
        if !self.stopped {
            return diagnostic::refuse(Reason::ProducerNotStopped);
        }
        if !self.spawn_attempted {
            return true;
        }
        let Some(client) = &mut self.client else {
            return diagnostic::refuse(Reason::ProducerMissing);
        };
        if !client.children_complete().unwrap_or(false) {
            return diagnostic::refuse(Reason::ChildrenIncomplete);
        }
        // A birth grant predates configd/address discovery. Process receipts
        // alone cannot prove that implicit network resources were removed.
        let Some(link) = &self.link else {
            if !client.ppp_may_have_run() {
                return true;
            }
            let (Some(before), Some(routes), Some(proof)) =
                (&self.before, &self.before_routes, client.supervised_ppp())
            else {
                return diagnostic::refuse(Reason::LinkEvidence);
            };
            return ppp_early_cleanup::complete(before, routes, proof.child()).unwrap_or(false)
                || diagnostic::refuse(Reason::EarlyAbsence);
        };
        let Ok(mut routes) = self.routes.try_lock() else {
            return diagnostic::refuse(Reason::RouteLock);
        };
        if let Some(lease) = self.lease.take()
            && routes.release(lease).is_err()
        {
            self.uncertain_cleanup = true;
            return diagnostic::refuse(Reason::RouteRelease);
        }
        if let Some(token) = &self.token {
            if !routes.backend_mut().begin_cleanup(token).unwrap_or(false) {
                return diagnostic::refuse(Reason::RouteBegin);
            }
            routes.retry_cleanup();
            if routes.has_owner(&self.owner) {
                return diagnostic::refuse(Reason::RouteOwner);
            }
            if routes.backend_mut().finish_cleanup(token).is_err() {
                return diagnostic::refuse(Reason::RouteFinish);
            }
            self.token = None;
        }
        routes.retry_cleanup();
        if routes.has_owner(&self.owner) {
            return diagnostic::refuse(Reason::RouteOwner);
        }
        if routes.backend_mut().reap_retired().is_err() {
            return diagnostic::refuse(Reason::RetiredResources);
        }
        routes
            .backend_mut()
            .ppp_cleanup_complete(link)
            .unwrap_or(false)
            || diagnostic::refuse(Reason::EarlyAbsence)
    }
}

#[cfg(test)]
mod abandon_tests {
    use super::*;
    use crate::{
        connection::{
            fence,
            macos::routing::retirement,
            routes::{Backend, Error, Key, Presence, Route},
        },
        storage::ProfileStore,
    };
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[derive(Default)]
    struct Fake {
        rows: BTreeMap<Key, Route>,
        removes: usize,
        scope: bool,
        retired: Vec<Owner>,
    }
    impl Backend for Fake {
        type Receipt = Key;
        fn existing(&mut self, key: Key) -> Result<Option<Route>, Error> {
            Ok(self.rows.get(&key).copied())
        }
        fn create(&mut self, route: Route) -> Result<Key, Error> {
            self.rows.insert(route.key, route);
            Ok(route.key)
        }
        fn receipt_state(&mut self, key: &Key) -> Result<Presence, Error> {
            Ok(if self.rows.contains_key(key) {
                Presence::Owned
            } else {
                Presence::Absent
            })
        }
        fn remove(&mut self, key: &Key) -> Result<(), Error> {
            self.removes += 1;
            self.rows.remove(key);
            Ok(())
        }
    }
    fn is_idle(routes: &mut Coordinator<Fake>, profiles: &Profiles) -> bool {
        !routes.has_resources()
            && !routes.backend_mut().scope
            && routes.backend_mut().retired.is_empty()
            && profiles.idle()
    }

    #[test]
    fn ready_passes_gateway_or_profile_networks_to_real_backend() {
        use crate::connection::controller::native::factory::{AttemptKind, NativeFactory};
        use crate::helper::controller_lock::ControllerLock;
        use std::os::unix::fs::OpenOptionsExt;

        struct Capture;
        impl Drop for Capture {
            fn drop(&mut self) {
                READY_NETWORKS.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let uid = unsafe { libc::geteuid() };
        assert_ne!(
            uid, 0,
            "fixture requires an ordinary user; never create routes or a sink"
        );
        for (own_networks, expected) in [
            (vec![], vec!["10.0.0.0/8", "172.16.0.0/16"]),
            (vec!["192.168.64.0/20"], vec!["192.168.64.0/20"]),
        ] {
            let root = Root(
                std::env::current_dir()
                    .unwrap()
                    .join("output/fixtures")
                    .join(format!(
                        "ready-networks-{}-{}",
                        std::process::id(),
                        NEXT.fetch_add(1, Ordering::Relaxed)
                    )),
            );
            fs::create_dir_all(&root.0).unwrap();
            fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
            let lock_dir = root.0.join("controller");
            fs::create_dir(&lock_dir).unwrap();
            fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(lock_dir.join(".controller.lock"))
                .unwrap();
            let controller = ControllerLock::fixture(&lock_dir, uid).unwrap();
            let mut profile: Profile = serde_json::from_value(serde_json::json!({"id":"example","name":"example","kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap();
            profile.networks = own_networks.into_iter().map(str::to_owned).collect();
            let store = ProfileStore::open(&root.0, uid).unwrap();
            store.save(profile.clone()).unwrap();
            let profiles = Arc::new(Profiles::fixture(ProfileStore::open(&root.0, uid).unwrap()));
            let routes = Arc::new(Mutex::new(
                Coordinator::new(NativeBackend::fixture(&controller).unwrap()).unwrap(),
            ));
            let factory = NativeFactory::new(routes.clone(), profiles.clone(), None, uid)
                .fixture_fence_root(root.0.clone(), uid);
            // The fixture must outlive the driver, including during unwind.
            let fixture = crate::connection::ssl::tests::Fixture::new();
            let mut attempt = match factory.create(
                profile.clone(),
                uid,
                1,
                Credentials {
                    password: "fictional".into(),
                    psk: "".into(),
                },
                Arc::new(AtomicBool::new(false)),
            ) {
                AttemptKind::Ssl(attempt) => attempt,
                _ => panic!("SSL factory expected"),
            };
            attempt.profile_use = Some(profiles.begin(&profile, 1).unwrap());
            let mut driver = fixture.start("ready.fixture.invalid");
            driver.fixture_output(b"INFO:   vpnt: split-route 10.0.0.0/255.0.0.0\nINFO:   vpnt: split-route 172.16.0.0/255.255.0.0\nINFO:   vpnt: split-routes 2\n").unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let observation = driver.split_observation();
                if observation.split_count == Some(2) {
                    assert!(!observation.split_invalid);
                    assert_eq!(observation.split.len(), 2);
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "split batch not observed from fixture pipe"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let link = OwnedPpp::fixture_with_child(driver.fixture_child_id()).unwrap();
            attempt.client = Some(driver);
            attempt.link = Some(Arc::new(link));
            attempt.spawn_attempted = true;
            READY_NETWORKS.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
            let _capture = Capture;
            assert!(
                attempt.ready().is_err(),
                "the actual native writer must reject an unprivileged fixture"
            );
            let observed = READY_NETWORKS.with(|slot| slot.borrow().clone().unwrap());
            assert_eq!(observed, expected);
            let plan =
                crate::connection::routes::ppp_networks(&observed, 42, true, false, None).unwrap();
            assert_eq!(plan.len(), expected.len());
            assert!(plan.iter().all(|route| route.key.network.prefix() > 1
                && route.next_hop == crate::connection::routes::NextHop::Interface));
            assert!(!routes.lock().unwrap().has_resources());
            assert!(
                !routes
                    .lock()
                    .unwrap()
                    .backend_mut()
                    .fixture_has_scope(&attempt.owner)
            );
        }
    }
    #[test]
    fn ready_delivers_profile_dns_and_logs_missing_gateway_servers() {
        use crate::connection::controller::native::factory::{AttemptKind, NativeFactory};
        use crate::helper::controller_lock::ControllerLock;
        use std::os::unix::fs::OpenOptionsExt;
        struct Capture;
        impl Drop for Capture {
            fn drop(&mut self) {
                READY_DNS.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let uid = unsafe { libc::geteuid() };
        assert_ne!(uid, 0, "fixture must run without root");
        for has_server in [true, false] {
            let root = Root(
                std::env::current_dir()
                    .unwrap()
                    .join("output/fixtures")
                    .join(format!(
                        "ready-dns-{}-{}",
                        std::process::id(),
                        NEXT.fetch_add(1, Ordering::Relaxed)
                    )),
            );
            fs::create_dir_all(&root.0).unwrap();
            fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
            let lock_dir = root.0.join("controller");
            fs::create_dir(&lock_dir).unwrap();
            fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(lock_dir.join(".controller.lock"))
                .unwrap();
            let controller = ControllerLock::fixture(&lock_dir, uid).unwrap();
            let profile: Profile = serde_json::from_value(serde_json::json!({"id":"example","name":"example","kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":["192.0.2.0/24"],"dnsDomains":["corp.example.com"],"port":443,"certificate":"","probeHost":"192.0.2.15","probePort":8443,"probeMethod":"tcp"})).unwrap();
            let store = ProfileStore::open(&root.0, uid).unwrap();
            store.save(profile.clone()).unwrap();
            let profiles = Arc::new(Profiles::fixture(ProfileStore::open(&root.0, uid).unwrap()));
            let routes = Arc::new(Mutex::new(
                Coordinator::new(NativeBackend::fixture(&controller).unwrap()).unwrap(),
            ));
            let factory = NativeFactory::new(routes, profiles.clone(), None, uid)
                .fixture_fence_root(root.0.clone(), uid);
            let fixture = crate::connection::ssl::tests::Fixture::new();
            let mut attempt = match factory.create(
                profile.clone(),
                uid,
                1,
                Credentials {
                    password: "fictional".into(),
                    psk: "".into(),
                },
                Arc::new(AtomicBool::new(false)),
            ) {
                AttemptKind::Ssl(attempt) => attempt,
                _ => panic!("SSL factory expected"),
            };
            attempt.profile_use = Some(profiles.begin(&profile, 1).unwrap());
            let mut driver = fixture.start("ready.fixture.invalid");
            let batch: &[u8] = if has_server {
                b"INFO:   vpnt: dns-server 172.16.0.4\nINFO:   vpnt: dns 1 0\n"
            } else {
                b"INFO:   vpnt: dns 0 0\n"
            };
            driver.fixture_output(batch).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let seen = driver.split_observation();
                if seen.dns_count == Some((usize::from(has_server), 0)) {
                    assert!(!seen.dns_invalid);
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "DNS batch not observed; server={has_server}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let link = OwnedPpp::fixture_with_child(driver.fixture_child_id()).unwrap();
            attempt.client = Some(driver);
            attempt.link = Some(Arc::new(link));
            READY_DNS.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
            let _capture = Capture;
            assert!(
                attempt.ready().is_ok_and(|ready| ready),
                "ready fixture server={has_server}"
            );
            let calls = READY_DNS.with(|slot| slot.borrow().clone().unwrap());
            if has_server {
                assert_eq!(
                    calls,
                    vec![(
                        vec!["172.16.0.4".parse().unwrap()],
                        vec!["corp.example.com".to_owned()]
                    )]
                );
            } else {
                assert!(calls.is_empty(), "must not publish without a server");
            }
            attempt.client.as_mut().unwrap().stop().unwrap();
            let log = fs::read_to_string(fixture.diagnostic_log()).unwrap();
            let note = "domínios internos configurados, mas o gateway não publicou servidores DNS";
            assert_eq!(
                log.contains(note),
                !has_server,
                "server={has_server}, log={log}"
            );
        }
    }
    #[test]
    fn native_abandon_persists_before_releasing_claim_and_reservation() {
        use crate::connection::controller::native::factory::{AttemptKind, NativeFactory};
        use crate::helper::controller_lock::ControllerLock;
        use std::os::unix::fs::OpenOptionsExt;
        let root = Root(
            std::env::current_dir()
                .unwrap()
                .join("output/fixtures")
                .join(format!(
                    "native-abandon-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )),
        );
        fs::create_dir_all(&root.0).unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_dir = root.0.join("controller");
        fs::create_dir(&lock_dir).unwrap();
        fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lock_dir.join(".controller.lock"))
            .unwrap();
        let uid = unsafe { libc::geteuid() };
        let controller = ControllerLock::fixture(&lock_dir, uid).unwrap();
        let profile: Profile = serde_json::from_value(serde_json::json!({"id":"example","name":"example","kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap();
        let store = ProfileStore::open(&root.0, uid).unwrap();
        store.save(profile.clone()).unwrap();
        let profiles = Arc::new(Profiles::fixture(ProfileStore::open(&root.0, uid).unwrap()));
        let owner = Owner {
            uid,
            profile: profile.id.clone(),
            generation: 1,
        };
        let route =
            crate::connection::routes::ppp_networks(&profile.networks, 3, true, false, None)
                .unwrap()[0];
        let mut routes = Coordinator::new(NativeBackend::fixture(&controller).unwrap()).unwrap();
        routes.fixture_borrowed_claim(owner.clone(), route);
        routes.backend_mut().fixture_scope(owner.clone(), route);
        routes.backend_mut().fixture_retired(owner.clone());
        let routes = Arc::new(Mutex::new(routes));
        let factory = NativeFactory::new(routes.clone(), profiles.clone(), None, uid)
            .fixture_fence_root(root.0.clone(), uid);
        let mut attempt = match factory.create(
            profile.clone(),
            uid,
            1,
            Credentials {
                password: "fictional".into(),
                psk: "".into(),
            },
            Arc::new(AtomicBool::new(false)),
        ) {
            AttemptKind::Ssl(attempt) => attempt,
            _ => panic!("SSL factory expected"),
        };
        attempt.profile_use = Some(profiles.begin(&profile, 1).unwrap());
        // The real cleanup path must reach and refuse a held coordinator lock.
        // The SSL child is the existing ordinary-user process fixture; the PPP
        // interface is synthetic but its process watches are real.
        let ssl_fixture = crate::connection::ssl::tests::Fixture::new();
        let driver = ssl_fixture.start("ready.fixture.invalid");
        let ppp = OwnedPpp::fixture_with_child(driver.fixture_child_id()).unwrap();
        attempt.client = Some(driver);
        attempt.link = Some(Arc::new(ppp));
        attempt.spawn_attempted = true;
        let held = routes.lock().unwrap();
        let cleanup_result = std::thread::scope(|scope| {
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let attempt = &mut attempt;
            scope.spawn(move || {
                diagnostic::begin();
                let result = attempt.cleanup_network();
                let _ = send.send((result, diagnostic::current_reason()));
            });
            let result = receive.recv_timeout(Duration::from_secs(5));
            drop(held);
            result
        });
        assert_eq!(cleanup_result.unwrap(), (false, Some(Reason::RouteLock)));
        assert!(routes.lock().unwrap().has_owner(&owner));
        attempt.client = None;
        attempt.link = None;
        attempt.spawn_attempted = false;
        attempt.stopped = false;
        let routes_guard = routes.lock().unwrap();
        let idle = std::thread::scope(|scope| {
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let factory = &factory;
            scope.spawn(move || {
                let _ = send.send(factory.idle());
            });
            let idle = receive.recv_timeout(Duration::from_millis(250));
            drop(routes_guard);
            idle
        });
        assert!(!idle.unwrap());
        // Holding either lock must produce a retryable refusal, not stall the
        // worker. Release the guard even when the timeout assertion fails.
        let routes_guard = routes.lock().unwrap();
        let result = std::thread::scope(|scope| {
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let attempt = &mut attempt;
            scope.spawn(move || {
                let _ = send.send(attempt.abandon(Reason::RouteOwner));
            });
            let result = receive.recv_timeout(Duration::from_millis(250));
            drop(routes_guard);
            result
        });
        assert_eq!(result.unwrap(), Err(AbandonError::Unsupported));
        assert!(!profiles.idle());
        let queue = routes.lock().unwrap().backend_mut().retirement_queue();
        let queue_guard = queue.lock().unwrap();
        let result = std::thread::scope(|scope| {
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let attempt = &mut attempt;
            scope.spawn(move || {
                let _ = send.send(attempt.abandon(Reason::RouteOwner));
            });
            let result = receive.recv_timeout(Duration::from_millis(250));
            drop(queue_guard);
            result
        });
        assert_eq!(result.unwrap(), Err(AbandonError::Unsupported));
        assert!(routes.lock().unwrap().has_owner(&owner));
        attempt.fence_owner = uid.wrapping_add(1);
        assert_eq!(
            attempt.abandon(Reason::RouteOwner),
            Err(AbandonError::Persist)
        );
        assert!(routes.lock().unwrap().has_owner(&owner));
        assert!(
            routes
                .lock()
                .unwrap()
                .backend_mut()
                .fixture_has_scope(&owner)
        );
        assert!(!profiles.idle());
        assert!(
            fence::read(&root.0, uid, uid, "example", 1)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            retirement::inventory(
                &routes
                    .lock()
                    .unwrap()
                    .backend_mut()
                    .retirement_queue()
                    .lock()
                    .unwrap(),
                &owner
            )
            .len(),
            1
        );
        assert!(!factory.idle());
        // idle() observes/reaps the synthetic empty retirement; insert it again
        // so the successful transaction has a retirement to serialize/detach.
        let queue = routes.lock().unwrap().backend_mut().retirement_queue();
        if retirement::inventory(&queue.lock().unwrap(), &owner).is_empty() {
            routes
                .lock()
                .unwrap()
                .backend_mut()
                .fixture_retired(owner.clone());
        }
        attempt.fence_owner = uid;
        assert_eq!(attempt.abandon(Reason::RouteOwner), Ok(()));
        let record = fence::read(&root.0, uid, uid, "example", 1)
            .unwrap()
            .expect("fence persisted");
        assert_eq!(record.routes.len(), 1);
        assert_eq!(record.routes[0].route, route);
        assert_eq!(record.retired.len(), 1);
        assert!(!routes.lock().unwrap().has_owner(&owner));
        assert!(
            !routes
                .lock()
                .unwrap()
                .backend_mut()
                .fixture_has_scope(&owner)
        );
        assert!(profiles.idle());
        assert!(factory.idle());
    }
    #[test]
    fn native_abandon_persists_dns_key_for_recovery() {
        use crate::connection::controller::native::factory::{AttemptKind, NativeFactory};
        use crate::connection::macos::{
            fence_recovery::tests::assert_attempt_dns_recovery, store::DnsLease,
        };
        use crate::helper::{controller_lock::ControllerLock, ppp_supervisor::ServiceId};
        use std::os::unix::fs::OpenOptionsExt;

        let root = Root(
            std::env::current_dir()
                .unwrap()
                .join("output/fixtures")
                .join(format!(
                    "native-abandon-dns-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )),
        );
        fs::create_dir_all(&root.0).unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_dir = root.0.join("controller");
        fs::create_dir(&lock_dir).unwrap();
        fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lock_dir.join(".controller.lock"))
            .unwrap();
        let uid = unsafe { libc::geteuid() };
        let controller = ControllerLock::fixture(&lock_dir, uid).unwrap();
        let profile: Profile = serde_json::from_value(serde_json::json!({"id":"example","name":"example","kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap();
        let store = ProfileStore::open(&root.0, uid).unwrap();
        store.save(profile.clone()).unwrap();
        let profiles = Arc::new(Profiles::fixture(ProfileStore::open(&root.0, uid).unwrap()));
        let routes = Arc::new(Mutex::new(
            Coordinator::new(NativeBackend::fixture(&controller).unwrap()).unwrap(),
        ));
        let factory = NativeFactory::new(routes, profiles.clone(), None, uid)
            .fixture_fence_root(root.0.clone(), uid);
        let fixture = crate::connection::ssl::tests::Fixture::new();
        let mut attempt = match factory.create(
            profile.clone(),
            uid,
            1,
            Credentials {
                password: "fictional".into(),
                psk: "".into(),
            },
            Arc::new(AtomicBool::new(false)),
        ) {
            AttemptKind::Ssl(attempt) => attempt,
            _ => panic!("SSL factory expected"),
        };
        attempt.profile_use = Some(profiles.begin(&profile, 1).unwrap());
        let driver = fixture.start("ready.fixture.invalid");
        let (service, _) = driver.recorded_processes().unwrap();
        let service = ServiceId::parse(&service).unwrap();
        let expected = format!("State:/Network/Service/{}/DNS", service.as_str());
        let (lease, state) = DnsLease::fixture(service);
        lease
            .publish(&["172.16.0.4".parse().unwrap()], &["corp.example".into()])
            .unwrap();
        assert_eq!(state.lock().unwrap().as_deref(), Some(expected.as_str()));
        attempt.client = Some(driver);
        attempt.dns = Some(lease);
        assert_eq!(attempt.abandon_ssl(Reason::RouteOwner), Ok(()));
        let record = fence::read(&root.0, uid, uid, &profile.id, 1)
            .unwrap()
            .expect("fence persisted");
        assert_eq!(
            record.service_id.as_deref(),
            Some(service_id_from_key(&expected))
        );
        assert_eq!(record.dns_key.as_deref(), Some(expected.as_str()));
        assert_attempt_dns_recovery(&root.0, uid, &profile, &expected, &state);
    }

    fn service_id_from_key(key: &str) -> &str {
        key.strip_prefix("State:/Network/Service/")
            .unwrap()
            .strip_suffix("/DNS")
            .unwrap()
    }
    #[test]
    fn durable_transaction_retains_everything_on_failure_and_releases_after_success() {
        let root = Root(
            std::env::current_dir()
                .unwrap()
                .join("output/fixtures")
                .join(format!(
                    "abandon-txn-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )),
        );
        fs::create_dir_all(&root.0).unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let store = ProfileStore::open(&root.0, uid).unwrap();
        let profile: Profile = serde_json::from_value(serde_json::json!({"id":"example","name":"example","kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap();
        store.save(profile.clone()).unwrap();
        let profiles = Profiles::fixture(ProfileStore::open(&root.0, uid).unwrap());
        let reservation = profiles.begin(&profile, 1).unwrap();
        let owner = Owner {
            uid,
            profile: profile.id.clone(),
            generation: 1,
        };
        let mut routes = Coordinator::new(Fake {
            scope: true,
            retired: vec![owner.clone()],
            ..Fake::default()
        })
        .unwrap();
        let route =
            crate::connection::routes::ppp_networks(&profile.networks, 3, true, false, None)
                .unwrap()[0];
        let _lease = routes.acquire(owner.clone(), &[route]).unwrap();
        let mut record = fence::Fence {
            version: 1,
            uid,
            profile: owner.profile.clone(),
            generation: 1,
            kind: fence::Kind::Ssl,
            reason: Reason::RouteOwner.id().into(),
            incomplete: false,
            written_unix_ms: 123,
            service_id: Some("12345678-1234-4123-8123-123456789ABC".into()),
            dns_key: None,
            processes: vec![fence::ProcessIdentity {
                pid: 42,
                start_sec: 123,
                start_usec: 45,
                program: "openfortivpn".into(),
            }],
            interface: Some(fence::Interface {
                name: "ppp0".into(),
                index: 3,
            }),
            sink: Some(fence::Sink {
                name: "utun5".into(),
                index: 5,
                source: Some("192.0.2.1".parse().unwrap()),
            }),
            retired: vec![fence::RetiredIdentity {
                interface: None,
                sink: Some(fence::Sink {
                    name: "utun5".into(),
                    index: 5,
                    source: Some("192.0.2.1".parse().unwrap()),
                }),
            }],
            routes: vec![],
        };
        let attempt = |routes: &mut Coordinator<Fake>, record: &mut fence::Fence, owner_uid| {
            reservation.abandon_after(
                || AbandonError::Unsupported,
                || {
                    persist_claims(
                        routes,
                        &owner,
                        record,
                        |value| {
                            fence::write(&root.0, owner_uid, value)
                                .map_err(|_| AbandonError::Persist)
                        },
                        |backend| {
                            backend.scope = false;
                            backend.retired.retain(|item| item != &owner);
                        },
                    )
                },
            )
        };
        assert_eq!(
            attempt(&mut routes, &mut record, uid.wrapping_add(1)),
            Err(AbandonError::Persist)
        );
        assert!(routes.has_owner(&owner));
        assert!(routes.backend_mut().scope);
        assert_eq!(routes.backend_mut().retired, vec![owner.clone()]);
        assert_eq!(routes.backend_mut().removes, 0);
        assert!(!is_idle(&mut routes, &profiles));
        assert_eq!(attempt(&mut routes, &mut record, uid), Ok(()));
        assert!(is_idle(&mut routes, &profiles));
        assert_eq!(routes.backend_mut().removes, 0);
        assert_eq!(routes.backend_mut().rows.get(&route.key), Some(&route));
        let saved = fence::read(&root.0, uid, uid, &owner.profile, 1)
            .unwrap()
            .unwrap();
        assert_eq!(saved, record);
        assert_eq!(saved.routes.len(), 1);
        assert_eq!(saved.routes[0].route, route);
        assert_eq!(
            saved.service_id.as_deref(),
            Some("12345678-1234-4123-8123-123456789ABC")
        );
        assert_eq!(saved.processes.len(), 1);
        assert_eq!(saved.interface.as_ref().unwrap().name, "ppp0");
        assert_eq!(saved.sink.as_ref().unwrap().name, "utun5");
        assert_eq!(saved.retired.len(), 1);
    }
}
