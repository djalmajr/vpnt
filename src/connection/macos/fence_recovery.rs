//! Observation-only recovery: recorded data never grants cleanup authority.
use super::{interfaces::Interfaces, process::Process, routing::Snapshot, store};
use crate::{
    connection::{
        fence::{self, Fence, Interface, ProcessIdentity, Sink},
        routes::Route,
    },
    helper::ppp_supervisor::ServiceId,
    model::{Profile, VpnKind},
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

trait Observer {
    fn process_absent(&mut self, process: &ProcessIdentity) -> Result<bool, ()>;
    fn service_absent(&mut self, service: &str) -> Result<bool, ()>;
    fn dns_absent(&mut self, key: &str) -> Result<bool, ()>;
    fn interface_absent(&mut self, name: &str, index: u32) -> Result<bool, ()>;
    fn route_absent(&mut self, route: Route) -> Result<bool, ()>;
    #[cfg(test)]
    fn remove_route(&mut self, _: Route) -> Result<(), ()> {
        Err(())
    }
    #[cfg(test)]
    fn remove_interface(&mut self, _: &str, _: u32) -> Result<(), ()> {
        Err(())
    }
    #[cfg(test)]
    fn terminate(&mut self, _: &ProcessIdentity) -> Result<(), ()> {
        Err(())
    }
}
struct NativeObserver;
fn different_or_exited(process: &ProcessIdentity, running: bool, start: (u64, u64)) -> bool {
    !running || start != (process.start_sec as u64, process.start_usec as u64)
}
impl Observer for NativeObserver {
    fn process_absent(&mut self, process: &ProcessIdentity) -> Result<bool, ()> {
        if process.pid == 0
            || process.pid > i32::MAX as u32
            || process.start_sec < 0
            || process.start_usec < 0
        {
            return Err(());
        }
        match Process::read(process.pid) {
            Ok(current) => Ok(different_or_exited(
                process,
                current.running,
                current.identity.start,
            )),
            Err(_) => {
                // Signal zero observes existence; it never signals or kills a process.
                if unsafe { libc::kill(process.pid as i32, 0) } == 0 {
                    return Err(());
                }
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                    Ok(true)
                } else {
                    Err(())
                }
            }
        }
    }
    fn service_absent(&mut self, service: &str) -> Result<bool, ()> {
        let service = ServiceId::parse(service).ok_or(())?;
        Ok(!store::has_attempt_key(&service).map_err(|_| ())?)
    }
    fn dns_absent(&mut self, key: &str) -> Result<bool, ()> {
        let id = key
            .strip_prefix("State:/Network/Service/")
            .and_then(|v| v.strip_suffix("/DNS"))
            .ok_or(())?;
        let service = ServiceId::parse(id).ok_or(())?;
        Ok(!store::has_dns_attempt_key(&service).map_err(|_| ())?)
    }
    fn interface_absent(&mut self, name: &str, index: u32) -> Result<bool, ()> {
        let interfaces = Interfaces::read().map_err(|_| ())?;
        Ok(!interfaces
            .entries
            .values()
            .any(|entry| entry.name == name && entry.index == index))
    }
    fn route_absent(&mut self, route: Route) -> Result<bool, ()> {
        let table = Snapshot::read().map_err(|_| ())?;
        match table.exact(route.key).map_err(|_| ())? {
            None => Ok(true),
            Some(record) => Ok(record.route().map_err(|_| ())? != route),
        }
    }
}
fn interface_absent(observer: &mut impl Observer, interface: &Interface) -> Result<bool, ()> {
    if interface.name.is_empty() || interface.index == 0 {
        return Err(());
    }
    observer.interface_absent(&interface.name, interface.index)
}
fn sink_absent(observer: &mut impl Observer, sink: &Sink) -> Result<bool, ()> {
    if sink.name.is_empty() || sink.index == 0 {
        return Err(());
    }
    observer.interface_absent(&sink.name, sink.index)
}
fn absent(record: &Fence, observer: &mut impl Observer) -> Result<bool, ()> {
    if record.incomplete {
        return Ok(false);
    }
    for process in &record.processes {
        if !observer.process_absent(process)? {
            return Ok(false);
        }
    }
    if let Some(service) = &record.service_id
        && !observer.service_absent(service)?
    {
        return Ok(false);
    }
    if let Some(key) = &record.dns_key {
        let id = key
            .strip_prefix("State:/Network/Service/")
            .and_then(|v| v.strip_suffix("/DNS"))
            .ok_or(())?;
        if record.service_id.as_deref() != Some(id) || ServiceId::parse(id).is_none() {
            return Err(());
        }
        if !observer.dns_absent(key)? {
            return Ok(false);
        }
    }
    if let Some(interface) = &record.interface
        && !interface_absent(observer, interface)?
    {
        return Ok(false);
    }
    if let Some(sink) = &record.sink
        && !sink_absent(observer, sink)?
    {
        return Ok(false);
    }
    for old in &record.retired {
        if let Some(interface) = &old.interface
            && !interface_absent(observer, interface)?
        {
            return Ok(false);
        }
        if let Some(sink) = &old.sink
            && !sink_absent(observer, sink)?
        {
            return Ok(false);
        }
    }
    for route in &record.routes {
        if !observer.route_absent(route.route)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) struct Recovery {
    root: PathBuf,
    owner: u32,
    uid: u32,
    global: bool,
    blocked: BTreeSet<String>,
}
impl Recovery {
    pub fn new(root: &Path, owner: u32, uid: u32) -> Self {
        let mut result = Self {
            root: root.into(),
            owner,
            uid,
            global: true,
            blocked: BTreeSet::new(),
        };
        result.reconcile(None, &mut NativeObserver);
        result
    }
    pub fn blocked(&self, profile: &Profile) -> bool {
        (self.global && profile.kind == VpnKind::Ssl) || self.blocked.contains(&profile.id)
    }
    pub fn verify(&mut self, profile: &Profile) -> bool {
        self.reconcile(Some(&profile.id), &mut NativeObserver);
        !self.blocked(profile)
    }
    fn reconcile(&mut self, target: Option<&str>, observer: &mut impl Observer) {
        let records = match fence::scan(&self.root, self.owner, self.uid) {
            Ok(records) => records,
            Err(_) => {
                self.global = true;
                return;
            }
        };
        let mut blocked = BTreeSet::new();
        for (profile, generation, record) in records {
            if target.is_some_and(|wanted| wanted != profile) {
                blocked.insert(profile);
                continue;
            }
            let verified = record
                .as_ref()
                .is_ok_and(|record| absent(record, observer).unwrap_or(false));
            if !verified
                || fence::remove(&self.root, self.owner, self.uid, &profile, generation).is_err()
            {
                blocked.insert(profile);
            }
        }
        self.global = false;
        self.blocked = blocked;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::connection::{
        fence::RetiredIdentity,
        routes::{AbandonedRoute, Key, Network, NextHop},
    };
    use std::{
        cell::RefCell,
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct Fake {
        process: Option<(bool, (u64, u64))>,
        fail: bool,
        route_present: bool,
        dns_present: bool,
        snapshot: Option<Snapshot>,
        calls: RefCell<Vec<&'static str>>,
        destructive: RefCell<Vec<&'static str>>,
    }
    impl Observer for Fake {
        fn process_absent(&mut self, p: &ProcessIdentity) -> Result<bool, ()> {
            self.calls.borrow_mut().push("process");
            if self.fail {
                return Err(());
            }
            Ok(self
                .process
                .is_none_or(|(running, start)| different_or_exited(p, running, start)))
        }
        fn service_absent(&mut self, _: &str) -> Result<bool, ()> {
            self.calls.borrow_mut().push("service");
            if self.fail { Err(()) } else { Ok(true) }
        }
        fn dns_absent(&mut self, _: &str) -> Result<bool, ()> {
            self.calls.borrow_mut().push("dns");
            if self.fail {
                Err(())
            } else {
                Ok(!self.dns_present)
            }
        }
        fn interface_absent(&mut self, _: &str, _: u32) -> Result<bool, ()> {
            self.calls.borrow_mut().push("interface");
            if self.fail { Err(()) } else { Ok(true) }
        }
        fn route_absent(&mut self, route: Route) -> Result<bool, ()> {
            self.calls.borrow_mut().push("route");
            if self.fail {
                Err(())
            } else if let Some(snapshot) = &self.snapshot {
                match snapshot.exact(route.key).map_err(|_| ())? {
                    None => Ok(true),
                    Some(record) => Ok(record.route().map_err(|_| ())? != route),
                }
            } else {
                Ok(!self.route_present)
            }
        }
        fn remove_route(&mut self, _: Route) -> Result<(), ()> {
            self.destructive.borrow_mut().push("route");
            Err(())
        }
        fn remove_interface(&mut self, _: &str, _: u32) -> Result<(), ()> {
            self.destructive.borrow_mut().push("interface");
            Err(())
        }
        fn terminate(&mut self, _: &ProcessIdentity) -> Result<(), ()> {
            self.destructive.borrow_mut().push("process");
            Err(())
        }
    }
    fn fake() -> Fake {
        Fake {
            process: None,
            fail: false,
            route_present: false,
            dns_present: false,
            snapshot: None,
            calls: RefCell::new(vec![]),
            destructive: RefCell::new(vec![]),
        }
    }
    fn profile(id: &str) -> Profile {
        serde_json::from_value(serde_json::json!({"id":id,"name":id,"kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap()
    }
    fn record(uid: u32, id: &str) -> Fence {
        Fence {
            version: 1,
            uid,
            profile: id.into(),
            generation: 1,
            kind: fence::Kind::Ssl,
            reason: "route_owner_pending".into(),
            incomplete: false,
            written_unix_ms: 1,
            service_id: Some("12345678-1234-4123-8123-123456789ABC".into()),
            dns_key: None,
            processes: vec![ProcessIdentity {
                pid: 42,
                start_sec: 123,
                start_usec: 456,
                program: "fixture".into(),
            }],
            interface: Some(Interface {
                name: "ppp0".into(),
                index: 3,
            }),
            sink: Some(Sink {
                name: "utun4".into(),
                index: 4,
                source: None,
            }),
            retired: vec![RetiredIdentity {
                interface: Some(Interface {
                    name: "ppp1".into(),
                    index: 5,
                }),
                sink: None,
            }],
            routes: vec![AbandonedRoute {
                route: Route {
                    key: Key {
                        network: "10.20.0.0/16".parse::<Network>().unwrap(),
                        scope: 0,
                    },
                    interface: 3,
                    next_hop: NextHop::Interface,
                },
                created: true,
            }],
        }
    }
    fn root() -> (Root, u32) {
        let path = std::env::current_dir().unwrap().join(format!(
            ".fence-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        (Root(path), unsafe { libc::geteuid() })
    }
    #[test]
    fn persisted_dns_key_blocks_recovery_until_absent() {
        let (root, uid) = root();
        let mut item = record(uid, "one");
        item.dns_key =
            Some("State:/Network/Service/12345678-1234-4123-8123-123456789ABC/DNS".into());
        fence::write(&root.0, uid, &item).unwrap();
        let loaded = fence::read(&root.0, uid, uid, "one", 1).unwrap().unwrap();
        assert_eq!(loaded.dns_key, item.dns_key);
        let mut recovery = Recovery {
            root: root.0.clone(),
            owner: uid,
            uid,
            global: false,
            blocked: BTreeSet::new(),
        };
        let mut observer = fake();
        observer.dns_present = true;
        recovery.reconcile(None, &mut observer);
        assert!(recovery.blocked(&profile("one")));
        assert!(observer.calls.borrow().contains(&"dns"));
        observer.dns_present = false;
        recovery.reconcile(Some("one"), &mut observer);
        assert!(!recovery.blocked(&profile("one")));
        assert!(fence::read(&root.0, uid, uid, "one", 1).unwrap().is_none());
        item.dns_key =
            Some("State:/Network/Service/12345678-1234-4123-8123-123456789ABB/DNS".into());
        assert!(absent(&item, &mut observer).is_err());
    }
    /// Persisted fence plus a routing snapshot, consumed through the actual
    /// recovery reconciliation and the controller dispatcher.
    pub(crate) struct RecoveryFixture {
        root: Root,
        uid: u32,
        state: std::sync::Mutex<(Recovery, Fake)>,
        verifies: std::sync::atomic::AtomicUsize,
    }
    impl RecoveryFixture {
        pub(crate) fn new() -> Self {
            let (root, uid) = root();
            let fence = record(uid, "one");
            fence::write(&root.0, uid, &fence).unwrap();
            let route = fence.routes[0].route;
            let mut observer = fake();
            observer.snapshot = Some(Snapshot {
                records: vec![super::super::routing::Record {
                    key: route.key,
                    interface: route.interface,
                    flags: libc::RTF_UP,
                    gateway: None,
                    source: None,
                }],
            });
            // Controls show that all three forbidden operations are observable
            // and rejected; clear them before exercising recovery.
            assert!(observer.remove_route(route).is_err());
            assert!(observer.remove_interface("ppp0", 3).is_err());
            assert!(observer.terminate(&fence.processes[0]).is_err());
            assert_eq!(
                &*observer.destructive.borrow(),
                &["route", "interface", "process"]
            );
            observer.destructive.borrow_mut().clear();
            let mut recovery = Recovery {
                root: root.0.clone(),
                owner: uid,
                uid,
                global: true,
                blocked: BTreeSet::new(),
            };
            recovery.reconcile(None, &mut observer);
            assert!(observer.destructive.borrow().is_empty());
            Self {
                root,
                uid,
                state: std::sync::Mutex::new((recovery, observer)),
                verifies: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        pub(crate) fn blocked(&self, profile: &Profile) -> bool {
            self.state.lock().unwrap().0.blocked(profile)
        }
        pub(crate) fn remove_observed_route(&self) {
            self.state
                .lock()
                .unwrap()
                .1
                .snapshot
                .as_mut()
                .unwrap()
                .records
                .clear();
        }
        pub(crate) fn verify(&self, profile: &Profile) -> bool {
            self.verifies.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().unwrap();
            let (recovery, observer) = &mut *state;
            recovery.reconcile(Some(&profile.id), observer);
            assert!(observer.destructive.borrow().is_empty());
            !recovery.blocked(profile)
        }
        pub(crate) fn fence_exists(&self) -> bool {
            fence::read(&self.root.0, self.uid, self.uid, "one", 1)
                .unwrap()
                .is_some()
        }
        pub(crate) fn verifies(&self) -> usize {
            self.verifies.load(Ordering::SeqCst)
        }
    }
    use std::os::unix::fs::DirBuilderExt;
    #[test]
    fn observation_errors_reused_pid_and_incomplete_record_fail_closed() {
        let record = record(501, "one");
        let mut observer = fake();
        observer.process = Some((true, (123, 456)));
        assert!(!absent(&record, &mut observer).unwrap());
        observer.process = Some((true, (123, 457)));
        assert!(absent(&record, &mut observer).unwrap());
        observer.fail = true;
        assert!(absent(&record, &mut observer).is_err());
        observer.fail = false;
        let mut incomplete = record.clone();
        incomplete.incomplete = true;
        assert!(!absent(&incomplete, &mut observer).unwrap());
        assert!(!observer.calls.borrow().contains(&"delete"));
    }
    #[test]
    fn reconciliation_removes_only_after_absence_and_blocks_invalid_by_profile() {
        let (root, uid) = root();
        let mut observer = fake();
        let mut first = record(uid, "one");
        fence::write(&root.0, uid, &first).unwrap();
        fence::write(&root.0, uid, &record(uid, "two")).unwrap();
        let mut recovery = Recovery {
            root: root.0.clone(),
            owner: uid,
            uid,
            global: true,
            blocked: BTreeSet::new(),
        };
        observer.route_present = true;
        recovery.reconcile(None, &mut observer);
        assert!(recovery.blocked(&profile("one")));
        assert!(recovery.blocked(&profile("two")));
        assert!(fence::read(&root.0, uid, uid, "one", 1).unwrap().is_some());
        observer.fail = true;
        observer.route_present = false;
        recovery.reconcile(Some("one"), &mut observer);
        assert!(recovery.blocked(&profile("one")));
        assert!(fence::read(&root.0, uid, uid, "one", 1).unwrap().is_some());
        observer.fail = false;
        observer.route_present = false;
        recovery.reconcile(Some("one"), &mut observer);
        assert!(!recovery.blocked(&profile("one")));
        assert!(recovery.blocked(&profile("two")));
        assert!(fence::read(&root.0, uid, uid, "one", 1).unwrap().is_none());
        first.profile = "bad".into();
        fence::write(&root.0, uid, &first).unwrap();
        let bad = root
            .0
            .join("fences")
            .join(uid.to_string())
            .join("bad-1.json");
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o644)).unwrap();
        recovery.reconcile(None, &mut observer);
        assert!(recovery.blocked(&profile("bad")));
        assert!(!recovery.blocked(&profile("two")));
        assert!(bad.exists());
    }
    #[test]
    fn untrusted_uid_and_owner_never_remove_fence() {
        let (root, uid) = root();
        fence::write(&root.0, uid, &record(uid, "one")).unwrap();
        let path = root
            .0
            .join("fences")
            .join(uid.to_string())
            .join("one-1.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["uid"] = serde_json::json!(uid.wrapping_add(1));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let mut recovery = Recovery {
            root: root.0.clone(),
            owner: uid,
            uid,
            global: false,
            blocked: BTreeSet::new(),
        };
        recovery.reconcile(None, &mut fake());
        assert!(recovery.blocked(&profile("one")));
        assert!(path.exists());
        recovery.owner = uid.wrapping_add(1);
        recovery.reconcile(None, &mut fake());
        assert!(recovery.blocked(&profile("one")));
        assert!(path.exists());
    }
}
