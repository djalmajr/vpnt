use super::*;
use crate::{
    connection::controller::profiles::{ProfileUse, Profiles},
    storage::ProfileStore,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::{atomic::AtomicU64, mpsc},
    time::Instant,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Catalog {
    profiles: Arc<Profiles>,
    cleanup: Arc<AtomicBool>,
}
struct Connection {
    profiles: Arc<Profiles>,
    profile: Profile,
    generation: u64,
    reservation: Option<ProfileUse>,
    cleanup: Arc<AtomicBool>,
}
impl Factory for Catalog {
    type Attempt = Connection;
    fn profiles(&self) -> Result<Option<Vec<Profile>>, ErrorCode> {
        self.profiles
            .load()
            .map(Some)
            .map_err(|_| ErrorCode::UntrustedConfiguration)
    }
    fn create(
        &self,
        profile: Profile,
        _uid: u32,
        generation: u64,
        _credentials: Credentials,
        _canceled: Arc<AtomicBool>,
    ) -> Connection {
        Connection {
            profiles: self.profiles.clone(),
            profile,
            generation,
            reservation: None,
            cleanup: self.cleanup.clone(),
        }
    }
    fn idle(&self) -> bool {
        self.profiles.idle()
    }
}
impl Attempt for Connection {
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        self.reservation = Some(
            self.profiles
                .begin(&self.profile, self.generation)
                .map_err(|_| Failure::unavailable())?,
        );
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        Ok(true)
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        self.reservation
            .as_ref()
            .unwrap()
            .validate()
            .map_err(|_| Failure::unavailable())
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        Ok(true)
    }
    fn cleanup(&mut self) -> bool {
        if !self.cleanup.load(Ordering::Acquire) {
            return false;
        }
        if let Some(r) = &self.reservation
            && r.complete().is_err()
        {
            return false;
        }
        self.reservation = None;
        true
    }
}
pub(super) struct Harness {
    pub(super) root: std::path::PathBuf,
    input: Option<SyncSender<Request>>,
    output: Receiver<Message>,
    task: Option<std::thread::JoinHandle<Result<(), ErrorCode>>>,
    pub(super) cleanup: Arc<AtomicBool>,
    next: u64,
}
impl Harness {
    pub(super) fn new(profiles: Vec<Profile>) -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "controller-catalog-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = ProfileStore::open(&root, fs::metadata(&root).unwrap().uid()).unwrap();
        for p in &profiles {
            store.save(p.clone()).unwrap();
        }
        let profiles_store = Arc::new(Profiles::fixture(store));
        let cleanup = Arc::new(AtomicBool::new(true));
        let factory = Catalog {
            profiles: profiles_store,
            cleanup: cleanup.clone(),
        };
        let (input, requests) = mpsc::sync_channel(32);
        let (send, output) = mpsc::sync_channel(64);
        let task = std::thread::spawn(move || {
            run(
                factory,
                501,
                profiles,
                requests,
                send,
                Timing {
                    poll: Duration::from_millis(5),
                    ..Timing::default()
                },
            )
        });
        Self {
            root,
            input: Some(input),
            output,
            task: Some(task),
            cleanup,
            next: 0,
        }
    }
    pub(super) fn store(&self) -> ProfileStore {
        ProfileStore::open(&self.root, fs::metadata(&self.root).unwrap().uid()).unwrap()
    }
    pub(super) fn send(&mut self, command: Command) -> String {
        self.next += 1;
        let id = format!("catalog-{}", self.next);
        let wire = serde_json::to_vec(&serde_json::json!({"id":id,"command":command})).unwrap();
        self.input
            .as_ref()
            .unwrap()
            .send(crate::helper::protocol::parse_request(&wire).unwrap())
            .unwrap();
        id
    }
    pub(super) fn wait(&self, mut accept: impl FnMut(&Message) -> bool) -> Message {
        let until = Instant::now() + Duration::from_secs(4);
        loop {
            let m = self
                .output
                .recv_timeout(until.saturating_duration_since(Instant::now()))
                .unwrap();
            if accept(&m) {
                return m;
            }
        }
    }
    pub(super) fn snapshot(&mut self) -> Message {
        let id = self.send(Command::Snapshot {});
        self.wait(
            |m| matches!(m,Message::Snapshot{id:got,..}|Message::Failed{id:got,..} if *got==id),
        )
    }
    pub(super) fn connect(&mut self, id: &str) {
        self.send(Command::Connect {
            id: id.into(),
            generation: 1,
            interval: crate::preferences::ProbeInterval::TEN,
            credentials: Credentials {
                password: "fictional".into(),
                psk: "".into(),
            },
        });
        self.wait(|m|matches!(m,Message::Changed{profile_id,generation:1,state:ConnectionState::Connected,..}if profile_id==id));
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.cleanup.store(true, Ordering::Release);
        self.input = None;
        while self.output.recv_timeout(Duration::from_millis(50)).is_ok() {}
        if let Some(task) = self.task.take() {
            assert!(task.join().unwrap().is_ok());
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
pub(super) fn profile(id: &str) -> Profile {
    serde_json::from_value(serde_json::json!({"id":id,"name":id,"kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap()
}
