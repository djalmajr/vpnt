use super::*;
use std::{
    path::PathBuf,
    sync::atomic::AtomicU64,
    time::{Duration, Instant},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(crate) struct Peer {
    client: Option<Client>,
    state: Arc<State>,
    root: PathBuf,
    pub marker: PathBuf,
}
impl Peer {
    pub fn new(mode: &str) -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "helper-client-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let marker = root.join("peer");
        let mut command = Command::new("/usr/bin/python3");
        command
            .arg(
                std::env::current_dir()
                    .unwrap()
                    .join("tests/fixtures/helper-client/peer.py"),
            )
            .arg(mode)
            .arg(&marker)
            .env("VPNT_MUST_NOT_REACH_HELPER", "fictional");
        let client = Client::fixture(command).unwrap();
        let state = client.state.clone();
        Self {
            client: Some(client),
            state,
            root,
            marker,
        }
    }
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
    pub fn take(&mut self) -> Client {
        self.client.take().unwrap()
    }
    pub fn advance(&self) {
        std::fs::write(self.marker.with_extension("advance"), b"").unwrap();
    }
    pub fn retiring(&self) -> bool {
        self.marker.with_extension("retiring").exists()
    }
    pub fn cleaned(&self) -> bool {
        self.marker.with_extension("cleaned").exists()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        // Release the fixture barrier even when a negative oracle panics.
        let _ = std::fs::write(self.marker.with_extension("allow_cleanup"), b"");
        if let Some(c) = &mut self.client {
            c.close();
        }
        let until = Instant::now() + Duration::from_secs(3);
        while !self.state.finished.load(Ordering::Acquire) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        if self.state.finished.load(Ordering::Acquire) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
fn wait(mut test: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(4);
    while !test() {
        assert!(Instant::now() < until, "helper client condition timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn a_private_child_receives_the_request_and_shutdown_waits_for_its_cleanup_without_killing_it() {
    let mut peer = Peer::new("flow");
    let mut client = peer.take();
    client
        .send(Request {
            id: "first".into(),
            command: super::super::protocol::Command::Snapshot {},
        })
        .unwrap();
    let mut got = false;
    wait(|| {
        got |= client
            .poll()
            .unwrap()
            .iter()
            .any(|m| matches!(m,Message::Snapshot {id,..} if id=="first"));
        got
    });
    client.close();
    wait(|| peer.retiring());
    assert!(!client.finished(), "EOF is not a cleanup exit receipt");
    wait(|| client.finished());
    assert!(peer.cleaned());
}
#[test]
fn malformed_and_incompatible_replies_fail_the_channel_instead_of_becoming_snapshots() {
    for (mode, expected) in [
        ("protocol", Error::Incompatible),
        ("old", Error::Incompatible),
        ("malformed", Error::Unavailable),
    ] {
        let mut peer = Peer::new(mode);
        let mut client = peer.take();
        client
            .send(Request {
                id: "first".into(),
                command: super::super::protocol::Command::Snapshot {},
            })
            .unwrap();
        wait(|| matches!(client.poll(),Err(e) if e==expected));
        if mode == "malformed" {
            wait(|| peer.retiring());
            assert!(
                !client.finished(),
                "protocol failure must reach the app while cleanup remains pending"
            );
            std::fs::write(peer.marker.with_extension("allow_cleanup"), b"").unwrap();
        }
        assert!(
            client
                .send(Request {
                    id: "later".into(),
                    command: super::super::protocol::Command::Snapshot {}
                })
                .is_err()
        );
        wait(|| client.finished());
        assert!(peer.cleaned());
    }
}

#[test]
fn a_genuine_protocol_two_helper_is_incompatible_and_receives_no_connect_command() {
    // `old2` sends a real v2 snapshot: its connections have no `failures`
    // field, so the frame fails the current typed shape before the version is
    // read. The helper client must still classify it as incompatible.
    let mut peer = Peer::new("old2");
    let mut client = peer.take();
    client
        .send(Request {
            id: "first".into(),
            command: super::super::protocol::Command::Snapshot {},
        })
        .unwrap();
    // Take the first terminal channel result and compare it, so a wrong
    // classification fails on the value instead of a waiter deadline.
    let deadline = Instant::now() + Duration::from_secs(4);
    let error = loop {
        match client.poll() {
            Ok(_) => {}
            Err(error) => break error,
        }
        assert!(
            Instant::now() < deadline,
            "helper client produced no terminal error"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(error, Error::Incompatible);
    // The channel is terminally failed: a credential-bearing request cannot be
    // written after the skew is detected.
    assert!(
        client
            .send(Request {
                id: "connect".into(),
                command: super::super::protocol::Command::Connect {
                    id: "one".into(),
                    generation: 1,
                    interval: crate::preferences::ProbeInterval::TEN,
                    credentials: crate::secrets::Credentials {
                        password: "fictional-client-secret".into(),
                        psk: "".into(),
                    },
                },
            })
            .is_err()
    );
    wait(|| client.finished());
    assert!(peer.cleaned());
    let commands =
        std::fs::read_to_string(peer.marker.with_extension("commands")).unwrap_or_default();
    assert!(
        !commands.lines().any(|command| command == "connect"),
        "an incompatible helper must never receive a connect command"
    );
}
