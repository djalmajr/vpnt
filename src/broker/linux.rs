use crate::{
    helper::local_socket::{Budget, TimedStream, connect_deadline},
    netd::protocol as netd,
};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::{Duration, Instant},
};

const PROBE_INTERVAL: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) mod component {
    pub(in crate::broker) struct Flow;
    impl Flow {
        pub(in crate::broker) fn new() -> Self {
            Self
        }
        pub(in crate::broker) fn busy(&self) -> bool {
            false
        }
        pub(in crate::broker) fn blocks_retry(&self) -> bool {
            false
        }
        pub(in crate::broker) fn status(&self) -> Option<&'static str> {
            None
        }
        pub(in crate::broker) fn close(&mut self) {}
    }
}

pub(super) struct NetdProbe {
    socket: PathBuf,
    next: Option<Instant>,
    pending: Option<Receiver<bool>>,
    installed: bool,
}

impl NetdProbe {
    pub(super) fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            next: None,
            pending: None,
            installed: false,
        }
    }
    pub(super) fn poll(&mut self, now: Instant) {
        if let Some(receiver) = &self.pending {
            self.installed = match receiver.try_recv() {
                Ok(installed) => installed,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => false,
            };
            self.pending = None;
        }
        if self.next.is_some_and(|next| now < next) {
            return;
        }
        self.next = Some(now + PROBE_INTERVAL);
        let socket = self.socket.clone();
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let (send, receive) = mpsc::channel();
        if thread::Builder::new()
            .name("vpnt-netd-status".into())
            .spawn(move || {
                let _ = send.send(probe(&socket, deadline).unwrap_or(false));
            })
            .is_ok()
        {
            self.pending = Some(receive);
        } else {
            self.installed = false;
        }
    }
    pub(super) fn status(&self) -> &'static str {
        if self.installed {
            "installed"
        } else {
            "missing"
        }
    }
}

fn probe(socket: &Path, deadline: Instant) -> io::Result<bool> {
    let budget = Budget::until(deadline, None)?;
    let stream = connect_deadline(socket, &budget)?;
    let mut stream = TimedStream::with_budget(stream, budget, netd::MAX_LINE)?;
    stream.write_all(&netd::encode_request(&netd::Request::Hello {
        version: netd::VERSION,
    }))?;
    let mut reply = Vec::new();
    BufReader::new(stream)
        .take(netd::MAX_LINE as u64)
        .read_until(b'\n', &mut reply)?;
    Ok(matches!(
        netd::decode_response(&reply),
        Ok(netd::Response::Version(netd::VERSION))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bridge::Command,
        broker::{Broker, State},
        helper::client::Client,
        model::VpnKind,
        netd::protocol as netd,
        secrets::{Credentials, SecretError, SecretStore},
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{self, BufRead, BufReader, Write},
        os::unix::{
            fs::{DirBuilderExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    #[derive(Clone, Default)]
    struct Secrets {
        presence: Arc<AtomicUsize>,
        loads: Arc<AtomicUsize>,
    }
    impl SecretStore for Secrets {
        fn contains(&self, _: &str, _: VpnKind) -> Result<bool, SecretError> {
            self.presence.fetch_add(1, Ordering::Relaxed);
            Ok(false)
        }
        fn load(&self, _: &str, _: VpnKind) -> Result<Credentials, SecretError> {
            self.loads.fetch_add(1, Ordering::Relaxed);
            Err(SecretError::Missing)
        }
        fn save(&self, _: &str, _: VpnKind, _: &Credentials) -> Result<(), SecretError> {
            unreachable!()
        }
        fn remove(&self, _: &str, _: VpnKind) -> Result<(), SecretError> {
            unreachable!()
        }
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let home = PathBuf::from(std::env::var_os("HOME").unwrap());
            let path = home.join(format!(
                ".vpnt-broker-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn wait<T>(mut observe: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if let Some(observed) = observe() {
                return observed;
            }
            assert!(Instant::now() < deadline, "broker fixture timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }

    struct RuntimeBroker(Broker<Secrets>);
    impl Drop for RuntimeBroker {
        fn drop(&mut self) {
            if let Some(client) = self.0.client.as_mut() {
                client.close();
                wait(|| client.finished().then_some(()));
            }
        }
    }

    #[test]
    fn ovpn_connect_sends_empty_credentials_without_consulting_store() {
        let fixture = Fixture::new();
        let executable = fixture.0.join("fixture-runtime");
        fs::write(&executable, r#"#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

assert sys.argv[1:] == ["helper", "runtime"]
with os.fdopen(os.dup(0), "w") as out:
    for line in sys.stdin:
        packet = json.loads(line)
        command = packet["command"]
        if command["type"] == "snapshot":
            print(json.dumps({"type":"snapshot","id":packet["id"],"version":"FIXTURE_VERSION","protocol_version":FIXTURE_PROTOCOL,"build":None,
                              "profiles":[{"id":"one","name":"Fixture","kind":"ovpn","gateway":"vpn.example.test","username":"",
                                           "networks":[],"port":1194,"certificate":"","probeHost":"192.0.2.1","probePort":443,
                                           "probeMethod":"tcp","ovpn":{"certificateId":"01ab","module":"/fixture/token.so"}}],
                              "connections":[{"id":"one","generation":0,"state":"off","failures":0,"cleaning":False}]}), file=out, flush=True)
        elif command["type"] == "connect":
            assert command["id"] == "one" and command["generation"] == 1
            assert command["credentials"] == {"password":"","psk":""}
            Path(__file__).with_suffix(".accepted").touch()
"#.replace("FIXTURE_VERSION", env!("CARGO_PKG_VERSION")).replace("FIXTURE_PROTOCOL", &crate::helper::protocol::VERSION.to_string())).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let client = Client::linux_for_executable(&executable).unwrap();
        let secrets = Secrets::default();
        let mut fixture_broker = RuntimeBroker(Broker::new(Some(client), secrets.clone()));
        let broker = &mut fixture_broker.0;
        wait(|| {
            broker.poll();
            broker.ready.then_some(())
        });
        let initial = broker.snapshot();
        let view = &initial.vpns[0];
        assert_eq!(view.state, State::Off);
        assert!(!view.has_password && !view.has_psk);
        assert_eq!(secrets.presence.load(Ordering::Relaxed), 0);
        let result = broker
            .dispatch(
                Command::Connect { id: "one".into() },
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        assert_eq!(secrets.loads.load(Ordering::Relaxed), 0);
        assert_eq!(result.vpns[0].state, State::Connecting);
        assert!(!result.vpns[0].has_password && !result.vpns[0].has_psk);
        wait(|| {
            executable
                .with_extension("accepted")
                .is_file()
                .then_some(())
        });
    }

    #[test]
    fn linux_build_matches_the_running_executable_and_install_is_unsupported() {
        let mut broker = Broker::new(None, Secrets::default());
        let mut file = fs::File::open(std::env::current_exe().unwrap()).unwrap();
        let mut hasher = Sha256::new();
        io::copy(&mut file, &mut hasher).unwrap();
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(broker.expected_build.as_deref(), Some(expected.as_str()));
        let before = broker.next;
        for command in [Command::InstallHelper {}, Command::RemoveHelper {}] {
            let result = broker.dispatch(command, Instant::now() + Duration::from_secs(1));
            assert!(matches!(result, Err("unsupported")));
        }
        assert_eq!(broker.next, before);
        assert!(!broker.component.busy());
        assert!(broker.snapshot().component_operation.is_none());
    }

    fn accept(listener: &UnixListener) -> UnixStream {
        let (stream, _) = wait(|| match listener.accept() {
            Ok(value) => Some(value),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            Err(error) => panic!("{error}"),
        });
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut hello = String::new();
        BufReader::new(&stream).read_line(&mut hello).unwrap();
        assert!(
            matches!(netd::parse_request(hello.as_bytes()), Ok(netd::Request::Hello { version }) if version == netd::VERSION)
        );
        stream
    }

    #[test]
    fn netd_hello_is_polled_asynchronously_and_caches_connections() {
        let f = Fixture::new();
        let socket = f.0.join("netd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut broker = Broker::new(None, Secrets::default());
        broker.netd = Some(NetdProbe::new(socket));
        assert_eq!(broker.snapshot().helper, "missing");
        accept(&listener)
            .write_all(&netd::encode_response(&netd::Response::Version(
                netd::VERSION,
            )))
            .unwrap();
        let mut connections = 1;
        wait(|| (broker.snapshot().helper == "installed").then_some(()));
        let probe = broker.netd.as_mut().unwrap();
        let next = probe.next.unwrap();
        probe.poll(next - Duration::from_millis(1));
        if probe.pending.is_some() {
            accept(&listener)
                .write_all(&netd::encode_response(&netd::Response::Version(
                    netd::VERSION,
                )))
                .unwrap();
            connections += 1;
        }
        assert_eq!(connections, 1);
        probe.poll(next);
        let mut peer = accept(&listener);
        assert_eq!(broker.snapshot().helper, "installed");
        peer.write_all(&netd::encode_response(&netd::Response::Version(
            netd::VERSION + 1,
        )))
        .unwrap();
        wait(|| (broker.snapshot().helper == "missing").then_some(()));
    }

    #[test]
    fn netd_silent_or_missing_socket_stays_missing() {
        let f = Fixture::new();
        let socket = f.0.join("netd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut broker = Broker::new(None, Secrets::default());
        broker.netd = Some(NetdProbe::new(socket.clone()));
        assert_eq!(broker.snapshot().helper, "missing");
        let mut peer = accept(&listener);
        let started = Instant::now();
        let mut unexpected = String::new();
        BufReader::new(&mut peer)
            .read_line(&mut unexpected)
            .unwrap();
        assert!(unexpected.is_empty());
        assert!(started.elapsed() < Duration::from_secs(2));
        wait(|| {
            broker.poll();
            broker
                .netd
                .as_ref()
                .unwrap()
                .pending
                .is_none()
                .then_some(())
        });
        assert_eq!(broker.snapshot().helper, "missing");
        drop(listener);
        fs::remove_file(socket).unwrap();
        let probe = broker.netd.as_mut().unwrap();
        probe.poll(probe.next.unwrap());
        wait(|| {
            broker.poll();
            broker
                .netd
                .as_ref()
                .unwrap()
                .pending
                .is_none()
                .then_some(())
        });
        assert_eq!(broker.snapshot().helper, "missing");
    }
}
