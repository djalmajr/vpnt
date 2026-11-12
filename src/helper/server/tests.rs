use super::*;
mod profiles;
use std::{
    io::{BufReader, Write},
    net::Shutdown,
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, net::UnixDatagram},
    },
    time::Instant,
};
fn caller(stream: UnixStream) -> Caller {
    Caller::from_fd(stream.into()).unwrap()
}
fn client(stream: UnixStream) -> BufReader<UnixStream> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    BufReader::new(stream)
}
#[test]
fn admin_does_not_take_the_network_lock_but_runtime_must() {
    let root = std::env::current_dir()
        .unwrap()
        .join("output/fixtures")
        .join(format!("helper-mode-lock-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(root.join(".controller.lock"))
        .unwrap();
    let uid = unsafe { libc::geteuid() };
    let runtime = ControllerLock::fixture(&root, uid).unwrap();
    assert!(matches!(
        mode_lock(Mode::Runtime, || ControllerLock::fixture(&root, uid)),
        Err(ErrorCode::ProfileBusy)
    ));
    assert!(matches!(
        mode_lock(Mode::Admin, || ControllerLock::fixture(&root, uid)),
        Ok(None)
    ));
    runtime.validate().unwrap();
    drop(runtime);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn only_closed_modes_and_connected_unix_stream_capabilities_are_admitted() {
    for arguments in [
        vec![],
        vec!["runtime", "501"],
        vec!["admin", "/tmp/config"],
        vec!["--fixture"],
        vec!["shell"],
    ] {
        assert!(
            Mode::parse(
                &arguments
                    .iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>()
            )
            .is_none()
        );
    }
    assert_eq!(Mode::parse(&["runtime".into()]), Some(Mode::Runtime));
    assert_eq!(Mode::parse(&["admin".into()]), Some(Mode::Admin));
    let (a, b) = UnixStream::pair().unwrap();
    assert_eq!(unsafe { libc::fcntl(a.as_raw_fd(), libc::F_SETFD, 0) }, 0);
    let value = caller(a);
    assert_eq!(value.uid, unsafe { libc::geteuid() });
    assert_ne!(
        unsafe { libc::fcntl(value.stream.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    drop(b);
    let file = std::fs::File::open("/dev/null").unwrap();
    assert!(Caller::from_fd(file.into()).is_err());
    let (a, _b) = UnixDatagram::pair().unwrap();
    assert!(Caller::from_fd(a.into()).is_err());
    let path = std::path::PathBuf::from(format!(
        "/private/tmp/vpnt-helper-peer-{}.sock",
        std::process::id()
    ));
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let named = UnixStream::connect(&path).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let client_result = Caller::from_fd(named.into());
    let server_result = Caller::from_fd(accepted.into());
    drop(listener);
    std::fs::remove_file(path).unwrap();
    assert!(client_result.is_err() && server_result.is_err());
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let tcp = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    assert!(Caller::from_fd(tcp.into()).is_err());
}
#[test]
fn runtime_carries_fragmented_requests_and_replies_and_closes_on_injection() {
    let (a, b) = UnixStream::pair().unwrap();
    let task = thread::spawn(move || {
        runtime(caller(a), |uid, requests, output| {
            assert_eq!(uid, unsafe { libc::geteuid() });
            let request = requests.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(request.id, "first");
            assert!(matches!(request.command, protocol::Command::Snapshot {}));
            output.send(Message::Accepted { id: request.id }).unwrap();
            assert!(requests.recv_timeout(Duration::from_secs(2)).is_err());
            Ok(())
        })
    });
    let mut c = client(b);
    for bytes in b"{\"id\":\"first\",\"command\":{\"type\":\"snapshot\"}}\n".chunks(3) {
        c.get_mut().write_all(bytes).unwrap();
    }
    assert!(
        matches!(protocol::read_message(&mut c).unwrap(),Some(Message::Accepted{id}) if id=="first")
    );
    c.get_mut().write_all(b"{\"id\":\"injected\",\"uid\":0,\"command\":{\"type\":\"save_profile\",\"profile\":{}}}\n").unwrap();
    assert!(matches!(
        protocol::read_message(&mut c).unwrap(),
        Some(Message::Fatal {
            error: ErrorCode::InvalidRequest
        })
    ));
    assert!(protocol::read_message(&mut c).unwrap().is_none());
    assert!(task.join().unwrap().is_ok());
}
#[test]
fn early_controller_failure_cancels_a_buffered_partial_request_without_waiting_for_eof() {
    let (a, mut b) = UnixStream::pair().unwrap();
    b.write_all(b"{\"id\":\"partial\"").unwrap();
    let started = Instant::now();
    let task =
        thread::spawn(move || runtime(caller(a), |_, _, _| Err(ErrorCode::UntrustedConfiguration)));
    let mut c = client(b);
    assert!(matches!(
        protocol::read_message(&mut c).unwrap(),
        Some(Message::Fatal {
            error: ErrorCode::UntrustedConfiguration
        })
    ));
    assert!(matches!(
        task.join().unwrap(),
        Err(ErrorCode::UntrustedConfiguration)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}
#[test]
fn half_closed_administration_waits_for_eof_and_never_mutates_on_a_second_document() {
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::current_dir()
        .unwrap()
        .join("output/fixtures")
        .join(format!(
            "helper-admin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(root.parent().unwrap()).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let store = ProfileStore::open(&root, unsafe { libc::geteuid() }).unwrap();
    let profile: crate::model::Profile = serde_json::from_value(serde_json::json!({
        "id":"one","name":"Fictional VPN","kind":"ssl","gateway":"vpn.example.test",
        "username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"",
        "probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"
    }))
    .unwrap();
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(".controller.lock"))
        .unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    let directory = root.clone();
    let task = thread::spawn(move || {
        admin(caller(a), |uid, request| {
            let store = ProfileStore::open(directory, uid).unwrap();
            apply_admin(&store, request)
        })
    });
    let mut c = client(b);
    protocol::write_admin_request(
        c.get_mut(),
        &protocol::AdminRequest {
            id: "save-one".into(),
            command: AdminCommand::SaveProfile {
                profile: profile.clone(),
            },
        },
    )
    .unwrap();
    assert!(store.load().unwrap().is_empty());
    c.get_mut().shutdown(Shutdown::Write).unwrap();
    assert!(
        matches!(protocol::read_message(&mut c).unwrap(),Some(Message::Accepted {id}) if id=="save-one")
    );
    assert!(task.join().unwrap().is_ok());
    let loaded = store.load().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, profile.id);
    assert_eq!(loaded[0].name, profile.name);
    for duplicate in [true, false] {
        let (a, b) = UnixStream::pair().unwrap();
        let directory = root.clone();
        let (observed, accepted) = mpsc::sync_channel(1);
        let task = thread::spawn(move || {
            admin(caller(a), |uid, request| {
                assert_eq!(uid, unsafe { libc::geteuid() });
                observed.send(()).unwrap();
                let store = ProfileStore::open(&directory, uid).unwrap();
                apply_admin(&store, request)
            })
        });
        let mut c = client(b);
        let wire=serde_json::to_vec(&serde_json::json!({"id":"admin-one","command":{"type":"remove_profile","id":profile.id}})).unwrap();
        c.get_mut().write_all(&wire).unwrap();
        c.get_mut().write_all(b"\n").unwrap();
        assert!(
            accepted.recv_timeout(Duration::from_millis(50)).is_err(),
            "no mutation before EOF"
        );
        assert_eq!(store.load().unwrap().len(), 1);
        if duplicate {
            c.get_mut().write_all(&wire).unwrap();
            c.get_mut().write_all(b"\n").unwrap();
        }
        c.get_mut().shutdown(Shutdown::Write).unwrap();
        let response = protocol::read_message(&mut c).unwrap().unwrap();
        if duplicate {
            assert!(matches!(
                response,
                Message::Fatal {
                    error: ErrorCode::InvalidRequest
                }
            ));
            assert!(task.join().unwrap().is_err());
            assert_eq!(store.load().unwrap().len(), 1);
        } else {
            assert!(matches!(response,Message::Accepted{id} if id=="admin-one"));
            assert!(task.join().unwrap().is_ok());
            assert!(store.load().unwrap().is_empty());
        }
    }
    // A changed per-profile reservation cannot authorize a profile write.
    std::fs::set_permissions(
        root.join(".profile-6f6e65.lock"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let result = apply_admin(
        &store,
        protocol::AdminRequest {
            id: "invalid-lock".into(),
            command: AdminCommand::SaveProfile { profile },
        },
    );
    assert!(matches!(
        result,
        Message::Failed {
            error: ErrorCode::UntrustedConfiguration,
            ..
        }
    ));
    assert!(store.load().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_admin_channel_kept_open_in_silence_expires_without_applying_an_operation() {
    let (a, b) = UnixStream::pair().unwrap();
    b.set_read_timeout(Some(Duration::from_secs(7))).unwrap();
    let task = thread::spawn(move || {
        admin(caller(a), |_, _| {
            panic!("silence must not create an operation")
        })
    });
    let mut c = BufReader::new(b);
    let started = Instant::now();
    assert!(matches!(
        protocol::read_message(&mut c).unwrap(),
        Some(Message::Fatal {
            error: ErrorCode::InvalidRequest
        })
    ));
    assert!(matches!(
        task.join().unwrap(),
        Err(ErrorCode::InvalidRequest)
    ));
    assert!(started.elapsed() >= Duration::from_millis(4500));
    assert!(started.elapsed() < Duration::from_secs(7));
}
