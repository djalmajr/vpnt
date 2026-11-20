//! Authenticated synchronous client for a single tunneld generation.
use super::protocol::{
    Backend, Credentials, ErrorCode, FrameError, Prepare, Request, Response, State, VERSION,
    decode_response, read_control, timed, write_control,
};
use crate::helper::local_socket::{Budget, connect_deadline, peer_uid};
use std::{
    fs,
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::Path,
    time::Instant,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Prepare,
    Credentials(Backend),
    Active,
}

pub struct Client {
    stream: Option<UnixStream>,
    phase: Phase,
}
impl Client {
    pub fn connect(path: &Path, deadline: Instant) -> Result<Self, FrameError> {
        Self::connect_as(path, deadline, 0, 0)
    }

    // UID overrides are only reachable by this module and its test fixtures.
    fn connect_as(
        path: &Path,
        deadline: Instant,
        owner_uid: u32,
        peer: u32,
    ) -> Result<Self, FrameError> {
        let budget = Budget::until(deadline, None)?;
        let parent = path.parent().ok_or(ErrorCode::PermissionDenied)?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let before = trusted_parent(parent, owner_uid)?;
        let stream = connect_deadline(path, &budget)?;
        let after = trusted_parent(parent, owner_uid)?;
        if before != after || peer_uid(&stream)? != peer {
            return Err(ErrorCode::PermissionDenied.into());
        }
        match exchange(&stream, Request::Hello { version: VERSION }, deadline)? {
            Response::Version { version: VERSION } => Ok(Self {
                stream: Some(stream),
                phase: Phase::Prepare,
            }),
            Response::Version { .. } => Err(ErrorCode::UnsupportedVersion.into()),
            _ => Err(ErrorCode::BadRequest.into()),
        }
    }

    pub fn prepare(&mut self, request: Prepare, deadline: Instant) -> Result<(), FrameError> {
        let backend = request.backend();
        self.in_phase(
            Phase::Prepare,
            Phase::Credentials(backend),
            |stream| match exchange(stream, request.into(), deadline)? {
                Response::Prepared {} => Ok(()),
                _ => Err(ErrorCode::BadRequest.into()),
            },
        )
    }

    /// Takes ownership so the write buffers are cleared on success or failure.
    pub fn send_credentials(
        &mut self,
        credentials: Credentials,
        deadline: Instant,
    ) -> Result<(), FrameError> {
        self.in_phase(
            Phase::Credentials(credentials.backend()),
            Phase::Active,
            |stream| credentials.write(&mut timed(stream, deadline)?),
        )
    }

    pub fn status(&mut self, deadline: Instant) -> Result<State, FrameError> {
        self.status_command(Request::Status {}, deadline)
    }

    pub fn stop(&mut self, deadline: Instant) -> Result<State, FrameError> {
        self.status_command(Request::Stop {}, deadline)
    }

    fn status_command(&mut self, request: Request, deadline: Instant) -> Result<State, FrameError> {
        self.in_phase(Phase::Active, Phase::Active, |stream| {
            match exchange(stream, request, deadline)? {
                Response::Status { state } => Ok(state),
                _ => Err(ErrorCode::BadRequest.into()),
            }
        })
    }

    fn in_phase<T>(
        &mut self,
        expected: Phase,
        next: Phase,
        operation: impl FnOnce(&UnixStream) -> Result<T, FrameError>,
    ) -> Result<T, FrameError> {
        let stream = self.stream.take().ok_or(ErrorCode::BadRequest)?;
        if self.phase != expected {
            return Err(ErrorCode::BadRequest.into());
        }
        let result = operation(&stream)?;
        self.stream = Some(stream);
        self.phase = next;
        Ok(result)
    }
}

fn trusted_parent(path: &Path, uid: u32) -> Result<(u64, u64), FrameError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(ErrorCode::PermissionDenied.into());
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn exchange(
    stream: &UnixStream,
    request: Request,
    deadline: Instant,
) -> Result<Response, FrameError> {
    let mut io = timed(stream, deadline)?;
    write_control(&mut io, &request)?;
    match read_control(&mut io, decode_response)? {
        Response::Error { code } => Err(code.into()),
        response => Ok(response),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunneld::protocol::{Command, Endpoint, FortinetRequest, ServerDecoder};
    use std::{
        io::{self, Read},
        os::unix::{
            fs::{DirBuilderExt, PermissionsExt},
            net::UnixListener,
        },
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    struct SocketFixture {
        dir: PathBuf,
        path: PathBuf,
        listener: UnixListener,
        owner: u32,
        peer: u32,
    }

    impl SocketFixture {
        fn new() -> Self {
            let dir = loop {
                let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let path =
                    std::env::temp_dir().join(format!("vpnt-td-{}-{id}", std::process::id()));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => break path,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create socket fixture: {error}"),
                }
            };
            let path = dir.join("test.sock");
            let fixture = (
                UnixListener::bind(&path),
                fs::metadata(&dir).map(|metadata| metadata.uid()),
            );
            let (listener, owner) = match fixture {
                (Ok(listener), Ok(owner)) => (listener, owner),
                (listener, owner) => {
                    let _ = fs::remove_file(&path);
                    let _ = fs::remove_dir(&dir);
                    panic!("create socket fixture: listener={listener:?}, owner={owner:?}");
                }
            };
            // SAFETY: geteuid has no preconditions.
            let peer = unsafe { libc::geteuid() };
            let fixture = Self {
                dir,
                path,
                listener,
                owner,
                peer,
            };
            fixture.listener.set_nonblocking(true).unwrap();
            fixture
        }

        fn accept(&self, expires: Instant) -> UnixStream {
            loop {
                match self.listener.accept() {
                    Ok((stream, _)) => return stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < expires =>
                    {
                        std::thread::yield_now();
                    }
                    Err(error) => panic!("accept socket fixture: {error}"),
                }
            }
        }
    }

    impl Drop for SocketFixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir(&self.dir);
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(3)
    }

    fn prepare() -> Prepare {
        Prepare::Fortinet(
            FortinetRequest::new(
                Endpoint::new("vpn.example".into(), 443).unwrap(),
                "user".into(),
                [42; 32],
            )
            .unwrap(),
        )
    }

    #[test]
    fn refuses_wrong_uid_before_sending_any_bytes() {
        let fixture = SocketFixture::new();
        let expires = Instant::now() + Duration::from_millis(300);
        assert!(matches!(
            Client::connect_as(&fixture.path, expires, fixture.owner, fixture.peer ^ 1),
            Err(FrameError::Protocol(ErrorCode::PermissionDenied))
        ));
        let mut accepted = fixture.accept(deadline());
        accepted
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            accepted.read(&mut byte).unwrap(),
            0,
            "no hello or secret before peer approval"
        );
    }

    #[test]
    fn refuses_unsafe_parent_before_connecting() {
        let fixture = SocketFixture::new();
        assert!(matches!(
            Client::connect_as(&fixture.path, deadline(), fixture.owner ^ 1, fixture.peer),
            Err(FrameError::Protocol(ErrorCode::PermissionDenied))
        ));
        for mode in [0o720, 0o702] {
            fs::set_permissions(&fixture.dir, fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(
                Client::connect_as(&fixture.path, deadline(), fixture.owner, fixture.peer),
                Err(FrameError::Protocol(ErrorCode::PermissionDenied))
            ));
        }
        assert_eq!(
            fixture.listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn trusted_peer_exchanges_one_generation() {
        let fixture = SocketFixture::new();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut decoder = ServerDecoder::new(fixture.accept(deadline()));
                decoder.hello(deadline()).unwrap();
                let Prepare::Fortinet(request) = decoder.prepare(deadline()).unwrap() else {
                    panic!("expected Fortinet");
                };
                assert_eq!(request.endpoint().host(), "vpn.example");
                assert_eq!(request.endpoint().port(), 443);
                assert_eq!(request.username(), "user");
                assert_eq!(request.certificate_sha256(), &[42; 32]);
                decoder.prepared(deadline()).unwrap();
                let secret = decoder.credentials(deadline()).unwrap();
                assert_eq!(secret.password(), "fixture-only");
                assert_eq!(secret.psk(), None);
                assert_eq!(decoder.command(deadline()).unwrap(), Command::Status);
                decoder.reply_status(State::Starting, deadline()).unwrap();
                for _ in 0..2 {
                    assert_eq!(decoder.command(deadline()).unwrap(), Command::Stop);
                    decoder.reply_status(State::Stopped, deadline()).unwrap();
                }
            });
            let mut client =
                Client::connect_as(&fixture.path, deadline(), fixture.owner, fixture.peer).unwrap();
            client.prepare(prepare(), deadline()).unwrap();
            client
                .send_credentials(Credentials::fortinet("fixture-only").unwrap(), deadline())
                .unwrap();
            assert_eq!(client.status(deadline()).unwrap(), State::Starting);
            assert_eq!(client.stop(deadline()).unwrap(), State::Stopped);
            assert_eq!(client.stop(deadline()).unwrap(), State::Stopped);
            server.join().unwrap();
        });
    }

    #[test]
    fn hello_response_expires_after_partial_read() {
        let fixture = SocketFixture::new();
        std::thread::scope(|scope| {
            let (close, wait_close) = std::sync::mpsc::channel();
            let fixture = &fixture;
            let server = scope.spawn(move || {
                let accepted = fixture.accept(deadline());
                let mut io = timed(&accepted, deadline()).unwrap();
                let request =
                    read_control(&mut io, crate::tunneld::protocol::decode_request).unwrap();
                assert!(matches!(request, Request::Hello { version: VERSION }));
                std::io::Write::write_all(&mut io, b"{\"op\":\"ver").unwrap();
                let _ = wait_close.recv_timeout(Duration::from_secs(3));
            });
            let expires = Instant::now() + Duration::from_millis(150);
            let result = Client::connect_as(&fixture.path, expires, fixture.owner, fixture.peer);
            close.send(()).unwrap();
            server.join().unwrap();
            assert!(matches!(
                result,
                Err(FrameError::Io(io::ErrorKind::TimedOut))
            ));
            assert!(Instant::now() >= expires);
        });
    }
}
