use super::{Error, State};
use crate::helper::protocol::{self, Message, Request};
use std::{
    io::{BufReader, Read, Write},
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const DEADLINE: Duration = Duration::from_secs(5);

pub(super) fn run(
    mut command: Command,
    requests: Receiver<Request>,
    output: SyncSender<Message>,
    stop: Arc<AtomicBool>,
    state: Arc<State>,
) {
    let result = (|| {
        let (mut stream, capability) = UnixStream::pair().map_err(|_| Error::Unavailable)?;
        stream
            .set_nonblocking(true)
            .map_err(|_| Error::Unavailable)?;
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(capability)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut child = command.spawn().map_err(|_| Error::Unavailable)?;
        drop(command); // close the parent's duplicate of the inherited endpoint
        let result = pump(&mut stream, &requests, &output, &stop);
        if let Err(error) = result {
            if let Ok(mut fault) = state.fault.lock() {
                *fault = Some(error);
            }
            stop.store(true, Ordering::Release);
        }
        let _ = stream.shutdown(Shutdown::Both);
        drop(stream);
        drop(requests); // queued credentials cannot outlive channel retirement
        // Even a protocol error only revokes admission. Keep/reap our direct
        // child without a kill deadline; its root cleanup owns the resource proof.
        let waited = child.wait().map_err(|_| Error::Unavailable);
        result.and(waited.map(|_| ()))
    })();
    if let Err(error) = result
        && let Ok(mut fault) = state.fault.lock()
    {
        *fault = Some(error);
    }
    state.finished.store(true, Ordering::Release);
}
fn pump(
    stream: &mut UnixStream,
    requests: &Receiver<Request>,
    output: &SyncSender<Message>,
    stop: &AtomicBool,
) -> Result<(), Error> {
    let mut incoming = Vec::new();
    let mut began = None;
    let mut sending: Option<(Zeroizing<Vec<u8>>, usize, Instant)> = None;
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        if sending.is_none() {
            match requests.try_recv() {
                Ok(request) => {
                    let mut frame = Zeroizing::new(Vec::new());
                    protocol::write_request(&mut *frame, &request)
                        .map_err(|_| Error::Unavailable)?;
                    sending = Some((frame, 0, Instant::now() + DEADLINE));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(()),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some((bytes, offset, deadline)) = &mut sending {
            if Instant::now() >= *deadline {
                return Err(Error::Unavailable);
            }
            match stream.write(&bytes[*offset..]) {
                Ok(0) => return Err(Error::Unavailable),
                Ok(count) => {
                    *offset += count;
                    if *offset == bytes.len() {
                        sending = None;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Error::Unavailable),
            }
        }
        for _ in 0..8 {
            let mut chunk = [0; 8192];
            let count = match stream.read(&mut chunk) {
                Ok(0) => return Err(Error::Unavailable),
                Ok(count) => count,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Error::Unavailable),
            };
            for byte in &chunk[..count] {
                if began.is_none() {
                    began = Some(Instant::now() + DEADLINE);
                }
                if *byte == b'\n' {
                    let mut frame = std::mem::take(&mut incoming);
                    frame.push(b'\n');
                    let message = protocol::read_message(&mut BufReader::new(frame.as_slice()))
                        .map_err(|e| {
                            if e == protocol::ProtocolError::UnsupportedVersion {
                                Error::Incompatible
                            } else {
                                Error::Unavailable
                            }
                        })?
                        .ok_or(Error::Unavailable)?;
                    output.try_send(message).map_err(|_| Error::Unavailable)?;
                    began = None;
                } else {
                    if incoming.len() >= protocol::MAX_MESSAGE_BYTES {
                        return Err(Error::Unavailable);
                    }
                    incoming.push(*byte);
                }
            }
        }
        if began.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(Error::Unavailable);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
