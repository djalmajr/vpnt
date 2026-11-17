//! Drain untrusted client output into bounded typed observations. Typed
//! observations stay in memory; the only retained copy of raw output is the
//! root-only `logs/openfortivpn.log` diagnostic, one timestamped line at a
//! time with secret-bearing lines redacted. Nothing raw reaches snapshots,
//! IPC, error values, app logs or the UI.
use super::ssl::{InterfaceName, SslFailure};
#[cfg(test)]
use crate::helper::redaction::SECRET_KEYWORDS;
use crate::helper::{
    paths,
    redaction::{REDACTED_LINE, contains_secret_keyword},
};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::ExitStatus,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

/// Same ceiling as the charon diagnostic: once reached, logging stops and the
/// connection continues without its diagnostic tail.
pub(crate) const OPENFORTIVPN_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const LONG_LINE: &str = "[linha longa descartada]";
const CURRENT_NAME: &str = "openfortivpn.log";
const PREVIOUS_NAME: &str = "openfortivpn.previous.log";

#[derive(Clone, Debug, Default)]
pub(super) struct Observation {
    pub candidate: Option<InterfaceName>,
    pub failure: Option<SslFailure>,
    pub split: Vec<(Ipv4Addr, u8)>,
    pub split_count: Option<usize>,
    pub split_invalid: bool,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_domains: Vec<String>,
    pub dns_count: Option<(usize, usize)>,
    pub dns_invalid: bool,
}

#[derive(Debug, Default)]
pub(super) struct Output {
    observed: Arc<Mutex<Observation>>,
    canceled: Arc<AtomicBool>,
    done: Arc<AtomicUsize>,
    workers: Vec<JoinHandle<()>>,
    log: Option<LogSender>,
    writer: Option<LogWriter>,
    finalized: bool,
}

impl Output {
    pub fn note_no_dns_servers(&self) {
        if let Some(log) = &self.log {
            log.push_line(
                "vpnt: domínios internos configurados, mas o gateway não publicou servidores DNS"
                    .as_bytes(),
                false,
            );
        }
    }
    pub fn note_no_dns_domain(&self) {
        if let Some(log) = &self.log {
            log.push_line(
                "vpnt: o gateway não publicou domínio; DNS não configurado".as_bytes(),
                false,
            );
        }
    }
    pub fn note_invalid_split(&self) {
        if let Some(log) = &self.log {
            log.push_line(
                "vpnt: o gateway não publicou rotas válidas".as_bytes(),
                false,
            );
        }
    }
    /// Enable per-attempt diagnostic logging. Never fails: any failure leaves
    /// logging disabled and the connection proceeds without it.
    pub fn open_log(&mut self, state: &Path, owner: u32) {
        let mut log = DiagnosticLog::open(state, owner);
        if log.file.is_some()
            && let Ok((sender, writer)) = start_writer(move |record| log.push_bytes(record))
        {
            self.log = Some(sender);
            self.writer = Some(writer);
        }
    }
    pub fn attach(&mut self, pipe: impl Read + AsRawFd + Send + 'static) -> io::Result<()> {
        let fd = pipe.as_raw_fd();
        // SAFETY: pipe owns a live descriptor and fcntl takes integer flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let (observed, canceled, done, log) = (
            Arc::clone(&self.observed),
            Arc::clone(&self.canceled),
            Arc::clone(&self.done),
            self.log.clone(),
        );
        self.workers.push(
            thread::Builder::new()
                .name("vpnt-ssl-output".into())
                .spawn(move || {
                    drain(pipe, &observed, &canceled, &log);
                    done.fetch_add(1, Ordering::Release);
                })?,
        );
        Ok(())
    }
    pub fn snapshot(&self) -> Observation {
        self.observed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
    /// Drain pipes before capturing the final observation and closing the log.
    pub fn finish_with_status(&mut self, status: Option<ExitStatus>) {
        self.finish();
        if !self.finalized {
            self.finalized = true;
            let candidate = self.snapshot().candidate.is_some();
            if let Some(writer) = self.writer.take() {
                if let Some(sender) = self.log.take() {
                    if sender.enabled.load(Ordering::Acquire) {
                        *writer
                            .summary
                            .lock()
                            .unwrap_or_else(|error| error.into_inner()) =
                            Some(completion_record(status, candidate));
                    }
                    drop(sender);
                }
                writer.wait();
            }
        }
    }
    pub fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_millis(100);
        while self.done.load(Ordering::Acquire) < self.workers.len() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        self.canceled.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Rotate `logs/openfortivpn.log` for one attempt, before the client spawns:
/// the previous attempt moves to `logs/openfortivpn.previous.log` and a new
/// empty 0600 file takes its place. Same guarantees as the charon log:
/// `logs/` 0700 owned by `owner`, no symlink followed, no link target
/// touched. Production callers ignore the error: a missing log never fails
/// the connection.
pub(crate) fn prepare_log(state: &Path, owner: u32) -> io::Result<()> {
    let path = paths::openfortivpn_log(state);
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state has no parent"))?;
    // `logs` may not exist yet (an SSL-only state, or a fresh fixture root).
    // mkdir never follows a final symlink; whatever already exists is
    // validated below and never repaired.
    match fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {
            // A restrictive umask may have removed owner bits from the
            // directory just created: set 0700 through its descriptor, never
            // by path, and only on this freshly created object.
            let created = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory)?;
            let meta = created.metadata()?;
            if !meta.is_dir() || meta.uid() != owner {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "diagnostic directory owner changed",
                ));
            }
            created.set_permissions(fs::Permissions::from_mode(0o700))?;
            // No fsync on the connection path: the diagnostic is best effort.
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    validate_directory(directory, owner)?;
    present(directory, CURRENT_NAME, owner)?;
    present(directory, PREVIOUS_NAME, owner)?;
    if fs::symlink_metadata(&path)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
    {
        fs::rename(&path, directory.join(PREVIOUS_NAME))?;
    }
    // create_new uses O_EXCL | O_CREAT with O_NOFOLLOW and mode 0600.
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    if !present(directory, CURRENT_NAME, owner)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic changed after create",
        ));
    }
    validate_directory(directory, owner)
}

fn validate_directory(directory: &Path, owner: u32) -> io::Result<()> {
    let denied = || io::Error::new(io::ErrorKind::PermissionDenied, "diagnostic directory");
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .map_err(|_| denied())?;
    let named = fs::symlink_metadata(directory).map_err(|_| denied())?;
    let opened = dir.metadata().map_err(|_| denied())?;
    if !named.is_dir()
        || named.uid() != owner
        || named.mode() & 0o7777 != 0o700
        || named.dev() != opened.dev()
        || named.ino() != opened.ino()
    {
        return Err(denied());
    }
    crate::fs_permissions::check_file(&dir, true)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "diagnostic directory acl"))
}

// Never read log contents into helper memory. Refuse links, foreign ownership,
// permissions and ACLs on either name in the protected directory.
fn present(directory: &Path, name: &str, owner: u32) -> io::Result<bool> {
    let denied = || io::Error::new(io::ErrorKind::PermissionDenied, "diagnostic changed");
    let path = directory.join(name);
    let named = match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(denied()),
        Ok(meta) => meta,
    };
    if !named.is_file()
        || named.uid() != owner
        || named.mode() & 0o7777 != 0o600
        || named.nlink() != 1
    {
        return Err(denied());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| denied())?;
    let opened = file.metadata().map_err(|_| denied())?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(denied());
    }
    crate::fs_permissions::check_file(&file, true).map_err(|_| denied())?;
    validate_directory(directory, owner)?;
    Ok(true)
}

#[derive(Debug, Default)]
struct DiagnosticLog {
    file: Option<fs::File>,
}

impl DiagnosticLog {
    fn disabled() -> Self {
        Self { file: None }
    }
    fn open(state: &Path, owner: u32) -> Self {
        match open_current(state, owner) {
            Some(file) => Self { file: Some(file) },
            None => Self::disabled(),
        }
    }
}

fn line_record(line: &[u8], discarded: bool) -> Zeroizing<Vec<u8>> {
    let mut record = Zeroizing::new(Vec::with_capacity(line.len() + 16));
    record.extend_from_slice(timestamp().as_bytes());
    record.push(b' ');
    if discarded {
        record.extend_from_slice(LONG_LINE.as_bytes());
    } else if contains_secret_keyword(line) {
        record.extend_from_slice(REDACTED_LINE.as_bytes());
    } else {
        record.extend_from_slice(line);
    }
    record.push(b'\n');
    record
}

fn completion_record(status: Option<ExitStatus>, candidate: bool) -> Zeroizing<Vec<u8>> {
    use std::os::unix::process::ExitStatusExt;
    let state = match status {
        Some(status) => match (status.code(), status.signal()) {
            (Some(code), _) => format!("código {code}"),
            (_, Some(signal)) => format!("sinal {signal}"),
            _ => "desconhecido".into(),
        },
        None => "desconhecido".into(),
    };
    let line = format!(
        "tentativa encerrada: {state}; candidato de interface: {}\n",
        if candidate { "sim" } else { "não" }
    );
    Zeroizing::new(line.into_bytes())
}

impl DiagnosticLog {
    /// Cap-checked append shared by content and completion lines: past the
    /// ceiling the log goes quiet and the connection continues. A write error
    /// disables logging the same way; it never fails the drain.
    fn push_bytes(&mut self, record: &[u8]) -> bool {
        let Some(file) = self.file.as_mut() else {
            return false;
        };
        let len = file.metadata().map(|meta| meta.len()).unwrap_or(u64::MAX);
        if len.saturating_add(record.len() as u64) > OPENFORTIVPN_LOG_MAX_BYTES {
            self.file = None;
            return false;
        }
        if file.write_all(record).is_err() {
            self.file = None;
            return false;
        }
        true
    }
}

const LOG_QUEUE_CAPACITY: usize = 128;
type Record = Zeroizing<Vec<u8>>;

#[derive(Clone, Debug)]
struct LogSender {
    tx: mpsc::SyncSender<Record>,
    enabled: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl LogSender {
    fn push_line(&self, line: &[u8], discarded: bool) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let record = line_record(line, discarded);
        match self.tx.try_send(record) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_record)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Disconnected(_record)) => {
                self.enabled.store(false, Ordering::Release);
            }
        }
    }
}

#[derive(Debug)]
struct LogWriter {
    summary: Arc<Mutex<Option<Record>>>,
    thread: JoinHandle<()>,
}

impl LogWriter {
    fn wait(self) {
        let deadline = Instant::now() + Duration::from_millis(100);
        while !self.thread.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        if self.thread.is_finished() {
            let _ = self.thread.join();
        }
    }
}

fn start_writer(
    mut write: impl FnMut(&[u8]) -> bool + Send + 'static,
) -> io::Result<(LogSender, LogWriter)> {
    let (tx, rx) = mpsc::sync_channel::<Record>(LOG_QUEUE_CAPACITY);
    let enabled = Arc::new(AtomicBool::new(true));
    let dropped = Arc::new(AtomicUsize::new(0));
    let summary = Arc::new(Mutex::new(None::<Record>));
    let worker_enabled = Arc::clone(&enabled);
    let worker_dropped = Arc::clone(&dropped);
    let worker_summary = Arc::clone(&summary);
    let thread = thread::Builder::new()
        .name("vpnt-ssl-log".into())
        .spawn(move || {
            let write_drops = |write: &mut dyn FnMut(&[u8]) -> bool| {
                let count = worker_dropped.swap(0, Ordering::AcqRel);
                if count == 0 {
                    true
                } else {
                    let record =
                        Zeroizing::new(format!("[{count} linhas descartadas]\n").into_bytes());
                    write(&record)
                }
            };
            for record in rx {
                if !write_drops(&mut write) || !write(&record) {
                    worker_enabled.store(false, Ordering::Release);
                    return;
                }
            }
            if write_drops(&mut write) {
                let record = worker_summary
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take();
                if let Some(record) = record {
                    let _ = write(&record);
                }
            }
            worker_enabled.store(false, Ordering::Release);
        })?;
    Ok((
        LogSender {
            tx,
            enabled,
            dropped,
        },
        LogWriter { summary, thread },
    ))
}

fn open_current(state: &Path, owner: u32) -> Option<fs::File> {
    let path = paths::openfortivpn_log(state);
    let directory = path.parent()?;
    validate_directory(directory, owner).ok()?;
    if !present(directory, CURRENT_NAME, owner).ok()? {
        return None;
    }
    let file = OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
        .ok()?;
    let meta = file.metadata().ok()?;
    let named = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file()
        || meta.uid() != owner
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.dev() != named.dev()
        || meta.ino() != named.ino()
    {
        return None;
    }
    crate::fs_permissions::check_file(&file, true).ok()?;
    Some(file)
}

// Wall clock, local `HH:MM:SS`, like the cleanup log and charon's
// `%H:%M:%S`: attempts correlate with user reports and the sibling log.
// Monotonic elapsed time would need an attempt start the drain never sees.
fn timestamp() -> String {
    // SAFETY: time/localtime_r write only initialized stack-owned objects.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return "00:00:00".into();
        }
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

fn observe(line: &[u8], discarded: bool, observed: &Mutex<Observation>, log: &Option<LogSender>) {
    if !discarded {
        parse(
            line,
            &mut observed.lock().unwrap_or_else(|error| error.into_inner()),
        );
    }
    if let Some(log) = log {
        log.push_line(line, discarded);
    }
}

fn drain(
    mut pipe: impl Read + AsRawFd,
    observed: &Mutex<Observation>,
    canceled: &AtomicBool,
    log: &Option<LogSender>,
) {
    let mut line = Zeroizing::new(Vec::with_capacity(4096));
    let mut chunk = Zeroizing::new([0; 4096]);
    let mut discarded = false;
    while !canceled.load(Ordering::Acquire) {
        let mut poll = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live descriptor and one correctly sized poll output.
        let result = unsafe { libc::poll(&mut poll, 1, 50) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if result == 0 {
            continue;
        }
        let length = match pipe.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        for byte in &chunk[..length] {
            if *byte == b'\n' {
                observe(&line, discarded, observed, log);
                line.zeroize();
                discarded = false;
            } else if !discarded {
                if line.len() == 4096 {
                    line.zeroize();
                    discarded = true;
                } else {
                    line.push(*byte);
                }
            }
        }
        chunk.zeroize();
    }
    // Incomplete/oversized lines are not candidates. Zeroizing also clears a
    // partial credential-bearing line when cancellation interrupts the reader.
}

fn parse(line: &[u8], observed: &mut Observation) {
    if let Some(value) = line.strip_prefix(b"INFO:   vpnt: dns-server ") {
        let server = std::str::from_utf8(value)
            .ok()
            .and_then(|s| s.parse::<Ipv4Addr>().ok());
        if observed.dns_count.is_some()
            || observed.dns_servers.len() >= 2
            || server.is_none_or(|ip| {
                ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || ip.is_link_local()
                    || ip.octets()[0] == 0
            })
        {
            observed.dns_invalid = true;
        } else {
            observed.dns_servers.push(server.unwrap());
        }
        return;
    }
    if let Some(value) = line.strip_prefix(b"INFO:   vpnt: dns-domain ") {
        let domain = std::str::from_utf8(value).ok().filter(|value| {
            !value.is_empty()
                && value.len() <= 253
                && value.is_ascii()
                && value.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })
        });
        match domain {
            Some(domain) if observed.dns_count.is_none() && observed.dns_domains.len() < 8 => {
                observed.dns_domains.push(domain.to_ascii_lowercase());
            }
            _ => observed.dns_invalid = true,
        }
        return;
    }
    if let Some(value) = line.strip_prefix(b"INFO:   vpnt: dns ") {
        let count = std::str::from_utf8(value).ok().and_then(|s| {
            let (servers, domains) = s.split_once(' ')?;
            let a = servers.parse::<usize>().ok()?;
            let b = domains.parse::<usize>().ok()?;
            (servers == a.to_string() && domains == b.to_string() && a <= 2 && b <= 8)
                .then_some((a, b))
        });
        if observed.dns_count.is_some()
            || count.is_none()
            || count != Some((observed.dns_servers.len(), observed.dns_domains.len()))
        {
            observed.dns_invalid = true;
        } else {
            observed.dns_count = count;
        }
        return;
    }
    if let Some(value) = line.strip_prefix(b"INFO:   vpnt: split-route ") {
        if observed.split_count.is_some() || observed.split.len() >= 64 {
            observed.split_invalid = true;
            return;
        }
        let parsed = std::str::from_utf8(value).ok().and_then(|text| {
            let (addr, mask) = text.split_once('/')?;
            let addr = addr.parse::<Ipv4Addr>().ok()?;
            let mask = mask.parse::<Ipv4Addr>().ok()?;
            let bits = u32::from(mask);
            let prefix = bits.leading_ones() as u8;
            if bits != u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
                || u32::from(addr) & bits != u32::from(addr)
            {
                return None;
            }
            Some((addr, prefix))
        });
        if let Some(route) = parsed {
            observed.split.push(route);
        } else {
            observed.split_invalid = true;
        }
        return;
    }
    if let Some(value) = line.strip_prefix(b"INFO:   vpnt: split-routes ") {
        let count = std::str::from_utf8(value).ok().and_then(|s| {
            let n = s.parse::<usize>().ok()?;
            (s == n.to_string() && n <= 64).then_some(n)
        });
        if observed.split_count.is_some() || count.is_none() {
            observed.split_invalid = true;
        } else {
            observed.split_count = count;
        }
        return;
    }
    if line==b"ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc." {
        observed.failure=Some(SslFailure::CredentialsRejected);
    } else if (line==b"ERROR:  connect: Connection timed out" || line==b"ERROR:  connect: Operation timed out") && observed.failure.is_none() {
        observed.failure=Some(SslFailure::GatewayTimeout);
    } else if let Some(value)=line.strip_prefix(b"INFO:   Interface ").and_then(|value|value.strip_suffix(b" is UP."))
        && let Ok(name)=std::str::from_utf8(value)
        && let Some(name)=InterfaceName::parse(name)
    {
        observed.candidate=Some(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::{
            fd::FromRawFd,
            unix::{
                fs::{PermissionsExt, symlink},
                process::ExitStatusExt,
            },
        },
        sync::atomic::AtomicU64,
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn dns_output_requires_strict_values_and_complete_counts() {
        let mut seen = Observation::default();
        for line in [
            "INFO:   vpnt: dns-server 172.20.0.4",
            "INFO:   vpnt: dns-server 172.20.0.3",
            "INFO:   vpnt: dns-domain CIT.Example",
            "INFO:   vpnt: dns 2 1",
        ] {
            parse(line.as_bytes(), &mut seen);
        }
        assert!(!seen.dns_invalid);
        assert_eq!(seen.dns_domains, ["cit.example"]);
        assert_eq!(seen.dns_count, Some((2, 1)));
        for line in [
            "INFO:   vpnt: dns-domain bad_name",
            "INFO:   vpnt: dns-domain -bad.example",
            "INFO:   vpnt: dns-server 127.0.0.1",
            "INFO:   vpnt: dns-server 224.0.0.1",
            "INFO:   vpnt: dns-server 0.0.0.0",
            "INFO:   vpnt: dns invalid",
            "INFO:   vpnt: dns 2 1",
        ] {
            let mut seen = Observation::default();
            parse(line.as_bytes(), &mut seen);
            assert!(seen.dns_invalid, "{line}");
        }
    }

    #[test]
    fn split_output_is_bounded_and_strict() {
        let mut observation = Observation::default();
        for line in [
            "INFO:   Connected to gateway.",
            "INFO:   Authenticated.",
            "INFO:   Remote gateway has allocated a VPN.",
            "INFO:   vpnt: split-route 10.0.0.0/255.0.0.0",
            "INFO:   vpnt: split-route 172.20.0.0/255.255.0.0",
            "INFO:   vpnt: split-route 192.168.1.0/255.255.255.0",
            "INFO:   vpnt: split-routes 3",
            "INFO:   Interface ppp0 is UP.",
            "INFO:   Tunnel is up and running.",
        ] {
            parse(line.as_bytes(), &mut observation);
        }
        assert_eq!(observation.split_count, Some(3));
        assert_eq!(observation.candidate.as_ref().unwrap().as_str(), "ppp0");
        assert_eq!(
            observation.split,
            vec![
                ("10.0.0.0".parse().unwrap(), 8),
                ("172.20.0.0".parse().unwrap(), 16),
                ("192.168.1.0".parse().unwrap(), 24)
            ]
        );
        assert!(!observation.split_invalid);

        for line in [
            "INFO:   vpnt: split-route 10.0.0.0/255.0.255.0",
            "INFO:   vpnt: split-route 10.1.0.1/255.255.0.0",
            "INFO:   vpnt: split-routes invalid",
        ] {
            let mut observation = Observation::default();
            parse(line.as_bytes(), &mut observation);
            assert!(observation.split_invalid, "{line}");
        }
        let mut observation = Observation::default();
        for _ in 0..65 {
            parse(
                b"INFO:   vpnt: split-route 10.0.0.0/255.0.0.0",
                &mut observation,
            );
        }
        assert!(observation.split_invalid);
        assert_eq!(observation.split.len(), 64);
    }
    struct State {
        directory: std::path::PathBuf,
    }
    impl State {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "vpnt-ssl-log-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&directory).unwrap();
            Self { directory }
        }
        fn owner() -> u32 {
            // SAFETY: UID queries have no memory preconditions.
            unsafe { libc::geteuid() }
        }
        fn log(&self) -> std::path::PathBuf {
            paths::openfortivpn_log(&self.directory)
        }
    }
    impl Drop for State {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    fn run_drain(input: &[u8], mut log: DiagnosticLog) -> Observation {
        let (sender, writer) = start_writer(move |record| log.push_bytes(record)).unwrap();
        let mut ends = [0; 2];
        // SAFETY: on success both entries are live owned pipe descriptors.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        // SAFETY: each descriptor transfers to exactly one owner here.
        let reader = unsafe { fs::File::from_raw_fd(ends[0]) };
        let mut pipe_writer = unsafe { fs::File::from_raw_fd(ends[1]) };
        pipe_writer.write_all(input).unwrap();
        drop(pipe_writer);
        let observed = Mutex::new(Observation::default());
        let canceled = AtomicBool::new(false);
        drain(reader, &observed, &canceled, &Some(sender));
        writer.wait();
        observed.into_inner().unwrap()
    }

    #[test]
    fn log_records_and_queue_use_zeroizing_buffers() {
        let _: Zeroizing<Vec<u8>> = line_record(b"fictional", false);
        let _: Zeroizing<Vec<u8>> = completion_record(None, false);
        let (sender, writer) = start_writer(|_| true).unwrap();
        let _: mpsc::SyncSender<Zeroizing<Vec<u8>>> = sender.tx.clone();
        let _: &Mutex<Option<Zeroizing<Vec<u8>>>> = &writer.summary;
        drop(sender);
        writer.wait();
    }

    #[test]
    fn child_exit_with_output_still_in_pipe_precedes_summary() {
        use std::process::{Command, Stdio};
        let state = State::new();
        prepare_log(&state.directory, State::owner()).unwrap();
        let mut child = Command::new("/usr/bin/printf")
            .arg("INFO:   Interface ppp42 is UP.\n")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());
        let mut output = Output::default();
        output.open_log(&state.directory, State::owner());
        output.attach(stdout).unwrap();
        output.finish_with_status(Some(status));
        output.finish_with_status(Some(status));
        assert_eq!(output.snapshot().candidate.unwrap().as_str(), "ppp42");
        let text = fs::read_to_string(state.log()).unwrap();
        assert_eq!(text.matches("tentativa encerrada:").count(), 1);
        assert!(
            text.lines()
                .last()
                .unwrap()
                .contains("candidato de interface: sim"),
            "{text}"
        );
    }

    #[test]
    fn blocked_writer_does_not_block_drain_or_finish_and_reports_drops() {
        use std::sync::mpsc;
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (records_tx, records_rx) = mpsc::channel();
        let mut first = true;
        let (sender, writer) = start_writer(move |record| {
            if first {
                first = false;
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }
            records_tx
                .send(String::from_utf8(record.to_vec()).unwrap())
                .unwrap();
            true
        })
        .unwrap();
        sender.push_line(b"first", false);
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        for _ in 0..LOG_QUEUE_CAPACITY + 3 {
            sender.push_line(b"queued", false);
        }
        assert_eq!(sender.dropped.load(Ordering::Relaxed), 3);
        let mut output = Output::default();
        output.log = Some(sender);
        output.writer = Some(writer);
        let mut ends = [0; 2];
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        let reader = unsafe { fs::File::from_raw_fd(ends[0]) };
        let mut pipe_writer = unsafe { fs::File::from_raw_fd(ends[1]) };
        pipe_writer.write_all(b"ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.\nINFO:   Interface ppp19 is UP.\n").unwrap();
        drop(pipe_writer);
        output.attach(reader).unwrap();
        let start = Instant::now();
        output.finish_with_status(None);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "finish took {elapsed:?}"
        );
        assert_eq!(
            output.snapshot().failure,
            Some(SslFailure::CredentialsRejected)
        );
        assert_eq!(output.snapshot().candidate.unwrap().as_str(), "ppp19");
        release_tx.send(()).unwrap();
        let mut records = Vec::new();
        while let Ok(record) = records_rx.recv_timeout(Duration::from_secs(2)) {
            records.push(record);
        }
        assert_eq!(records[1], "[5 linhas descartadas]\n", "{records:?}");
        assert!(records[2].contains("queued"), "{records:?}");
        assert!(
            records
                .last()
                .unwrap()
                .contains("candidato de interface: sim")
        );
    }

    #[test]
    fn final_summary_waits_for_pending_pipe_output_and_is_unique() {
        use std::sync::mpsc;
        struct GatedReader {
            file: fs::File,
            ready: mpsc::Sender<()>,
            release: Option<mpsc::Receiver<()>>,
        }
        impl AsRawFd for GatedReader {
            fn as_raw_fd(&self) -> std::os::fd::RawFd {
                self.file.as_raw_fd()
            }
        }
        impl Read for GatedReader {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if let Some(release) = self.release.take() {
                    self.ready.send(()).unwrap();
                    release.recv().unwrap();
                }
                self.file.read(bytes)
            }
        }
        let state = State::new();
        prepare_log(&state.directory, State::owner()).unwrap();
        let mut ends = [0; 2];
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        let reader = unsafe { fs::File::from_raw_fd(ends[0]) };
        let mut writer = unsafe { fs::File::from_raw_fd(ends[1]) };
        writer
            .write_all(b"INFO:   Interface ppp42 is UP.\n")
            .unwrap();
        drop(writer);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut output = Output::default();
        output.open_log(&state.directory, State::owner());
        output
            .attach(GatedReader {
                file: reader,
                ready: ready_tx,
                release: Some(release_rx),
            })
            .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            started_tx.send(()).unwrap();
            output.finish_with_status(None);
            output.finish_with_status(None);
            output
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        thread::sleep(Duration::from_millis(30));
        release_tx.send(()).unwrap();
        let output = handle.join().unwrap();
        assert_eq!(output.snapshot().candidate.unwrap().as_str(), "ppp42");
        let text = fs::read_to_string(state.log()).unwrap();
        assert_eq!(text.matches("tentativa encerrada:").count(), 1);
        assert!(
            text.lines()
                .last()
                .unwrap()
                .contains("candidato de interface: sim"),
            "{text}"
        );
    }

    #[test]
    fn only_exact_bounded_messages_become_typed_observations() {
        let mut observed = Observation::default();
        for line in [
            b"INFO:   Tunnel is up and running.".as_slice(),
            b"INFO:   Interface en0 is UP.",
            b"INFO:   Interface ppp1;touch is UP.",
            b"password: fictional",
        ] {
            parse(line, &mut observed);
        }
        assert!(observed.candidate.is_none());
        assert!(observed.failure.is_none());
        parse(b"INFO:   Interface ppp12 is UP.", &mut observed);
        assert_eq!(observed.candidate.as_ref().unwrap().as_str(), "ppp12");
        assert!(!format!("{observed:?}").contains("fictional"));
    }

    #[test]
    fn redaction_covers_every_listed_keyword_in_any_case() {
        for keyword in SECRET_KEYWORDS {
            let mixed: String = keyword
                .char_indices()
                .map(|(index, letter)| {
                    if index % 2 == 0 {
                        letter.to_ascii_uppercase()
                    } else {
                        letter
                    }
                })
                .collect();
            for rendering in [keyword.to_string(), keyword.to_uppercase(), mixed] {
                let line = format!("INFO:   negotiated {rendering}=hunter2");
                assert!(
                    contains_secret_keyword(line.as_bytes()),
                    "{rendering} must redact"
                );
            }
        }
        // `passwd` and `set-cookie` ride the loop above; a clean line passes through.
        assert!(!contains_secret_keyword(b"INFO:   Interface ppp7 is UP."));
        // End to end: the auth error still observes CredentialsRejected while the
        // file keeps only the placeholder, never the raw line.
        let state = State::new();
        prepare_log(&state.directory, State::owner()).unwrap();
        let log = DiagnosticLog::open(&state.directory, State::owner());
        let observed = run_drain(
            b"ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.\n",
            log,
        );
        assert_eq!(observed.failure, Some(SslFailure::CredentialsRejected));
        let text = fs::read_to_string(state.log()).unwrap();
        assert_eq!(text, format!("{} {REDACTED_LINE}\n", &text[..8]));
    }

    #[test]
    fn clean_lines_keep_their_bytes_with_a_timestamp_prefix() {
        let state = State::new();
        prepare_log(&state.directory, State::owner()).unwrap();
        let log = DiagnosticLog::open(&state.directory, State::owner());
        let observed = run_drain(b"INFO:   Interface ppp12 is UP.\n", log);
        assert_eq!(observed.candidate.as_ref().unwrap().as_str(), "ppp12");
        let text = fs::read_to_string(state.log()).unwrap();
        assert!(text.ends_with(" INFO:   Interface ppp12 is UP.\n"));
        assert_eq!(
            text.len(),
            8 + 1 + b"INFO:   Interface ppp12 is UP.\n".len()
        );
    }

    #[test]
    fn oversized_lines_become_a_single_placeholder() {
        let state = State::new();
        prepare_log(&state.directory, State::owner()).unwrap();
        let log = DiagnosticLog::open(&state.directory, State::owner());
        let mut input = vec![b'x'; 5000];
        input.push(b'\n');
        let observed = run_drain(&input, log);
        assert!(observed.candidate.is_none());
        assert!(observed.failure.is_none());
        let text = fs::read_to_string(state.log()).unwrap();
        assert_eq!(
            text,
            format!("{} {LONG_LINE}\n", &text[..8]),
            "oversized content must never reach the file"
        );
    }

    #[test]
    fn eight_mebibyte_cap_stops_logging_without_breaking_the_drain() {
        let state = State::new();
        prepare_log(&state.directory, State::owner()).unwrap();
        let path = state.log();
        fs::write(&path, b"seed").unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(OPENFORTIVPN_LOG_MAX_BYTES - 10)
            .unwrap();
        let log = DiagnosticLog::open(&state.directory, State::owner());
        let observed = run_drain(
            b"INFO:   Interface ppp12 is UP.\nERROR:  connect: Operation timed out\n",
            log,
        );
        // The drain still observes everything even as the log goes quiet.
        assert_eq!(observed.candidate.as_ref().unwrap().as_str(), "ppp12");
        assert_eq!(observed.failure, Some(SslFailure::GatewayTimeout));
        let len = fs::metadata(&path).unwrap().len();
        assert!(
            len <= OPENFORTIVPN_LOG_MAX_BYTES,
            "log grew past the ceiling: {len}"
        );
    }

    #[test]
    fn disabled_log_keeps_parsing_and_never_fails() {
        // prepare on a path whose parent is a file: rotation cannot exist.
        let state = State::new();
        let blocker = state.directory.join("blocker");
        fs::write(&blocker, b"not a directory").unwrap();
        assert!(prepare_log(&blocker, State::owner()).is_err());
        let log = DiagnosticLog::open(&blocker, State::owner());
        assert!(log.file.is_none());
        let observed = run_drain(
            b"ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.\nINFO:   Interface ppp3 is UP.\n",
            log,
        );
        assert_eq!(observed.failure, Some(SslFailure::CredentialsRejected));
        assert_eq!(observed.candidate.as_ref().unwrap().as_str(), "ppp3");
    }

    #[test]
    fn completion_line_names_exit_code_or_signal_and_candidate() {
        let state = State::new();
        prepare_log(&state.directory, State::owner()).unwrap();
        let log = DiagnosticLog::open(&state.directory, State::owner());
        let mut log = log;
        let code = std::process::Command::new("/usr/bin/true")
            .status()
            .unwrap();
        assert_eq!(code.code(), Some(0));
        assert!(log.push_bytes(&completion_record(Some(code), true)));
        let signal = std::process::Command::new("/bin/sh")
            .args(["-c", "kill -TERM $$"])
            .status()
            .unwrap();
        assert!(signal.signal().is_some());
        assert!(log.push_bytes(&completion_record(Some(signal), false)));
        assert!(log.push_bytes(&completion_record(None, false)));
        let text = fs::read_to_string(state.log()).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].ends_with("tentativa encerrada: código 0; candidato de interface: sim"));
        assert!(
            lines[1].ends_with("tentativa encerrada: sinal 15; candidato de interface: não"),
            "unexpected: {}",
            lines[1]
        );
        assert!(
            lines[2].ends_with("tentativa encerrada: desconhecido; candidato de interface: não")
        );
    }

    #[test]
    fn prepare_rotates_with_private_modes_and_owner() {
        let state = State::new();
        // Missing `logs/` is created private on first prepare.
        // Missing `logs/` is created private by the first prepare.
        let log = state.log();
        let previous = log.with_file_name(PREVIOUS_NAME);
        assert!(!log.parent().unwrap().exists());
        assert!(!previous.exists());
        for content in ["first attempt", "second attempt", "third attempt"] {
            prepare_log(&state.directory, State::owner()).unwrap();
            let meta = fs::symlink_metadata(&log).unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.uid(), State::owner());
            assert_eq!(meta.mode() & 0o7777, 0o600);
            assert_eq!(meta.len(), 0);
            assert_eq!(meta.nlink(), 1);
            let directory = fs::symlink_metadata(log.parent().unwrap()).unwrap();
            assert_eq!(directory.uid(), State::owner());
            assert_eq!(directory.mode() & 0o7777, 0o700);
            let expected = match content {
                "first attempt" => None,
                "second attempt" => Some("first attempt"),
                _ => Some("second attempt"),
            };
            assert_eq!(fs::read_to_string(&previous).ok().as_deref(), expected);
            if previous.exists() {
                let meta = fs::symlink_metadata(&previous).unwrap();
                assert_eq!(meta.uid(), State::owner());
                assert_eq!(meta.mode() & 0o7777, 0o600);
            }
            fs::write(&log, content).unwrap();
        }
    }

    #[test]
    fn prepare_refuses_symlinks_modes_and_foreign_owner_without_touching_targets() {
        for change in [
            "directory-link",
            "directory-mode",
            "owner",
            "current-link",
            "previous-link",
            "file-mode",
            "hardlink",
        ] {
            let state = State::new();
            let log = state.log();
            let directory = log.parent().unwrap();
            let target = state.directory.join("sentinel");
            fs::write(&target, "unchanged").unwrap();
            if change == "directory-link" {
                symlink(&state.directory, directory).unwrap();
            } else {
                prepare_log(&state.directory, State::owner()).unwrap();
                match change {
                    "directory-mode" => {
                        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap()
                    }
                    "current-link" => {
                        fs::remove_file(&log).unwrap();
                        symlink(&target, &log).unwrap();
                    }
                    "previous-link" => {
                        symlink(&target, log.with_file_name(PREVIOUS_NAME)).unwrap();
                    }
                    "file-mode" => {
                        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap()
                    }
                    "hardlink" => fs::hard_link(&log, state.directory.join("alias")).unwrap(),
                    _ => {}
                }
            }
            let owner = if change == "owner" {
                State::owner().wrapping_add(1)
            } else {
                State::owner()
            };
            assert!(prepare_log(&state.directory, owner).is_err(), "{change}");
            assert_eq!(fs::read_to_string(&target).unwrap(), "unchanged");
            // A refused rotation never leaves a stray current behind it.
            if change == "previous-link" {
                assert!(fs::symlink_metadata(&log).unwrap().is_file());
            }
        }
    }
}
