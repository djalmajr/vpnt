//! Bounded, secret-free diagnostics; never grants cleanup authority.
use crate::{connection::routes::Owner, helper::paths, model::valid_profile_id};
use std::{
    cell::RefCell,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};

// Same ceiling as producer::diagnostic::CHARON_LOG_MAX_BYTES. The helper has
// no child RLIMIT; enforce it before each append, across all worker threads.
const CLEANUP_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;
const REPEAT_AFTER: Duration = Duration::from_secs(30);
static WRITER: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reason {
    ProducerNotStopped,
    FenceIncomplete,
    AbsenceFallback,
    AbsenceKnownUtun,
    PinStillOwned,
    LedgerVersionChanged,
    RuntimeValidation,
    UnrepresentedProducer,
    AdmissionCleanup,
    RouteLock,
    RouteBegin,
    RouteRelease,
    RouteOwner,
    RetiredResources,
    RouteFinish,
    RegistryRelease,
    ProfileCompletion,
    ProducerMissing,
    ChildrenIncomplete,
    LinkEvidence,
    EarlyAbsence,
    UncertainCleanup,
    NamespaceOccupied,
    DurableCompletion,
    ObservationFailed,
    /// Fence reason of a preventive journal; never a cleanup refusal.
    Journal,
}
impl Reason {
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::ProducerNotStopped => "producer_not_stopped",
            Self::FenceIncomplete => "fence_incomplete",
            Self::AbsenceFallback => "absence_fallback_not_positive",
            Self::AbsenceKnownUtun => "absence_known_utun_not_positive",
            Self::PinStillOwned => "pin_still_owned",
            Self::LedgerVersionChanged => "ledger_version_changed",
            Self::RuntimeValidation => "runtime_validation_failed",
            Self::UnrepresentedProducer => "unrepresented_producer",
            Self::AdmissionCleanup => "admission_cleanup_failed",
            Self::RouteLock => "route_lock_failed",
            Self::RouteBegin => "route_begin_incomplete",
            Self::RouteRelease => "route_release_incomplete",
            Self::RouteOwner => "route_owner_pending",
            Self::RetiredResources => "retired_resources_pending",
            Self::RouteFinish => "route_finish_failed",
            Self::RegistryRelease => "registry_release_failed",
            Self::ProfileCompletion => "profile_completion_failed",
            Self::ProducerMissing => "producer_missing",
            Self::ChildrenIncomplete => "children_incomplete",
            Self::LinkEvidence => "link_evidence_missing",
            Self::EarlyAbsence => "early_absence_not_positive",
            Self::UncertainCleanup => "cleanup_uncertain",
            Self::NamespaceOccupied => "namespace_occupied",
            Self::DurableCompletion => "durable_completion_failed",
            Self::ObservationFailed => "observation_failed",
            Self::Journal => "journal",
        }
    }
}
#[derive(Default)]
struct Diagnostic {
    reason: Option<Reason>,
    attempts: u64,
    last: Option<(Reason, Instant)>,
    journal: bool,
    journal_last: Option<Instant>,
}
thread_local! { static DIAGNOSTIC: RefCell<Diagnostic> = RefCell::default(); }
pub(crate) fn begin() {
    DIAGNOSTIC.with(|d| {
        let mut d = d.borrow_mut();
        d.reason = None;
        d.journal = false;
    });
}
/// A preventive journal write failed. `finish` logs it on its own line and
/// never lets it replace the refusal reason, which also names an abandonment.
pub(crate) fn journal_failed() {
    DIAGNOSTIC.with(|d| d.borrow_mut().journal = true);
}
#[cfg(test)]
pub(crate) fn journal_failure() -> bool {
    DIAGNOSTIC.with(|d| d.borrow().journal)
}
pub(crate) fn current_reason() -> Option<Reason> {
    DIAGNOSTIC.with(|d| d.borrow().reason)
}
pub(crate) fn mark(reason: Reason) {
    DIAGNOSTIC.with(|d| {
        let mut d = d.borrow_mut();
        if d.reason.is_none() {
            d.reason = Some(reason);
        }
    });
}
pub(crate) fn refuse(reason: Reason) -> bool {
    mark(reason);
    false
}
pub(crate) fn finish(state: &Path, owner: &Owner, complete: bool) {
    finish_at(state, 0, owner, complete, Instant::now());
}
fn finish_at(state: &Path, uid: u32, owner: &Owner, complete: bool, now: Instant) {
    DIAGNOSTIC.with(|d| {
        let mut d = d.borrow_mut();
        d.attempts = d.attempts.saturating_add(1);
        if !complete {
            let reason = d.reason.unwrap_or(Reason::ObservationFailed);
            if due(d.last, reason, now) && append(state, uid, owner, d.attempts, reason).is_ok() {
                d.last = Some((reason, now));
            }
        }
        if d.journal
            && d.journal_last
                .is_none_or(|at| now.saturating_duration_since(at) >= REPEAT_AFTER)
            && valid_profile_id(&owner.profile)
            && write_line(
                state,
                uid,
                &format!(
                    "{} profile={} attempt={} journal=failed\n",
                    timestamp(),
                    owner.profile,
                    d.attempts
                ),
            )
            .is_ok()
        {
            d.journal_last = Some(now);
        }
    });
}
/// The exit watchdog's last line: whether a live attempt had no journal.
/// It runs before `_exit` and takes the same writer lock as every append.
pub(crate) fn deadline(state: &Path, unjournaled: bool) {
    let _ = deadline_at(state, 0, unjournaled);
}
pub(crate) fn deadline_at(state: &Path, uid: u32, unjournaled: bool) -> io::Result<()> {
    write_line(
        state,
        uid,
        &format!(
            "{} exit=deadline unjournaled={}\n",
            timestamp(),
            if unjournaled { "yes" } else { "no" }
        ),
    )
}
fn due(last: Option<(Reason, Instant)>, reason: Reason, now: Instant) -> bool {
    last.is_none_or(|(previous, at)| {
        previous != reason || now.saturating_duration_since(at) >= REPEAT_AFTER
    })
}
fn private(meta: &fs::Metadata, owner: u32, directory: bool) -> bool {
    meta.uid() == owner
        && meta.mode() & 0o7777 == if directory { 0o700 } else { 0o600 }
        && if directory {
            meta.is_dir()
        } else {
            meta.is_file() && meta.nlink() == 1
        }
}
fn append(state: &Path, uid: u32, owner: &Owner, attempt: u64, reason: Reason) -> io::Result<()> {
    if !valid_profile_id(&owner.profile) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let line = format!(
        "{} profile={} attempt={} reason={}\n",
        timestamp(),
        owner.profile,
        attempt,
        reason.id()
    );
    write_line(state, uid, &line)
}
fn write_line(state: &Path, uid: u32, line: &str) -> io::Result<()> {
    let _guard = WRITER.lock().map_err(|_| io::ErrorKind::Other)?;
    let path = paths::cleanup_log(state);
    let directory = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    // `logs` may not exist yet (no charon spawn so far, or an SSL cleanup).
    // mkdir never follows a final symlink; whatever already exists is
    // validated below and never repaired.
    match fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {
            // A restrictive umask may have removed owner bits from the
            // directory we just created: set 0700 through its descriptor,
            // never by path, and only on this freshly created object.
            let created = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory)?;
            let meta = created.metadata()?;
            if !meta.is_dir() || meta.uid() != uid {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            created.set_permissions(fs::Permissions::from_mode(0o700))?;
            fs::File::open(state)?.sync_all()?;
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?;
    let named_dir = fs::symlink_metadata(directory)?;
    let opened_dir = dir.metadata()?;
    if !private(&named_dir, uid, true)
        || named_dir.dev() != opened_dir.dev()
        || named_dir.ino() != opened_dir.ino()
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    crate::fs_permissions::check_file(&dir, true).map_err(|_| io::ErrorKind::PermissionDenied)?;
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)?;
    let meta = file.metadata()?;
    let named = fs::symlink_metadata(&path)?;
    if !private(&meta, uid, false) || meta.dev() != named.dev() || meta.ino() != named.ino() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    crate::fs_permissions::check_file(&file, true).map_err(|_| io::ErrorKind::PermissionDenied)?;
    if meta.len().saturating_add(line.len() as u64) <= CLEANUP_LOG_MAX_BYTES {
        file.write_all(line.as_bytes())?;
    }
    Ok(())
}
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
#[cfg(test)]
#[path = "runtime_cleanup_tests.rs"]
mod tests;
