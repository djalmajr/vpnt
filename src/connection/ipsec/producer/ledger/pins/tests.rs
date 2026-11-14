//! Synthetic ordinary-file FDs and passive views. No SDK/interface/route reads.
use super::*;
use crate::connection::{
    macos::{
        ipsec_early_cleanup,
        routing::{Record, Snapshot},
        utun_observer::InterfaceObservation,
    },
    routes::{Key, Network},
};
use std::{
    cell::Cell,
    fs::OpenOptions,
    os::fd::{AsRawFd, OwnedFd},
    sync::atomic::{AtomicUsize, Ordering},
};

struct Fallback {
    answer: Result<bool, Error>,
    calls: AtomicUsize,
}
impl Fallback {
    fn new(answer: Result<bool, Error>) -> Self {
        Self {
            answer,
            calls: AtomicUsize::new(0),
        }
    }
}
impl Absence for Fallback {
    fn complete(&self) -> Result<bool, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.answer
    }
}
const UP: u32 = libc::IFF_UP as u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

fn identity(fd: i32) -> std::io::Result<FileIdentity> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes one correctly sized stat and only observes the fd.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized the output.
    let stat = unsafe { stat.assume_init() };
    Ok(FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

struct FixturePath(std::path::PathBuf);
impl Drop for FixturePath {
    fn drop(&mut self) {
        // Only this create_new file; never a directory or another fixture.
        let _ = std::fs::remove_file(&self.0);
    }
}

struct FdProbe {
    number: i32,
    original: FileIdentity,
    // Keep the original inode named until all observations finish, so it
    // cannot be recycled even if its descriptor number is reused elsewhere.
    _path: FixturePath,
}

fn captured() -> (PinState<'static>, FdProbe) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("output/fixtures/captured-retirement-fds");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let path = FixturePath(path);
    let fd: OwnedFd = file.into();
    let raw = fd.as_raw_fd();
    let probe = FdProbe {
        number: raw,
        original: identity(raw).unwrap(),
        _path: path,
    };
    let observation = InterfaceObservation::synthetic_for_test("utun3", 3, 4, 0x55, 0x77);
    (
        PinState::Captured(RetainedInterface::synthetic_for_test(fd, observation)),
        probe,
    )
}
fn assert_open(fd: &FdProbe) {
    assert_eq!(
        identity(fd.number).unwrap(),
        fd.original,
        "original fixture object is not open"
    );
}
fn assert_closed_at(number: i32, original: FileIdentity) {
    match identity(number) {
        Ok(current) => assert_ne!(current, original, "original captured file is still open"),
        Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EBADF)),
    }
}
fn assert_closed(fd: &FdProbe) {
    // Another thread may reuse the number; never close or overwrite it here.
    assert_closed_at(fd.number, fd.original);
}
fn capture_domain(retained: &RetainedInterface) -> Result<RetiredUtun, Error> {
    RetiredUtun::captured_for_test(
        retained,
        |_| Ok(()),
        || {
            Ok(RetiredUtun::view_for_test(&[(
                "utun3",
                3,
                UP,
                &["10.0.0.2", "fe80::1"],
            )]))
        },
    )
}
fn route(address: &str, prefix: u8, interface: u16) -> Record {
    Record {
        key: Key {
            network: Network::new(address.parse().unwrap(), prefix).unwrap(),
            scope: 0,
        },
        interface,
        flags: libc::RTF_UP,
        gateway: None,
        source: None,
    }
}
#[test]
fn captured_retirement_keeps_known_domain_after_fd_close_despite_foreign_delta() {
    let (mut pin, fd) = captured();
    let before = RetiredUtun::view_for_test(&[]);
    let foreign = RetiredUtun::view_for_test(&[("utun9", 9, UP, &["10.99.0.2"])]);
    let table = Snapshot { records: vec![] };
    let fallback = Fallback::new(Ok(ipsec_early_cleanup::observed(
        &before, &table, &foreign, &table,
    )));
    assert_eq!(fallback.answer, Ok(false));
    assert_open(&fd);
    assert_eq!(
        pin.claim_absence_with(&fallback, |_| panic!("not released")),
        Ok(None)
    );
    assert!(pin.release_with(capture_domain).changed);
    assert_closed(&fd);
    assert!(!pin.empty());
    assert!(pin.take_retained().is_none());
    for _ in 0..3 {
        assert_eq!(
            pin.claim_absence_with(&fallback, |r| Ok(r.gone_for_test(&foreign, &table))),
            Ok(Some(true)),
            "captured metadata lost to global fallback"
        );
        assert!(
            !pin.release_with(|_| panic!("capture repeated after FD close"))
                .changed
        );
    }
    assert_eq!(fallback.calls.load(Ordering::Relaxed), 0);
}
#[test]
fn captured_retirement_refuses_residual_domain_and_fresh_read_errors() {
    let (mut pin, fd) = captured();
    let fallback = Fallback::new(Ok(true));
    assert!(pin.release_with(capture_domain).changed);
    assert_closed(&fd);
    for view in [
        RetiredUtun::view_for_test(&[("utun3", 3, UP, &[])]),
        RetiredUtun::view_for_test(&[("utun3", 8, UP, &[])]),
        RetiredUtun::view_for_test(&[("utun8", 3, UP, &[])]),
    ] {
        assert_eq!(
            pin.claim_absence_with(&fallback, |r| Ok(
                r.gone_for_test(&view, &Snapshot { records: vec![] })
            )),
            Ok(Some(false))
        );
    }
    let gone = RetiredUtun::view_for_test(&[]);
    for residual in [
        route("10.20.0.0", 24, 3),
        route("10.0.0.2", 32, 1),
        route("fe80::1", 128, 1),
    ] {
        assert_eq!(
            pin.claim_absence_with(&fallback, |r| Ok(r.gone_for_test(
                &gone,
                &Snapshot {
                    records: vec![residual]
                }
            ))),
            Ok(Some(false)),
            "captured address or own route was forgotten"
        );
    }
    for error in [Error::Unavailable, Error::Changed] {
        assert_eq!(
            pin.claim_absence_with(&fallback, |_| Err(error)),
            Err(error)
        );
    }
    assert_eq!(fallback.calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        pin.claim_absence_with(&fallback, |r| Ok(
            r.gone_for_test(&gone, &Snapshot { records: vec![] })
        )),
        Ok(Some(true))
    );
}
#[test]
fn captured_retirement_capture_failures_close_fd_and_preserve_fallback() {
    for failure in ["before", "read", "missing", "index", "after"] {
        let (mut pin, fd) = captured();
        let validations = Cell::new(0);
        let reads = Cell::new(0);
        let mut outcome = None;
        let result = pin.release_with(|retained| {
            let capture = RetiredUtun::captured_for_test(
                retained,
                |_| {
                    let n = validations.get() + 1;
                    validations.set(n);
                    if failure == "before" || (failure == "after" && n == 2) {
                        Err(Error::Changed)
                    } else {
                        Ok(())
                    }
                },
                || {
                    reads.set(reads.get() + 1);
                    match failure {
                        "read" => Err(Error::Unavailable),
                        "missing" => Ok(RetiredUtun::view_for_test(&[])),
                        "index" => Ok(RetiredUtun::view_for_test(&[("utun3", 4, UP, &[])])),
                        _ => Ok(RetiredUtun::view_for_test(&[(
                            "utun3",
                            3,
                            UP,
                            &["fe80::1"],
                        )])),
                    }
                },
            );
            outcome = Some(capture.as_ref().err().copied());
            capture
        });
        assert!(result.changed);
        assert_closed(&fd);
        assert!(
            outcome.unwrap().is_some(),
            "{failure}: incomplete metadata accepted"
        );
        assert_eq!(validations.get(), if failure == "after" { 2 } else { 1 });
        assert_eq!(reads.get(), if failure == "before" { 0 } else { 1 });
        for answer in [Ok(false), Err(Error::Unavailable), Ok(true)] {
            let fallback = Fallback::new(answer);
            assert_eq!(
                pin.claim_absence_with(&fallback, |_| panic!("invalid metadata used")),
                answer.map(Some)
            );
            assert_eq!(fallback.calls.load(Ordering::Relaxed), 1);
        }
        assert!(
            !pin.release_with(|_| panic!("recapture after failed release"))
                .changed
        );
    }
}
#[test]
fn captured_retirement_empty_fallback_and_live_capture_are_unchanged() {
    let mut empty = PinState::new();
    assert!(empty.empty());
    assert!(
        !empty
            .release_with(|_| panic!("Empty has no metadata"))
            .changed
    );
    let fallback = Fallback::new(Ok(false));
    assert_eq!(
        empty.claim_absence_with(&fallback, |_| panic!("Empty must use fallback")),
        Ok(Some(false))
    );
    let (mut pin, fd) = captured();
    assert_eq!(
        pin.claim_absence_with(&Fallback::new(Ok(true)), |_| panic!("live pin")),
        Ok(None)
    );
    let retained = pin.take_retained().unwrap();
    assert!(pin.empty());
    assert_open(&fd);
    drop(retained);
    assert_closed(&fd);
    // Exercise the reused-number verdict using an independently owned file.
    // No dup2/close is ever issued against the released number.
    let (other_pin, other) = captured();
    assert_open(&other);
    assert_closed_at(other.number, fd.original);
    assert_closed(&fd);
    drop(other_pin);
    assert_closed(&other);
}
