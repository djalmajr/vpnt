use super::super::super::resource::Absence;
use super::{Hold, Release};
use crate::connection::ipsec::Error;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Fallback {
    value: AtomicBool,
    calls: AtomicUsize,
}

impl Fallback {
    fn new(value: bool) -> Self {
        Self {
            value: AtomicBool::new(value),
            calls: AtomicUsize::new(0),
        }
    }
}

impl Absence for Fallback {
    fn complete(&self) -> Result<bool, Error> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(self.value.load(Ordering::Acquire))
    }
}

struct Meta {
    value: std::sync::atomic::AtomicU8,
    calls: AtomicUsize,
}

impl Meta {
    fn new(value: Result<bool, Error>) -> Self {
        Self {
            value: std::sync::atomic::AtomicU8::new(match value {
                Ok(true) => 1,
                Ok(false) => 0,
                Err(_) => 2,
            }),
            calls: AtomicUsize::new(0),
        }
    }

    fn read(&self) -> Result<bool, Error> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        match self.value.load(Ordering::Acquire) {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Unavailable),
        }
    }
}

struct Payload {
    drops: Arc<AtomicUsize>,
}

impl Drop for Payload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn strong_is_owned_until_release_and_external_blocks_absence() {
    let drops = Arc::new(AtomicUsize::new(0));
    let payload = Arc::new(Payload {
        drops: drops.clone(),
    });
    let external = payload.clone();
    let mut hold = Hold::new(payload, Some(Meta::new(Ok(true))));
    let fallback = Fallback::new(false);
    assert!(
        hold.claim_absence(|_| Ok(true), &fallback)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        hold.release(),
        Release {
            changed: true,
            external: true
        }
    );
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert!(
        hold.claim_absence(|_| Ok(true), &fallback)
            .unwrap()
            .is_none()
    );
    drop(external);
    assert_eq!(
        hold.claim_absence(|meta| meta.read(), &fallback).unwrap(),
        Some(true)
    );
    assert_eq!(fallback.calls.load(Ordering::Acquire), 0);
    assert_eq!(
        hold.release(),
        Release {
            changed: false,
            external: false
        }
    );
}

#[test]
fn known_absence_is_fresh_and_bypasses_fallback() {
    let mut hold = Hold::new(
        Arc::new(Payload {
            drops: Arc::new(AtomicUsize::new(0)),
        }),
        Some(Meta::new(Ok(true))),
    );
    let fallback = Fallback::new(false);
    hold.release();
    let answer = |meta: &Meta| meta.read();
    assert_eq!(hold.claim_absence(answer, &fallback).unwrap(), Some(true));
    let meta = hold.metadata().unwrap();
    assert_eq!(meta.calls.load(Ordering::Acquire), 1);
    meta.value.store(0, Ordering::Release);
    assert_eq!(hold.claim_absence(answer, &fallback).unwrap(), Some(false));
    assert_eq!(meta.calls.load(Ordering::Acquire), 2);
    meta.value.store(2, Ordering::Release);
    assert_eq!(
        hold.claim_absence(answer, &fallback).err(),
        Some(Error::Unavailable)
    );
    assert_eq!(fallback.calls.load(Ordering::Acquire), 0);
}

#[test]
fn missing_metadata_uses_fallback_and_failed_payload_retains_metadata() {
    let mut missing = Hold::new(
        Arc::new(Payload {
            drops: Arc::new(AtomicUsize::new(0)),
        }),
        None::<Meta>,
    );
    let fallback = Fallback::new(true);
    missing.release();
    assert_eq!(
        missing.claim_absence(|_| Ok(false), &fallback).unwrap(),
        Some(true)
    );
    assert_eq!(fallback.calls.load(Ordering::Acquire), 1);

    let drops = Arc::new(AtomicUsize::new(0));
    let mut failed = Hold::new(
        Arc::new(Payload {
            drops: drops.clone(),
        }),
        Some(Meta::new(Ok(true))),
    );
    assert_eq!(
        failed.release(),
        Release {
            changed: true,
            external: false
        }
    );
    assert_eq!(drops.load(Ordering::Acquire), 1);
    let fallback = Fallback::new(false);
    assert_eq!(
        failed.claim_absence(|meta| meta.read(), &fallback).unwrap(),
        Some(true)
    );
    assert_eq!(fallback.calls.load(Ordering::Acquire), 0);
    assert_eq!(
        failed.release(),
        Release {
            changed: false,
            external: false
        }
    );
}
