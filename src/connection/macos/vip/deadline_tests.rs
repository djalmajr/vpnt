//! Absolute-deadline and post-readback budget cases.
//!
//! These drive the same production `preflight::assign` with the private fake
//! `Api`/`current` seam. The opaque `ConfiguredUtun` entry points are only
//! type-checked; no retained interface, controller or native call is faked.
use super::preflight::assign;
use super::tests::{Fake, expires, fake, interfaces, ok, target};
use super::{Api, ConfiguredUtun, MAX_TIMEOUT, VipFailure, cap_deadline};
use crate::connection::ipsec::{Candidate, Error};
use crate::connection::macos::interfaces::Interfaces;
use crate::connection::macos::utun_observer::RetainedInterface;
use crate::helper::controller_lock::ControllerLock;
use std::{
    io,
    net::IpAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

struct Hooked<F> {
    inner: Fake,
    reads: usize,
    hook: F,
}

impl<F: FnMut(usize)> Api for Hooked<F> {
    fn interfaces(&mut self) -> io::Result<Interfaces> {
        self.reads += 1;
        (self.hook)(self.reads);
        self.inner.interfaces()
    }

    fn assign(&mut self, name: &str, vip: IpAddr) -> io::Result<()> {
        self.inner.assign(name, vip)
    }
}

fn v4() -> IpAddr {
    "192.0.2.10".parse().unwrap()
}

// Mutation: drop the check after the second `current()`. The callback cancels
// itself, so without the recheck the alias is written and only then refused.
#[test]
fn canceled_second_current_issues_no_write() {
    let mut fake = fake(vec![interfaces(&[("utun6", 6, true, &[])])]);
    let cancel = AtomicBool::new(false);
    let mut calls = 0;
    let mut current = || {
        calls += 1;
        if calls == 2 {
            cancel.store(true, Ordering::Release);
        }
        Ok(())
    };
    assert_eq!(
        assign(
            &mut fake,
            &target(),
            &[v4()],
            expires(),
            &cancel,
            &mut current
        ),
        Err(Error::Canceled)
    );
    assert_eq!(calls, 2);
    assert!(fake.calls.is_empty(), "canceled callback wrote an alias");
}

// Mutation: same missing recheck, but the callback outlives the absolute
// deadline instead of canceling.
#[test]
fn second_current_outliving_the_absolute_deadline_issues_no_write() {
    let mut fake = fake(vec![interfaces(&[("utun6", 6, true, &[])])]);
    let cancel = AtomicBool::new(false);
    let expires = Instant::now() + Duration::from_millis(150);
    let mut calls = 0;
    let mut current = || {
        calls += 1;
        if calls == 2 {
            let remaining = expires.saturating_duration_since(Instant::now());
            std::thread::sleep(remaining + Duration::from_millis(20));
        }
        Ok(())
    };
    assert_eq!(
        assign(
            &mut fake,
            &target(),
            &[v4()],
            expires,
            &cancel,
            &mut current
        ),
        Err(Error::Timeout)
    );
    assert!(fake.calls.is_empty(), "expired callback wrote an alias");
}

// Mutation: drop the post-readback check. The readback is complete and valid,
// so without it the assignment reports success after the budget was canceled.
#[test]
fn canceled_last_readback_does_not_report_success() {
    let cancel = AtomicBool::new(false);
    let flag = &cancel;
    let mut api = Hooked {
        inner: fake(vec![
            interfaces(&[("utun6", 6, true, &[])]),
            interfaces(&[("utun6", 6, true, &["192.0.2.10"])]),
        ]),
        reads: 0,
        hook: move |read: usize| {
            if read == 2 {
                flag.store(true, Ordering::Release);
            }
        },
    };
    assert_eq!(
        assign(&mut api, &target(), &[v4()], expires(), &cancel, &mut ok()),
        Err(Error::Canceled)
    );
    assert_eq!(api.reads, 2);
    assert_eq!(api.inner.calls.len(), 1);
}

// Mutation: same missing post-readback check, with the readback itself past the
// absolute deadline.
#[test]
fn expired_last_readback_does_not_report_success() {
    let expires = Instant::now() + Duration::from_millis(150);
    let cancel = AtomicBool::new(false);
    let mut api = Hooked {
        inner: fake(vec![
            interfaces(&[("utun6", 6, true, &[])]),
            interfaces(&[("utun6", 6, true, &["192.0.2.10"])]),
        ]),
        reads: 0,
        hook: move |read: usize| {
            if read == 2 {
                let remaining = expires.saturating_duration_since(Instant::now());
                std::thread::sleep(remaining + Duration::from_millis(20));
            }
        },
    };
    assert_eq!(
        assign(&mut api, &target(), &[v4()], expires, &cancel, &mut ok()),
        Err(Error::Timeout)
    );
    assert_eq!(api.inner.calls.len(), 1);
}

// Mutation: rebase the deadline to `now + MAX_TIMEOUT`. A caller deadline
// shorter than the operation cap must stay exactly where the caller put it.
#[test]
fn absolute_cap_preserves_a_shorter_caller_deadline() {
    let now = Instant::now();
    let caller = now + Duration::from_millis(50);
    assert_eq!(cap_deadline(caller, now), caller);
    let beyond = now + MAX_TIMEOUT + Duration::from_secs(1);
    assert_eq!(cap_deadline(beyond, now), now + MAX_TIMEOUT);
}

// Compile-time shape of the new absolute entry point: no runtime fake of the
// opaque retained pin or controller is used to prove it.
#[test]
fn absolute_entry_signature_is_the_documented_one() {
    fn absolute<'a>(
        f: fn(
            RetainedInterface,
            &Candidate,
            &'a ControllerLock,
            Instant,
            &AtomicBool,
        ) -> Result<ConfiguredUtun<'a>, VipFailure>,
    ) -> fn(
        RetainedInterface,
        &Candidate,
        &'a ControllerLock,
        Instant,
        &AtomicBool,
    ) -> Result<ConfiguredUtun<'a>, VipFailure> {
        f
    }
    let _ = absolute(ConfiguredUtun::configure_until);
}
