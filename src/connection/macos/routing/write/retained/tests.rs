//! Real ADD-core tests over a private UDS datagram. The opaque
//! `ConfiguredUtun` adapter remains compile/static only; no route socket,
//! UTUN or real RTM_ADD is used. Bytes are validated by the existing C
//! consumer (`tests/fixtures/route_add.c`).
use super::support::*;
use super::*;
use crate::helper::controller_lock::ControllerLock;
use std::{
    net::IpAddr,
    os::unix::net::UnixDatagram,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

#[test]
fn exact_family_source_and_missing_family_send_or_refuse() {
    let fixture = Fixture::new();
    let source = FakeSource::new(&fixture.controller, [Some(V4), Some(v6())]);
    for (mode, network) in [("ok", "10.40.0.0/16"), ("v6", "2001:db8:42::/64")] {
        let (fd, mut consumer) = fixture.consumer(mode);
        let mut writer = fixture.writer(fd);
        let receipt = writer
            .add_retained(
                &source,
                network.parse().unwrap(),
                Duration::from_secs(1),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(receipt.confirmation(), Ok(()), "mode {mode}");
        assert_eq!(receipt.route().interface, 234);
        consumer.finish();
    }
    for (vips, network) in [
        ([Some(V4), None], "2001:db8:42::/64"),
        ([None, Some(v6())], "10.40.0.0/16"),
    ] {
        let source = FakeSource::new(&fixture.controller, vips);
        let (fd, server) = quiet();
        let mut writer = fixture.writer(fd);
        expect_error(
            writer.add_retained(
                &source,
                network.parse().unwrap(),
                Duration::from_secs(1),
                &AtomicBool::new(false),
            ),
            Error::Invalid,
        );
        no_bytes(&server);
    }
}

#[test]
fn controller_identity_and_stale_before_send_write_nothing() {
    let one = Fixture::new();
    let two = Fixture::new();
    let foreign = FakeSource::new(&two.controller, [Some(V4), None]);
    let (fd, server) = quiet();
    let mut writer = one.writer(fd);
    expect_error(
        writer.add_retained(
            &foreign,
            "10.40.0.0/16".parse().unwrap(),
            Duration::from_secs(1),
            &AtomicBool::new(false),
        ),
        Error::Invalid,
    );
    no_bytes(&server);
    let stale = FakeSource::new(&one.controller, [Some(V4), None]).stale_after(0);
    let (fd, server) = quiet();
    let mut writer = one.writer(fd);
    expect_error(
        writer.add_retained(
            &stale,
            "10.40.0.0/16".parse().unwrap(),
            Duration::from_secs(1),
            &AtomicBool::new(false),
        ),
        Error::Changed,
    );
    no_bytes(&server);
    let mut zero = FakeSource::new(&one.controller, [Some(V4), None]);
    zero.index = 0;
    let (fd, server) = quiet();
    let mut writer = one.writer(fd);
    expect_error(
        writer.add_retained(
            &zero,
            "10.40.0.0/16".parse().unwrap(),
            Duration::from_secs(1),
            &AtomicBool::new(false),
        ),
        Error::Invalid,
    );
    no_bytes(&server);
}

#[test]
fn lost_ack_and_stale_after_ack_stay_in_the_receipt() {
    let fixture = Fixture::new();
    let source = FakeSource::new(&fixture.controller, [Some(V4), None]);
    let (fd, mut consumer) = fixture.consumer("lost");
    let mut writer = fixture.writer(fd);
    let receipt = writer
        .add_retained(
            &source,
            "10.40.0.0/16".parse().unwrap(),
            Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(receipt.confirmation(), Err(Error::Unavailable));
    assert_eq!(receipt.route().interface, 234);
    consumer.finish();
    let stale = FakeSource::new(&fixture.controller, [Some(V4), None]).stale_after(1);
    let (fd, mut consumer) = fixture.consumer("ok");
    let mut writer = fixture.writer(fd);
    let receipt = writer
        .add_retained(
            &stale,
            "10.40.0.0/16".parse().unwrap(),
            Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(receipt.confirmation(), Err(Error::Changed));
    consumer.finish();
}

#[test]
fn timeout_and_cancellation_preserve_dispatch_state() {
    let fixture = Fixture::new();
    let source = FakeSource::new(&fixture.controller, [Some(V4), None]);
    let (fd, server) = quiet();
    let mut writer = fixture.writer(fd);
    expect_error(
        writer.add_retained(
            &source,
            "10.40.0.0/16".parse().unwrap(),
            Duration::from_secs(1),
            &AtomicBool::new(true),
        ),
        Error::Canceled,
    );
    no_bytes(&server);
    let (fd, server) = quiet();
    let mut writer = fixture.writer(fd);
    expect_error(
        writer.add_retained(
            &source,
            "10.40.0.0/16".parse().unwrap(),
            Duration::ZERO,
            &AtomicBool::new(false),
        ),
        Error::Invalid,
    );
    no_bytes(&server);
    let (fd, mut consumer) = fixture.consumer("silent");
    let mut writer = fixture.writer(fd);
    let receipt = writer
        .add_retained(
            &source,
            "10.40.0.0/16".parse().unwrap(),
            Duration::from_millis(100),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(receipt.confirmation(), Err(Error::TimedOut));
    consumer.finish();
    let (client, server) = UnixDatagram::pair().unwrap();
    client.set_nonblocking(true).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let notify = cancel.clone();
    let worker = thread::spawn(move || {
        assert!(server.recv(&mut [0; 1024]).unwrap() > 0);
        notify.store(true, Ordering::Release);
    });
    let mut writer = fixture.writer(client.into());
    let receipt = writer
        .add_retained(
            &source,
            "10.40.0.0/16".parse().unwrap(),
            Duration::from_secs(1),
            &cancel,
        )
        .unwrap();
    worker.join().unwrap();
    assert_eq!(receipt.confirmation(), Err(Error::Canceled));
}

struct FakeSource<'a> {
    controller: &'a ControllerLock,
    index: u32,
    vips: [Option<IpAddr>; 2],
    calls: AtomicUsize,
    fail_after: usize,
}
impl<'a> FakeSource<'a> {
    fn new(controller: &'a ControllerLock, vips: [Option<IpAddr>; 2]) -> Self {
        Self {
            controller,
            index: 234,
            vips,
            calls: AtomicUsize::new(0),
            fail_after: usize::MAX,
        }
    }
    fn stale_after(mut self, successful: usize) -> Self {
        self.fail_after = successful;
        self
    }
}
impl Source for FakeSource<'_> {
    fn controller(&self) -> &ControllerLock {
        self.controller
    }
    fn validate(&self) -> Result<(), Error> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call > self.fail_after {
            Err(Error::Changed)
        } else {
            Ok(())
        }
    }
    fn index(&self) -> u32 {
        self.index
    }
    fn vip(&self, family: Family) -> Option<IpAddr> {
        match family {
            Family::V4 => self.vips[0],
            Family::V6 => self.vips[1],
        }
    }
}
