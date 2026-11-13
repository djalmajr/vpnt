use super::*;
use std::{sync::mpsc, time::Duration};
mod boundaries;
mod fixture;
mod limits;
use fixture::{Fixture, Peer};

fn budget() -> Budget {
    Budget::new(Duration::from_secs(3)).unwrap()
}
fn collect(peer: &Peer, kind: Kind, budget: &Budget) -> Result<Collection, Error> {
    collect_transport(peer, kind, std::process::id(), 73, budget)
}

// Mutations: omit the send, accept foreign PID/type, lose either countdown
// entry, or expose the raw authentication key through the collected DTO.
#[test]
fn independent_peer_observes_fixed_queries_and_collector_filters_foreign_records() {
    let fixture = Fixture::new();
    for kind in [Kind::Sad, Kind::Spd] {
        let peer = fixture.peer("normal");
        let batch = collect(&peer, kind, &budget()).expect("complete peer countdown");
        assert_eq!(batch.kind, kind);
        assert_eq!(batch.end, ProtocolEnd::Countdown { first: 1 });
        let ids: Vec<_> = batch
            .entries
            .iter()
            .map(|e| match e {
                Entry::Sa(sa) => sa.spi,
                Entry::Policy(p) => p.id,
                _ => panic!("data entry expected"),
            })
            .collect();
        let base = if kind == Kind::Sad {
            0x1234abcd
        } else {
            0x10203040
        };
        assert_eq!(ids, [base + 1, base + 2]);
        assert!(!format!("{batch:?}").contains("fake-sa-key-0001"));
        peer.finish();
    }
}

// Mutations: accept an unmatched empty nonce, turn denial into emptiness,
// or infer full-table completeness from a one-record countdown suffix.
#[test]
fn explicit_empty_and_suffix_are_protocol_observations_and_errors_stay_errors() {
    let fixture = Fixture::new();
    for kind in [Kind::Sad, Kind::Spd] {
        let peer = fixture.peer("empty");
        assert_eq!(
            collect(&peer, kind, &budget()),
            Ok(Collection {
                kind,
                entries: vec![],
                end: ProtocolEnd::EmptyReply,
            })
        );
        peer.finish();
        let peer = fixture.peer("suffix");
        let suffix = collect(&peer, kind, &budget()).unwrap();
        assert_eq!(suffix.entries.len(), 1);
        assert_eq!(suffix.end, ProtocolEnd::Countdown { first: 0 });
        peer.finish();
        for (mode, expected) in [
            ("bad-empty", Error::Changed),
            ("denied", Error::PermissionDenied),
            ("failed", Error::Unavailable),
            ("zero", Error::Unavailable),
        ] {
            let peer = fixture.peer(mode);
            assert_eq!(collect(&peer, kind, &budget()), Err(expected), "{mode}");
            peer.finish();
        }
    }
}

// Mutations: publish a partial prefix, ignore sequence gaps/duplicates,
// tolerate a malformed packet, or stop before checking queued extra replies.
#[test]
fn broken_countdowns_and_queued_extras_never_publish_a_prefix() {
    let fixture = Fixture::new();
    for kind in [Kind::Sad, Kind::Spd] {
        for (mode, expected) in [
            ("gap", Error::Changed),
            ("duplicate", Error::Changed),
            ("partial-error", Error::Changed),
            ("malformed", Error::Invalid),
            ("extra", Error::Changed),
            ("huge", Error::Exhausted),
        ] {
            let peer = fixture.peer(mode);
            assert_eq!(collect(&peer, kind, &budget()), Err(expected), "{mode}");
            peer.finish();
        }
    }
}

// Mutations: lose cancellation or expiry in the native receive wait.
// The post-send rebase has its own test below; peers stay alive until release.
#[test]
fn incomplete_live_peers_obey_absolute_deadlines_and_cancellation() {
    let fixture = Fixture::new();
    for mode in ["partial", "silence"] {
        let (ready, started) = mpsc::channel();
        let mut peer = fixture.peer(mode);
        peer.ready = Some(ready);
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let timer = std::thread::spawn(move || {
            started.recv_timeout(Duration::from_secs(3)).unwrap();
            std::thread::sleep(Duration::from_millis(25));
            signal.store(true, Ordering::Release);
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        let b = Budget::until(deadline, Some(cancel)).unwrap();
        assert_eq!(collect(&peer, Kind::Sad, &b), Err(Error::Canceled));
        timer.join().unwrap();
        peer.finish();

        let peer = fixture.peer(mode);
        let b = Budget::new(Duration::from_millis(150)).unwrap();
        assert_eq!(collect(&peer, Kind::Sad, &b), Err(Error::Timeout));
        peer.finish();
    }
}

// Mutation: re-base the absolute deadline after the send. The fixture's
// receive guard fails instead of letting a fresh 150 ms window reopen.
#[test]
fn expired_send_never_rebases_deadline_before_receive() {
    let fixture = Fixture::new();
    let mut peer = fixture.peer("silence");
    // The peer consumes 160 ms after signalling readiness, so the 150 ms
    // budget is already spent when `send` returns.
    peer.expire_after_ready = true;
    let b = Budget::new(Duration::from_millis(150)).unwrap();
    let started = Instant::now();
    assert_eq!(collect(&peer, Kind::Spd, &b), Err(Error::Timeout));
    // Anti-hang ceiling only; the oracle is Timeout plus the peer's guard that
    // receive never runs after the expired send (a re-based deadline calls it).
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "collector returned without waiting for a second deadline"
    );
    peer.finish();
}
