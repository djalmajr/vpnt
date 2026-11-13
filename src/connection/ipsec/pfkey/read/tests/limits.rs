use super::*;
use socket::Transport;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
};

fn header(size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..16].copy_from_slice(&request(Kind::Sad, 42, 73));
    bytes[4..6].copy_from_slice(&((size / 8) as u16).to_ne_bytes());
    bytes
}

// Mutations: omit either global limit, reject the boundary, or fail to check
// envelopes of foreign messages. Foreign traffic cannot consume unbounded IO.
#[test]
fn packet_and_byte_limits_include_foreign_traffic_without_rejecting_the_boundary() {
    let mut batch = batch::Batch::new(Kind::Sad, 1, 73);
    for _ in 0..4096 {
        batch.push(&header(16)).unwrap();
    }
    assert_eq!(batch.push(&header(16)), Err(Error::Exhausted));
    assert_eq!(batch.finish(), Err(Error::Changed));
    let mut batch = batch::Batch::new(Kind::Sad, 1, 73);
    for _ in 0..32 {
        batch.push(&header(524_280)).unwrap();
    }
    batch.push(&header(256)).unwrap(); // exactly 16 MiB
    assert_eq!(batch.push(&header(16)), Err(Error::Exhausted));
    let mut batch = batch::Batch::new(Kind::Sad, 1, 73);
    let mut invalid = header(16);
    invalid[0] = 1;
    assert_eq!(batch.push(&invalid), Err(Error::Invalid));
    let mut short = header(16);
    short[4] = 1;
    assert_eq!(batch.push(&short), Err(Error::Invalid));
}

struct Feed {
    frames: RefCell<VecDeque<Vec<u8>>>,
    sends: Cell<usize>,
}
impl Transport for Feed {
    fn send(&self, _: &[u8; 16], _: &Budget) -> Result<(), Error> {
        self.sends.set(self.sends.get() + 1);
        Ok(())
    }
    fn pending(&self, _: &Budget) -> Result<bool, Error> {
        Ok(!self.frames.borrow().is_empty())
    }
    fn receive(&self, bytes: &mut [u8], _: &Budget) -> Result<usize, Error> {
        assert!(
            bytes.iter().all(|b| *b == 0),
            "raw receive buffer cleared before reuse"
        );
        let next = self
            .frames
            .borrow_mut()
            .pop_front()
            .ok_or(Error::Unavailable)?;
        bytes[..next.len()].copy_from_slice(&next);
        Ok(next.len())
    }
}

// Mutations: remove zeroization between packets or fail to check a canceled
// budget before the first send. Frames still originate in the independent C peer.
#[test]
fn raw_receive_storage_is_cleared_before_reuse_and_preflight_cancellation_stops_io() {
    let fixture = Fixture::new();
    let peer = fixture.peer("suffix");
    peer.send(&request(Kind::Sad, std::process::id(), 73), &budget())
        .unwrap();
    let mut frame = vec![0; 524_280];
    let n = peer.receive(&mut frame, &budget()).unwrap();
    frame.truncate(n);
    peer.finish();
    let mut first = frame.clone();
    first[8..12].copy_from_slice(&1u32.to_ne_bytes());
    let feed = Feed {
        frames: RefCell::new(VecDeque::from([first, frame])),
        sends: Cell::new(0),
    };
    let batch = collect_transport(&feed, Kind::Sad, std::process::id(), 73, &budget()).unwrap();
    assert_eq!(batch.entries.len(), 2);
    assert_eq!(feed.sends.get(), 1);
    let cancel = Arc::new(AtomicBool::new(false));
    let budget = Budget::until(
        Instant::now() + Duration::from_secs(3),
        Some(cancel.clone()),
    )
    .unwrap();
    cancel.store(true, Ordering::Release);
    assert_eq!(
        collect_transport(&feed, Kind::Sad, std::process::id(), 73, &budget),
        Err(Error::Canceled)
    );
    assert_eq!(feed.sends.get(), 1, "canceled preflight cannot send");
}
