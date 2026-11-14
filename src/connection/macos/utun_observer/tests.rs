use super::*;
use crate::connection::macos::utun_socket::{Error as SocketError, Observation};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

mod native;

const PIPE: u32 = libc::PROX_FDTYPE_PIPE as u32;
const SOCK: u32 = libc::PROX_FDTYPE_SOCKET as u32;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

fn open() -> AtomicBool {
    AtomicBool::new(false)
}

struct Fake {
    pid: u32,
    fds: Vec<(i32, u32)>,
    swap_at: Option<usize>,
    next_fds: Option<Vec<(i32, u32)>>,
    next_sockets: Option<BTreeMap<i32, Result<Observation, SocketError>>>,
    list_calls: usize,
    sockets: BTreeMap<i32, Result<Observation, SocketError>>,
    indexes: VecDeque<u32>,
    names: BTreeMap<u32, String>,
    hint: Option<usize>,
}

impl Fake {
    fn new() -> Self {
        Self {
            pid: 4242,
            fds: Vec::new(),
            swap_at: None,
            next_fds: None,
            next_sockets: None,
            list_calls: 0,
            sockets: BTreeMap::new(),
            indexes: VecDeque::new(),
            names: BTreeMap::new(),
            hint: None,
        }
    }

    fn utun(unit: u32) -> Observation {
        Observation {
            unit,
            socket: 0x1111_0000_0000_0000 + u64::from(unit),
            pcb: 0x2222_0000_0000_0000 + u64::from(unit),
        }
    }
}

impl Source for Fake {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn hint(&mut self) -> Result<usize, Error> {
        Ok(self.hint.unwrap_or(self.fds.len() + 20))
    }

    fn list(&mut self, capacity: usize) -> Result<Vec<(i32, u32)>, Error> {
        if self.swap_at == Some(self.list_calls) {
            if let Some(next) = self.next_fds.take() {
                self.fds = next;
            }
            if let Some(next) = self.next_sockets.take() {
                self.sockets = next;
            }
        }
        self.list_calls += 1;
        Ok(self.fds.iter().copied().take(capacity).collect())
    }

    fn socket(&mut self, fd: i32) -> Result<Observation, SocketError> {
        self.sockets
            .get(&fd)
            .copied()
            .unwrap_or(Err(SocketError::NotUtun))
    }

    fn index_of(&mut self, _name: &str) -> u32 {
        self.indexes.pop_front().unwrap_or(0)
    }

    fn name_of(&mut self, index: u32) -> Option<String> {
        self.names.get(&index).cloned()
    }
}

// Mutation: derive the interface from `unit` instead of `unit - 1`, so the
// reverse name check rejects the synthetic singleton.
#[test]
fn synthetic_singleton_observation_is_exact() {
    let mut fake = Fake::new();
    fake.fds = vec![(1, PIPE), (4, SOCK)];
    fake.sockets.insert(4, Ok(Fake::utun(5)));
    fake.indexes = VecDeque::from([9, 9]);
    fake.names.insert(9, "utun4".into());
    let observation = collect_pair(&mut fake, deadline(), &open(), || Ok(())).unwrap();
    assert_eq!(observation.name(), "utun4");
    assert_eq!(observation.index(), 9);
    assert_eq!(observation.fd, 4);
    assert_eq!(observation.unit, 5);
    assert_eq!(observation.socket, 0x1111_0000_0000_0005);
    assert_eq!(observation.pcb, 0x2222_0000_0000_0005);
    assert_eq!(observation.pid, 4242);
}

// Mutation: stop rejecting a second utun candidate, so the ambiguous inventory
// is published as a singleton.
#[test]
fn synthetic_zero_duplicate_and_ambiguous_fail_closed() {
    let mut empty = Fake::new();
    empty.fds = vec![(4, SOCK)];
    assert_eq!(
        collect_pair(&mut empty, deadline(), &open(), || Ok(())),
        Err(Error::NotFound)
    );

    let mut duplicate = Fake::new();
    duplicate.fds = vec![(1, PIPE), (1, SOCK)];
    assert_eq!(
        collect_pair(&mut duplicate, deadline(), &open(), || Ok(())),
        Err(Error::Invalid)
    );

    let mut ambiguous = Fake::new();
    ambiguous.fds = vec![(4, SOCK), (5, SOCK)];
    ambiguous.sockets.insert(4, Ok(Fake::utun(5)));
    ambiguous.sockets.insert(5, Ok(Fake::utun(6)));
    assert_eq!(
        collect_pair(&mut ambiguous, deadline(), &open(), || Ok(())),
        Err(Error::Ambiguous)
    );
}

// Mutation: ignore the second-sample comparison, so a descriptor or interface
// swap is accepted as the same observation.
#[test]
fn synthetic_swap_and_metadata_changes_are_changed() {
    let mut fd_swap = Fake::new();
    fd_swap.fds = vec![(4, SOCK)];
    fd_swap.sockets.insert(4, Ok(Fake::utun(5)));
    fd_swap.swap_at = Some(2);
    fd_swap.next_fds = Some(vec![(5, SOCK)]);
    fd_swap
        .next_sockets
        .get_or_insert_with(BTreeMap::new)
        .insert(5, Ok(Fake::utun(5)));
    fd_swap.indexes = VecDeque::from([9, 9]);
    fd_swap.names.insert(9, "utun4".into());
    assert_eq!(
        collect_pair(&mut fd_swap, deadline(), &open(), || Ok(())),
        Err(Error::Changed)
    );

    let mut unit_change = Fake::new();
    unit_change.fds = vec![(4, SOCK)];
    unit_change.sockets.insert(4, Ok(Fake::utun(5)));
    unit_change.swap_at = Some(2);
    unit_change.next_fds = Some(vec![(4, SOCK)]);
    unit_change
        .next_sockets
        .get_or_insert_with(BTreeMap::new)
        .insert(4, Ok(Fake::utun(6)));
    unit_change.indexes = VecDeque::from([9, 9]);
    unit_change.names.insert(9, "utun4".into());
    assert_eq!(
        collect_pair(&mut unit_change, deadline(), &open(), || Ok(())),
        Err(Error::Changed)
    );

    let mut index_change = Fake::new();
    index_change.fds = vec![(4, SOCK)];
    index_change.sockets.insert(4, Ok(Fake::utun(5)));
    index_change.indexes = VecDeque::from([9, 10]);
    index_change.names.insert(9, "utun4".into());
    index_change.names.insert(10, "utun4".into());
    assert_eq!(
        collect_pair(&mut index_change, deadline(), &open(), || Ok(())),
        Err(Error::Changed)
    );
}

// Mutation: treat a saturated inventory as complete instead of growing it.
#[test]
fn synthetic_growth_and_cap_fail_closed() {
    let mut growth = Fake::new();
    growth.fds = (1..=40).map(|fd| (fd, PIPE)).collect();
    growth.fds[32] = (33, SOCK);
    growth.sockets.insert(33, Ok(Fake::utun(7)));
    growth.hint = Some(0);
    growth.indexes = VecDeque::from([9, 9]);
    growth.names.insert(9, "utun6".into());
    let observation = collect_pair(&mut growth, deadline(), &open(), || Ok(())).unwrap();
    assert_eq!(observation.fd, 33);
    assert_eq!(observation.unit, 7);
    assert_eq!(observation.name(), "utun6");

    let mut capped = Fake::new();
    capped.fds = (1..=FD_LIMIT as i32).map(|fd| (fd, PIPE)).collect();
    capped.hint = Some(0);
    assert_eq!(
        collect_pair(&mut capped, deadline(), &open(), || Ok(())),
        Err(Error::Exhausted)
    );
}

// Mutation: ignore the cancellation flag, so a canceled sample is published.
#[test]
fn synthetic_cancelled_and_expired_budgets_fail_closed() {
    let mut fake = Fake::new();
    fake.fds = vec![(4, SOCK)];
    fake.sockets.insert(4, Ok(Fake::utun(5)));
    fake.indexes = VecDeque::from([9, 9]);
    fake.names.insert(9, "utun4".into());
    let canceled = AtomicBool::new(true);
    assert_eq!(
        collect_pair(&mut fake, deadline(), &canceled, || Ok(())),
        Err(Error::Canceled)
    );
    assert_eq!(
        collect_pair(
            &mut fake,
            Instant::now() - Duration::from_millis(1),
            &open(),
            || Ok(())
        ),
        Err(Error::Timeout)
    );
}
