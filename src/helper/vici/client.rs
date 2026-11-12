//! One command per peer-authenticated connection, with a total I/O deadline.
use super::{Error, Message, Packet, read_packet, valid_name, write_packet};
use crate::helper::local_socket::{TimedStream, connect_deadline, peer_uid};
use std::{
    collections::BTreeSet,
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};
const MAX_EVENTS: usize = 256;
const MAX_RECEIVED: usize = 4 * 1024 * 1024;

pub struct CommandResult {
    pub response: Message,
    pub events: Vec<(String, Message)>,
}

pub struct Client {
    stream: UnixStream,
    timeout: Duration,
}

impl Client {
    /// The driver supplies a socket inside its admitted root-owned directory.
    /// This check also rejects a different user impersonating a charon peer.
    pub fn connect(path: &Path, owner: u32, timeout: Duration) -> Result<Self, Error> {
        if !path.is_absolute() {
            return Err(Error::InvalidMessage);
        }
        Self::from_stream(connect_deadline(path, timeout)?, owner, timeout)
    }
    pub fn from_stream(stream: UnixStream, owner: u32, timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err(Error::Timeout);
        }
        if peer_uid(&stream)? != owner {
            return Err(Error::UntrustedPeer);
        }
        stream.set_nonblocking(true)?;
        Ok(Self { stream, timeout })
    }
    pub fn command(
        self,
        name: &str,
        message: Message,
        events: &[&str],
    ) -> Result<CommandResult, Error> {
        if !valid_name(name) || events.iter().any(|name| !valid_name(name)) {
            return Err(Error::InvalidMessage);
        }
        let registered: BTreeSet<_> = events.iter().copied().collect();
        if registered.len() != events.len() || registered.len() > 16 {
            return Err(Error::Limit);
        }
        let mut stream = TimedStream::new(self.stream, self.timeout, MAX_RECEIVED)?;
        let mut received = Vec::new();
        // Do not expect confirmations before events from subscriptions that
        // have already been confirmed: charon can emit at any time.
        let mut confirmed = BTreeSet::new();
        for event in events {
            write_packet(&mut stream, &Packet::Register((*event).into()))?;
            loop {
                match read_packet(&mut stream)? {
                    Packet::Confirm => {
                        confirmed.insert(*event);
                        break;
                    }
                    Packet::UnknownEvent => return Err(Error::UnknownEvent),
                    Packet::Event(name, message) if confirmed.contains(name.as_str()) => {
                        push_event(&mut received, name, message)?
                    }
                    _ => return Err(Error::UnexpectedPacket),
                }
            }
        }
        write_packet(&mut stream, &Packet::Request(name.into(), message))?;
        loop {
            match read_packet(&mut stream)? {
                Packet::Response(response) => {
                    return Ok(CommandResult {
                        response,
                        events: received,
                    });
                }
                Packet::UnknownCommand => return Err(Error::UnknownCommand),
                Packet::Event(name, message) if registered.contains(name.as_str()) => {
                    push_event(&mut received, name, message)?
                }
                _ => return Err(Error::UnexpectedPacket),
            }
        }
        // Dropping this connection removes its subscriptions at charon. A new
        // connection is mandatory for any subsequent command, including cancel.
    }
}

fn push_event(
    events: &mut Vec<(String, Message)>,
    name: String,
    message: Message,
) -> Result<(), Error> {
    if events.len() >= MAX_EVENTS {
        return Err(Error::Limit);
    }
    events.push((name, message));
    Ok(())
}
