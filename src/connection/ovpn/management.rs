//! The subset of the OpenVPN management protocol the OVPN driver speaks.
//! Lines from openvpn are untrusted: they are parsed into typed events with a
//! hard length bound and their text is never retained.
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    io::{self, BufRead, Read},
    net::Ipv4Addr,
};

/// Longest line accepted from openvpn. A PK_SIGN payload is a few hundred
/// bytes; anything near this bound is not a message the driver understands.
pub const MAX_LINE: usize = 16 * 1024;

pub const VERSION: &str = "version 3\n";
pub const STATE_ON: &str = "state on\n";
pub const HOLD_RELEASE: &str = "hold release\n";
pub const TERMINATE: &str = "signal SIGTERM\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    Hold,
    State(State),
    NeedCertificate,
    Sign {
        data: Vec<u8>,
        algorithm: Option<String>,
    },
    /// A PK_SIGN whose data cannot be decoded; it still needs an answer.
    UnreadableSign,
    Fatal,
    Ignored,
    Malformed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub phase: Phase,
    pub reason: Option<Reason>,
    pub tunnel_ipv4: Option<Ipv4Addr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Connecting,
    Wait,
    Auth,
    GetConfig,
    AssignIp,
    AddRoutes,
    Connected,
    Reconnecting,
    Exiting,
    Other,
}

/// Why openvpn left or restarted a session, from the STATE description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    AuthFailure,
    TlsError,
    PingRestart,
    /// openvpn stopped on an internal error (>FATAL).
    Fatal,
    Other,
}

/// Parses one line obtained from `read_line`, which bounds its length.
pub fn parse(line: &[u8]) -> Event {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Ok(line) = std::str::from_utf8(line) else {
        return Event::Malformed;
    };
    let Some((kind, payload)) = line.strip_prefix('>').and_then(|rest| rest.split_once(':')) else {
        return Event::Ignored;
    };
    match kind {
        "HOLD" => Event::Hold,
        "STATE" => state(payload).map_or(Event::Malformed, Event::State),
        "NEED-CERTIFICATE" => Event::NeedCertificate,
        "PK_SIGN" => sign(payload),
        "FATAL" => Event::Fatal,
        _ => Event::Ignored,
    }
}

fn state(payload: &str) -> Option<State> {
    let mut fields = payload.split(',');
    fields.next()?.parse::<u64>().ok()?;
    let phase = match fields.next()? {
        "CONNECTING" | "RESOLVE" | "TCP_CONNECT" => Phase::Connecting,
        "WAIT" => Phase::Wait,
        "AUTH" | "AUTH_PENDING" => Phase::Auth,
        "GET_CONFIG" => Phase::GetConfig,
        "ASSIGN_IP" => Phase::AssignIp,
        "ADD_ROUTES" => Phase::AddRoutes,
        "CONNECTED" => Phase::Connected,
        "RECONNECTING" => Phase::Reconnecting,
        "EXITING" => Phase::Exiting,
        _ => Phase::Other,
    };
    let description = fields.next().unwrap_or_default();
    let reason = matches!(phase, Phase::Reconnecting | Phase::Exiting).then(|| match description {
        "auth-failure" => Reason::AuthFailure,
        "tls-error" => Reason::TlsError,
        "ping-restart" => Reason::PingRestart,
        _ => Reason::Other,
    });
    let tunnel_ipv4 = fields.next().and_then(|address| address.parse().ok());
    Some(State {
        phase,
        reason,
        tunnel_ipv4,
    })
}

fn sign(payload: &str) -> Event {
    let (data, algorithm) = match payload.split_once(',') {
        Some((data, algorithm)) => (data, Some(algorithm.to_owned())),
        None => (payload, None),
    };
    match STANDARD.decode(data) {
        Ok(data) if !data.is_empty() => Event::Sign { data, algorithm },
        _ => Event::UnreadableSign,
    }
}

/// Reads one line of at most MAX_LINE bytes. Ok(false) means end of stream;
/// a longer line is an error, so a misbehaving peer cannot grow the buffer.
pub fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<bool> {
    line.clear();
    let read = reader
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', line)?;
    if read == 0 {
        return Ok(false);
    }
    if line.len() > MAX_LINE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "management line too long",
        ));
    }
    Ok(true)
}

pub fn certificate(der: &[u8]) -> String {
    let mut command = String::from("certificate\n-----BEGIN CERTIFICATE-----\n");
    push_wrapped(&mut command, der);
    command.push_str("-----END CERTIFICATE-----\nEND\n");
    command
}

pub fn signature(signature: &[u8]) -> String {
    let mut command = String::from("pk-sig\n");
    push_wrapped(&mut command, signature);
    command.push_str("END\n");
    command
}

fn push_wrapped(command: &mut String, bytes: &[u8]) {
    let encoded = STANDARD.encode(bytes);
    for chunk in encoded.as_bytes().chunks(64) {
        // Base64 output is ASCII, so every chunk is valid UTF-8.
        command.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        command.push('\n');
    }
}

#[cfg(test)]
#[path = "management_tests.rs"]
mod tests;
