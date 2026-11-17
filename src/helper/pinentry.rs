//! The small Assuan subset used by openfortivpn 1.24.1. The caller must bind
//! `obtain` to an authenticated owned child, never to SETKEYINFO/prompt text.
//! This codec does not itself provide the privileged credential transport.
use crate::{
    model::VpnKind,
    secrets::{Credentials, Secret},
};
use std::io::{BufRead, Write};
use zeroize::Zeroizing;

const MAX_LINE: usize = 8192;
const FAILURE: &[u8] = b"ERR 1 unavailable\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Io,
    InvalidQuery,
    Limit,
    Unavailable,
}

/// Obtain at most one password, after a complete GETPIN. Metadata queries are
/// acknowledged without looking up credentials. All errors have a fixed reply.
pub fn serve(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    obtain: impl FnOnce() -> Result<Secret, Error>,
) -> Result<(), Error> {
    reply(writer, b"OK vpnt\n")?;
    let result = exchange(reader, writer, obtain);
    if result.is_err() {
        let _ = reply(writer, FAILURE);
    }
    result
}

fn exchange(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    obtain: impl FnOnce() -> Result<Secret, Error>,
) -> Result<(), Error> {
    for _ in 0..32 {
        let line = line(reader)?;
        if line.as_slice() == b"GETPIN" {
            let credentials = Credentials {
                password: obtain()?,
                psk: Secret::from(""),
            };
            credentials
                .validate(VpnKind::Ssl)
                .map_err(|_| Error::Unavailable)?;
            // Reserve once; no old credential fragments survive reallocations.
            // One short write also accommodates openfortivpn's parser, which
            // accepts the D line before consuming the final OK.
            let mut response = Zeroizing::new(Vec::with_capacity(3 * 256 + 8));
            response.extend_from_slice(b"D ");
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            for byte in credentials.password.expose().bytes() {
                if !(0x21..0x7f).contains(&byte) || byte == b'%' {
                    response.extend_from_slice(&[
                        b'%',
                        HEX[(byte >> 4) as usize],
                        HEX[(byte & 15) as usize],
                    ]);
                } else {
                    response.push(byte);
                }
            }
            response.extend_from_slice(b"\nOK\n");
            return reply(writer, &response);
        }
        if line.as_slice() == b"BYE" {
            return reply(writer, b"OK\n");
        }
        if line.as_slice() == b"RESET"
            || [
                b"SETTITLE ".as_slice(),
                b"SETDESC ",
                b"SETKEYINFO ",
                b"SETPROMPT ",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        {
            reply(writer, b"OK\n")?;
        } else {
            return Err(Error::InvalidQuery);
        }
    }
    Err(Error::Limit)
}

fn reply(writer: &mut impl Write, bytes: &[u8]) -> Result<(), Error> {
    writer
        .write_all(bytes)
        .and_then(|()| writer.flush())
        .map_err(|_| Error::Io)
}

fn line(reader: &mut impl BufRead) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE));
    loop {
        let bytes = reader.fill_buf().map_err(|_| Error::Io)?;
        if bytes.is_empty() {
            return Err(Error::InvalidQuery);
        }
        let end = bytes.iter().position(|byte| *byte == b'\n');
        let length = end.unwrap_or(bytes.len());
        if length > MAX_LINE - line.len() {
            return Err(Error::Limit);
        }
        line.extend_from_slice(&bytes[..length]);
        reader.consume(length + usize::from(end.is_some()));
        if end.is_some() {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() || line.iter().any(|byte| !(0x20..0x7f).contains(byte)) {
                return Err(Error::InvalidQuery);
            }
            return Ok(line);
        }
    }
}
