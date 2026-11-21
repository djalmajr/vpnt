//! Application datagrams on the authenticated writer–IPsec instance channel.
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{
    handshake::MAX_FRAME,
    protocol::{self, CidrV4, ErrorCode},
};
use crate::{model::VpnKind, secrets::Credentials};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Order {
    Start(Start),
    Stop {},
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub remote_ipv4: Ipv4Addr,
    pub port: u16,
    pub peer_identity: String,
    pub username: String,
    pub if_id: u32,
    pub reqid: u16,
    /// A sole `dynamic` selector or canonical IPv4 CIDRs.
    pub local_ts: Vec<String>,
    pub remote_ts: Vec<CidrV4>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Established {
        if_id: u32,
        reqid: u16,
        virtual_ipv4: Ipv4Addr,
        remote_ts: Vec<CidrV4>,
    },
    Failed {
        code: ErrorCode,
    },
    Stopped {},
}

// Same credential representation as the public writer protocol: two
// big-endian u16 lengths, each immediately followed by its UTF-8 bytes.
// The frame limit of the authenticated transport, one constant for both
// directions, covers two 4096-byte secrets and their lengths.

/// Encode a separate credential datagram. The caller must keep the returned
/// buffer owned through send so it is wiped on both success and failure.
pub fn encode_credentials(
    credentials: &protocol::Credentials,
) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
    let psk = credentials.psk().ok_or(ErrorCode::BadRequest)?;
    let size = 4 + credentials.password().len() + psk.len();
    if size > MAX_FRAME {
        return Err(ErrorCode::BadRequest);
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(size));
    credentials
        .write(&mut *frame)
        .map_err(|_| ErrorCode::BadRequest)?;
    Ok(frame)
}

/// Consume a mutable datagram and wipe it even if its contents are refused.
pub(super) fn decode_credentials(frame: &mut [u8]) -> Result<Credentials, ErrorCode> {
    fn read<'a>(input: &mut &'a [u8]) -> Option<&'a str> {
        let (size, rest) = input.split_first_chunk::<2>()?;
        let (value, rest) = rest.split_at_checked(u16::from_be_bytes(*size).into())?;
        *input = rest;
        std::str::from_utf8(value).ok()
    }

    let result = (|| {
        if frame.len() > MAX_FRAME {
            return Err(ErrorCode::BadRequest);
        }
        let mut input = &*frame;
        let password = read(&mut input).ok_or(ErrorCode::BadRequest)?;
        let psk = read(&mut input).ok_or(ErrorCode::BadRequest)?;
        if !input.is_empty() {
            return Err(ErrorCode::BadRequest);
        }
        let credentials = Credentials {
            password: password.into(),
            psk: psk.into(),
        };
        credentials
            .validate(VpnKind::Ipsec)
            .map_err(|_| ErrorCode::BadRequest)?;
        Ok(credentials)
    })();
    frame.zeroize();
    result
}
