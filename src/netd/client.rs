//! Synchronous client for a single netd session.
use super::protocol::{
    Config, ErrorCode, MAX_LINE, Request, Response, TunName, VERSION, decode_response,
    encode_request, read_line,
};
use crate::helper::local_socket::{Budget, TimedStream, connect_deadline};
use std::{
    fmt,
    io::{self, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

pub const SOCKET_PATH: &str = "/run/vpnt/netd.sock";
const SHORT: Duration = Duration::from_secs(10);
const CONFIGURE: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    Refused(ErrorCode),
    Protocol,
}
impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "netd I/O: {error}"),
            Self::Refused(code) => write!(f, "netd refused request ({code:?})"),
            Self::Protocol => f.write_str("invalid netd reply"),
        }
    }
}
impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct Client {
    stream: Option<UnixStream>,
}
impl Client {
    pub fn connect(path: &Path) -> Result<Self, ClientError> {
        let stream = connect_deadline(path, &Budget::new(SHORT)?)?;
        let mut client = Self {
            stream: Some(stream),
        };
        client.exchange(
            Request::Hello { version: VERSION },
            SHORT,
            |reply| match reply {
                Response::Version(VERSION) => Some(()),
                _ => None,
            },
        )?;
        Ok(client)
    }
    pub fn open_tun(&mut self) -> Result<TunName, ClientError> {
        self.exchange(Request::OpenTun, SHORT, |reply| match reply {
            Response::Opened(name) => Some(name),
            _ => None,
        })
    }
    pub fn configure(&mut self, config: &Config) -> Result<(), ClientError> {
        config.validate().map_err(ClientError::Refused)?;
        self.ack(Request::Configure(config.into()), CONFIGURE)
    }
    pub fn close_tun(&mut self, name: &TunName) -> Result<(), ClientError> {
        self.ack(
            Request::CloseTun {
                ifname: name.to_string(),
            },
            SHORT,
        )
    }
    fn ack(&mut self, request: Request, timeout: Duration) -> Result<(), ClientError> {
        self.exchange(request, timeout, |reply| {
            matches!(reply, Response::Ok).then_some(())
        })
    }
    fn exchange<T>(
        &mut self,
        request: Request,
        timeout: Duration,
        convert: impl FnOnce(Response) -> Option<T>,
    ) -> Result<T, ClientError> {
        let stream = self.stream.take().ok_or(ClientError::Protocol)?;
        let mut io = TimedStream::new(stream.try_clone()?, timeout, MAX_LINE)?;
        io.write_all(&encode_request(&request))?;
        let response = read_line(&mut BufReader::new(io))?;
        let response = decode_response(&response).map_err(|_| ClientError::Protocol)?;
        // A transport error or unexpected reply leaves this session unusable.
        if let Response::Error(error) = response {
            self.stream = Some(stream);
            return Err(ClientError::Refused(error));
        }
        let result = convert(response).ok_or(ClientError::Protocol)?;
        self.stream = Some(stream);
        Ok(result)
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
