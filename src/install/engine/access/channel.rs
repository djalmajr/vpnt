use super::*;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: String,
}
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Reply<'a> {
    Ready {
        format: u32,
        version: &'a str,
    },
    Removed {
        id: &'a str,
        component_present: bool,
    },
    Failed {
        id: Option<&'a str>,
        error: Error,
    },
}

pub(in crate::install::engine) fn serve(
    mut caller: Caller,
    executor: &mut Executor,
) -> Result<(), Error> {
    caller.stream.set_nonblocking(true).map_err(|_| Error::Io)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    write(
        &mut caller.stream,
        &Reply::Ready {
            format: 1,
            version: env!("CARGO_PKG_VERSION"),
        },
        deadline,
    )?;
    let request = (|| {
        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            if Instant::now() >= deadline {
                return Err(Error::InvalidRequest);
            }
            match caller.stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    bytes.extend_from_slice(&buffer[..n]);
                    if bytes.len() > 4096 {
                        return Err(Error::InvalidRequest);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(Error::InvalidRequest),
            }
        }
        if bytes.last() != Some(&b'\n') {
            return Err(Error::InvalidRequest);
        }
        let request: Request = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?;
        if request.id.is_empty()
            || request.id.len() > 64
            || !request
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Error::InvalidRequest);
        }
        Ok(request)
    })();
    let reply = match &request {
        Ok(request) => match executor.remove(caller.uid) {
            Ok(outcome) => Reply::Removed {
                id: &request.id,
                component_present: !outcome.users.is_empty(),
            },
            Err(error) => Reply::Failed {
                id: Some(&request.id),
                error,
            },
        },
        Err(error) => Reply::Failed {
            id: None,
            error: *error,
        },
    };
    write(
        &mut caller.stream,
        &reply,
        Instant::now() + Duration::from_secs(5),
    )?;
    drop(caller.stream);
    Ok(())
}
fn write(
    stream: &mut std::os::unix::net::UnixStream,
    reply: &Reply<'_>,
    deadline: Instant,
) -> Result<(), Error> {
    let mut bytes = serde_json::to_vec(reply).map_err(|_| Error::Io)?;
    bytes.push(b'\n');
    let mut written = 0;
    while written < bytes.len() {
        if Instant::now() >= deadline {
            return Err(Error::Io);
        }
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err(Error::Io),
            Ok(n) => written += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => return Err(Error::Io),
        }
    }
    Ok(())
}
