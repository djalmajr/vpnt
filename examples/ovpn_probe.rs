//! Manual check of the OVPN driver against a real server, without privilege:
//! openvpn runs with a null device and no ifconfig or routes, so the session
//! authenticates and receives its configuration but changes nothing locally.
//!
//! cargo run --example ovpn_probe -- --openvpn PATH --config PROFILE.ovpn \
//!     --module /usr/lib/libpkcs11-module.so --key-id HEX [--hold SECONDS] \
//!     [--log FILE] [--pkcs1-only] [-- extra openvpn arguments]
#[cfg(unix)]
fn main() -> Result<(), String> {
    use std::{
        ffi::OsString,
        path::PathBuf,
        thread,
        time::{Duration, Instant},
    };
    use vpnt::connection::ovpn::{
        management::Phase,
        pkcs11::TokenKey,
        session::{Launch, Progress, Session, Signatures},
    };

    let mut args = std::env::args_os().skip(1);
    let (mut openvpn, mut config, mut module, mut key_id) = (None, None, None, None);
    let (mut hold, mut signatures, mut extra) = (
        Duration::from_secs(5),
        Signatures::Any,
        Vec::<OsString>::new(),
    );
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg:?} needs a value"));
        match arg.to_str() {
            Some("--openvpn") => openvpn = Some(PathBuf::from(value()?)),
            Some("--config") => config = Some(PathBuf::from(value()?)),
            Some("--module") => module = Some(PathBuf::from(value()?)),
            Some("--key-id") => key_id = Some(hex(&value()?.to_string_lossy())?),
            Some("--hold") => {
                hold = Duration::from_secs(
                    value()?
                        .to_string_lossy()
                        .parse()
                        .map_err(|_| "bad --hold")?,
                )
            }
            Some("--log") => extra.extend([OsString::from("--log"), value()?]),
            Some("--pkcs1-only") => signatures = Signatures::Pkcs1Only,
            Some("--") => extra.extend(args.by_ref()),
            _ => return Err(format!("unknown argument {arg:?}")),
        }
    }
    let token = TokenKey::open(
        &module.ok_or("--module is required")?,
        &key_id.ok_or("--key-id is required")?,
    )
    .map_err(|error| format!("token: {error:?}"))?;
    extra.splice(
        0..0,
        [
            "--dev",
            "null",
            "--dev-type",
            "null",
            "--script-security",
            "1",
        ]
        .map(OsString::from),
    );
    let launch = Launch {
        openvpn: openvpn.ok_or("--openvpn is required")?,
        config: config.ok_or("--config is required")?,
        dev: None,
        signatures,
        extra,
        env: Vec::new(),
    };
    let session = Session::start(launch, token).map_err(|error| format!("start: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut connected = false;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match session.progress().recv_timeout(left) {
            Ok(Progress::State(state)) => {
                println!(
                    "state: {:?} reason={:?} tunnel={:?}",
                    state.phase, state.reason, state.tunnel_ipv4
                );
                if state.phase == Phase::Connected {
                    connected = true;
                    break;
                }
                if state.phase == Phase::Exiting {
                    break;
                }
            }
            Ok(progress) => println!("progress: {progress:?}"),
            Err(_) => break,
        }
    }
    if connected {
        thread::sleep(hold);
    }
    let _ = session.stop();
    let outcome = session.wait().map_err(|error| format!("wait: {error}"))?;
    println!(
        "outcome: connected={connected} reason={:?} status={}",
        outcome.reason, outcome.status
    );
    connected
        .then_some(())
        .ok_or_else(|| "did not connect".to_owned())
}

#[cfg(unix)]
fn hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("--key-id must have an even number of hex digits".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&text[at..at + 2], 16).map_err(|_| "--key-id is not hex".to_owned())
        })
        .collect()
}

#[cfg(not(unix))]
fn main() {}
