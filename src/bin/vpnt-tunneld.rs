#[cfg(target_os = "linux")]
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};
#[cfg(target_os = "linux")]
use vpnt::tunneld::{
    fortinet_instance,
    handshake::{self, Backend},
    ipsec_instance,
    protocol::ErrorCode,
};

#[cfg(target_os = "linux")]
fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some((command, args)) = args.split_first() {
        if command == "policy" {
            std::process::exit(vpnt::tunneld::admin::run(args));
        }
        if command == "instance" {
            let status = match run_instance(args) {
                Ok(()) => 0,
                Err(InstanceError::Refused(ErrorCode::BadRequest)) => {
                    eprintln!("usage: vpnt-tunneld instance <ipsec|fortinet> <generation>");
                    64
                }
                Err(InstanceError::Refused(code)) => {
                    eprintln!("tunnel instance: {code:?}");
                    69
                }
                Err(InstanceError::Io(error)) => {
                    eprintln!("tunnel instance: {error}");
                    1
                }
            };
            std::process::exit(status);
        }
    }
    // SAFETY: standalone main before threads; the activation descriptor is unowned.
    let code = unsafe { vpnt::tunneld::server::run_linux(&args) };
    if code == 64 {
        eprintln!("started by systemd through vpnt-tunneld.socket; not for direct use");
    }
    std::process::exit(code);
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum InstanceError {
    Refused(ErrorCode),
    Io(io::Error),
}

#[cfg(target_os = "linux")]
fn parse_instance(args: &[OsString]) -> Result<(Backend, &str), InstanceError> {
    let invalid = || InstanceError::Refused(ErrorCode::BadRequest);
    let [backend, generation] = args else {
        return Err(invalid());
    };
    let backend = match backend.to_str() {
        Some("ipsec") => Backend::Ipsec,
        Some("fortinet") => Backend::Fortinet,
        _ => return Err(invalid()),
    };
    let generation = generation.to_str().ok_or_else(invalid)?;
    if generation.len() != 32
        || !generation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid());
    }
    Ok((backend, generation))
}

#[cfg(target_os = "linux")]
fn instance_handshake_paths() -> (PathBuf, PathBuf) {
    let directory = Path::new(handshake::INSTANCE_HANDSHAKE_DIRECTORY);
    (
        directory.join(handshake::CONTROL_SOCKET_NAME),
        directory.join(handshake::RECORD_NAME),
    )
}

#[cfg(target_os = "linux")]
fn run_instance(args: &[OsString]) -> Result<(), InstanceError> {
    let (backend, generation) = parse_instance(args)?;
    let invocation = std::env::var("INVOCATION_ID")
        .map_err(|_| InstanceError::Io(io::Error::other("missing or invalid INVOCATION_ID")))?;
    if backend == Backend::Fortinet {
        let (socket, record) = instance_handshake_paths();
        let channel =
            handshake::connect_instance(&socket, &record, generation, backend, &invocation, 0)
                .map_err(InstanceError::Io)?;
        fortinet_instance::run_instance(channel).map_err(InstanceError::Io)?;
        return Ok(());
    }
    let runtime_directory = std::env::var_os("RUNTIME_DIRECTORY")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| InstanceError::Io(io::Error::other("missing RUNTIME_DIRECTORY")))?;
    let (socket, record) = instance_handshake_paths();
    let channel =
        handshake::connect_instance(&socket, &record, generation, backend, &invocation, 0)
            .map_err(InstanceError::Io)?;
    ipsec_instance::run(
        channel,
        ipsec_instance::Params {
            directory: runtime_directory.into(),
        },
    )
    .map_err(InstanceError::Io)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(77);
}

#[cfg(all(test, target_os = "linux"))]
mod tunneld_tests {
    use super::*;
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    const GENERATION: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn tunneld_instance_rejects_invalid_arguments_before_setup() {
        for args in [
            vec![],
            vec!["ipsec"],
            vec!["unknown", GENERATION],
            vec!["ipsec", "0123456789ABCDEF0123456789abcdef"],
            vec!["ipsec", "0123456789abcdef0123456789abcde"],
            vec!["ipsec", "0123456789abcdef0123456789abcdef0"],
            vec!["ipsec", "../0123456789abcdef0123456789abcde"],
            vec!["fortinet", GENERATION, "extra"],
        ] {
            let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
            assert!(matches!(
                run_instance(&args),
                Err(InstanceError::Refused(ErrorCode::BadRequest))
            ));
        }
        let non_utf8 = OsStr::from_bytes(b"\xff").to_os_string();
        assert!(matches!(
            run_instance(&["ipsec".into(), non_utf8]),
            Err(InstanceError::Refused(ErrorCode::BadRequest))
        ));
    }

    #[test]
    fn tunneld_instance_contract_matches_units_and_fortinet_needs_its_handshake() {
        assert_eq!(
            parse_instance(&["ipsec".into(), GENERATION.into()]).unwrap(),
            (Backend::Ipsec, GENERATION)
        );
        assert_eq!(
            parse_instance(&["fortinet".into(), GENERATION.into()]).unwrap(),
            (Backend::Fortinet, GENERATION)
        );
        // Fortinet now runs the supervisor: without the unit's invocation and
        // handshake directory it fails closed with an I/O error, never as
        // "program missing" and never by starting anything.
        assert!(matches!(
            run_instance(&["fortinet".into(), GENERATION.into()]),
            Err(InstanceError::Io(_))
        ));
        let (socket, record) = instance_handshake_paths();
        assert_eq!(socket, Path::new("/run/vpnt-instance/control.sock"));
        assert_eq!(record, Path::new("/run/vpnt-instance/record.json"));
        for (backend, unit) in [
            (
                "ipsec",
                include_str!("../../packaging/linux/vpnt-tunneld-ipsec@.service"),
            ),
            (
                "fortinet",
                include_str!("../../packaging/linux/vpnt-tunneld-fortinet@.service"),
            ),
        ] {
            let bind = format!(
                "BindReadOnlyPaths={}/%i:{}",
                handshake::GENERATION_ROOT,
                handshake::INSTANCE_HANDSHAKE_DIRECTORY
            );
            assert!(unit.lines().any(|line| line == bind));
            assert!(
                unit.lines()
                    .any(|line| line == "RuntimeDirectory=vpnt-instance-%i")
            );
            assert!(unit.lines().any(|line| line == "RuntimeDirectoryMode=0700"));
            let exec = format!("ExecStart=/usr/lib/vpnt/vpnt-tunneld instance {backend} %i");
            assert!(unit.lines().any(|line| line == exec));
        }
    }
}
