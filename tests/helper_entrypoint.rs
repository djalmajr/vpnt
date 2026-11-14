#![cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[test]
fn helper_executable_rejects_unprivileged_modes_and_environment_identity_overrides() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run these fixtures as an ordinary user"
    );
    for mode in ["runtime", "admin"] {
        let output = Command::new(env!("CARGO_BIN_EXE_vpnt-helper"))
            .arg(mode)
            .env("SUDO_UID", "0")
            .env("SUDO_USER", "root")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(77));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    for arguments in [
        vec![],
        vec!["runtime", "501"],
        vec!["admin", "/tmp/arbitrary"],
        vec!["--fixture"],
        vec!["shell"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vpnt-helper"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}
