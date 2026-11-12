use std::process::Command;
use vpnt::helper::ppp_supervisor;
unsafe extern "C" {
    fn geteuid() -> u32;
}
fn main() {
    if !ppp_supervisor::valid_arguments(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        std::process::exit(77);
    }
    let executable = std::env::current_exe().unwrap();
    let mode = executable
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("adapter-")
        .unwrap();
    let directory = executable.parent().unwrap();
    let payload_mode = mode.strip_prefix("host-").unwrap_or(mode);
    let mut command = Command::new(if payload_mode == "exec-failure" {
        directory.join("absent-child")
    } else {
        directory.join("child")
    });
    command
        .arg(payload_mode)
        .arg(directory.join(format!("marker-{mode}")))
        .env("VPNT_MUST_NOT_REACH_PPP", "fixture");
    // SAFETY: this fixture is a one-shot supervisor; the C parent reserved
    // FD 3/4. Production has no UID, command, path or mode overrides.
    let owner = unsafe { geteuid() };
    let result = unsafe {
        ppp_supervisor::inherited_supervise(
            if mode == "wrong-peer" {
                owner.wrapping_add(1)
            } else {
                owner
            },
            command,
        )
    };
    std::process::exit(match result {
        Ok(status) => status.code().unwrap_or(1),
        Err(_) => 2,
    });
}
