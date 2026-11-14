#[cfg(target_os = "macos")]
fn main() {
    use vpnt::helper::ppp_supervisor;
    // SAFETY: UID queries have no memory preconditions. This entrypoint has no
    // fixture UID/path/environment override and accepts only the closed argv.
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 }
        || !ppp_supervisor::valid_arguments(&std::env::args_os().skip(1).collect::<Vec<_>>())
        || vpnt::helper::ppp_config::verify().is_err()
    {
        std::process::exit(77);
    }
    let command = ppp_supervisor::system_command();
    // SAFETY: this one-shot process reserves FD 3/4 for the inherited channels;
    // no preceding operation opens, owns or aliases them. Command is fixed.
    let result = unsafe { ppp_supervisor::inherited_supervise(0, command) };
    std::process::exit(match result {
        Ok(status) => status.code().unwrap_or(1),
        Err(_) => 1,
    });
}
#[cfg(not(target_os = "macos"))]
fn main() {
    std::process::exit(77);
}
