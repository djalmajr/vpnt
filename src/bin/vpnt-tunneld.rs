#[cfg(target_os = "linux")]
fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    // SAFETY: standalone main before threads; the activation descriptor is unowned.
    let code = unsafe { vpnt::tunneld::server::run_linux(&args) };
    if code == 64 {
        eprintln!("started by systemd through vpnt-tunneld.socket; not for direct use");
    }
    std::process::exit(code);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(77);
}
