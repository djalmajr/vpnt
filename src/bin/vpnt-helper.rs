#[cfg(target_os = "macos")]
fn main() {
    use vpnt::helper::{
        protocol::ErrorCode,
        server::{self, Mode},
    };
    let Some(mode) = Mode::parse(&std::env::args_os().skip(1).collect::<Vec<_>>()) else {
        std::process::exit(64);
    };
    // SAFETY: standalone process; no stdin handle or alias has been created.
    let result = unsafe { server::inherited_run(mode) };
    std::process::exit(match result {
        Ok(()) => 0,
        Err(ErrorCode::PermissionDenied) => 77,
        Err(_) => 1,
    });
}
#[cfg(target_os = "linux")]
fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    // SAFETY: standalone main before threads. The activation descriptor is still unowned.
    std::process::exit(unsafe { vpnt::netd::server::run_linux(&args) });
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn main() {
    std::process::exit(77);
}
