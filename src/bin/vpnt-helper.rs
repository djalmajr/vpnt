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
#[cfg(not(target_os = "macos"))]
fn main() {
    std::process::exit(77);
}
