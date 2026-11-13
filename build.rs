//! Builds the macOS-only utun socket decoder shim.
//!
//! The shim owns the SDK `socket_fdinfo`/`kern_ctl_info` layout and returns a
//! private fixed-primitive ABI; no SDK struct reaches Rust. Other targets do
//! not compile or call any C SDK code.

fn main() {
    println!("cargo:rerun-if-changed=native/utun_socket.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    cc::Build::new()
        .file("native/utun_socket.c")
        .flag("-std=c11")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Werror")
        .flag("-fvisibility=hidden")
        .compile("vpnt_utun_socket");
}
