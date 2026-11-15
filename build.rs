//! Selects the immutable build identity and builds the macOS utun decoder shim.
//!
//! The shim owns the SDK `socket_fdinfo`/`kern_ctl_info` layout and returns a
//! private fixed-primitive ABI; no SDK struct reaches Rust. Other targets do
//! not compile or call any C SDK code, but still receive the selected identity.

fn main() {
    identifiers();
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

fn identifiers() {
    println!("cargo:rerun-if-env-changed=VPNT_CHANNEL");
    println!("cargo:rerun-if-changed=native/identifier-channels.conf");
    let channel = std::env::var("VPNT_CHANNEL").unwrap_or_else(|_| "dev".into());
    let base = include_str!("native/identifier-channels.conf")
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(key, value)| (key == channel).then_some(value))
        .expect("VPNT_CHANNEL must be dev or prd");
    println!("cargo:rustc-env=VPNT_CHANNEL={channel}");
    println!("cargo:rustc-env=VPNT_BASE={base}");
    for (name, suffix) in [
        ("APP", "app"),
        ("HELPER", "helper"),
        ("ASKPASS", "askpass"),
        ("INSTALLER", "install"),
        ("STAGING", "staging"),
        ("PINENTRY", "pinentry"),
        ("PPP_SUPERVISOR", "pppd"),
        ("RUNTIME", "runtime"),
        ("CREDENTIALS", "credentials.v1"),
        ("COMPONENT", "component"),
    ] {
        println!("cargo:rustc-env=VPNT_{name}_ID={base}.{suffix}");
        println!("cargo:rustc-env=VPNT_{name}_PATH=/Library/PrivilegedHelperTools/{base}.{suffix}");
    }
    // sudo ignores files containing dots; aliases accept only letters/digits/_ .
    let policy = base.replace(['.', '-'], "_");
    println!("cargo:rustc-env=VPNT_POLICY_PREFIX={policy}");
    println!(
        "cargo:rustc-env=VPNT_POLICY_ALIAS={}",
        policy.to_uppercase()
    );
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // A data section lets packagers check the build channel without running
        // the host/helper or extending their command protocols.
        let marker =
            std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("vpnt-channel");
        std::fs::write(&marker, format!("vpnt-channel:{channel}:{base}\0")).unwrap();
        println!(
            "cargo:rustc-link-arg=-Wl,-sectcreate,__TEXT,__vpnt_channel,{}",
            marker.display()
        );
    }
}
