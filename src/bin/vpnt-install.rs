#[cfg(unix)]
fn main() {
    use std::path::Path;
    use vpnt::install::{payload::Payload, policy};
    // These are read-only preparation modes. Privileged activation/removal is
    // deliberately absent until the transaction and recovery gates exist.
    if unsafe { libc::getuid() == 0 || libc::geteuid() != libc::getuid() } {
        std::process::exit(77);
    }
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [command, path] if command == "inspect" => {
            let path = Path::new(path);
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                std::env::current_dir().unwrap().join(path)
            };
            Payload::inspect(&path, unsafe { libc::getuid() })
                .map(|p| serde_json::to_string(p.summary()).unwrap())
        }
        [command, uid, helper, installer] if command == "policy" => uid
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
            .zip(helper.to_str())
            .zip(installer.to_str())
            .ok_or(vpnt::install::Error::InvalidManifest)
            .and_then(|((uid, helper), installer)| policy::sudoers(uid, helper, installer)),
        _ => std::process::exit(64),
    };
    match result {
        Ok(value) => print!("{value}"),
        Err(error) => {
            eprintln!("{}", serde_json::to_string(&error).unwrap());
            std::process::exit(1);
        }
    }
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(77);
}
