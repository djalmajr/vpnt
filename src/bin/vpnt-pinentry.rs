#[cfg(unix)]
fn main() {
    use std::io::{self, BufReader};
    use vpnt::helper::{pinentry, pinentry_channel};
    // SAFETY: UID queries have no memory preconditions. No arguments/paths or
    // test override may select another credential source in this executable.
    let root = unsafe { libc::getuid() == 0 && libc::geteuid() == 0 };
    if !root || std::env::args_os().count() != 1 {
        eprintln!("vpnt pinentry requires its privileged parent");
        std::process::exit(77);
    }
    if pinentry::serve(
        &mut BufReader::new(io::stdin().lock()),
        &mut io::stdout().lock(),
        // SAFETY: the helper reserves FD 3 for this one-shot adapter. Nothing in
        // this executable opens or aliases it before this single callback.
        || unsafe { pinentry_channel::inherited_password(0) },
    )
    .is_err()
    {
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(77);
}
