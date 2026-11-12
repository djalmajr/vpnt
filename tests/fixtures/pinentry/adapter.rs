use std::io::{self, BufReader};
use vpnt::helper::{pinentry, pinentry_channel};
unsafe extern "C" {
    fn geteuid() -> u32;
}
fn main() {
    let result = pinentry::serve(
        &mut BufReader::new(io::stdin().lock()),
        &mut io::stdout().lock(),
        || {
            // SAFETY: this fixture's parent reserved FD 3 just as the real helper.
            let owner = unsafe { geteuid() };
            unsafe {
                pinentry_channel::inherited_password(if cfg!(wrong_peer) {
                    owner.wrapping_add(1)
                } else {
                    owner
                })
            }
        },
    );
    if result.is_err() {
        std::process::exit(2);
    }
}
