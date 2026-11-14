#![allow(dead_code)]
// Compile the production renderer and its path validator, without a root/path
// override in the product or any process, socket, plugin or kernel operation.
use std::num::NonZeroU16;
use vpnt::connection::ipsec::Error;
#[path = "../../src/fs_permissions.rs"]
mod fs_permissions;
mod producer {
    use super::Error;
    use std::num::NonZeroU16;
    mod files {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/connection/ipsec/producer/files.rs"
        ));
    }
    mod config {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/connection/ipsec/producer/config.rs"
        ));
    }
    pub fn render(path: &std::path::Path) -> String {
        config::render(path).unwrap()
    }
    pub fn render_bound(path: &std::path::Path, index: NonZeroU16) -> String {
        config::render_bound(path, index).unwrap()
    }
}
fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments
        .next()
        .expect("configuration directory");
    match arguments.next() {
        None => print!("{}", producer::render(std::path::Path::new(&path))),
        Some(raw) => {
            let raw = raw.to_str().expect("numeric index");
            let index: u16 = raw.parse().expect("numeric index");
            let index = NonZeroU16::new(index).expect("index in 1..65535");
            print!(
                "{}",
                producer::render_bound(std::path::Path::new(&path), index)
            );
        }
    }
}
