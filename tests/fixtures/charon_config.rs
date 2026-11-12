#![allow(dead_code)]
// Compile the production renderer and its path validator, without a root/path
// override in the product or any process, socket, plugin or kernel operation.
use vpnt::connection::ipsec::Error;
#[path = "../../src/fs_permissions.rs"]
mod fs_permissions;
mod producer {
    use super::Error;
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
}
fn main() {
    let path = std::env::args_os().nth(1).expect("configuration directory");
    print!("{}", producer::render(std::path::Path::new(&path)));
}
