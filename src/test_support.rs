//! Helpers shared by unit tests.
use std::{path::Path, process::Command};

/// Writes `content` to `path` as a 0700 executable, from a child process.
///
/// Writing it in this process would hold a write descriptor until it closes,
/// and a test thread that forks meanwhile copies that descriptor into a child
/// that keeps it until its own exec. Executing the script in that window fails
/// with ETXTBSY. The child below holds the only write descriptor, and it has
/// exited, closing it, when this returns.
pub(crate) fn write_script(path: &Path, content: &str) {
    let status = Command::new("/bin/sh")
        .args([
            "-c",
            r#"umask 077 && printf '%s' "$2" > "$1" && chmod 700 "$1""#,
            "sh",
        ])
        .arg(path)
        .arg(content)
        .status()
        .expect("/bin/sh writes the fixture script");
    assert!(
        status.success(),
        "writing {} ended with {status}",
        path.display()
    );
}
