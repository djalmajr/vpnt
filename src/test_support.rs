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
    write_script_with_mode(path, content, 0o700);
}

/// Like [`write_script`], but sets explicit Unix mode bits on the fixture.
///
/// The `chmod` runs in the same short-lived child as the write, so the caller
/// still has no write descriptor when it executes the script. Fixtures that
/// assert or require a mode other than 0700 use this variant.
pub(crate) fn write_script_with_mode(path: &Path, content: &str, mode: u32) {
    let status = Command::new("/bin/sh")
        .args([
            "-c",
            r#"umask 077 && printf '%s' "$3" > "$1" && chmod "$2" "$1""#,
            "sh",
        ])
        .arg(path)
        .arg(format!("{mode:o}"))
        .arg(content)
        .status()
        .expect("/bin/sh writes the fixture script");
    assert!(
        status.success(),
        "writing {} ended with {status}",
        path.display()
    );
}

#[cfg(test)]
mod oracle_tests {
    use super::write_script;
    use std::{
        fs, io,
        path::PathBuf,
        process::Command,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
    };

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Forkers {
        stop: Arc<AtomicBool>,
        threads: Vec<thread::JoinHandle<()>>,
    }
    impl Drop for Forkers {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            for thread in self.threads.drain(..) {
                let _ = thread.join();
            }
        }
    }

    /// Guards the reason `write_script` exists: a concurrent `fork` must not
    /// inherit a write descriptor that keeps the new script busy at exec time.
    #[test]
    fn write_script_survives_concurrent_forks() {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "vpnt-write-script-oracle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        // Declared after the directory so the forkers stop before its cleanup.
        let scratch = Scratch(root.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let forkers = Forkers {
            stop: stop.clone(),
            threads: (0..4)
                .map(|_| {
                    let stop = Arc::clone(&stop);
                    thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            let _ = Command::new("/bin/true").status();
                        }
                    })
                })
                .collect(),
        };

        let mut busy = 0;
        for round in 0..200 {
            let path = scratch.0.join(format!("script-{round}"));
            write_script(&path, "#!/bin/sh\nexit 0\n");
            match Command::new(&path).status() {
                Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => busy += 1,
                other => assert!(other.unwrap().success(), "round {round}"),
            }
        }
        assert_eq!(busy, 0, "executions hit ETXTBSY");
        drop(forkers);
        drop(scratch);
    }
}
