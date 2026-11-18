use super::*;

#[test]
fn linux_children_do_not_inherit_stray_descriptors() {
    use std::os::fd::{FromRawFd, OwnedFd};
    // A pipe without CLOEXEC, as a launcher could leave it, moved to a high fd.
    let mut ends = [0; 2];
    // SAFETY: pipe writes two new descriptors into the array.
    assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
    // SAFETY: dup2 to an unused high number; the originals are closed below.
    let stray = unsafe { libc::dup2(ends[0], 777) };
    assert_eq!(stray, 777);
    // SAFETY: each descriptor is owned here exactly once.
    let _owned = unsafe {
        [
            OwnedFd::from_raw_fd(ends[0]),
            OwnedFd::from_raw_fd(ends[1]),
            OwnedFd::from_raw_fd(stray),
        ]
    };
    let probe = |prepare: bool| {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "[ ! -e /proc/self/fd/777 ]"]);
        if prepare {
            linux_inherit_session(&mut command);
        }
        command.status().unwrap().success()
    };
    // The control proves the probe sees an inherited descriptor.
    assert!(!probe(false), "the stray descriptor was not inheritable");
    assert!(probe(true), "the child inherited the stray descriptor");
}
