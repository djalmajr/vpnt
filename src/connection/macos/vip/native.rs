//! Production adapter: real interfaces snapshot plus the existing alias
//! encoder/ioctl from the sink module. No new ABI and no prefix math here.
use super::Api;
use crate::{
    connection::macos::{interfaces::Interfaces, sink},
    helper::fd_guard,
};
use std::{
    io,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub(super) struct Native;

impl Api for Native {
    fn interfaces(&mut self) -> io::Result<Interfaces> {
        Interfaces::read()
    }

    fn assign(&mut self, name: &str, vip: IpAddr) -> io::Result<()> {
        // Assigning a live alias mutates the interface table; only a real and
        // effective root may reach the encoder, socket or ioctl. Ordinary users
        // are refused before any name validation or syscall.
        // SAFETY: UID queries have no memory preconditions.
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut bytes = sink::alias(name, vip)?;
        let family = if vip.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        // The descriptor is created and marked close-on-exec under the helper
        // guard; the guard is released before the ioctl, which never forks.
        let fd = {
            let _guard = fd_guard::spawn();
            // SAFETY: no memory arguments; the new descriptor has one owner.
            let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fresh descriptor, transferred into one owner.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // SAFETY: the live descriptor accepts FD_CLOEXEC.
            if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            fd
        };
        let request = if vip.is_ipv4() {
            sink::ALIAS4
        } else {
            sink::ALIAS6
        };
        // SAFETY: `bytes` is the SDK-exact alias encoding and `fd` the matching
        // address-family dgram socket; the kernel reads the buffer only.
        if unsafe { libc::ioctl(fd.as_raw_fd(), request, bytes.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod abi_tests {
    use super::super::Api;

    #[test]
    fn ordinary_user_is_refused_before_alias_or_socket_work() {
        // The suite runs as the ordinary build user; root would invalidate the
        // expected denial, so fail loudly instead of exercising another path.
        // SAFETY: UID query has no memory preconditions.
        assert_ne!(unsafe { libc::geteuid() }, 0, "requires an ordinary user");
        let mut native = super::Native;
        // Invalid NUL name and TEST-NET VIP: if the root guard were removed,
        // `sink::alias` would reject the NUL with InvalidInput before any
        // socket/ioctl, which is the mutation assertion below.
        let result = Api::assign(&mut native, "bad\0name", "192.0.2.10".parse().unwrap());
        let error = result.expect_err("ordinary user must be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn sdk_layout_consumer_accepts_the_vip_encodings() {
        let directory = std::env::temp_dir().join(format!("vpnt-vip-abi-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&directory);
        let consumer = directory.join("vip_abi");
        let result = std::process::Command::new("/usr/bin/cc")
            .arg("-mmacosx-version-min=13.0")
            .args(["-Wall", "-Wextra", "-Werror"])
            .arg(format!(
                "-DVPNT_ALIAS4={}",
                crate::connection::macos::sink::ALIAS4
            ))
            .arg(format!(
                "-DVPNT_ALIAS6={}",
                crate::connection::macos::sink::ALIAS6
            ))
            .arg("tests/fixtures/vip_abi.c")
            .arg("-o")
            .arg(&consumer)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut child = std::process::Command::new(&consumer)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            let stdin = child.stdin.as_mut().unwrap();
            for vip in ["192.0.2.10", "2001:db8::10"] {
                stdin
                    .write_all(
                        &crate::connection::macos::sink::alias("utun6", vip.parse().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
            }
        }
        assert!(child.wait().unwrap().success());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
