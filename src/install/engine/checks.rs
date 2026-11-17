use super::*;
use crate::helper::process::ManagedChild;
use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
pub(super) struct Checks {
    pub global: PathBuf,
}
impl Checks {
    pub fn syntax_image(&self, image: &Image) -> Result<(), Error> {
        self.run(Path::new("-"), Some(&image.bytes)).map(|_| ())
    }
    pub fn installed(&self, policies: &[PathBuf]) -> Result<(), Error> {
        let text = self.run(&self.global, None)?;
        for path in policies {
            if !text
                .lines()
                .any(|line| line == format!("{}: parsed OK", path.display()))
            {
                return Err(Error::PolicyRejected);
            }
        }
        Ok(())
    }
    fn run(&self, path: &Path, input: Option<&[u8]>) -> Result<String, Error> {
        let mut command = Command::new("/usr/sbin/visudo");
        command.args(["-c", "-s", "-f"]).arg(path);
        let mut child = ManagedChild::spawn(&mut command).map_err(|_| Error::PolicyRejected)?;
        let mut stdin = child.take_stdin();
        if input.is_none() {
            drop(stdin.take());
        }
        let mut written = 0;
        if let Some(stdin) = &stdin {
            let flags = unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe {
                    libc::fcntl(stdin.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                } < 0
            {
                return Err(Error::PolicyRejected);
            }
        }
        let mut out = child.take_stdout().ok_or(Error::PolicyRejected)?;
        let mut err = child.take_stderr().ok_or(Error::PolicyRejected)?;
        for fd in [out.as_raw_fd(), err.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(Error::PolicyRejected);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let (mut out_eof, mut err_eof) = (false, false);
        loop {
            if Instant::now() >= deadline {
                return Err(Error::PolicyRejected);
            }
            if let Some(pipe) = &mut stdin {
                let input = input.ok_or(Error::PolicyRejected)?;
                match pipe.write(&input[written..]) {
                    Ok(n) => {
                        written += n;
                        if written == input.len() {
                            drop(stdin.take());
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(Error::PolicyRejected),
                }
            }
            pump(&mut out, &mut stdout, &mut out_eof)?;
            pump(&mut err, &mut stderr, &mut err_eof)?;
            if let Some(status) = child.poll().map_err(|_| Error::PolicyRejected)?
                && out_eof
                && err_eof
            {
                if !status.success() {
                    return Err(Error::PolicyRejected);
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        String::from_utf8(stdout).map_err(|_| Error::PolicyRejected)
    }
}
fn pump(reader: &mut impl Read, bytes: &mut Vec<u8>, eof: &mut bool) -> Result<(), Error> {
    if *eof {
        return Ok(());
    }
    let mut buffer = [0; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                *eof = true;
                return Ok(());
            }
            Ok(n) => {
                bytes.extend_from_slice(&buffer[..n]);
                if bytes.len() > 262_144 {
                    return Err(Error::PolicyRejected);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::PolicyRejected),
        }
    }
}
