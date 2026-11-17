use super::*;
use std::{
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Child, Stdio},
    time::Duration,
};
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.wait();
    }
}
pub(super) fn run(
    kind: Kind,
    id: String,
    locale: Locale,
    expires: Instant,
    prepare: impl FnOnce() -> Result<plan::Plan, Error>,
    state: Arc<State>,
) {
    let mut reaped = true;
    let result = (|| {
        check(&state, expires)?;
        let mut plan = prepare()?;
        check(&state, expires)?;
        if !std::path::Path::new(plan.command.get_program()).is_absolute() {
            return Err(Error::Untrusted);
        }
        state.prepared.store(true, Ordering::Release);
        while !state.proceed.load(Ordering::Acquire) {
            check(&state, expires)?;
            std::thread::sleep(Duration::from_millis(5));
        }
        check(&state, expires)?;
        plan.revalidate()?;
        let mut channel = None;
        plan.command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if kind == Kind::Remove {
            let (client, capability) = UnixStream::pair().map_err(|_| Error::Unavailable)?;
            client
                .set_nonblocking(true)
                .map_err(|_| Error::Unavailable)?;
            let remaining = expires.saturating_duration_since(Instant::now());
            let until = crate::helper::admin_client::monotonic_ns()
                .map_err(|_| Error::Unavailable)?
                .checked_add(u64::try_from(remaining.as_nanos()).map_err(|_| Error::Expired)?)
                .ok_or(Error::Expired)?;
            plan.command
                .env("SUDO_ASKPASS", crate::helper::paths::ASKPASS)
                .env("VPNT_AUTH_LOCALE", locale.code())
                .env("VPNT_AUTH_UNTIL_NS", until.to_string())
                .stdin(Stdio::from(OwnedFd::from(capability)));
            channel = Some(client);
        } else {
            plan.command.stdin(Stdio::null());
        }
        check(&state, expires)?;
        let mut child = OwnedChild(plan.command.spawn().map_err(|_| Error::Unavailable)?);
        plan.command.stdin(Stdio::null());
        reaped = false;
        let receipt = if let Some(stream) = &mut channel {
            removal::exchange(stream, &id, expires, &state)
        } else {
            Ok(None)
        };
        if let Err(error) = receipt {
            publish(&state, Err(error));
        }
        if let Some(stream) = channel {
            let _ = stream.shutdown(Shutdown::Both);
            drop(stream);
        }
        let status = loop {
            if let Some(status) = child.0.try_wait().map_err(|_| Error::Unavailable)? {
                break status;
            }
            if let Err(error) = check(&state, expires) {
                publish(&state, Err(error));
                break child.0.wait().map_err(|_| Error::Unavailable)?;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        reaped = true;
        check(&state, expires)?;
        if !status.success() {
            return Err(Error::Unavailable);
        }
        if kind == Kind::Install {
            plan.installed()
        } else {
            receipt?.ok_or(Error::InvalidReply)
        }
    })();
    publish(&state, result);
    state.finished.store(reaped, Ordering::Release);
}
