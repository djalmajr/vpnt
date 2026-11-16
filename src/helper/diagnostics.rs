//! Fixed-path, bounded and redacted diagnostic reading after receipt admission.
use super::{
    paths,
    redaction::{REDACTED_LINE, contains_secret_keyword},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
use zeroize::Zeroizing;

const LIMIT: u64 = 64 * 1024;
const LINES: usize = 200;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    pub name: String,
    pub status: Status,
    pub modified: Option<u64>,
    pub lines: usize,
    pub text: String,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Present,
    Missing,
    Unavailable,
}

fn unavailable(name: &str, status: Status) -> Log {
    Log {
        name: name.into(),
        status,
        modified: None,
        lines: 0,
        text: String::new(),
    }
}
fn directory(file: &File, owner: u32) -> bool {
    file.metadata()
        .is_ok_and(|meta| meta.is_dir() && meta.uid() == owner && meta.mode() & 0o7777 == 0o700)
        && crate::fs_permissions::check_file(file, true).is_ok()
}
fn open_at(parent: &File, name: &std::ffi::CStr, flags: i32) -> std::io::Result<File> {
    // SAFETY: parent owns a live descriptor and name is NUL-terminated.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful openat returns a new uniquely-owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The closure is called before any diagnostic path is opened. It must verify
/// the installed receipt and return true only for its sole registered UID.
pub(crate) fn collect(state: &Path, owner: u32, admit: impl FnOnce() -> bool) -> Option<Vec<Log>> {
    if !admit() {
        return None;
    }
    let ssl = paths::openfortivpn_log(state);
    let charon = paths::charon_log(state);
    let files = [
        ssl.clone(),
        ssl.with_file_name("openfortivpn.previous.log"),
        charon.clone(),
        charon.with_file_name("charon.previous.log"),
    ];
    let state_dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state);
    let logs_dir = match state_dir {
        Ok(state_dir) if directory(&state_dir, owner) => {
            match open_at(
                &state_dir,
                c"logs",
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            ) {
                Ok(dir) if directory(&dir, owner) => Ok(dir),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Status::Missing),
                _ => Err(Status::Unavailable),
            }
        }
        _ => Err(Status::Unavailable),
    };
    Some(
        files
            .iter()
            .map(|path| {
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    return unavailable("unknown", Status::Unavailable);
                };
                match &logs_dir {
                    Ok(dir) => read_log(dir, owner, name),
                    Err(status) => unavailable(name, *status),
                }
            })
            .collect(),
    )
}

fn read_log(directory: &File, owner: u32, name: &str) -> Log {
    let Ok(component) = std::ffi::CString::new(name) else {
        return unavailable(name, Status::Unavailable);
    };
    let mut file = match open_at(
        directory,
        &component,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
    ) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return unavailable(name, Status::Missing);
        }
        Err(_) => return unavailable(name, Status::Unavailable),
    };
    let Ok(meta) = file.metadata() else {
        return unavailable(name, Status::Unavailable);
    };
    if !meta.is_file()
        || meta.uid() != owner
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || crate::fs_permissions::check_file(&file, true).is_err()
    {
        return unavailable(name, Status::Unavailable);
    }
    let start = meta.len().saturating_sub(LIMIT);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return unavailable(name, Status::Unavailable);
    }
    let mut data = Zeroizing::new(Vec::new());
    if file.take(LIMIT).read_to_end(&mut data).is_err() {
        return unavailable(name, Status::Unavailable);
    }
    // The cut can split a keyword: never publish the partial first line.
    let offset = if start == 0 {
        0
    } else {
        data.iter()
            .position(|b| *b == b'\n')
            .map_or(data.len(), |i| i + 1)
    };
    let mut lines: Vec<&[u8]> = data[offset..].split(|b| *b == b'\n').collect();
    // An in-progress final line may not yet contain its secret keyword.
    // Publish only newline-terminated records, never an incomplete suffix.
    lines.pop();
    let start_line = lines.len().saturating_sub(LINES);
    let mut text = String::new();
    let mut count = 0;
    for line in &lines[start_line..] {
        let rendered = if contains_secret_keyword(line) {
            REDACTED_LINE.to_owned()
        } else {
            String::from_utf8_lossy(line)
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect()
        };
        // A lossy conversion can grow; omit a whole line instead of exceeding
        // the ceiling or cutting a secret-bearing line into fragments.
        if text.len().saturating_add(rendered.len()).saturating_add(1) > LIMIT as usize {
            continue;
        }
        text.push_str(&rendered);
        text.push('\n');
        count += 1;
    }
    Log {
        name: name.into(),
        status: Status::Present,
        modified: u64::try_from(meta.mtime()).ok(),
        lines: count,
        text,
    }
}
