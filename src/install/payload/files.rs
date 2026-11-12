use super::*;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Component,
};

pub(crate) fn directory(path: &Path, owner: u32, private: bool) -> Result<(), Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::UntrustedPath);
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| Error::UntrustedPath)?;
        let own = ancestor == path;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != owner)
            || metadata.mode() & 0o7022 != 0
            || (own && (metadata.uid() != owner || (private && metadata.mode() & 0o777 != 0o700)))
        {
            return Err(Error::UntrustedPath);
        }
        crate::fs_permissions::check_path(ancestor, own && private)
            .map_err(|_| Error::UntrustedPath)?;
    }
    Ok(())
}

pub(crate) fn read(path: &Path, owner: u32, limit: u64) -> Result<Vec<u8>, Error> {
    directory(path.parent().ok_or(Error::UntrustedPath)?, owner, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::UntrustedPath)?;
    let metadata = file.metadata().map_err(|_| Error::Io)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || metadata.len() > limit
    {
        return Err(Error::UntrustedPath);
    }
    crate::fs_permissions::check_file(&file, false).map_err(|_| Error::UntrustedPath)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Integrity);
    }
    Ok(bytes)
}

pub(super) fn inventory(
    root: &Path,
    owner: u32,
) -> Result<(BTreeSet<String>, BTreeSet<String>), Error> {
    fn walk(
        root: &Path,
        dir: &Path,
        owner: u32,
        files: &mut BTreeSet<String>,
        dirs: &mut BTreeSet<String>,
    ) -> Result<(), Error> {
        directory(dir, owner, dir == root)?;
        for entry in fs::read_dir(dir).map_err(|_| Error::Io)? {
            let path = entry.map_err(|_| Error::Io)?.path();
            let relative = path.strip_prefix(root).map_err(|_| Error::UntrustedPath)?;
            if relative.components().count() > 10 {
                return Err(Error::Integrity);
            }
            let name = relative.to_str().ok_or(Error::UntrustedPath)?.to_owned();
            let metadata = fs::symlink_metadata(&path).map_err(|_| Error::Io)?;
            if metadata.is_dir() {
                dirs.insert(name);
                if dirs.len() > 144 {
                    return Err(Error::Integrity);
                }
                walk(root, &path, owner, files, dirs)?;
            } else if metadata.is_file() {
                files.insert(name);
                if files.len() > 73 {
                    return Err(Error::Integrity);
                }
            } else {
                return Err(Error::UntrustedPath);
            }
        }
        Ok(())
    }
    let (mut files, mut dirs) = (BTreeSet::new(), BTreeSet::new());
    walk(root, root, owner, &mut files, &mut dirs)?;
    Ok((files, dirs))
}
