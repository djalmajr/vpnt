use super::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::PathBuf};
const ACTIVE: &str = ".installation-transaction";
const RETIRED: &str = ".installation-completed";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub key: String,
    pub before: Option<Stamp>,
    pub after: Option<Stamp>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: u32,
    entries: Vec<Entry>,
}
pub(super) struct Journal {
    pub root: PathBuf,
    pub entries: Vec<Entry>,
}

impl Journal {
    pub fn pending(tree: &Tree) -> Result<bool, Error> {
        match fs::symlink_metadata(tree.state.join(ACTIVE)) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(Error::RecoveryRequired),
        }
    }
    pub fn prepare(
        tree: &Tree,
        changes: &BTreeMap<String, Option<Image>>,
        expected: &BTreeMap<String, Option<Stamp>>,
    ) -> Result<Self, Error> {
        let root = tree.state.join(ACTIVE);
        if root.try_exists().map_err(|_| Error::Io)? {
            return Err(Error::RecoveryRequired);
        }
        let mut entries = Vec::new();
        let mut backups = Vec::new();
        let mut total = 0usize;
        for (key, after) in changes {
            let before = image::snapshot(tree, key)?;
            if !image::same(before.as_ref(), expected[key].as_ref()) {
                return Err(Error::Conflict);
            }
            if let Some(before) = &before {
                total = total
                    .checked_add(before.bytes.len())
                    .ok_or(Error::Integrity)?;
            }
            if total > 256 * 1024 * 1024 {
                return Err(Error::Integrity);
            }
            entries.push(Entry {
                key: key.clone(),
                before: before.as_ref().map(|i| i.stamp.clone()),
                after: after.as_ref().map(|i| i.stamp.clone()),
            });
            backups.push(before);
        }
        let document = Document { format: 1, entries };
        tree.directory(&root, 0o700)?;
        image::atomic(
            tree,
            &root.join("manifest.json"),
            &Image::new(serde_json::to_vec(&document).map_err(|_| Error::Io)?, 0o600),
        )?;
        for (index, before) in backups.into_iter().enumerate() {
            if let Some(before) = before {
                image::atomic(
                    tree,
                    &root.join(backup(index)),
                    &Image::new(before.bytes, 0o600),
                )?;
            }
        }
        tree.sync(&root)?;
        Ok(Self {
            root,
            entries: document.entries,
        })
    }
    pub fn load(tree: &Tree, root: PathBuf) -> Result<Self, Error> {
        payload::files::directory(&root, tree.owner, true).map_err(|_| Error::RecoveryRequired)?;
        let bytes = payload::files::read(&root.join("manifest.json"), tree.owner, 262_144)
            .map_err(|_| Error::RecoveryRequired)?;
        let doc: Document = serde_json::from_slice(&bytes).map_err(|_| Error::RecoveryRequired)?;
        if serde_json::to_vec(&doc).map_err(|_| Error::Io)? != bytes
            || doc.format != 1
            || doc.entries.len() > 256
        {
            return Err(Error::RecoveryRequired);
        }
        let mut keys = BTreeSet::new();
        let mut allowed = BTreeSet::from(["manifest.json".into(), "settled".into()]);
        for (index, e) in doc.entries.iter().enumerate() {
            tree.resolve(&e.key).map_err(|_| Error::RecoveryRequired)?;
            if !keys.insert(e.key.clone())
                || e.before
                    .iter()
                    .chain(e.after.iter())
                    .any(|s| !valid_hash(&s.hash) || s.mode != tree::mode(&e.key))
            {
                return Err(Error::RecoveryRequired);
            }
            if e.before.is_some() {
                allowed.insert(backup(index));
            }
        }
        for entry in fs::read_dir(&root).map_err(|_| Error::RecoveryRequired)? {
            let name = entry
                .map_err(|_| Error::RecoveryRequired)?
                .file_name()
                .into_string()
                .map_err(|_| Error::RecoveryRequired)?;
            if !allowed.contains(&name) {
                return Err(Error::RecoveryRequired);
            }
        }
        let journal = Self {
            root,
            entries: doc.entries,
        };
        for (index, entry) in journal.entries.iter().enumerate() {
            journal.before(tree, index, entry)?;
        }
        Ok(journal)
    }
    fn before(&self, tree: &Tree, index: usize, e: &Entry) -> Result<Option<Image>, Error> {
        if let Some(stamp) = &e.before {
            let path = self.root.join(backup(index));
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let bytes = payload::files::read(&path, tree.owner, 64 * 1024 * 1024)
                        .map_err(|_| Error::RecoveryRequired)?;
                    if hash(&bytes) != stamp.hash {
                        return Err(Error::RecoveryRequired);
                    }
                    Ok(Some(Image {
                        stamp: stamp.clone(),
                        bytes,
                    }))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(Error::RecoveryRequired),
            }
        } else {
            Ok(None)
        }
    }
    pub fn verify(&self, tree: &Tree, after: bool) -> Result<(), Error> {
        for entry in &self.entries {
            if !image::same(
                image::snapshot(tree, &entry.key)?.as_ref(),
                if after {
                    entry.after.as_ref()
                } else {
                    entry.before.as_ref()
                },
            ) {
                return Err(Error::RecoveryRequired);
            }
        }
        Ok(())
    }
    pub fn rollback(&self, tree: &Tree) -> Result<(), Error> {
        if self.verify(tree, false).is_ok() {
            return Ok(());
        }
        // Refuse all restoration if any target has an unrecognized image.
        for entry in &self.entries {
            let current = image::snapshot(tree, &entry.key)?;
            if !image::same(current.as_ref(), entry.before.as_ref())
                && !image::same(current.as_ref(), entry.after.as_ref())
                && !(entry.key.starts_with("policy/") && current.is_none())
            {
                return Err(Error::RecoveryRequired);
            }
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.before.is_some()
                && (entry.key.starts_with("policy/")
                    || !image::same(
                        image::snapshot(tree, &entry.key)?.as_ref(),
                        entry.before.as_ref(),
                    ))
                && self.before(tree, index, entry)?.is_none()
            {
                return Err(Error::RecoveryRequired);
            }
        }
        self.suspend(tree)?;
        for policy in [false, true] {
            for (index, entry) in self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.key.starts_with("policy/") == policy)
            {
                let current = image::snapshot(tree, &entry.key)?;
                if image::same(current.as_ref(), entry.before.as_ref()) {
                    continue;
                }
                let before = self.before(tree, index, entry)?;
                if entry.before.is_some() && before.is_none() {
                    return Err(Error::RecoveryRequired);
                }
                image::set(
                    tree,
                    &entry.key,
                    current.as_ref().map(|i| &i.stamp),
                    before.as_ref(),
                )?;
            }
        }
        self.verify(tree, false)
    }
    pub fn suspend(&self, tree: &Tree) -> Result<(), Error> {
        for entry in self.entries.iter().filter(|e| e.key.starts_with("policy/")) {
            if let Some(current) = image::snapshot(tree, &entry.key)? {
                if !image::same(Some(&current), entry.before.as_ref())
                    && !image::same(Some(&current), entry.after.as_ref())
                {
                    return Err(Error::RecoveryRequired);
                }
                image::set(tree, &entry.key, Some(&current.stamp), None)?;
            }
        }
        Ok(())
    }
}

mod settlement;
fn backup(index: usize) -> String {
    format!("backup-{index:03}")
}
