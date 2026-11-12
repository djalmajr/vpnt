use super::{Error, policy, valid_hash};
use crate::helper::runtime::Runtime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
pub(crate) mod files;
mod manifest;
use manifest::Manifest;

pub const ADAPTERS: [&str; 5] = ["helper", "installer", "pinentry", "pppd", "askpass"];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub id: String,
    pub uid: u32,
    pub app_version: String,
    #[serde(rename = "minimumMacOS")]
    pub minimum_macos: String,
    pub files: usize,
}
pub struct Payload {
    summary: Summary,
    root: PathBuf,
    owner: u32,
}
impl Payload {
    pub fn inspect(root: &Path, owner: u32) -> Result<Self, Error> {
        files::directory(root, owner, true)?;
        let bytes = files::read(&root.join("payload.json"), owner, 65_536)?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidManifest)?;
        policy::account(manifest.uid)?;
        if manifest.format != 1
            || manifest.app_version != env!("CARGO_PKG_VERSION")
            || manifest.files.len() > 72
            || manifest.files.values().any(|h| !valid_hash(h))
        {
            return Err(Error::InvalidManifest);
        }
        let runtime =
            Runtime::inspect(root.join("runtime"), owner).map_err(|_| Error::Incompatible)?;
        let mut expected: BTreeSet<String> = runtime
            .file_hashes()
            .keys()
            .map(|n| format!("runtime/{n}"))
            .collect();
        expected.insert("runtime/manifest.json".into());
        expected.insert("policy/sudoers".into());
        expected.extend(ADAPTERS.map(|name| format!("adapters/{name}")));
        if expected != manifest.files.keys().cloned().collect() {
            return Err(Error::InvalidManifest);
        }
        let mut dirs = BTreeSet::new();
        for name in &expected {
            for parent in Path::new(name)
                .ancestors()
                .skip(1)
                .filter(|p| !p.as_os_str().is_empty())
            {
                dirs.insert(parent.to_str().ok_or(Error::InvalidManifest)?.to_owned());
            }
        }
        let (actual, actual_dirs) = files::inventory(root, owner)?;
        let mut all = expected.clone();
        all.insert("payload.json".into());
        if actual != all || actual_dirs != dirs {
            return Err(Error::Integrity);
        }
        for (name, expected) in &manifest.files {
            if hash(&files::read(&root.join(name), owner, 64 * 1024 * 1024)?) != *expected {
                return Err(Error::Integrity);
            }
        }
        for name in ADAPTERS {
            Runtime::inspect_adapter(&root.join("adapters").join(name), owner)
                .map_err(|_| Error::Incompatible)?;
        }
        let expected_policy = policy::sudoers(
            manifest.uid,
            &manifest.files["adapters/helper"],
            &manifest.files["adapters/installer"],
        )?;
        if files::read(&root.join("policy/sudoers"), owner, 16_384)? != expected_policy.as_bytes() {
            return Err(Error::Integrity);
        }
        let summary = Summary {
            id: hash(&bytes),
            uid: manifest.uid,
            app_version: manifest.app_version,
            minimum_macos: runtime.minimum_macos().into(),
            files: manifest.files.len(),
        };
        Ok(Self {
            summary,
            root: root.into(),
            owner,
        })
    }
    pub fn summary(&self) -> &Summary {
        &self.summary
    }
    pub fn revalidate(&self) -> Result<(), Error> {
        let current = Self::inspect(&self.root, self.owner)?;
        if current.summary.id != self.summary.id {
            return Err(Error::Integrity);
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn owner(&self) -> u32 {
        self.owner
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn materialize(&self) -> Result<BTreeMap<String, Vec<u8>>, Error> {
        self.revalidate()?;
        let manifest: Manifest = serde_json::from_slice(&files::read(
            &self.root.join("payload.json"),
            self.owner,
            65_536,
        )?)
        .map_err(|_| Error::InvalidManifest)?;
        let mut total = 0usize;
        let mut data = BTreeMap::new();
        for (name, expected) in manifest.files {
            let bytes = files::read(&self.root.join(&name), self.owner, 64 * 1024 * 1024)?;
            total = total.checked_add(bytes.len()).ok_or(Error::Integrity)?;
            if total > 256 * 1024 * 1024 || hash(&bytes) != expected {
                return Err(Error::Integrity);
            }
            data.insert(name, bytes);
        }
        self.revalidate()?;
        Ok(data)
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
pub(crate) mod tests;
