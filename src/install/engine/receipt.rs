use super::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Receipt {
    pub format: u32,
    pub app_version: String,
    pub build: String,
    pub files: BTreeMap<String, Stamp>,
    pub users: BTreeMap<u32, String>,
}
impl Receipt {
    pub fn load(tree: &Tree) -> Result<Option<Self>, Error> {
        let Some(image) = image::snapshot(tree, "receipt")? else {
            return Ok(None);
        };
        if image.stamp.mode != 0o600 || image.bytes.len() > 131_072 {
            return Err(Error::Integrity);
        }
        let receipt: Self =
            serde_json::from_slice(&image.bytes).map_err(|_| Error::InvalidManifest)?;
        if serde_json::to_vec(&receipt).map_err(|_| Error::Io)? != image.bytes
            || receipt.format != 1
            || !tree::version_ok(&receipt.app_version)
            || !valid_hash(&receipt.build)
            || receipt.files.len() > 128
            || receipt.users.len() > 64
        {
            return Err(Error::InvalidManifest);
        }
        for (key, stamp) in &receipt.files {
            tree.resolve(key)?;
            if key == "receipt"
                || key.starts_with("policy/")
                || !valid_hash(&stamp.hash)
                || stamp.mode != tree::mode(key)
            {
                return Err(Error::InvalidManifest);
            }
        }
        for (uid, h) in &receipt.users {
            policy::account(*uid)?;
            if !valid_hash(h) {
                return Err(Error::InvalidManifest);
            }
        }
        if receipt.users.is_empty() != receipt.files.is_empty() {
            return Err(Error::InvalidManifest);
        }
        if !receipt.users.is_empty() {
            for key in payload::ADAPTERS
                .map(|n| format!("adapters/{n}"))
                .into_iter()
                .chain(
                    [
                        "manifest.json",
                        "bin/charon",
                        "bin/openfortivpn",
                        "certs/ca-bundle.pem",
                    ]
                    .map(|n| format!("runtime/{}/{n}", receipt.app_version)),
                )
            {
                if !receipt.files.contains_key(&key) {
                    return Err(Error::InvalidManifest);
                }
            }
            if receipt.files.keys().any(|key| {
                key.starts_with("runtime/")
                    && !key.starts_with(&format!("runtime/{}/", receipt.app_version))
            }) {
                return Err(Error::InvalidManifest);
            }
        }
        Ok(Some(receipt))
    }
    pub fn image(&self) -> Result<Image, Error> {
        Ok(Image::new(
            serde_json::to_vec(self).map_err(|_| Error::Io)?,
            0o600,
        ))
    }
    pub fn expected(&self) -> BTreeMap<String, Stamp> {
        let mut expected = self.files.clone();
        expected.extend(self.users.iter().map(|(uid, h)| {
            (
                format!("policy/{uid}"),
                Stamp {
                    hash: h.clone(),
                    mode: 0o440,
                },
            )
        }));
        expected
    }
    pub fn verify(&self, tree: &Tree) -> Result<(), Error> {
        for (key, stamp) in self.expected() {
            if !image::same(image::snapshot(tree, &key)?.as_ref(), Some(&stamp)) {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
}
