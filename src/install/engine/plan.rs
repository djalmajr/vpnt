use super::*;
pub(super) struct Plan {
    pub wanted: BTreeMap<String, Option<Image>>,
    pub before: BTreeMap<String, Option<Stamp>>,
    pub result: Receipt,
}
impl Plan {
    pub fn activate(tree: &Tree, old: Option<&Receipt>, payload: &Payload) -> Result<Self, Error> {
        if payload.owner() != tree.owner {
            return Err(Error::PermissionDenied);
        }
        let data = payload.materialize()?;
        let mut wanted = BTreeMap::new();
        let mut files = BTreeMap::new();
        for (name, bytes) in data.iter().filter(|(n, _)| n.as_str() != "policy/sudoers") {
            let key = if let Some(name) = name.strip_prefix("runtime/") {
                format!("runtime/{}/{name}", payload.summary().app_version)
            } else {
                name.clone()
            };
            tree.resolve(&key)?;
            let image = Image::new(bytes.clone(), tree::mode(&key));
            files.insert(key.clone(), image.stamp.clone());
            wanted.insert(key, Some(image));
        }
        let mut users = old
            .map(|r| r.users.keys().copied().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        users.insert(payload.summary().uid);
        if users.len() > 64 {
            return Err(Error::Integrity);
        }
        let mut policies = BTreeMap::new();
        for uid in users {
            let key = format!("policy/{uid}");
            let bytes = policy::sudoers(
                uid,
                &files["adapters/helper"].hash,
                &files["adapters/installer"].hash,
            )?
            .into_bytes();
            let image = Image::new(bytes, 0o440);
            policies.insert(uid, image.stamp.hash.clone());
            wanted.insert(key, Some(image));
        }
        let result = Receipt {
            format: 1,
            app_version: payload.summary().app_version.clone(),
            build: payload.summary().id.clone(),
            files,
            users: policies,
        };
        Self::finish(tree, old, wanted, result)
    }
    pub fn remove(tree: &Tree, old: &Receipt, uid: u32) -> Result<Self, Error> {
        policy::account(uid)?;
        let mut result = old.clone();
        result.users.remove(&uid);
        if result.users.is_empty() {
            result.files.clear();
        }
        let mut wanted = BTreeMap::new();
        for key in result.expected().keys() {
            wanted.insert(key.clone(), image::snapshot(tree, key)?);
        }
        Self::finish(tree, Some(old), wanted, result)
    }
    fn finish(
        tree: &Tree,
        old: Option<&Receipt>,
        mut wanted: BTreeMap<String, Option<Image>>,
        result: Receipt,
    ) -> Result<Self, Error> {
        let expected = old.map(Receipt::expected).unwrap_or_default();
        for key in expected.keys() {
            wanted.entry(key.clone()).or_insert(None);
        }
        wanted.insert("receipt".into(), Some(result.image()?));
        let mut changed = false;
        let mut before = BTreeMap::new();
        let receipt_before = old.map(Receipt::image).transpose()?;
        for (key, next) in &wanted {
            let current = image::snapshot(tree, key)?;
            if !image::same(
                current.as_ref(),
                if key == "receipt" {
                    receipt_before.as_ref().map(|i| &i.stamp)
                } else {
                    expected.get(key)
                },
            ) {
                return Err(Error::Conflict);
            }
            if !image::same(current.as_ref(), next.as_ref().map(|i| &i.stamp)) {
                changed = true;
            }
            before.insert(key.clone(), current.map(|i| i.stamp));
        }
        if !changed {
            wanted.clear();
        } else {
            wanted.retain(|key, next| {
                key.starts_with("policy/")
                    || before[key].as_ref() != next.as_ref().map(|i| &i.stamp)
            });
        }
        if wanted.len() > 256 {
            return Err(Error::Integrity);
        }
        Ok(Self {
            wanted,
            before,
            result,
        })
    }
}
