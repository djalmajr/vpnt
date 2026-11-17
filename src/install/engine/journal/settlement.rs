use super::*;
impl Journal {
    pub fn settle(&self, tree: &Tree, after: bool) -> Result<bool, Error> {
        self.verify(tree, after)?;
        image::atomic(
            tree,
            &self.root.join("settled"),
            &Image::new(
                if after {
                    b"after\n".to_vec()
                } else {
                    b"before\n".to_vec()
                },
                0o600,
            ),
        )?;
        let retired = tree.state.join(RETIRED);
        if fs::symlink_metadata(&retired).is_ok() {
            return Err(Error::RecoveryRequired);
        }
        fs::rename(&self.root, &retired).map_err(|_| Error::RecoveryRequired)?;
        tree.sync(&tree.state)?;
        Ok(Self::collect(tree).is_err())
    }
    pub fn recover(tree: &Tree) -> Result<(), Error> {
        Self::collect(tree)?;
        if !Self::pending(tree)? {
            return Ok(());
        }
        let journal = Self::load(tree, tree.state.join(ACTIVE))?;
        match journal.disposition(tree)? {
            Some(after) => {
                journal.verify(tree, after)?;
                journal.settle(tree, after)?;
            }
            None => {
                journal.rollback(tree)?;
                journal.settle(tree, false)?;
            }
        }
        Ok(())
    }
    fn disposition(&self, tree: &Tree) -> Result<Option<bool>, Error> {
        let path = self.root.join("settled");
        match fs::symlink_metadata(&path) {
            Ok(_) => match payload::files::read(&path, tree.owner, 16)?.as_slice() {
                b"after\n" => Ok(Some(true)),
                b"before\n" => Ok(Some(false)),
                _ => Err(Error::RecoveryRequired),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::RecoveryRequired),
        }
    }
    pub fn collect(tree: &Tree) -> Result<(), Error> {
        let root = tree.state.join(RETIRED);
        match fs::symlink_metadata(&root) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Error::RecoveryRequired),
        }
        payload::files::directory(&root, tree.owner, true).map_err(|_| Error::RecoveryRequired)?;
        if fs::symlink_metadata(root.join("manifest.json")).is_err() {
            let names = fs::read_dir(&root)
                .map_err(|_| Error::RecoveryRequired)?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::RecoveryRequired)?;
            if names.len() == 1 && names[0] == "settled" {
                let marker = payload::files::read(&root.join("settled"), tree.owner, 16)?;
                if marker != b"after\n" && marker != b"before\n" {
                    return Err(Error::RecoveryRequired);
                }
                fs::remove_file(root.join("settled")).map_err(|_| Error::RecoveryRequired)?;
            } else if !names.is_empty() {
                return Err(Error::RecoveryRequired);
            }
            fs::remove_dir(&root).map_err(|_| Error::RecoveryRequired)?;
            return tree.sync(&tree.state);
        }
        let journal = Self::load(tree, root)?;
        if journal.disposition(tree)?.is_none() {
            return Err(Error::RecoveryRequired);
        }
        for (index, e) in journal.entries.iter().enumerate() {
            if e.before.is_some() {
                match fs::remove_file(journal.root.join(backup(index))) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(Error::RecoveryRequired),
                }
            }
        }
        fs::remove_file(journal.root.join("manifest.json")).map_err(|_| Error::RecoveryRequired)?;
        fs::remove_file(journal.root.join("settled")).map_err(|_| Error::RecoveryRequired)?;
        fs::remove_dir(&journal.root).map_err(|_| Error::RecoveryRequired)?;
        tree.sync(&tree.state)
    }
}
