use super::invariants::files;
use super::*;

fn update(f: &Fixture) -> plan::Plan {
    f.revise();
    let old = Receipt::load(&f.executor.tree).unwrap();
    plan::Plan::activate(&f.executor.tree, old.as_ref(), &f.source.inspect().unwrap()).unwrap()
}
fn change_helper(f: &Fixture, plan: &plan::Plan) {
    image::set(
        &f.executor.tree,
        "adapters/helper",
        plan.before["adapters/helper"].as_ref(),
        plan.wanted["adapters/helper"].as_ref(),
    )
    .unwrap();
}

#[test]
fn damaged_or_missing_backups_never_allow_partial_restoration() {
    for corruption in [false, true] {
        let mut f = Fixture::new();
        f.activate().unwrap();
        let plan = update(&f);
        let journal = Journal::prepare(&f.executor.tree, &plan.wanted, &plan.before).unwrap();
        journal.suspend(&f.executor.tree).unwrap();
        change_helper(&f, &plan);
        assert_eq!(journal.entries[0].key, "adapters/helper");
        assert_eq!(journal.entries[1].key, "policy/601");
        let backup = journal.root.join(if corruption {
            "backup-000"
        } else {
            "backup-001"
        });
        if corruption {
            fs::write(&backup, b"damaged backup").unwrap();
        } else {
            fs::remove_file(&backup).unwrap();
        }
        let before = files(&f.root);
        assert_eq!(
            Journal::recover(&f.executor.tree),
            Err(Error::RecoveryRequired)
        );
        assert_eq!(files(&f.root), before, "corruption={corruption}");
    }
}

#[test]
fn incomplete_backup_preparation_is_discarded_only_when_live_images_are_unchanged() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let before = files(&f.root);
    let plan = update(&f);
    let journal = Journal::prepare(&f.executor.tree, &plan.wanted, &plan.before).unwrap();
    fs::remove_file(journal.root.join("backup-001")).unwrap();
    Journal::recover(&f.executor.tree).unwrap();
    assert_eq!(files(&f.root), before);
}

#[test]
fn durable_commit_is_finalized_and_an_inconsistent_commit_marker_is_preserved() {
    for valid in [false, true] {
        let mut f = Fixture::new();
        f.activate().unwrap();
        let plan = update(&f);
        let journal = Journal::prepare(&f.executor.tree, &plan.wanted, &plan.before).unwrap();
        journal.suspend(&f.executor.tree).unwrap();
        if valid {
            for phase in [0, 1, 2] {
                for (key, next) in plan.wanted.iter().filter(|(key, _)| rank(key) == phase) {
                    let before = if key.starts_with("policy/") {
                        None
                    } else {
                        plan.before[key].as_ref()
                    };
                    image::set(&f.executor.tree, key, before, next.as_ref()).unwrap();
                }
            }
        }
        image::atomic(
            &f.executor.tree,
            &journal.root.join("settled"),
            &Image::new(b"after\n".to_vec(), 0o600),
        )
        .unwrap();
        let before = files(&f.root);
        let result = Journal::recover(&f.executor.tree);
        if valid {
            result.unwrap();
            plan.result.verify(&f.executor.tree).unwrap();
            assert_eq!(
                Receipt::load(&f.executor.tree).unwrap().unwrap().build,
                plan.result.build
            );
            assert!(!Journal::pending(&f.executor.tree).unwrap());
        } else {
            assert_eq!(result, Err(Error::RecoveryRequired));
            assert_eq!(files(&f.root), before);
        }
    }
}

#[test]
fn interrupted_collection_accepts_only_recorded_terminal_contents() {
    for state in ["manifest", "marker", "empty", "bad-marker", "foreign"] {
        let mut f = Fixture::new();
        f.activate().unwrap();
        let before = files(&f.root);
        let plan = update(&f);
        let journal = Journal::prepare(&f.executor.tree, &plan.wanted, &plan.before).unwrap();
        image::atomic(
            &f.executor.tree,
            &journal.root.join("settled"),
            &Image::new(b"before\n".to_vec(), 0o600),
        )
        .unwrap();
        let retired = f.executor.tree.state.join(".installation-completed");
        fs::rename(&journal.root, &retired).unwrap();
        fs::remove_file(retired.join("backup-000")).unwrap();
        if state != "manifest" {
            for entry in fs::read_dir(&retired).unwrap() {
                let path = entry.unwrap().path();
                if path.file_name().unwrap() != "settled" {
                    fs::remove_file(path).unwrap();
                }
            }
        }
        match state {
            "empty" => fs::remove_file(retired.join("settled")).unwrap(),
            "bad-marker" => fs::write(retired.join("settled"), b"garbled\n").unwrap(),
            "foreign" => fs::write(retired.join("unknown"), b"retain this").unwrap(),
            _ => {}
        }
        let pending = files(&f.root);
        let result = Journal::recover(&f.executor.tree);
        if matches!(state, "bad-marker" | "foreign") {
            assert_eq!(result, Err(Error::RecoveryRequired));
            assert_eq!(files(&f.root), pending);
        } else {
            result.unwrap();
            assert_eq!(files(&f.root), before, "{state}");
            assert!(!retired.exists());
        }
    }
}
