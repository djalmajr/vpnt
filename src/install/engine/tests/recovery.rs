use super::invariants::files;
use super::*;

#[test]
fn every_injected_install_update_and_remove_failure_restores_the_previous_file_images() {
    for (operation, steps) in [("install", 11), ("update", 4), ("remove", 12)] {
        for step in 0..steps {
            let mut f = Fixture::new();
            if operation != "install" {
                f.activate().unwrap();
            }
            if operation == "update" {
                f.revise();
            }
            let before = files(&f.root);
            let lock = f.executor.tree.state.join(".controller.lock");
            let inode = fs::metadata(&lock).unwrap().ino();
            f.executor.fault = Some(Fault {
                remaining: step,
                crash: false,
            });
            let result = if operation == "remove" {
                f.executor.remove(601)
            } else {
                f.activate()
            };
            assert!(
                matches!(result, Err(Error::Io)),
                "{operation}/{step}: {result:?}"
            );
            assert_eq!(files(&f.root), before, "{operation}/{step}");
            assert_eq!(fs::metadata(lock).unwrap().ino(), inode);
            assert!(!Journal::pending(&f.executor.tree).unwrap());
        }
    }
}

#[test]
fn recovery_restores_interrupted_updates_but_never_overwrites_an_unrecognized_image() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let before = files(&f.root);
    f.revise();
    let old = Receipt::load(&f.executor.tree).unwrap();
    let plan =
        plan::Plan::activate(&f.executor.tree, old.as_ref(), &f.source.inspect().unwrap()).unwrap();
    let journal = Journal::prepare(&f.executor.tree, &plan.wanted, &plan.before).unwrap();
    journal.suspend(&f.executor.tree).unwrap();
    let image = plan.wanted["adapters/helper"].as_ref().unwrap();
    image::set(
        &f.executor.tree,
        "adapters/helper",
        plan.before["adapters/helper"].as_ref(),
        Some(image),
    )
    .unwrap();
    assert_eq!(
        access::admit(&f.executor.tree, 601),
        Err(Error::RecoveryRequired)
    );
    Journal::recover(&f.executor.tree).unwrap();
    assert_eq!(files(&f.root), before);
    let journal = Journal::prepare(&f.executor.tree, &plan.wanted, &plan.before).unwrap();
    let path = f.executor.tree.resolve("adapters/helper").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&path, b"unknown writer").unwrap();
    let contents = fs::read(&path).unwrap();
    assert_eq!(
        Journal::recover(&f.executor.tree),
        Err(Error::RecoveryRequired)
    );
    assert_eq!(fs::read(&path).unwrap(), contents);
    assert!(journal.root.exists());
}
