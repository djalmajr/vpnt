use super::invariants::files;
use super::*;
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
#[ignore = "child harness executed by abrupt_process_exit_is_recovered_under_the_persistent_lock"]
fn abrupt_exit_child() {
    let root =
        fs::canonicalize(std::env::var_os("VPNT_ENGINE_TEST_ROOT").expect("child fixture root"))
            .unwrap();
    let fixtures =
        fs::canonicalize(std::env::current_dir().unwrap().join("output/fixtures")).unwrap();
    assert!(root.starts_with(fixtures) && root.extension().is_some_and(|e| e == "engine"));
    let tree = Tree::fixture(&root);
    payload::files::directory(&root, tree.owner, true).unwrap();
    let mut executor = Executor {
        tree,
        checks: Checks {
            global: root.join("sudoers"),
        },
        fault: Some(Fault {
            remaining: std::env::var("VPNT_ENGINE_TEST_STEP")
                .unwrap()
                .parse()
                .unwrap(),
            crash: true,
        }),
    };
    let source = Payload::inspect(&root.with_extension(""), unsafe { libc::getuid() }).unwrap();
    let result = executor.activate(&source);
    panic!("child completed without the expected exit: {result:?}");
}

#[test]
fn abrupt_process_exit_is_recovered_under_the_persistent_lock() {
    for step in 0..4 {
        let mut f = Fixture::new();
        f.activate().unwrap();
        let before = files(&f.root);
        f.revise();
        let path = f.executor.tree.state.join(".controller.lock");
        let inode = fs::metadata(&path).unwrap().ino();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "install::engine::tests::crash::abrupt_exit_child",
                "--nocapture",
            ])
            .env("VPNT_ENGINE_TEST_ROOT", &f.root)
            .env("VPNT_ENGINE_TEST_STEP", step.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(40);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= until {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("owned crash fixture exceeded its deadline");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(
            status.code(),
            Some(81),
            "child must exit after the intended write, step {step}"
        );
        assert_eq!(f.policy(601).exists(), step == 3, "policy ordering/{step}");
        let helper = f.executor.tree.resolve("adapters/helper").unwrap();
        let revised = fs::read(f.source.root.join("adapters/helper")).unwrap();
        assert_eq!(fs::read(helper).unwrap() == revised, step >= 1);
        if step == 3 {
            Receipt::load(&f.executor.tree)
                .unwrap()
                .unwrap()
                .verify(&f.executor.tree)
                .expect("policy may return only after matching binaries and receipt");
        }
        assert_eq!(
            access::admit(&f.executor.tree, 601),
            Err(Error::RecoveryRequired)
        );
        let guard = f.executor.tree.bootstrap().unwrap();
        Journal::recover(&f.executor.tree).unwrap();
        drop(guard);
        assert_eq!(files(&f.root), before, "crash prefix {step}");
        assert_eq!(fs::metadata(path).unwrap().ino(), inode);
        access::admit(&f.executor.tree, 601).unwrap();
    }
}
