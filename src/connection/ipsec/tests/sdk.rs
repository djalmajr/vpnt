use super::*;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn darwin_sdk_and_allocator_agree_on_the_manual_reqid_limit() {
    let directory = std::env::temp_dir().join(format!(
        "vpnt-ipsec-sdk-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&directory).unwrap();
    let f = Fixture(directory);
    let executable = f.0.join("consumer");
    let compiled = Command::new("/usr/bin/xcrun")
        .args(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(
            std::env::current_dir()
                .unwrap()
                .join("tests/fixtures/ipsec/reqid.c"),
        )
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "SDK consumer compilation failed");
    let output = Command::new(executable).output().unwrap();
    assert!(output.status.success());
    let sdk: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(sdk["bits"], 16);
    let mut registry = Registry::new(Observation::default());
    let reservation = registry.reserve(owner("Case", 1)).unwrap();
    assert_eq!(
        u64::from(reservation.reqid()),
        sdk["manualMax"].as_u64().unwrap(),
        "a manual reqid must survive the kernel policy parser without reassignment"
    );
}
