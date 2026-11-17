use super::*;

#[test]
fn well_formed_archives_with_changed_script_payload_mode_or_extra_content_are_rejected() {
    let f = Package::new();
    let result = f.build();
    let package = PathBuf::from(result["package"].as_str().unwrap());
    for kind in [
        "script-bytes",
        "payload-mode",
        "payload-bytes",
        "extra-file",
    ] {
        let forged = f.repository.root.join(format!("{kind}.pkg"));
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/installation/forge.py");
        let output = Command::new("python3")
            .arg(fixture)
            .arg(&f.repository.root)
            .arg(&package)
            .arg(result.to_string())
            .arg(kind)
            .arg(&forged)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rejected = f.verify(&forged);
        assert!(!rejected.status.success(), "admitted {kind}");
        let reason = if kind == "script-bytes" {
            "Package script changed"
        } else {
            "Extracted payload differs"
        };
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains(reason),
            "{kind}: {}",
            String::from_utf8_lossy(&rejected.stderr)
        );
    }
}
