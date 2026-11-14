use std::process::Command;

// Mutation captured: treating an invalid preview port as the default unexpectedly starts a server.
#[test]
fn invalid_arguments_are_rejected_without_starting_the_app() {
    for args in [
        vec!["--demo-server", "not-a-port"],
        vec!["--demo-server", "0"],
        vec!["--unknown"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vpnt"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}
