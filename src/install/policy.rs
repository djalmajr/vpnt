use super::{Error, valid_hash};
use crate::helper::paths;
use paths::INSTALLER;

pub fn account(uid: u32) -> Result<(), Error> {
    // Exclude root, macOS service accounts and reserved negative uid_t values.
    if (501..=i32::MAX as u32).contains(&uid) {
        Ok(())
    } else {
        Err(Error::InvalidManifest)
    }
}

pub fn sudoers(uid: u32, helper: &str, installer: &str) -> Result<String, Error> {
    account(uid)?;
    if !valid_hash(helper) || !valid_hash(installer) {
        return Err(Error::InvalidManifest);
    }
    let runtime = format!("VPNT_{uid}_RUNTIME");
    let admin = format!("VPNT_{uid}_ADMIN");
    let remove = format!("VPNT_{uid}_REMOVE");
    Ok(format!(
        "# Managed by vpnt for numeric uid {uid}. No other command is authorized.\n\
Cmnd_Alias {runtime} = sha256:{helper} {} runtime\n\
Cmnd_Alias {admin} = sha256:{helper} {} admin\n\
Cmnd_Alias {remove} = sha256:{installer} {INSTALLER} remove\n\
Defaults!{runtime},{admin},{remove} !use_pty, !log_input, !log_output, !log_stdin, !log_stdout, !log_stderr, !log_ttyin, !log_ttyout, !log_subcmds, !intercept\n\
#{uid} ALL=(root) NOPASSWD: NOSETENV: NOLOG_INPUT: NOLOG_OUTPUT: NOINTERCEPT: EXEC: {runtime}\n\
#{uid} ALL=(root) PASSWD: NOSETENV: NOLOG_INPUT: NOLOG_OUTPUT: NOINTERCEPT: EXEC: {admin}, {remove}\n",
        paths::HELPER,
        paths::HELPER
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_runtime_is_passwordless_and_all_commands_have_fixed_paths_arguments_and_digests() {
        let helper = "a".repeat(64);
        let installer = "b".repeat(64);
        let text = sudoers(601, &helper, &installer).unwrap();
        let grants = text
            .lines()
            .filter(|line| line.starts_with("#601 ALL="))
            .collect::<Vec<_>>();
        assert_eq!(grants.len(), 2);
        assert!(grants[0].contains("NOPASSWD:") && grants[0].ends_with("VPNT_601_RUNTIME"));
        assert!(
            grants[1].contains(" PASSWD:")
                && !grants[1].contains("NOPASSWD")
                && grants[1].ends_with("VPNT_601_ADMIN, VPNT_601_REMOVE")
        );
        for grant in grants {
            for tag in [
                "(root)",
                "NOSETENV:",
                "NOLOG_INPUT:",
                "NOLOG_OUTPUT:",
                "NOINTERCEPT:",
            ] {
                assert!(grant.contains(tag), "{tag}");
            }
        }
        let aliases = text
            .lines()
            .filter(|line| line.starts_with("Cmnd_Alias "))
            .collect::<Vec<_>>();
        assert_eq!(aliases.len(), 3);
        assert!(aliases[0].contains(&format!("sha256:{helper} {} runtime", paths::HELPER)));
        assert!(aliases[1].contains(&format!("sha256:{helper} {} admin", paths::HELPER)));
        assert!(aliases[2].contains(&format!("sha256:{installer} {INSTALLER} remove")));
        for line in aliases {
            assert!(!line.contains(['*', '?', '[', '\"', '\\']));
        }
        let defaults = text
            .lines()
            .find(|line| line.starts_with("Defaults!"))
            .unwrap();
        for setting in [
            "!use_pty",
            "!log_input",
            "!log_output",
            "!log_stdin",
            "!log_stdout",
            "!log_stderr",
            "!log_ttyin",
            "!log_ttyout",
            "!log_subcmds",
            "!intercept",
        ] {
            assert!(defaults.contains(setting), "{setting}");
        }
        for uid in [0, 1, 500, u32::MAX] {
            assert!(sudoers(uid, &helper, &installer).is_err());
        }
        for value in ["*", "a\nALL", &"A".repeat(64)] {
            assert!(sudoers(601, value, &installer).is_err());
        }
    }
}
