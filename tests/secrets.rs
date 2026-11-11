use vpnt::{
    model::VpnKind,
    secrets::{Credentials, Secret},
};

#[test]
fn credentials_cannot_be_printed_through_debug_and_validate_the_client_input_boundary() {
    let credentials = Credentials {
        password: Secret::from("fictional-password"),
        psk: Secret::from("fictional-psk"),
    };
    let debug = format!("{credentials:?}");
    assert!(!debug.contains("fictional"));
    assert!(credentials.validate(VpnKind::Ipsec).is_ok());
    for password in ["", "bad\nvalue", "bad\rvalue", "bad\0value"] {
        assert!(
            Credentials {
                password: Secret::from(password),
                psk: Secret::from("psk")
            }
            .validate(VpnKind::Ipsec)
            .is_err()
        );
    }
    let ssl = Credentials {
        password: Secret::from("password"),
        psk: Secret::from(""),
    };
    assert!(ssl.validate(VpnKind::Ssl).is_ok());
    assert!(ssl.validate(VpnKind::Ipsec).is_err());
}
