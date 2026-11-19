#![cfg(unix)]
//! Opt-in with VPNT_TEST_SOFTHSM pointing to a SoftHSM module.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    object::{Attribute, CertificateType, KeyType, ObjectClass},
    session::{Session, UserType},
    types::AuthPin,
};
use std::{
    fs::{self, DirBuilder},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use vpnt::connection::ovpn::pkcs11::list_certificates;

const LABEL: &str = "vpnt-fixture";
const PIN: &str = "18273645";
const SO_PIN: &str = "83726190";
const CHILD: &str = "VPNT_TEST_SOFTHSM_FIXTURE_DIR";

struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn available(program: &str) -> bool {
    Command::new(program).arg("--help").output().is_ok()
}

fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{:?}: {}",
        command.get_program(),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn lists_only_certificates_with_a_visible_private_key() {
    let Some(module) = std::env::var_os("VPNT_TEST_SOFTHSM") else {
        eprintln!("skipped: VPNT_TEST_SOFTHSM is unset (SoftHSM opt-in)");
        return;
    };
    let utility = available("softhsm2-util");
    let pkcs11_tool = available("pkcs11-tool");
    if !utility && !pkcs11_tool {
        eprintln!("skipped: neither softhsm2-util nor pkcs11-tool is on PATH");
        return;
    }
    if !available("openssl") {
        eprintln!("skipped: openssl is not on PATH");
        return;
    }
    let module = Path::new(&module);
    assert!(module.is_file(), "VPNT_TEST_SOFTHSM does not name a file");

    if let Some(directory) = std::env::var_os(CHILD) {
        assert_eq!(
            std::env::var_os("SOFTHSM2_CONF").map(PathBuf::from),
            Some(Path::new(&directory).join("softhsm2.conf")),
        );
        exercise(module, Path::new(&directory), utility);
        return;
    }

    let root = std::env::temp_dir().join(format!("vpnt-softhsm-{}", std::process::id()));
    DirBuilder::new().mode(0o700).create(&root).unwrap();
    let root = Temp(root);
    let storage = root.0.join("tokens");
    fs::create_dir(&storage).unwrap();
    let config = root.0.join("softhsm2.conf");
    fs::write(
        &config,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\n",
            storage.display()
        ),
    )
    .unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "lists_only_certificates_with_a_visible_private_key",
            "--nocapture",
        ])
        .env(CHILD, &root.0)
        .env("SOFTHSM2_CONF", config)
        .status()
        .unwrap();
    assert!(status.success());
}

fn exercise(module: &Path, root: &Path, utility: bool) {
    let context = Pkcs11::new(module).unwrap();
    context
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = context.get_all_slots().unwrap()[0];
    let so_pin = AuthPin::new(SO_PIN.into());
    let user_pin = AuthPin::new(PIN.into());
    context.init_token(slot, &so_pin, LABEL).unwrap();
    let slot = context
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| {
            context
                .get_token_info(*slot)
                .is_ok_and(|info| info.label() == LABEL)
        })
        .unwrap();
    {
        let session = context.open_rw_session(slot).unwrap();
        session.login(UserType::So, Some(&so_pin)).unwrap();
        session.init_pin(&user_pin).unwrap();
    }

    for (stem, subject) in [("matched", "Matched"), ("unmatched", "Unmatched")] {
        run(Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                &format!("/CN={subject}"),
                "-days",
                "2",
                "-outform",
                "DER",
                "-out",
            ])
            .arg(root.join(format!("{stem}.der")))
            .arg("-keyout")
            .arg(root.join(format!("{stem}.pem"))));
    }
    let key = root.join("matched.pem");
    let rsa = run(Command::new("openssl")
        .arg("rsa")
        .arg("-in")
        .arg(&key)
        .args(["-traditional", "-outform", "DER"]));
    if utility {
        run(Command::new("softhsm2-util")
            .arg("--import")
            .arg(&key)
            .args(["--token", LABEL, "--id", "01", "--pin", PIN]));
    } else {
        let der_key = root.join("matched-key.der");
        fs::write(&der_key, &rsa.stdout).unwrap();
        run(Command::new("pkcs11-tool")
            .arg("--module")
            .arg(module)
            .args([
                "--token-label",
                LABEL,
                "--login",
                "--pin",
                PIN,
                "--write-object",
            ])
            .arg(der_key)
            .args(["--type", "privkey", "--id", "01"]));
    }

    let key_query = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Id(vec![1]),
    ];
    let hidden = context
        .open_ro_session(slot)
        .unwrap()
        .find_objects(&key_query)
        .unwrap()
        .is_empty();
    let cert = root.join("matched.der");
    {
        let session = context.open_rw_session(slot).unwrap();
        session.login(UserType::User, Some(&user_pin)).unwrap();
        if hidden {
            // Import tools usually mark private keys private. Provision a
            // synthetic, publicly discoverable key object for the no-login
            // production path. Its ID and RSA material match the CLI import.
            import_visible_key(&session, &rsa.stdout);
        }
        for (id, file) in [(1, cert.clone()), (2, root.join("unmatched.der"))] {
            session
                .create_object(&[
                    Attribute::Class(ObjectClass::CERTIFICATE),
                    Attribute::CertificateType(CertificateType::X_509),
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Id(vec![id]),
                    Attribute::Subject(vec![0x30, 0]),
                    Attribute::Value(fs::read(file).unwrap()),
                ])
                .unwrap();
        }
        session.logout().unwrap();
    }

    {
        let session = context.open_ro_session(slot).unwrap();
        assert!(!session.find_objects(&key_query).unwrap().is_empty());
        assert_eq!(
            session
                .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
                .unwrap()
                .len(),
            2
        );
    }
    let result = list_certificates(module).unwrap();
    let [certificate] = result.as_slice() else {
        panic!("expected one certificate, got {}", result.len());
    };
    assert_eq!(certificate.id, [1]);
    assert_eq!(certificate.subject.as_deref(), Some("Matched"));
    assert_eq!(certificate.issuer.as_deref(), Some("Matched"));
    let output = run(Command::new("openssl")
        .args([
            "x509",
            "-inform",
            "DER",
            "-noout",
            "-startdate",
            "-enddate",
            "-dateopt",
            "iso_8601",
            "-in",
        ])
        .arg(&cert));
    let dates = std::str::from_utf8(&output.stdout).unwrap();
    let date = |key| {
        dates
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap()
            .replace(' ', "T")
    };
    assert_eq!(
        certificate.not_before.as_deref(),
        Some(date("notBefore=").as_str())
    );
    assert_eq!(
        certificate.not_after.as_deref(),
        Some(date("notAfter=").as_str())
    );
}

fn import_visible_key(session: &Session, mut der: &[u8]) {
    // Parse the nine INTEGERs of the PKCS#1 fixture emitted by openssl rsa.
    fn take<'a>(input: &mut &'a [u8], tag: u8) -> &'a [u8] {
        let (&actual, tail) = input.split_first().unwrap();
        assert_eq!(actual, tag);
        let (&first, mut tail) = tail.split_first().unwrap();
        let len = if first < 128 {
            usize::from(first)
        } else {
            let (bytes, rest) = tail.split_at(usize::from(first & 0x7f));
            tail = rest;
            bytes
                .iter()
                .fold(0, |n, &byte| (n << 8) | usize::from(byte))
        };
        let (value, tail) = tail.split_at(len);
        *input = tail;
        value
    }
    let mut sequence = take(&mut der, 0x30);
    assert!(der.is_empty());
    assert_eq!(take(&mut sequence, 2), [0]);
    let mut integer = || {
        let value = take(&mut sequence, 2);
        value.strip_prefix(&[0]).unwrap_or(value).to_vec()
    };
    session
        .create_object(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Id(vec![1]),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Sensitive(true),
            Attribute::Sign(true),
            Attribute::Modulus(integer()),
            Attribute::PublicExponent(integer()),
            Attribute::PrivateExponent(integer()),
            Attribute::Prime1(integer()),
            Attribute::Prime2(integer()),
            Attribute::Exponent1(integer()),
            Attribute::Exponent2(integer()),
            Attribute::Coefficient(integer()),
        ])
        .unwrap();
    assert!(sequence.is_empty());
}
