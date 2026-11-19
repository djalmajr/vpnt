use super::*;
#[cfg(target_os = "linux")]
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if value.len() < 128 {
        result.push(value.len() as u8);
    } else {
        let size = (value.len() as u32).to_be_bytes();
        let start = size.iter().position(|byte| *byte != 0).unwrap();
        result.push(0x80 | (4 - start) as u8);
        result.extend_from_slice(&size[start..]);
    }
    result.extend_from_slice(value);
    result
}

fn sequence(values: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &values.concat())
}

fn name(oid_last: u8, value_tag: u8, value: &[u8]) -> Vec<u8> {
    sequence(&[tlv(
        0x31,
        &sequence(&[tlv(6, &[0x55, 4, oid_last]), tlv(value_tag, value)]),
    )])
}

fn certificate(subject: Vec<u8>, body_tail: Vec<u8>) -> Vec<u8> {
    sequence(&[
        sequence(&[
            tlv(2, &[1]),
            sequence(&[]),
            name(3, 0x13, b"Issuer"),
            sequence(&[tlv(0x17, b"491231235959Z"), tlv(0x18, b"20500228000000Z")]),
            subject,
            body_tail,
        ]),
        sequence(&[]),
        tlv(3, &[0]),
    ])
}

#[test]
fn valid_fields_and_name_encodings() {
    for (tag, value, expected) in [
        (0x0c, "Ágata".as_bytes(), "Ágata"),
        (0x13, b"Printable".as_slice(), "Printable"),
        (0x16, b"IA5".as_slice(), "IA5"),
        (0x1e, b"\x00\xc1\x00g".as_slice(), "Ág"),
    ] {
        let parsed = read_certificate(&certificate(name(3, tag, value), vec![]));
        assert_eq!(parsed.subject.as_deref(), Some(expected));
        assert_eq!(parsed.issuer.as_deref(), Some("Issuer"));
        assert_eq!(parsed.not_before.as_deref(), Some("2049-12-31T23:59:59Z"));
        assert_eq!(parsed.not_after.as_deref(), Some("2050-02-28T00:00:00Z"));
    }
    let parsed = read_certificate(&certificate(name(10, 0x13, b"Fallback"), vec![]));
    assert_eq!(parsed.subject.as_deref(), Some("Fallback"));
}

#[test]
fn hostile_lengths_and_truncations_do_not_expose_any_fields() {
    let input = certificate(name(3, 0x0c, b"Visible"), vec![]);
    assert_eq!(read_certificate(&input).subject.as_deref(), Some("Visible"));
    for len in 0..input.len() {
        assert_eq!(
            read_certificate(&input[..len]),
            Fields::default(),
            "cut at {len}"
        );
    }
    for header in [
        vec![0x30, 0x82, 0x01, 0x00],
        vec![0x30, 0x80],
        vec![0x30, 0x85, 1, 0, 0, 0, 0],
    ] {
        let mut malformed = header;
        malformed.extend_from_slice(&input[2..]);
        assert_eq!(read_certificate(&malformed), Fields::default());
    }
    let large = |size| certificate(name(3, 0x0c, b"Visible"), tlv(4, &vec![0; size]));
    let overhead = large(60_000).len() - 60_000;
    let boundary = large(64 * 1024 - overhead);
    assert_eq!(boundary.len(), 64 * 1024);
    assert_eq!(
        read_certificate(&boundary).subject.as_deref(),
        Some("Visible")
    );
    let oversized = large(64 * 1024 + 1 - overhead);
    assert_eq!(oversized.len(), 64 * 1024 + 1);
    assert_eq!(read_certificate(&oversized), Fields::default());
}

#[test]
fn constructed_depth_is_bounded_even_in_ignored_tbs_fields() {
    let nested = |depth: usize| (0..depth).fold(tlv(5, &[]), |child, _| sequence(&[child]));
    let ordinary = certificate(name(3, 0x0c, b"Visible"), nested(5));
    assert_eq!(
        read_certificate(&ordinary).subject.as_deref(),
        Some("Visible")
    );
    let deep = certificate(name(3, 0x0c, b"Visible"), nested(9));
    assert_eq!(read_certificate(&deep), Fields::default());
}

#[test]
fn control_names_are_rejected_and_long_names_are_capped_by_characters() {
    for bytes in [b"before\x00after".as_slice(), b"before\nafter".as_slice()] {
        let parsed = read_certificate(&certificate(name(3, 0x0c, bytes), vec![]));
        assert_eq!(parsed.subject, None);
        assert_eq!(parsed.issuer.as_deref(), Some("Issuer"));
    }
    let name_text = "é".repeat(201);
    let parsed = read_certificate(&certificate(name(3, 0x0c, name_text.as_bytes()), vec![]));
    assert_eq!(parsed.subject.unwrap().chars().count(), 200);
}

// The oracle prints dates with `-dateopt`, an OpenSSL 3 option. macOS ships
// LibreSSL as `openssl`, and OVPN profiles only connect on Linux.
#[cfg(target_os = "linux")]
#[test]
fn openssl_generated_certificates_match_displayed_names_and_dates() {
    match Command::new("openssl").arg("version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: openssl is not on PATH");
            return;
        }
        result => assert!(result.unwrap().status.success()),
    }
    for (cn, days, expected_end) in [("Example", "2", 0x17), ("Ágata", "15000", 0x18)] {
        // Only the certificate leaves the process. OpenSSL discards the synthetic key.
        let generated = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-utf8",
                "-subj",
                &format!("/O=Example Org/CN={cn}"),
                "-days",
                days,
                "-keyout",
                "/dev/null",
                "-outform",
                "DER",
            ])
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "openssl req: {}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let mut outer = expect(&mut generated.stdout.as_slice(), SEQUENCE).unwrap();
        let mut tbs = expect(&mut outer, SEQUENCE).unwrap();
        if tbs.first() == Some(&0xa0) {
            expect(&mut tbs, 0xa0).unwrap();
        }
        for tag in [2, SEQUENCE, SEQUENCE] {
            expect(&mut tbs, tag).unwrap();
        }
        let mut dates = expect(&mut tbs, SEQUENCE).unwrap();
        assert_eq!(read(&mut dates).unwrap().tag, 0x17);
        assert_eq!(read(&mut dates).unwrap().tag, expected_end);
        let info = read_certificate(&generated.stdout);
        let mut display = Command::new("openssl")
            .args([
                "x509",
                "-inform",
                "DER",
                "-noout",
                "-subject",
                "-issuer",
                "-startdate",
                "-enddate",
                "-dateopt",
                "iso_8601",
                "-nameopt",
                "utf8",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        display
            .stdin
            .take()
            .unwrap()
            .write_all(&generated.stdout)
            .unwrap();
        let display = display.wait_with_output().unwrap();
        assert!(display.status.success());
        let text = std::str::from_utf8(&display.stdout).unwrap();
        let get = |prefix| {
            text.lines()
                .find_map(|line| line.strip_prefix(prefix))
                .unwrap()
                .trim()
        };
        for (prefix, actual) in [("subject=", &info.subject), ("issuer=", &info.issuer)] {
            assert_eq!(actual.as_deref(), Some(cn));
            assert!(
                get(prefix).contains(&format!("CN={cn}"))
                    || get(prefix).contains(&format!("CN = {cn}")),
                "{text}"
            );
        }
        assert_eq!(
            info.not_before.as_deref(),
            Some(get("notBefore=").replace(' ', "T").as_str())
        );
        assert_eq!(
            info.not_after.as_deref(),
            Some(get("notAfter=").replace(' ', "T").as_str())
        );
        let end_year = info.not_after.unwrap()[..4].parse::<u16>().unwrap();
        assert_eq!(end_year >= 2050, expected_end == 0x18);
    }
}
