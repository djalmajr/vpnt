use super::*;

#[test]
fn pkcs1_request_signs_with_pkcs1_padding() {
    assert_eq!(
        Padding::from_request(Some("RSA_PKCS1_PADDING")),
        Ok(Padding::Pkcs1)
    );
}

#[test]
fn a_request_without_algorithm_is_unsupported() {
    // Mutation captured: defaulting to PKCS#1 trusts a request that openvpn
    // never sends after the driver announced management version 3.
    assert_eq!(Padding::from_request(None), Err(Unsupported));
}

#[test]
fn pss_uses_the_requested_hash_under_either_openssl_name() {
    // Mutation captured: ignoring hashalg (always SHA-256) breaks SHA-384.
    for (algorithm, hash) in [
        (
            "RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest",
            Hash::Sha256,
        ),
        (
            "RSA_PKCS1_PSS_PADDING,hashalg=SHA2-256,saltlen=digest",
            Hash::Sha256,
        ),
        (
            "RSA_PKCS1_PSS_PADDING,saltlen=digest,hashalg=SHA384",
            Hash::Sha384,
        ),
        (
            "RSA_PKCS1_PSS_PADDING,hashalg=sha2-512,saltlen=digest",
            Hash::Sha512,
        ),
    ] {
        assert_eq!(
            Padding::from_request(Some(algorithm)),
            Ok(Padding::Pss(hash)),
            "{algorithm}"
        );
    }
}

#[test]
fn pss_with_a_salt_other_than_the_digest_length_is_unsupported() {
    // Mutation captured: accepting "max" would sign with the wrong salt and
    // fail the handshake only on the server.
    assert_eq!(
        Padding::from_request(Some("RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=max")),
        Err(Unsupported)
    );
}

#[test]
fn pss_without_a_known_hash_is_unsupported() {
    for algorithm in [
        "RSA_PKCS1_PSS_PADDING,saltlen=digest",
        "RSA_PKCS1_PSS_PADDING,hashalg=MD5,saltlen=digest",
        "RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest,extra=1",
    ] {
        assert_eq!(
            Padding::from_request(Some(algorithm)),
            Err(Unsupported),
            "{algorithm}"
        );
    }
}

#[test]
fn raw_rsa_ecdsa_and_decorated_pkcs1_are_unsupported() {
    for algorithm in [
        "RSA_NO_PADDING",
        "ECDSA",
        "RSA_PKCS1_PADDING,hashalg=SHA256",
        "",
    ] {
        assert_eq!(
            Padding::from_request(Some(algorithm)),
            Err(Unsupported),
            "{algorithm:?}"
        );
    }
}

/// DER DigestInfo header for SHA-256 (RFC 8017, section 9.2), written out
/// independently of the table under test.
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

#[test]
fn pkcs1_accepts_a_digest_info_with_a_digest_of_the_named_hash() {
    let mut data = SHA256_DIGEST_INFO.to_vec();
    data.extend([7; 32]);
    assert!(Padding::Pkcs1.accepts(&data));
}

#[test]
fn pkcs1_refuses_anything_that_is_not_a_complete_digest_info() {
    // Mutation captured: a length-only check lets a peer have arbitrary bytes
    // signed with a legally binding certificate.
    let mut truncated = SHA256_DIGEST_INFO.to_vec();
    truncated.extend([7; 31]);
    let mut extended = SHA256_DIGEST_INFO.to_vec();
    extended.extend([7; 33]);
    for data in [vec![0; 51], truncated, extended, Vec::new()] {
        assert!(!Padding::Pkcs1.accepts(&data), "{} bytes", data.len());
    }
}

#[test]
fn pss_accepts_only_a_digest_of_the_requested_hash() {
    assert!(Padding::Pss(Hash::Sha256).accepts(&[0; 32]));
    assert!(!Padding::Pss(Hash::Sha256).accepts(&[0; 48]));
    assert!(Padding::Pss(Hash::Sha384).accepts(&[0; 48]));
}
