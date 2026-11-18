//! Maps the algorithm named in a PK_SIGN request onto a token signature. The
//! token never hashes: openvpn sends either a DigestInfo to pad (PKCS#1 v1.5)
//! or a bare digest to PSS-encode.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn parse(name: &str) -> Option<Self> {
        // OpenSSL 3 reports either the legacy or the SHA2-prefixed name.
        match name
            .to_ascii_uppercase()
            .replace("SHA2-", "SHA")
            .replace("SHA-", "SHA")
            .as_str()
        {
            "SHA1" => Some(Self::Sha1),
            "SHA224" => Some(Self::Sha224),
            "SHA256" => Some(Self::Sha256),
            "SHA384" => Some(Self::Sha384),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Padding {
    /// Data is a DigestInfo; the token applies PKCS#1 v1.5 padding.
    Pkcs1,
    /// Data is a bare digest; the salt is as long as the digest, as TLS uses.
    Pss(Hash),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unsupported;

impl Padding {
    /// The driver announces management version 3, after which openvpn always
    /// names the algorithm; a request without one is not trusted.
    pub fn from_request(algorithm: Option<&str>) -> Result<Self, Unsupported> {
        let algorithm = algorithm.ok_or(Unsupported)?;
        let mut parts = algorithm.split(',');
        match parts.next() {
            Some("RSA_PKCS1_PADDING") if parts.next().is_none() => Ok(Self::Pkcs1),
            Some("RSA_PKCS1_PSS_PADDING") => {
                let (mut hash, mut digest_salt) = (None, false);
                for parameter in parts {
                    match parameter.split_once('=') {
                        Some(("hashalg", name)) => hash = Hash::parse(name),
                        Some(("saltlen", "digest")) => digest_salt = true,
                        _ => return Err(Unsupported),
                    }
                }
                match (hash, digest_salt) {
                    (Some(hash), true) => Ok(Self::Pss(hash)),
                    _ => Err(Unsupported),
                }
            }
            _ => Err(Unsupported),
        }
    }

    /// Rejects input that cannot be what openvpn sends for this padding. The
    /// key may be a legally binding signature certificate, so the token only
    /// ever signs a digest, never arbitrary bytes a confused peer supplies.
    pub fn accepts(self, data: &[u8]) -> bool {
        match self {
            Self::Pkcs1 => DIGEST_INFO.iter().any(|(prefix, hash)| {
                data.len() == prefix.len() + hash.digest_len() && data.starts_with(prefix)
            }),
            Self::Pss(hash) => data.len() == hash.digest_len(),
        }
    }
}

/// DER DigestInfo headers (RFC 8017, section 9.2) that precede the digest.
const DIGEST_INFO: [(&[u8], Hash); 5] = [
    (
        &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        Hash::Sha1,
    ),
    (&sha2_header(0x2d, 0x04, 0x1c), Hash::Sha224),
    (&sha2_header(0x31, 0x01, 0x20), Hash::Sha256),
    (&sha2_header(0x41, 0x02, 0x30), Hash::Sha384),
    (&sha2_header(0x51, 0x03, 0x40), Hash::Sha512),
];

const fn sha2_header(total: u8, oid_last: u8, digest: u8) -> [u8; 19] {
    [
        0x30, total, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        oid_last, 0x05, 0x00, 0x04, digest,
    ]
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;
