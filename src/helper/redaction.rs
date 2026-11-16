//! One shared ASCII keyword policy for untrusted diagnostic lines.
pub(crate) const REDACTED_LINE: &str = "[linha redigida]";
// Substring match, ASCII case-insensitive. `set-cookie` is listed explicitly
// so a future edit cannot silently remove it with the broader `cookie` case.
pub(crate) const SECRET_KEYWORDS: [&str; 8] = [
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "otp",
    "authorization",
    "set-cookie",
];

pub(crate) fn contains_secret_keyword(line: &[u8]) -> bool {
    SECRET_KEYWORDS.iter().any(|keyword| {
        let needle = keyword.as_bytes();
        !needle.is_empty()
            && line.len() >= needle.len()
            && (0..=line.len() - needle.len()).any(|start| {
                line[start..start + needle.len()]
                    .iter()
                    .zip(needle)
                    .all(|(hay, pin)| hay.to_ascii_lowercase() == *pin)
            })
    })
}
