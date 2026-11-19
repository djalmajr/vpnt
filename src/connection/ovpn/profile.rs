//! Inspection of untrusted client profiles before handing them to OpenVPN.
use std::{fmt, net::Ipv4Addr};

const MAX_PROFILE_BYTES: usize = 32 * 1024;
// OpenVPN's 256-byte option line buffer also needs the LF and trailing NUL.
const MAX_LINE_BYTES: usize = 254;
const INLINE: &[&str] = &["ca", "tls-crypt", "tls-auth", "tls-crypt-v2", "extra-certs"];

#[derive(Debug, Eq, PartialEq)]
pub enum ImportError {
    TooLarge,
    NotUtf8,
    Forbidden(String),
    Malformed,
    NoRemote,
    MissingBlock(&'static str),
}

pub struct Inspected {
    pub name: Option<String>,
    pub remotes: Vec<Remote>,
    pub normalized: String,
}

impl fmt::Debug for Inspected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inspected")
            .field("normalized_len", &self.normalized.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    pub proto: Option<Proto>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("profile too large"),
            Self::NotUtf8 => f.write_str("profile is not UTF-8"),
            Self::Forbidden(name) => write!(f, "forbidden directive: {name}"),
            Self::Malformed => f.write_str("malformed profile"),
            Self::NoRemote => f.write_str("no remote"),
            Self::MissingBlock(block) => write!(f, "missing inline {block} block"),
        }
    }
}

impl std::error::Error for ImportError {}

pub fn inspect(content: &[u8]) -> Result<Inspected, ImportError> {
    if content.len() > MAX_PROFILE_BYTES {
        return Err(ImportError::TooLarge);
    }
    let input = std::str::from_utf8(content).map_err(|_| ImportError::NotUtf8)?;
    // A profile is text: besides tab and line ends, control characters (even
    // in comments) are refused. This also keeps the JSON escape of an
    // accepted profile within twice its size (only quotes and backslashes
    // grow), which the bridge and admin frame limits rely on.
    if content
        .iter()
        .any(|&byte| byte.is_ascii_control() && !matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(ImportError::Malformed);
    }
    let lines = input.replace("\r\n", "\n").replace('\r', "\n");
    let mut normalized = String::with_capacity(lines.len() + 1);
    let mut name = None;
    let mut saw_name = false;
    let mut header = true;
    let mut remotes = Vec::new();
    let mut block = None;
    let mut has_ca = false;

    for line in lines.split_terminator('\n') {
        let line = line.trim_end_matches([' ', '\t']);
        if line.len() > MAX_LINE_BYTES {
            return Err(ImportError::Malformed);
        }
        normalized.push_str(line);
        normalized.push('\n');
        let line = line.trim_start_matches([' ', '\t']);

        if let Some(open) = block {
            if closing_tag(line) == Some(open) {
                has_ca |= open == "ca";
                block = None;
            } else if line.starts_with('<') || has_syntax_control(line) {
                // Tag-like boundaries must be exact. In particular, a close
                // tag followed by more text cannot hide subsequent directives.
                return Err(ImportError::Malformed);
            }
            continue;
        }

        if line.is_empty() || line.starts_with(['#', ';']) {
            if header
                && !saw_name
                && let Some(raw_name) = line.strip_prefix("# Name:")
            {
                saw_name = true;
                let candidate = raw_name.trim_matches(' ');
                if !candidate.is_empty()
                    && candidate.chars().count() <= 120
                    && !candidate.chars().any(char::is_control)
                {
                    name = Some(candidate.to_owned());
                }
            }
            continue;
        }
        header = false;
        if has_syntax_control(line) {
            return Err(ImportError::Malformed);
        }

        if line.starts_with('<') {
            let tag = line
                .strip_prefix('<')
                .and_then(|tag| tag.strip_suffix('>'))
                .filter(|tag| directive_name(tag))
                .ok_or(ImportError::Malformed)?;
            if !INLINE.contains(&tag) {
                return Err(ImportError::Forbidden(tag.to_owned()));
            }
            block = Some(tag);
            continue;
        }

        let (word, rest) = line
            .find([' ', '\t'])
            .map_or((line, ""), |offset| line.split_at(offset));
        let directive = word.strip_prefix("--").unwrap_or(word);
        if !directive_name(directive) {
            return Err(ImportError::Malformed);
        }
        if !allowed(directive) {
            return Err(ImportError::Forbidden(directive.to_owned()));
        }
        let args = arguments(rest)?;
        match directive {
            "remote" => remotes.push(parse_remote(&args)?),
            "setenv" => check_setenv(&args)?,
            "remote-cert-tls" if args.as_slice() != ["server"] => {
                return Err(ImportError::Forbidden("remote-cert-tls".into()));
            }
            _ => {}
        }
    }

    if block.is_some() {
        return Err(ImportError::Malformed);
    }
    if remotes.is_empty() {
        return Err(ImportError::NoRemote);
    }
    if !has_ca {
        return Err(ImportError::MissingBlock("ca"));
    }
    // Normalizing can add a final newline. The limit holds for the stored text
    // too, so inspecting the normalized text again accepts it.
    if normalized.len() > MAX_PROFILE_BYTES {
        return Err(ImportError::TooLarge);
    }
    Ok(Inspected {
        name,
        remotes,
        normalized,
    })
}

fn closing_tag(line: &str) -> Option<&str> {
    line.strip_prefix("</")?.strip_suffix('>')
}

fn has_syntax_control(line: &str) -> bool {
    line.bytes()
        .any(|byte| byte.is_ascii_control() && byte != b'\t')
}

fn directive_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn allowed(name: &str) -> bool {
    matches!(
        name,
        "client"
            | "tls-client"
            | "pull"
            | "dev"
            | "dev-type"
            | "proto"
            | "remote"
            | "remote-random"
            | "resolv-retry"
            | "nobind"
            | "float"
            | "connect-retry"
            | "connect-retry-max"
            | "server-poll-timeout"
            | "explicit-exit-notify"
            | "persist-key"
            | "persist-tun"
            | "ping"
            | "ping-restart"
            | "ping-exit"
            | "keepalive"
            | "hand-window"
            | "tls-timeout"
            | "tran-window"
            | "reneg-sec"
            | "remote-cert-tls"
            | "verify-x509-name"
            | "cipher"
            | "data-ciphers"
            | "data-ciphers-fallback"
            | "auth"
            | "tls-version-min"
            | "tls-cipher"
            | "tls-ciphersuites"
            | "key-direction"
            | "auth-nocache"
            | "topology"
            | "tun-mtu"
            | "mssfix"
            | "fragment"
            | "sndbuf"
            | "rcvbuf"
            | "comp-lzo"
            | "compress"
            | "allow-compression"
            | "verb"
            | "mute"
            | "mute-replay-warnings"
            | "setenv"
            | "ignore-unknown-option"
            | "push-peer-info"
    )
}

fn arguments(input: &str) -> Result<Vec<String>, ImportError> {
    let mut chars = input.chars().peekable();
    let mut args = Vec::new();
    while let Some(first) = chars.next() {
        if matches!(first, ' ' | '\t') {
            continue;
        }
        if matches!(first, '#' | ';') {
            break;
        }

        let quote = matches!(first, '\'' | '"').then_some(first);
        let mut current = if quote.is_some() {
            chars.next()
        } else {
            Some(first)
        };
        let mut arg = String::new();
        loop {
            match current {
                None if quote.is_some() => return Err(ImportError::Malformed),
                None => break,
                Some(ch) if Some(ch) == quote => {
                    if chars
                        .peek()
                        .is_some_and(|ch| !matches!(ch, ' ' | '\t' | '#' | ';'))
                    {
                        return Err(ImportError::Malformed);
                    }
                    break;
                }
                Some(' ' | '\t') if quote.is_none() => break,
                Some('\'' | '"') if quote.is_none() => return Err(ImportError::Malformed),
                Some('\\') if quote != Some('\'') => {
                    let escaped = chars
                        .next()
                        .filter(|ch| matches!(ch, '\\' | '"' | ' ' | '\t'));
                    arg.push(escaped.ok_or(ImportError::Malformed)?);
                }
                Some(ch) => arg.push(ch),
            }
            current = chars.next();
        }
        args.push(arg);
    }
    Ok(args)
}

fn check_setenv(args: &[String]) -> Result<(), ImportError> {
    let name = args.first().ok_or(ImportError::Malformed)?;
    if name == "opt" {
        return Err(ImportError::Forbidden("setenv opt".to_owned()));
    }
    let mut bytes = name.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ImportError::Malformed);
    }
    Ok(())
}

fn parse_remote(args: &[String]) -> Result<Remote, ImportError> {
    let [host, optional @ ..] = args else {
        return Err(ImportError::Malformed);
    };
    if !valid_host(host) || optional.len() > 2 {
        return Err(ImportError::Malformed);
    }
    let port = match optional.first() {
        None => 1194,
        Some(port) if port.bytes().all(|byte| byte.is_ascii_digit()) => port
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or(ImportError::Malformed)?,
        Some(_) => return Err(ImportError::Malformed),
    };
    let proto = match optional.get(1).map(String::as_str) {
        None => None,
        Some("udp" | "udp4" | "udp6") => Some(Proto::Udp),
        Some("tcp" | "tcp-client" | "tcp4-client" | "tcp6-client") => Some(Proto::Tcp),
        Some(_) => return Err(ImportError::Malformed),
    };
    Ok(Remote {
        host: host.clone(),
        port,
        proto,
    })
}

fn valid_host(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && !(host.contains('.')
            && host
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.'))
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
