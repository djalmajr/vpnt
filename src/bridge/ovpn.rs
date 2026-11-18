//! OpenVPN bridge requests, separate from the snapshot dispatcher.
#[cfg(all(unix, not(target_os = "macos")))]
use super::CertificateView;
#[cfg(unix)]
use super::OvpnInspection;
use super::{Command, Reply};
#[cfg(unix)]
use crate::connection::ovpn::profile::{ImportError, inspect};
#[cfg(all(unix, not(target_os = "macos")))]
use crate::{
    connection::ovpn::pkcs11::{CertificateInfo, TokenError, list_certificates},
    model::valid_module_path,
};
#[cfg(all(unix, not(target_os = "macos")))]
use std::{path::Path, sync::mpsc, thread, time::Duration};

#[cfg(all(unix, not(target_os = "macos")))]
const CERTIFICATE_LIST_TIMEOUT: Duration = Duration::from_secs(30);

pub fn reply(id: &str, command: &Command) -> Option<Reply> {
    match command {
        Command::InspectOvpn { content } => Some(inspect_reply(id, content)),
        Command::ListCertificates { module } => Some(certificates_reply(id, module)),
        _ => None,
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn certificates_reply(id: &str, module: &str) -> Reply {
    certificates_reply_with(id, module, CERTIFICATE_LIST_TIMEOUT, list_certificates)
}

#[cfg(any(not(unix), target_os = "macos"))]
fn certificates_reply(id: &str, _: &str) -> Reply {
    Reply::error(id.into(), "unsupported")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn certificates_reply_with(
    id: &str,
    module: &str,
    timeout: Duration,
    list: impl FnOnce(&Path) -> Result<Vec<CertificateInfo>, TokenError> + Send + 'static,
) -> Reply {
    if !valid_module_path(module) {
        return Reply::error(id.into(), "invalid_module");
    }
    let module = module.to_owned();
    let (send, receive) = mpsc::channel();
    let Ok(_worker) = thread::Builder::new()
        .name("vpnt-certificate-list".into())
        .spawn(move || {
            let _ = send.send(list(Path::new(&module)));
        })
    else {
        return Reply::error(id.into(), "token_unavailable");
    };

    // Timing out ends the reply wait. The provider may still be inside a native call.
    match receive.recv_timeout(timeout) {
        Ok(Ok(certificates)) => Reply {
            id: id.into(),
            certificates: Some(
                certificates
                    .into_iter()
                    .map(|certificate| CertificateView {
                        id: certificate
                            .id
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect(),
                        subject: certificate.subject,
                        issuer: certificate.issuer,
                        not_before: certificate.not_before,
                        not_after: certificate.not_after,
                    })
                    .collect(),
            ),
            ..Reply::default()
        },
        _ => Reply::error(id.into(), "token_unavailable"),
    }
}

#[cfg(unix)]
fn inspect_reply(id: &str, content: &str) -> Reply {
    let result = inspect(content.as_bytes()).map(|info| {
        // The inspector enforces a nonempty list of remotes.
        let remote = &info.remotes[0];
        OvpnInspection {
            name: info.name,
            gateway: remote.host.clone(),
            port: remote.port,
        }
    });
    match result {
        Ok(info) => Reply {
            id: id.into(),
            ovpn: Some(info),
            ..Reply::default()
        },
        Err(error) => Reply {
            detail: Some(match error {
                ImportError::TooLarge => "too_large".into(),
                ImportError::NotUtf8 => "not_utf8".into(),
                ImportError::Forbidden(name) => name,
                ImportError::Malformed => "malformed".into(),
                ImportError::NoRemote => "no_remote".into(),
                ImportError::MissingBlock(_) => "missing_ca".into(),
            }),
            ..Reply::error(id.into(), "invalid_ovpn")
        },
    }
}

#[cfg(not(unix))]
fn inspect_reply(id: &str, _: &str) -> Reply {
    Reply::error(id.into(), "unsupported")
}

pub(crate) fn validate_config(content: &str) -> Result<(), &'static str> {
    #[cfg(unix)]
    {
        inspect(content.as_bytes())
            .map(|_| ())
            .map_err(|_| "invalid_ovpn")
    }
    #[cfg(not(unix))]
    {
        let _ = content;
        Err("unsupported")
    }
}

#[cfg(all(test, unix, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn certificate_listing_deadline_returns_before_provider_finishes() {
        let (release, wait) = mpsc::channel::<()>();
        let (finish, finished) = mpsc::channel();
        let reply = certificates_reply_with(
            "deadline",
            "/unused/token.so",
            Duration::from_millis(20),
            move |_| {
                // The fallback lets the test finish if the reply stops enforcing a deadline.
                let _ = wait.recv_timeout(Duration::from_secs(1));
                let _ = finish.send(());
                Ok(vec![])
            },
        );
        drop(release);
        finished.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(reply.id, "deadline");
        assert_eq!(reply.error.as_deref(), Some("token_unavailable"));
        assert!(reply.certificates.is_none());
    }

    #[test]
    fn certificate_listing_maps_ids_and_optional_metadata() {
        let reply = certificates_reply_with(
            "list",
            "/unused/token.so",
            CERTIFICATE_LIST_TIMEOUT,
            |module| {
                assert_eq!(module, Path::new("/unused/token.so"));
                Ok(vec![CertificateInfo {
                    id: vec![0x00, 0x0a, 0xbc, 0xff],
                    subject: Some("Example".into()),
                    issuer: None,
                    not_before: None,
                    not_after: Some("2035-01-02".into()),
                }])
            },
        );
        assert_eq!(
            serde_json::to_value(reply).unwrap(),
            serde_json::json!({
                "id":"list", "certificates":[
                    {"id":"000abcff","subject":"Example","notAfter":"2035-01-02"}
                ]
            })
        );
    }
}
