use super::{Error, files::checked_path};
use std::{num::NonZeroU16, path::Path};

pub(super) fn render(directory: &Path, log: &Path) -> Result<String, Error> {
    render_with(directory, log, None)
}

/// Test/consumer-only bound renderer. The caller must derive `index` solely
/// from a revalidated opaque IpsecEgress (not a tunnel UTUN); this function
/// does not dispatch a producer or authorize one. Default `render` stays
/// unbound and never enables the protected transport setting.
pub(super) fn render_bound(
    directory: &Path,
    log: &Path,
    index: NonZeroU16,
) -> Result<String, Error> {
    render_with(directory, log, Some(index))
}

fn render_with(directory: &Path, log: &Path, bound: Option<NonZeroU16>) -> Result<String, Error> {
    let log = checked_path(log)?;
    let socket = directory.join("v");
    let pid = directory.join("pid");
    let socket = checked_path(&socket)?;
    if socket.len() >= 104 {
        return Err(Error::Invalid);
    }
    let pid = checked_path(&pid)?;
    let socket_default = bound
        .map(|index| {
            format!(
                " socket-default {{\n  vpnt_protect_transport = yes\n  vpnt_ifindex = {}\n }}",
                index.get()
            )
        })
        .unwrap_or_default();
    Ok(format!(
        "charon {{\n load_modular = no\n load = aes des sha1 sha2 md4 hmac kdf random nonce openssl eap-identity eap-mschapv2 kernel-libipsec kernel-pfroute socket-default vici\n port = 0\n port_nat_t = 0\n install_routes = no\n install_virtual_ip = no\n vpnt_pid_file = \"{pid}\"\n vpnt_parent_eof = yes\n plugins {{ vici {{ socket = \"unix://{socket}\" }} kernel-libipsec {{ vpnt_retain_utun = yes }}{socket_default} }}\n filelog {{\n  diagnostic {{\n   path = \"{log}\"\n   append = yes\n   flush_line = yes\n   time_format = %H:%M:%S\n   ike_name = yes\n   default = 0\n   ike = 2\n   cfg = 2\n   chd = 1\n   dmn = 1\n   net = 1\n   knl = 1\n   enc = 0\n   mgr = 0\n   lib = 1\n   asn = 0\n   job = 0\n   esp = 0\n   tls = 0\n   tnc = -1\n   imc = -1\n   imv = -1\n   pts = -1\n  }}\n  stderr {{ default = -1 }}\n }}\n syslog {{ daemon {{ default = -1 }} auth {{ default = -1 }} }}\n}}\n"
    ))
}
