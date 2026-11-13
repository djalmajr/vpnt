use super::{Error, files::checked_path};
use std::{num::NonZeroU16, path::Path};

pub(super) fn render(directory: &Path) -> Result<String, Error> {
    render_with(directory, None)
}

/// Test/consumer-only bound renderer. The caller must derive `index` solely
/// from a revalidated opaque IpsecEgress (not a tunnel UTUN); this function
/// does not dispatch a producer or authorize one. Default `render` stays
/// byte-identical and never enables the protected transport setting.
pub(super) fn render_bound(directory: &Path, index: NonZeroU16) -> Result<String, Error> {
    render_with(directory, Some(index))
}

fn render_with(directory: &Path, bound: Option<NonZeroU16>) -> Result<String, Error> {
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
        "charon {{\n load_modular = no\n load = aes des sha1 sha2 md4 hmac kdf random nonce openssl eap-identity eap-mschapv2 kernel-libipsec kernel-pfroute socket-default vici\n port = 0\n port_nat_t = 0\n install_routes = no\n install_virtual_ip = no\n vpnt_pid_file = \"{pid}\"\n vpnt_parent_eof = yes\n plugins {{ vici {{ socket = \"unix://{socket}\" }} kernel-libipsec {{ vpnt_retain_utun = yes }}{socket_default} }}\n filelog {{ stderr {{ default = -1 }} }}\n syslog {{ daemon {{ default = -1 }} auth {{ default = -1 }} }}\n}}\n"
    ))
}
