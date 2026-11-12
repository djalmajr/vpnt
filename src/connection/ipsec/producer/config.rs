use super::{Error, files::checked_path};
use std::path::Path;
pub(super) fn render(directory: &Path) -> Result<String, Error> {
    let socket = directory.join("v");
    let pid = directory.join("pid");
    let socket = checked_path(&socket)?;
    if socket.len() >= 104 {
        return Err(Error::Invalid);
    }
    let pid = checked_path(&pid)?;
    Ok(format!(
        "charon {{\n load_modular = no\n load = aes des sha1 sha2 md4 hmac kdf random nonce openssl eap-identity eap-mschapv2 kernel-pfkey kernel-pfroute socket-default vici\n port = 0\n port_nat_t = 0\n install_routes = no\n install_virtual_ip = no\n vpnt_pid_file = \"{pid}\"\n plugins {{ vici {{ socket = \"unix://{socket}\" }} }}\n filelog {{ stderr {{ default = -1 }} }}\n syslog {{ daemon {{ default = -1 }} auth {{ default = -1 }} }}\n}}\n"
    ))
}
