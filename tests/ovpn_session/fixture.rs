//! A throwaway CA, a point-to-point openvpn server and a key-file signer that
//! stands in for the token by calling `openssl pkeyutl`.
//!
//! VPNT_TEST_OPENSSL names the OpenSSL 3 or later binary for both, `openssl`
//! from PATH by default. On macOS that can be LibreSSL or OpenSSL 1.1, and
//! both refuse `req` under `OPENSSL_CONF=/dev/null`.
use std::{
    env,
    ffi::OsString,
    fs,
    io::Write,
    net::{Ipv4Addr, UdpSocket},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
};
use vpnt::connection::ovpn::{
    session::{SignError, Signer},
    signing::{Hash, Padding},
};

pub struct Fixture {
    pub directory: PathBuf,
    pub openvpn: PathBuf,
}

impl Fixture {
    /// None when VPNT_TEST_OPENVPN is unset; with it set, a missing `openssl`
    /// is a failure rather than a silent skip.
    pub fn new(name: &str) -> Option<Self> {
        let Some(openvpn) = env::var_os("VPNT_TEST_OPENVPN") else {
            eprintln!("{name}: skipped, VPNT_TEST_OPENVPN is not set");
            return None;
        };
        let directory = env::temp_dir().join(format!("vpnt-ovpn-it-{name}-{}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let fixture = Self {
            directory,
            openvpn: PathBuf::from(openvpn),
        };
        fixture.openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-days",
            "1",
            "-subj",
            "/CN=vpnt-test-ca",
        ]);
        for (peer, usage) in [("server", "serverAuth"), ("client", "clientAuth")] {
            let usages =
                format!("extendedKeyUsage={usage}\nkeyUsage=digitalSignature,keyEncipherment\n");
            fs::write(fixture.path(&format!("{peer}.ext")), usages).unwrap();
            let (key, csr, crt) = (
                format!("{peer}.key"),
                format!("{peer}.csr"),
                format!("{peer}.crt"),
            );
            let subject = format!("/CN=vpnt-test-{peer}");
            fixture.openssl(&[
                "req", "-newkey", "rsa:2048", "-nodes", "-keyout", &key, "-out", &csr, "-subj",
                &subject,
            ]);
            let extensions = format!("{peer}.ext");
            fixture.openssl(&[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                &crt,
                "-days",
                "1",
                "-extfile",
                &extensions,
            ]);
        }
        fixture.openssl(&[
            "x509",
            "-in",
            "client.crt",
            "-outform",
            "DER",
            "-out",
            "client.der",
        ]);
        Some(fixture)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn openssl(&self, args: &[&str]) {
        let output = openssl()
            .args(args)
            .current_dir(&self.directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .output()
            .expect("VPNT_TEST_OPENVPN is set, so the openssl command is required");
        assert!(
            output.status.success(),
            "openssl {args:?} ended with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// A default server: it offers TLS 1.3 and RSA-PSS, like the real ones.
    pub fn server(&self, ports: (u16, u16)) -> Server {
        self.server_with_address(ports, Ipv4Addr::new(10, 81, 0, 2))
    }

    pub fn server_with_address(&self, ports: (u16, u16), address: Ipv4Addr) -> Server {
        let mut command = Command::new(&self.openvpn);
        command
            .current_dir(&self.directory)
            .args([
                "--tls-server",
                "--dev",
                "null",
                "--dh",
                "none",
                "--proto",
                "udp4",
            ])
            .args([
                "--local",
                "127.0.0.1",
                "--ca",
                "ca.crt",
                "--cert",
                "server.crt",
            ])
            .args(["--key", "server.key", "--verb", "1"])
            .args([
                "--lport",
                &ports.0.to_string(),
                "--remote",
                "127.0.0.1",
                &ports.1.to_string(),
            ])
            .args([
                "--push",
                "topology subnet",
                "--push",
                &format!("ifconfig {address} 255.255.255.0"),
                "--push",
                "route-gateway 10.81.0.1",
                "--push",
                "route 10.82.0.0 255.255.0.0",
                "--push",
                "route 10.83.0.0 255.255.0.0",
                "--push",
                "dhcp-option DNS 10.81.0.1",
                "--push",
                "dhcp-option DNS 10.81.0.3",
                "--push",
                "dhcp-option DOMAIN example.test",
                "--ifconfig-noexec",
                "--route-noexec",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Server(command.spawn().unwrap())
    }

    /// Fixture-only directives that the production profile inspector does
    /// not allow. On macOS they go to trusted launch arguments instead.
    #[cfg(not(target_os = "linux"))]
    fn fixture_only(line: &str) -> bool {
        line.starts_with("log ") || line.starts_with("tls-version-max ")
    }

    /// `extra` lines are appended to the profile on Linux. On macOS the
    /// profile is production-shaped (inline CA, allowlisted directives only)
    /// and the fixture-only options move to `client_extra`.
    pub fn client_config(&self, ports: (u16, u16), extra: &str) -> PathBuf {
        let path = self.path("client.ovpn");
        #[cfg(target_os = "linux")]
        let config = format!(
            "tls-client\npull\ndev null\nproto udp4\nlocal 127.0.0.1\nlport {}\nremote 127.0.0.1 {}\n\
             ca {}\nremote-cert-tls server\nverb 1\n{extra}",
            ports.1,
            ports.0,
            self.path("ca.crt").display()
        );
        #[cfg(not(target_os = "linux"))]
        let config = {
            let profile_extra: String = extra
                .lines()
                .filter(|line| !Self::fixture_only(line))
                .map(|line| format!("{line}\n"))
                .collect();
            format!(
                "tls-client\npull\ndev null\nproto udp4\nremote 127.0.0.1 {}\n\
                 <ca>\n{}</ca>\nremote-cert-tls server\nverb 1\n{profile_extra}",
                ports.0,
                fs::read_to_string(self.path("ca.crt")).unwrap()
            )
        };
        fs::write(&path, config).unwrap();
        path
    }

    /// Trusted argv for options that belong to this fixture, not to an
    /// imported profile. Linux keeps them in the profile as before.
    pub fn client_extra(&self, ports: (u16, u16), extra: &str) -> Vec<OsString> {
        #[cfg(target_os = "linux")]
        {
            let _ = (ports, extra);
            Vec::new()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut args: Vec<OsString> = vec![
                "--local".into(),
                "127.0.0.1".into(),
                "--lport".into(),
                ports.1.to_string().into(),
            ];
            for line in extra.lines().filter(|line| Self::fixture_only(line)) {
                let (name, value) = line.split_once(' ').unwrap();
                args.push(format!("--{name}").into());
                args.push(value.into());
            }
            args
        }
    }

    pub fn signer(&self) -> KeyFileSigner {
        KeyFileSigner {
            key: self.path("client.key"),
            certificate: fs::read(self.path("client.der")).unwrap(),
            paddings: Arc::default(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone)]
pub struct KeyFileSigner {
    key: PathBuf,
    certificate: Vec<u8>,
    pub paddings: Arc<Mutex<Vec<Padding>>>,
}

impl Signer for KeyFileSigner {
    fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
        Ok(self.certificate.clone())
    }

    fn sign(&mut self, padding: Padding, data: &[u8]) -> Result<Vec<u8>, SignError> {
        self.paddings.lock().unwrap().push(padding);
        let options: &[&str] = match padding {
            Padding::Pkcs1 => &["-pkeyopt", "rsa_padding_mode:pkcs1"],
            Padding::Pss(Hash::Sha256) => &[
                "-pkeyopt",
                "rsa_padding_mode:pss",
                "-pkeyopt",
                "rsa_pss_saltlen:digest",
                "-pkeyopt",
                "digest:sha256",
            ],
            Padding::Pss(_) => return Err(SignError::Unsupported),
        };
        let mut child = openssl()
            .args(["pkeyutl", "-sign", "-inkey"])
            .arg(&self.key)
            .args(options)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| SignError::Unavailable)?;
        let mut stdin = child.stdin.take().ok_or(SignError::Unavailable)?;
        stdin.write_all(data).map_err(|_| SignError::Unavailable)?;
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|_| SignError::Unavailable)?;
        output
            .status
            .success()
            .then_some(output.stdout)
            .ok_or(SignError::Unavailable)
    }
}

fn openssl() -> Command {
    Command::new(env::var_os("VPNT_TEST_OPENSSL").unwrap_or_else(|| OsString::from("openssl")))
}

pub fn free_udp_ports() -> (u16, u16) {
    let first = UdpSocket::bind("127.0.0.1:0").unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").unwrap();
    (
        first.local_addr().unwrap().port(),
        second.local_addr().unwrap().port(),
    )
}
