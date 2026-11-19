#!/usr/bin/env python3
"""Check the staged OpenVPN management boundary without creating a tunnel."""
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "target/vpnt-runtime"
BINARY = RUNTIME / "bin/openvpn"


def main():
    if os.geteuid() == 0:
        raise RuntimeError("OpenVPN oracle must run without root")
    env = {key: value for key, value in os.environ.items() if not key.startswith(("DYLD_", "LD_"))}
    env.update(DYLD_LIBRARY_PATH=str(RUNTIME / "lib"), OPENSSL_CONF="/dev/null", OPENSSL_MODULES=str(RUNTIME / "lib/ossl-modules"))
    version = subprocess.run([str(BINARY), "--version"], env=env, capture_output=True, text=True, timeout=10, check=True).stdout
    lines = version.splitlines()
    if not lines or not lines[0].startswith("OpenVPN 2.7.9 "):
        raise RuntimeError("unexpected OpenVPN version")
    defines = next((line for line in lines if line.startswith("Compile time defines:")), "")
    for feature in ("enable_management=yes", "enable_plugins=no", "enable_pkcs11=no", "enable_dco=no"):
        if feature not in defines.split():
            raise RuntimeError(f"OpenVPN missing required compile setting: {feature}")
    with tempfile.TemporaryDirectory(prefix="vpnt-ovpn-oracle-") as temporary:
        root = Path(temporary)
        config = root / "fixture.conf"
        config.write_text("client\nremote vpn.example.test 1194\n")
        path = root / "management"
        with socket.socket(socket.AF_UNIX) as listener:
            listener.settimeout(10)
            listener.bind(str(path))
            listener.listen(1)
            arguments = [str(BINARY), "--config", str(config), "--dev", "null", "--dev-type", "tun", "--disable-dco", "--dns-updown", "disable", "--script-security", "0", "--management", str(path), "unix", "--management-client", "--management-hold", "--management-up-down", "--management-external-cert", "vpnt", "--management-external-key", "pkcs1", "--tls-version-max", "1.2", "--ifconfig-noexec", "--route-noexec", "--remote-cert-tls", "server", "--peer-fingerprint", ":".join(["AA"] * 32)]
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env)
            try:
                deadline = time.monotonic() + 10
                while not select.select([listener], [], [], 0.1)[0]:
                    if process.poll() is not None:
                        _, error = process.communicate()
                        raise RuntimeError(f"OpenVPN exited before management: {error[-1000:]}")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("OpenVPN did not connect to management")
                with listener.accept()[0] as connection:
                    connection.settimeout(10)
                    stream = connection.makefile("rb")
                    try:
                        def read_until(prefix):
                            for _ in range(128):
                                line = stream.readline(8193)
                                if not line or len(line) > 8192 or not line.endswith(b"\n"):
                                    break
                                if line.startswith(prefix):
                                    return True
                            return False

                        if not read_until(b">HOLD:") or process.poll() is not None:
                            raise RuntimeError("OpenVPN did not reach management hold while alive")
                        connection.sendall(b"signal SIGTERM\n")
                        if not read_until(b"SUCCESS: signal SIGTERM thrown"):
                            raise RuntimeError("OpenVPN did not acknowledge SIGTERM")
                    finally:
                        stream.close()
                _, error = process.communicate(timeout=10)
                if process.returncode:
                    raise RuntimeError(f"OpenVPN did not exit cleanly: {error[-1000:]}")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
    print("OpenVPN 2.7.9: required features and management hold verified")


if __name__ == "__main__":
    main()
