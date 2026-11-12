"""Unprivileged source builds needed by the macOS private VPN runtime."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

FORTI_VERSION = "1.24.1"
FORTI_URL = "https://github.com/adrienverge/openfortivpn/archive/refs/tags/v1.24.1.tar.gz"
FORTI_SHA = "c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465"
TOOLS = [
    ("autoconf", "2.73", "gz", "259ddfa3bddc799cfb81489cc0f17dfdf1bd6d1505dda53c0f45ff60d6a4f9a7"),
    ("automake", "1.20", "xz", "f6f34dad4cbe395715762b0710f7c511e39bd5cf777e6b95818ccbecf7714248"),
]


def verified_source(cache, name, version, suffix, url, expected, fresh=False):
    archive = cache / f"{name}-{version}.tar.{suffix}"
    if not archive.exists():
        with urlopen(url, timeout=30) as response:
            data = response.read(80_000_001)
        if len(data) > 80_000_000 or hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"{name} source hash mismatch")
        archive.write_bytes(data)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise RuntimeError(f"{name} source hash mismatch")
    source = cache / f"{name}-{version}"
    if fresh or not source.exists():
        with tempfile.TemporaryDirectory(prefix=f"vpnt-{name}-", dir=cache) as temporary:
            with tarfile.open(archive) as package:
                package.extractall(temporary, filter="data")
            if source.exists():
                if source.is_symlink() or not source.is_dir():
                    raise RuntimeError("Unrecognized source cache")
                shutil.rmtree(source)
            shutil.move(str(Path(temporary) / source.name), source)
    return source


def build_fortinet(root, cache, openssl, pkgconf, jobs, run, runtime_prefix):
    prefix = root / "target/build-tools"
    m4 = Path(subprocess.check_output(["brew", "--prefix", "m4"], text=True).strip()) / "bin/m4"
    if not m4.is_file():
        raise RuntimeError("A current GNU m4 is required for the local build tools")
    env = {key: value for key, value in os.environ.items() if not key.startswith(("DYLD_", "LD_"))}
    env.update(PATH=f"{prefix}/bin:{m4.parent}:{env.get('PATH', '')}", M4=str(m4), PERL="/usr/bin/perl")
    for name, version, suffix, expected in TOOLS:
        executable = prefix / "bin" / name
        if executable.is_file() and subprocess.check_output([executable, "--version"], text=True).splitlines()[0].endswith(version):
            continue
        source = verified_source(cache, name, version, suffix, f"https://ftp.gnu.org/gnu/{name}/{name}-{version}.tar.{suffix}", expected)
        build = root / "target/runtime-build" / name
        build.mkdir(parents=True, exist_ok=True)
        log = build.with_suffix(".log")
        run([source / "configure", f"--prefix={prefix}"], build, env, log)
        run(["/usr/bin/make", f"-j{jobs}"], build, env, log)
        run(["/usr/bin/make", "install"], build, env, log)
    source = verified_source(cache, "openfortivpn", FORTI_VERSION, "gz", FORTI_URL, FORTI_SHA, fresh=True)
    build = root / "target/runtime-build/openfortivpn"
    build.mkdir(parents=True, exist_ok=True)
    log = build.with_suffix(".log")
    env.update(PKG_CONFIG=str(pkgconf), PKG_CONFIG_PATH=str(openssl / "lib/pkgconfig"), ACLOCAL_PATH=str(prefix / "share/aclocal"), CPPFLAGS=f"-I{openssl}/include", LDFLAGS=f"-L{openssl}/lib -Wl,-headerpad_max_install_names")
    for patch in ["openfortivpn-no-routes.patch", "openfortivpn-bound-transport.patch", "openfortivpn-ppp-supervisor.patch"]:
        run(["/usr/bin/patch", "-t", "-p1", "-i", root / "scripts/macos/patches" / patch], source, env, log)
    run(["/bin/sh", source / "autogen.sh"], source, env, log)
    run([source / "configure", f"--prefix={runtime_prefix}", "--with-pppd=/usr/sbin/pppd", "--with-netstat=/usr/sbin/netstat", "--with-resolvconf=DISABLED", "--with-systemdsystemunitdir=no", "--enable-legacy-pppd"], build, env, log)
    run(["/usr/bin/make", f"-j{jobs}"], build, env, log)
    # Exercise the actual patched up callback with all route/DNS writes
    # intercepted. It can run without privilege and never creates an interface.
    checker = build / "check-routes"
    run(["/usr/bin/cc", "-ffunction-sections", "-Wl,-dead_strip", "-DHAVE_USR_SBIN_PPPD=1", "-DHAVE_UTIL_H=1", "-DHAVE_STRUCT_TERMIOS=1", '-DPPP_PATH="/usr/sbin/pppd"', f"-I{source}/src", f"-I{openssl}/include", f"-L{openssl}/lib", "-lssl", "-lcrypto", root / "tests/fixtures/fortinet_routes.c", "-o", checker], build, env, log)
    run([checker], build, env, log)
    checker = build / "check-transport"
    run(["/usr/bin/cc", "-ffunction-sections", "-Wl,-dead_strip", "-DHAVE_USR_SBIN_PPPD=1", "-DHAVE_UTIL_H=1", "-DHAVE_STRUCT_TERMIOS=1", '-DPPP_PATH="/usr/sbin/pppd"', f"-I{source}/src", f"-I{openssl}/include", f"-L{openssl}/lib", "-lssl", "-lcrypto", root / "tests/fixtures/fortinet_transport.c", "-o", checker], build, env, log)
    run([checker], build, env, log)
    return build / "openfortivpn", source
