"""Unprivileged source builds needed by the macOS private VPN runtime."""
from identifiers import tool
import hashlib
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

FORTI_VERSION = "1.24.1"
FORTI_URL = "https://github.com/adrienverge/openfortivpn/archive/refs/tags/v1.24.1.tar.gz"
FORTI_SHA = "c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465"
OVPN_VERSION = "2.7.9"
OVPN_URL = "https://github.com/OpenVPN/openvpn/releases/download/v2.7.9/openvpn-2.7.9.tar.gz"
OVPN_SHA = "c42a6ed892ddfe2d6e3317a5040f19bec5827564affb2fe3f2b3904a94daacb1"
LZO_VERSION = "2.10"
LZO_URL = "https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz"
LZO_SHA = "c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072"
LZ4_VERSION = "1.11.1"
LZ4_URL = "https://github.com/lz4/lz4/archive/refs/tags/v1.11.1.tar.gz"
LZ4_SHA = "683fed08a844ad012196381e40badf80c0bbe4962959761416d41c9e67d77ec7"
TOOLS = [
    ("autoconf", "2.73", "gz", "259ddfa3bddc799cfb81489cc0f17dfdf1bd6d1505dda53c0f45ff60d6a4f9a7"),
    ("automake", "1.20", "xz", "f6f34dad4cbe395715762b0710f7c511e39bd5cf777e6b95818ccbecf7714248"),
]


def supervisor_header(path):
    path.write_text(f'#define VPNT_PPP_SUPERVISOR "{tool("pppd")}"\n')


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


def build_openvpn(root, cache, openssl, pkgconf, jobs, run, runtime_prefix):
    sources = [verified_source(cache, name, version, "gz", url, sha, fresh=True)
               for name, version, url, sha in [
                   ("openvpn", OVPN_VERSION, OVPN_URL, OVPN_SHA),
                   ("lzo", LZO_VERSION, LZO_URL, LZO_SHA),
                   ("lz4", LZ4_VERSION, LZ4_URL, LZ4_SHA),
               ]]
    source, lzo, lz4 = sources
    build_root = root / "target/runtime-build/openvpn-private"
    if build_root.exists():
        if build_root.is_symlink() or not (build_root / ".vpnt-openvpn-build").is_file():
            raise RuntimeError("Refusing unrecognized OpenVPN build directory")
        shutil.rmtree(build_root)
    build_root.mkdir(parents=True)
    (build_root / ".vpnt-openvpn-build").write_text("1\n")
    lzo_build = build_root / "lzo"
    lzo_build.mkdir()
    prefix = build_root / "deps"
    log = root / "target/runtime-build/openvpn-private.log"
    env = {key: value for key, value in os.environ.items() if not key.startswith(("DYLD_", "LD_"))}
    run([lzo / "configure", f"--prefix={prefix}", "--disable-shared", "--enable-static"], lzo_build, env, log)
    run(["/usr/bin/make", f"-j{jobs}"], lzo_build, env, log)
    run(["/usr/bin/make", "install"], lzo_build, env, log)
    run(["/usr/bin/make", f"-j{jobs}", "liblz4.a"], lz4 / "lib", env, log)
    build = build_root / "openvpn"
    build.mkdir()
    env.update(PKG_CONFIG=str(pkgconf), PKG_CONFIG_PATH=str(openssl / "lib/pkgconfig"),
               LZO_CFLAGS=f"-I{prefix}/include", LZO_LIBS=str(prefix / "lib/liblzo2.a"),
               LZ4_CFLAGS=f"-I{lz4}/lib", LZ4_LIBS=str(lz4 / "lib/liblz4.a"),
               LDFLAGS=f"-L{lz4}/lib -Wl,-headerpad_max_install_names")
    run([source / "configure", f"--prefix={runtime_prefix}", "--disable-plugins", "--disable-pkcs11", "--disable-dco"], build, env, log)
    run(["/usr/bin/make", f"-j{jobs}"], build, env, log)
    return build / "src/openvpn/openvpn", source, lzo, lz4


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
    channel_header = build / "vpnt-channel.h"
    supervisor_header(channel_header)
    env.update(PKG_CONFIG=str(pkgconf), PKG_CONFIG_PATH=str(openssl / "lib/pkgconfig"), ACLOCAL_PATH=str(prefix / "share/aclocal"), CPPFLAGS=f"-I{openssl}/include -include {shlex.quote(str(channel_header))}", LDFLAGS=f"-L{openssl}/lib -Wl,-headerpad_max_install_names")
    for patch in ["openfortivpn-no-routes.patch", "openfortivpn-bound-transport.patch", "openfortivpn-ppp-supervisor.patch", "openfortivpn-split-routes.patch", "openfortivpn-split-dns.patch"]:
        run(["/usr/bin/patch", "-t", "-p1", "-i", root / "scripts/macos/patches" / patch], source, env, log)
    run(["/bin/sh", source / "autogen.sh"], source, env, log)
    run([source / "configure", f"--prefix={runtime_prefix}", "--with-pppd=/usr/sbin/pppd", "--with-netstat=/usr/sbin/netstat", "--with-resolvconf=DISABLED", "--with-systemdsystemunitdir=no", "--enable-legacy-pppd"], build, env, log)
    run(["/usr/bin/make", f"-j{jobs}"], build, env, log)
    # Exercise the actual patched up callback with all route/DNS writes
    # intercepted. It can run without privilege and never creates an interface.
    checker = build / "check-routes"
    run(["/usr/bin/cc", "-ffunction-sections", "-Wl,-dead_strip", "-include", channel_header, "-DHAVE_USR_SBIN_PPPD=1", "-DHAVE_UTIL_H=1", "-DHAVE_STRUCT_TERMIOS=1", '-DPPP_PATH="/usr/sbin/pppd"', f"-I{source}/src", f"-I{openssl}/include", f"-L{openssl}/lib", "-lssl", "-lcrypto", root / "tests/fixtures/fortinet_routes.c", "-o", checker], build, env, log)
    run([checker], build, env, log)
    # Both values of HAVE_SO_BINDTODEVICE: current macOS SDKs declare the
    # option, so configure sets 1 and the Darwin path must still bind the source.
    for bindtodevice in ("0", "1"):
        checker = build / f"check-transport-{bindtodevice}"
        run(["/usr/bin/cc", "-ffunction-sections", "-Wl,-dead_strip", "-include", channel_header, f"-DHAVE_SO_BINDTODEVICE={bindtodevice}", "-DHAVE_USR_SBIN_PPPD=1", "-DHAVE_UTIL_H=1", "-DHAVE_STRUCT_TERMIOS=1", '-DPPP_PATH="/usr/sbin/pppd"', f"-I{source}/src", f"-I{openssl}/include", f"-L{openssl}/lib", "-lssl", "-lcrypto", root / "tests/fixtures/fortinet_transport.c", "-o", checker], build, env, log)
        run([checker], build, env, log)
    return build / "openfortivpn", source
