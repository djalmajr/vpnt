#!/usr/bin/env python3
"""Prepare a private VPN runtime in target/, without installing or connecting."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import tomllib
from urllib.request import urlopen
from runtime_sources import build_fortinet, FORTI_VERSION, FORTI_URL, FORTI_SHA

ROOT = Path(__file__).resolve().parents[2]
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
PREFIX = Path("/Library/PrivilegedHelperTools/dev.vpnt.runtime") / VERSION
SWAN_VERSION = "6.1.0"
SWAN_URL = f"https://download.strongswan.org/strongswan-{SWAN_VERSION}.tar.bz2"
SWAN_SHA = "fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4"
PKGCONF_VERSION = "3.0.10"
PKGCONF_SHA = "9371b2f6372da574d4c6dc96fe9b1463037bcf6afcb6671c1555afde7b17e2de"
MACH_MAGICS = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
PID_PATCH = ROOT / "scripts/macos/patches/charon-private-pid.patch"
FORTI_PATCH = ROOT / "scripts/macos/patches/openfortivpn-no-routes.patch"


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def capture(args):
    return subprocess.check_output([str(arg) for arg in args], text=True).strip()


def run(args, cwd, env, log):
    print("Running", Path(str(args[0])).name, flush=True)
    with log.open("ab") as output:
        result = subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"Build failed; see {log.relative_to(ROOT)}")


def is_macho(path):
    if not path.is_file():
        return False
    with path.open("rb") as handle:
        return handle.read(4) in MACH_MAGICS


def local_pkgconf(cache, jobs):
    prefix = ROOT / "target/build-tools"
    executable = prefix / "bin/pkgconf"
    if executable.is_file() and capture([executable, "--version"]) == PKGCONF_VERSION:
        return executable
    archive = cache / f"pkgconf-{PKGCONF_VERSION}.tar.xz"
    if not archive.exists():
        with urlopen(f"https://distfiles.ariadne.space/pkgconf/pkgconf-{PKGCONF_VERSION}.tar.xz", timeout=30) as response:
            data = response.read(20_000_001)
        if len(data) > 20_000_000 or hashlib.sha256(data).hexdigest() != PKGCONF_SHA:
            raise RuntimeError("pkgconf source digest mismatch")
        archive.write_bytes(data)
    if digest(archive) != PKGCONF_SHA:
        raise RuntimeError("pkgconf source digest mismatch")
    source = cache / f"pkgconf-{PKGCONF_VERSION}"
    if not source.exists():
        with tarfile.open(archive) as package:
            package.extractall(cache, filter="data")
    build = ROOT / "target/runtime-build/pkgconf"
    build.mkdir(parents=True, exist_ok=True)
    log = ROOT / "target/runtime-build/pkgconf.log"
    run([source / "configure", f"--prefix={prefix}", "--disable-shared", "--enable-static"], build, os.environ.copy(), log)
    run(["/usr/bin/make", f"-j{jobs}"], build, os.environ.copy(), log)
    run(["/usr/bin/make", "install"], build, os.environ.copy(), log)
    return executable


def dependencies(path):
    lines = capture(["/usr/bin/otool", "-L", path]).splitlines()[1:]
    result = [line.strip().split(" (compatibility version", 1)[0] for line in lines if line.startswith("\t")]
    if path.suffix == ".dylib":
        own_id = capture(["/usr/bin/otool", "-D", path]).splitlines()[1:]
        result = [name for name in result if name not in own_id]
    return result


def remove_rpaths(path):
    lines = capture(["/usr/bin/otool", "-l", path]).splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH":
            for detail in lines[index + 1:index + 4]:
                if detail.strip().startswith("path "):
                    value = detail.strip()[5:].split(" (offset ", 1)[0]
                    subprocess.run(["/usr/bin/install_name_tool", "-delete_rpath", value, str(path)], check=True, capture_output=True)
                    break


def minimum_macos(path):
    command = ""
    versions = []
    for line in capture(["/usr/bin/otool", "-l", path]).splitlines():
        line = line.strip()
        if line.startswith("cmd "):
            command = line[4:]
        if (command == "LC_BUILD_VERSION" and line.startswith("minos ")) or (command == "LC_VERSION_MIN_MACOSX" and line.startswith("version ")):
            versions.append(tuple(int(part) for part in line.split()[1].split(".")))
    if not versions:
        raise RuntimeError(f"Missing macOS deployment metadata: {path.name}")
    return max(versions)


def private_libraries(payload):
    """Relocate every non-system dylib to the final root-owned runtime prefix."""
    queue = [path for path in payload.rglob("*") if is_macho(path)]
    visited = set()
    original_hashes = {}
    while queue:
        path = queue.pop(0)
        if path in visited:
            continue
        visited.add(path)
        for dependency in dependencies(path):
            if ".." in Path(dependency).parts:
                raise RuntimeError("Dependency install name contains traversal")
            if dependency.startswith(("/usr/lib/", "/System/Library/")):
                continue
            if dependency.startswith(str(PREFIX) + "/"):
                target = payload / Path(dependency).relative_to(PREFIX)
                if not target.is_file():
                    raise RuntimeError(f"Missing private dependency: {dependency}")
                continue
            if dependency.startswith("@"):
                raise RuntimeError(f"Unresolved relative install name: {dependency}")
            source = Path(dependency).resolve(strict=True)
            target = payload / "lib" / source.name
            target.parent.mkdir(parents=True, exist_ok=True)
            source_digest = digest(source)
            if target.exists() and original_hashes.get(target, digest(target)) != source_digest:
                raise RuntimeError(f"Dependency filename collision: {source.name}")
            if not target.exists():
                shutil.copy2(source, target)
                original_hashes[target] = source_digest
                queue.append(target)
            destination = str(PREFIX / target.relative_to(payload))
            subprocess.run(["/usr/bin/install_name_tool", "-change", dependency, destination, str(path)], check=True, capture_output=True)
        if path.suffix == ".dylib":
            subprocess.run(["/usr/bin/install_name_tool", "-id", str(PREFIX / path.relative_to(payload)), str(path)], check=True, capture_output=True)
    for path in visited:
        # All dependency install names are now absolute, so no mutable fallback
        # search path is needed by these C executables/libraries.
        remove_rpaths(path)
        # The development package is not hardened; signatures must be refreshed
        # after rewriting Mach-O load commands on Apple Silicon.
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(path)], check=True, capture_output=True)
        path.chmod(0o555)
        for dependency in dependencies(path):
            if not dependency.startswith(("/usr/lib/", "/System/Library/", str(PREFIX) + "/")):
                raise RuntimeError("Runtime still references a mutable library prefix")


def verify_runtime(root):
    if root.is_symlink():
        raise RuntimeError("Runtime directory must not be a symlink")
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest["format"] != 1 or manifest["appVersion"] != VERSION or manifest["prefix"] != str(PREFIX):
        raise RuntimeError("Runtime manifest does not match this app")
    if manifest["strongswan"]["patches"] != {PID_PATCH.name: digest(PID_PATCH)}:
        raise RuntimeError("Runtime does not include the expected private PID patch")
    if manifest["openfortivpn"]["patches"] != {FORTI_PATCH.name: digest(FORTI_PATCH)}:
        raise RuntimeError("Runtime does not include the expected route isolation patch")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise RuntimeError("Runtime may not contain symlinks")
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
    if actual != set(manifest["files"]) | {"manifest.json"}:
        raise RuntimeError("Runtime contains missing or unlisted files")
    for name, expected in manifest["files"].items():
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or str(path) != name:
            raise RuntimeError("Non-canonical manifest path")
        if digest(root / name) != expected:
            raise RuntimeError(f"Runtime hash mismatch: {name}")
    machos = [path for path in root.rglob("*") if is_macho(path)]
    minimum = ".".join(map(str, max(minimum_macos(path) for path in machos)))
    if manifest["minimumMacOS"] != minimum:
        raise RuntimeError("Incorrect minimum macOS metadata")
    for path in machos:
        for dependency in dependencies(path):
            if ".." in Path(dependency).parts or not dependency.startswith(("/usr/lib/", "/System/Library/", str(PREFIX) + "/")):
                raise RuntimeError("Runtime still has an external mutable dependency")
            if dependency.startswith(str(PREFIX) + "/") and str(Path(dependency).relative_to(PREFIX)) not in manifest["files"]:
                raise RuntimeError("Private dependency is not included in the manifest")
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(path)], check=True, capture_output=True)
    if str(PREFIX / "run/charon.pid").encode() not in (root / "bin/charon").read_bytes():
        raise RuntimeError("charon does not use its private PID directory")
    if b"charon.vpnt_pid_file" not in (root / "bin/charon").read_bytes():
        raise RuntimeError("charon does not support a private PID per profile")
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(root / "certs/ca-bundle.pem")
    # Test actual loading in the staging directory. These overrides are for this
    # unprivileged --version check; installed clients use their fixed private paths.
    temporary_parent = ROOT / "target/runtime-build"
    temporary_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vpnt-version-", dir=temporary_parent) as temporary:
        configuration = Path(temporary) / "strongswan.conf"
        configuration.write_text("charon {\n  load_modular = no\n}\n")
        configuration.chmod(0o600)
        env = {key: value for key, value in os.environ.items() if not key.startswith(("DYLD_", "LD_"))}
        env.update(DYLD_LIBRARY_PATH=str(root / "lib"), STRONGSWAN_CONF=str(configuration), OPENSSL_CONF="/dev/null", OPENSSL_MODULES=str(root / "lib/ossl-modules"))
        for program, expected in [("charon", f"strongSwan {SWAN_VERSION}"), ("openfortivpn", FORTI_VERSION)]:
            arguments = [str(root / "bin" / program)]
            if program == "openfortivpn":
                # Parse the driver's fixed options in the real client, then
                # exit via --version before config, credentials or networking.
                arguments += ["--config=/dev/null", "--no-routes", "--no-dns", "--pppd-no-peerdns", "--pppd-accept-remote=0", "--persistent=0", "--username=fixture", "--pinentry=/Library/PrivilegedHelperTools/dev.vpnt.pinentry", f"--ca-file={PREFIX}/certs/ca-bundle.pem", "--trusted-cert=" + "a1" * 32]
            result = subprocess.run(arguments + ["--version"], env=env, cwd=temporary, capture_output=True, text=True, timeout=10)
            if result.returncode or result.stdout.strip() != expected:
                raise RuntimeError(f"Private {program} startup/version check failed")
    print(f"Verified {len(manifest['files'])} runtime files; minimum macOS {minimum}; versions OK", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error("jobs must be between 1 and 32")
    if os.uname().sysname != "Darwin":
        parser.error("This runtime is built on macOS.")
    if args.verify_only:
        verify_runtime(ROOT / "target/vpnt-runtime")
        return
    openssl = Path(capture(["brew", "--prefix", "openssl@4"]))
    cache = ROOT / "target/runtime-sources"
    cache.mkdir(parents=True, exist_ok=True)
    pkgconf = local_pkgconf(cache, args.jobs)
    forti, forti_source = build_fortinet(ROOT, cache, openssl, pkgconf, args.jobs, run, PREFIX)
    archive = cache / f"strongswan-{SWAN_VERSION}.tar.bz2"
    if not archive.exists():
        print("Downloading verified strongSwan source", flush=True)
        with urlopen(SWAN_URL, timeout=30) as response:
            data = response.read(80_000_001)
        if len(data) > 80_000_000 or hashlib.sha256(data).hexdigest() != SWAN_SHA:
            raise RuntimeError("strongSwan source digest mismatch")
        archive.write_bytes(data)
    if digest(archive) != SWAN_SHA:
        raise RuntimeError("strongSwan source digest mismatch")
    source = cache / f"strongswan-{SWAN_VERSION}"
    # Restore all sources from the verified archive on every build; an old
    # extracted cache must not silently supply changed source to the root runtime.
    with tempfile.TemporaryDirectory(prefix="vpnt-swan-", dir=cache) as temporary:
        with tarfile.open(archive) as package:
            package.extractall(temporary, filter="data")
        if source.exists():
            if source.is_symlink() or not (source / "src/charon/charon.c").is_file():
                raise RuntimeError("Refusing to replace unrecognized source directory")
            shutil.rmtree(source)
        shutil.move(str(Path(temporary) / source.name), source)
    build = ROOT / "target/runtime-build/strongswan"
    build.mkdir(parents=True, exist_ok=True)
    log = ROOT / "target/runtime-build/strongswan.log"
    run(["/usr/bin/patch", "-t", "-p1", "-i", PID_PATCH], source, os.environ.copy(), log)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("DYLD_", "LD_"))}
    env.update(CPPFLAGS=f"-I{openssl}/include", LDFLAGS=f"-L{openssl}/lib", PKG_CONFIG=str(pkgconf), PKG_CONFIG_PATH=str(openssl / "lib/pkgconfig"))
    configure = [
        source / "configure",
        f"--prefix={PREFIX}",
        f"--with-piddir={PREFIX}/run",
        "--disable-defaults",
        "--disable-shared",
        "--enable-static",
        "--enable-monolithic",
        "--enable-charon",
        "--enable-ikev2",
        "--enable-vici",
        "--enable-kernel-pfkey",
        "--enable-kernel-pfroute",
        "--enable-socket-default",
        "--enable-eap-identity",
        "--enable-eap-mschapv2",
        "--enable-openssl",
        "--enable-nonce",
        "--enable-kdf",
        "--enable-random",
        "--enable-aes",
        "--enable-des",
        "--enable-md4",
        "--enable-sha1",
        "--enable-sha2",
        "--enable-hmac",
    ]
    marker = build / ".vpnt-configure.json"
    signature = json.dumps([str(value) for value in configure] + [str(openssl)])
    if not marker.exists() or marker.read_text() != signature:
        run(configure, build, env, log)
        marker.write_text(signature)
    run(["/usr/bin/make", f"-j{args.jobs}"], build, env, log)
    staging_parent = ROOT / "target/runtime-build"
    with tempfile.TemporaryDirectory(prefix="vpnt-stage-", dir=staging_parent) as temporary:
        temporary = Path(temporary)
        run(["/usr/bin/make", "install", f"DESTDIR={temporary / 'install'}"], build, env, log)
        installed = temporary / "install" / str(PREFIX).lstrip("/")
        payload = temporary / "payload"
        (payload / "bin").mkdir(parents=True)
        shutil.copy2(installed / "libexec/ipsec/charon", payload / "bin/charon")
        shutil.copy2(forti, payload / "bin/openfortivpn")
        # Only public system roots, never the user's login/custom keychains or
        # a CA path under a user-writable package-manager prefix.
        certificates = payload / "certs/ca-bundle.pem"
        certificates.parent.mkdir()
        public_roots = subprocess.check_output([
            "/usr/bin/security", "find-certificate", "-a", "-p",
            "/System/Library/Keychains/SystemRootCertificates.keychain",
        ])
        if b"-----BEGIN CERTIFICATE-----" not in public_roots:
            raise RuntimeError("No public system roots exported; Security.framework access may be restricted")
        certificates.write_bytes(public_roots)
        certificates.chmod(0o444)
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(certificates)
        providers = openssl / "lib/ossl-modules"
        if providers.is_dir():
            for provider in providers.glob("*.dylib"):
                destination = payload / "lib/ossl-modules" / provider.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(provider, destination)
        private_libraries(payload)
        minimum = max(minimum_macos(path) for path in payload.rglob("*") if is_macho(path))
        licenses = payload / "licenses"
        licenses.mkdir()
        shutil.copy2(source / "COPYING", licenses / "strongswan.txt")
        shutil.copy2(forti_source / "LICENSE", licenses / "openfortivpn.txt")
        shutil.copy2(forti_source / "LICENSE.OpenSSL", licenses / "openfortivpn-openssl-exception.txt")
        openssl_license = openssl / "LICENSE.txt"
        if not openssl_license.is_file():
            raise RuntimeError("OpenSSL license missing")
        shutil.copy2(openssl_license, licenses / "openssl.txt")
        files = {str(path.relative_to(payload)): digest(path) for path in sorted(payload.rglob("*")) if path.is_file()}
        manifest = {
            "format": 1,
            "appVersion": VERSION,
            "prefix": str(PREFIX),
            "minimumMacOS": ".".join(map(str, minimum)),
            "strongswan": {
                "version": SWAN_VERSION,
                "source": SWAN_URL,
                "sha256": SWAN_SHA,
                "pidDirectory": str(PREFIX / "run"),
                "patches": {PID_PATCH.name: digest(PID_PATCH)},
            },
            "openfortivpn": {
                "version": FORTI_VERSION,
                "source": FORTI_URL,
                "sha256": FORTI_SHA,
                "patches": {FORTI_PATCH.name: digest(FORTI_PATCH)},
            },
            "files": files,
        }
        (payload / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        destination = ROOT / "target/vpnt-runtime"
        if destination.exists():
            old = destination / "manifest.json"
            if not old.is_file() or json.loads(old.read_text()).get("format") != 1:
                raise RuntimeError("Refusing to replace an unrecognized runtime directory")
            shutil.rmtree(destination)
        shutil.move(str(payload), destination)
    print(f"Prepared {destination.relative_to(ROOT)}; no installation performed", flush=True)
    verify_runtime(destination)


if __name__ == "__main__":
    main()
