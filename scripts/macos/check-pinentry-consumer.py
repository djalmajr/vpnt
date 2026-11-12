#!/usr/bin/env python3
"""Exercise our pinentry codec through openfortivpn's original C password reader.

Uses only generated fictional values, no VPN process/network/privileges. The C
password reader comes from the pinned archive and is not linked into the app.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE_SHA = "c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465"
ARCHIVE_URL = "https://github.com/adrienverge/openfortivpn/archive/refs/tags/v1.24.1.tar.gz"


def main():
    if os.geteuid() == 0:
        raise RuntimeError("Run these fictional fixtures as an unprivileged user")
    cache = ROOT / "target/runtime-sources"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / "openfortivpn-1.24.1.tar.gz"
    if not archive.exists():
        with urlopen(ARCHIVE_URL, timeout=30) as response:
            data = response.read(20_000_001)
        if len(data) > 20_000_000 or hashlib.sha256(data).hexdigest() != ARCHIVE_SHA:
            raise RuntimeError("openfortivpn source hash mismatch")
        archive.write_bytes(data)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA:
        raise RuntimeError("openfortivpn source hash mismatch")
    subprocess.run(["cargo", "build", "--locked", "--no-default-features", "--offline", "--lib", "--bin", "vpnt-pinentry"], cwd=ROOT, check=True)
    fixtures = ROOT / "output/fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pinentry-consumer-", dir=fixtures) as temporary:
        directory = Path(temporary)
        with tarfile.open(archive) as package:
            for name in ["userinput.c", "userinput.h", "log.h"]:
                data = package.extractfile(f"openfortivpn-1.24.1/src/{name}").read()
                (directory / name).write_bytes(data)
        source = ROOT / "tests/fixtures/pinentry"
        subprocess.run(["rustfmt", "--edition", "2024", "--check", source / "adapter.rs", source / "owner.rs"], check=True)
        adapter=directory / "adapter"
        wrong_peer=directory / "wrong-peer"
        consumer=directory / "consumer"
        owner=directory / "owner"
        library=["--edition=2024","--extern",f"vpnt={ROOT}/target/debug/libvpnt.rlib","-L",f"dependency={ROOT}/target/debug/deps"]
        for executable,flags in [(adapter,[]),(wrong_peer,["--cfg","wrong_peer"])]:
            subprocess.run(["rustc",source / "adapter.rs",*library,*flags,"-o",executable],check=True)
        subprocess.run(["/usr/bin/cc","-DHAVE_VDPRINTF",source / "consumer.c",directory / "userinput.c","-I",directory,"-o",consumer],check=True)
        subprocess.run(["rustc",source / "owner.rs",*library,"-o",owner],check=True)
        result=subprocess.run([owner,consumer,adapter,wrong_peer,ROOT / "target/debug/vpnt-pinentry"],capture_output=True,timeout=30)
        if result.returncode:
            raise RuntimeError(f"Native pinentry consumer failed (exit {result.returncode}): {result.stderr.decode(errors='replace')}")
    receipt = {"upstream": "openfortivpn 1.24.1 userinput.c", "archiveSha256": ARCHIVE_SHA, "casesPassed": 12, "vpnStarted": False, "credentials": "fictional", "transport":"inherited socket per owned child"}
    (fixtures / "pinentry-consumer.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Native openfortivpn password reader: 12 inherited-channel scenarios passed; no VPN started")


if __name__ == "__main__":
    main()
