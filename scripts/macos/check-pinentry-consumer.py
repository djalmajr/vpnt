#!/usr/bin/env python3
"""Exercise our pinentry codec through openfortivpn's original C password reader.

Uses only generated fictional values, no VPN process/network/privileges. All C
sources come from the pinned upstream archive; nothing is linked into the app.
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
    subprocess.run(["cargo", "build", "--locked", "--no-default-features", "--offline", "--lib"], cwd=ROOT, check=True)
    fixtures = ROOT / "output/fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pinentry-consumer-", dir=fixtures) as temporary:
        directory = Path(temporary)
        with tarfile.open(archive) as package:
            for name in ["userinput.c", "userinput.h", "log.h"]:
                data = package.extractfile(f"openfortivpn-1.24.1/src/{name}").read()
                (directory / name).write_bytes(data)
        (directory / "adapter.rs").write_text('''
use std::io::{self, BufReader};
use vpnt::{helper::pinentry, secrets::Secret};
fn main() {
    let result=pinentry::serve(&mut BufReader::new(io::stdin().lock()),&mut io::stdout().lock(),|| {
        Ok(Secret::from(match std::env::var("VPNT_FIXTURE_CASE").unwrap().as_str() {
            "0"=>" %fixture+é ".into(), "1"=>"x".repeat(256), "2"=>"é".repeat(128), _=>panic!("fixture case")
        }))
    });
    if result.is_err() {std::process::exit(2);}
}
''')
        (directory / "consumer.c").write_text(r'''
#include "userinput.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
enum log_verbosity loglevel = OFV_LOG_MUTE;
void do_log(int verbosity, const char *format, ...) { (void)verbosity; (void)format; }
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char password[257] = {0}, expected[257] = {0};
    int fixture = atoi(getenv("VPNT_FIXTURE_CASE"));
    if (fixture == 0) strcpy(expected, " %fixture+\xc3\xa9 ");
    else if (fixture == 1) memset(expected, 'x', 256);
    else if (fixture == 2) for (int i=0; i<256; i+=2) { expected[i]=(char)0xc3; expected[i+1]=(char)0xa9; }
    else return 2;
    read_password(argv[1], "fictional-hint", "Password:", password, 256);
    int result = strcmp(password, expected) == 0 ? 0 : 1;
    volatile char *p = password; for (int i=0; i<257; i++) p[i]=0;
    return result;
}
'''.replace(r"\\x", r"\x"))
        adapter = directory / "adapter"
        consumer = directory / "consumer"
        subprocess.run(["rustc", directory / "adapter.rs", "--edition=2024", "--extern", f"vpnt={ROOT}/target/debug/libvpnt.rlib", "-L", f"dependency={ROOT}/target/debug/deps", "-o", adapter], check=True)
        subprocess.run(["/usr/bin/cc", "-DHAVE_VDPRINTF", directory / "consumer.c", directory / "userinput.c", "-o", consumer], check=True)
        for case in range(3):
            environment = os.environ.copy()
            environment["VPNT_FIXTURE_CASE"] = str(case)
            result = subprocess.run([consumer, adapter], env=environment, capture_output=True, timeout=10)
            if result.returncode:
                raise RuntimeError(f"Native pinentry consumer fixture {case} failed (exit {result.returncode})")
    receipt = {"upstream": "openfortivpn 1.24.1 userinput.c", "archiveSha256": ARCHIVE_SHA, "casesPassed": 3, "vpnStarted": False, "credentials": "fictional"}
    (fixtures / "pinentry-consumer.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Native openfortivpn password reader: 3 fictional pinentry cases passed; no VPN started")


if __name__ == "__main__":
    main()
