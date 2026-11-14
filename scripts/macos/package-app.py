#!/usr/bin/env python3
"""Package an already-built vpnt binary into a local, unsigned macOS app."""
import argparse
import os
from pathlib import Path
import plistlib
import shutil
import tempfile
import tomllib
from app_component import include as include_component

root = Path(__file__).resolve().parents[2]
version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, default=Path("target/debug/vpnt"))
parser.add_argument("--output", type=Path, default=Path("target/vpnt.app"))
parser.add_argument("--replace", action="store_true")
parser.add_argument("--component-payload", type=Path, help="Include the audited local component from this admitted payload")
args = parser.parse_args()
if not args.binary.is_file():
    parser.error("Build the binary first.")
if args.output.exists():
    info = args.output / "Contents/Info.plist"
    if args.output.is_symlink() or not args.replace or not info.is_file():
        parser.error("Output exists; use --replace only for a previous vpnt build.")
    with info.open("rb") as handle:
        if plistlib.load(handle).get("CFBundleIdentifier") != "dev.vpnt.app":
            parser.error("Refusing to replace a different application.")
args.output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="vpnt-package-", dir=args.output.parent) as temporary:
    bundle = Path(temporary) / "vpnt.app"
    executable = bundle / "Contents/MacOS/vpnt"
    executable.parent.mkdir(parents=True)
    shutil.copy2(args.binary, executable)
    os.chmod(executable, 0o755)
    resources = bundle / "Contents/Resources"
    resources.mkdir()
    shutil.copy2(root / "LICENSE", resources / "LICENSE")
    notices = root / "LICENSES"
    if notices.is_dir():
        shutil.copytree(notices, resources / "LICENSES")
    minimum = "13.0"
    if args.component_payload:
        minimum = include_component(args.component_payload.resolve(), resources, executable)
    with (bundle / "Contents/Info.plist").open("wb") as handle:
        plistlib.dump({"CFBundleIdentifier": "dev.vpnt.app", "CFBundleName": "VPN Tray", "CFBundleDisplayName": "VPN Tray", "CFBundleExecutable": "vpnt", "CFBundlePackageType": "APPL", "CFBundleShortVersionString": version, "CFBundleVersion": "1", "LSMinimumSystemVersion": minimum, "LSUIElement": True, "NSHighResolutionCapable": True}, handle)
    if args.output.exists():
        shutil.rmtree(args.output)
    shutil.move(str(bundle), str(args.output))
print(args.output)
