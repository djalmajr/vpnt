#!/usr/bin/env python3
"""Render assets/macos/AppIcon.svg into the committed AppIcon.icns.

Run only after editing the SVG. Requires rsvg-convert (librsvg) and the
system iconutil; the app packager reads the committed .icns and needs neither.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assets/macos/AppIcon.svg'
OUTPUT = ROOT / 'assets/macos/AppIcon.icns'
SIZES = [16, 32, 128, 256, 512]


def main():
    renderer = shutil.which('rsvg-convert')
    if renderer is None:
        raise SystemExit('rsvg-convert not found; install librsvg')
    with tempfile.TemporaryDirectory(prefix='vpnt-icon-') as temporary:
        iconset = Path(temporary) / 'AppIcon.iconset'
        iconset.mkdir()
        for size in SIZES:
            for scale in [1, 2]:
                suffix = '' if scale == 1 else '@2x'
                pixels = size * scale
                subprocess.run([renderer, '-w', str(pixels), '-h', str(pixels), str(SOURCE),
                                '-o', str(iconset / f'icon_{size}x{size}{suffix}.png')], check=True)
        subprocess.run(['/usr/bin/iconutil', '-c', 'icns', str(iconset), '-o', str(OUTPUT)], check=True)
    print(OUTPUT)


if __name__ == '__main__':
    main()
