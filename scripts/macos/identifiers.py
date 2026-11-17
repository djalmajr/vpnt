"""Build-time channel selection shared with Cargo; never inspect live state."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASES = dict(line.split('=', 1) for line in
             (ROOT / 'native/identifier-channels.conf').read_text().splitlines())
CHANNEL = os.environ.get('VPNT_CHANNEL', 'dev')
if CHANNEL not in BASES:
    raise ValueError('VPNT_CHANNEL must be dev or prd')
BASE = BASES[CHANNEL]


def identifier(suffix):
    return f'{BASE}.{suffix}'


def tool(suffix):
    return f'/Library/PrivilegedHelperTools/{identifier(suffix)}'


def require_binary_channel(binary):
    """Read only the dedicated Mach-O section, without executing the binary."""
    result = subprocess.run(['/usr/bin/otool', '-l', str(binary)],
                            check=True, capture_output=True, text=True)
    sections = []
    for section in result.stdout.split('Section\n')[1:]:
        fields = dict(line.strip().split(maxsplit=1) for line in section.split('Load command', 1)[0].splitlines()
                      if len(line.strip().split(maxsplit=1)) == 2)
        if fields.get('sectname') == '__vpnt_channel' and fields.get('segname') == '__TEXT':
            sections.append((int(fields['offset']), int(fields['size'], 16)))
    wanted = f'vpnt-channel:{CHANNEL}:{BASE}\0'.encode()
    if len(sections) != 1 or sections[0][1] != len(wanted):
        raise RuntimeError(f'Binary build channel does not match VPNT_CHANNEL={CHANNEL}: {binary}')
    with Path(binary).open('rb') as source:
        source.seek(sections[0][0])
        if source.read(len(wanted)) != wanted:
            raise RuntimeError(f'Binary build channel does not match VPNT_CHANNEL={CHANNEL}: {binary}')
