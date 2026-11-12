"""Closed development package contract. This module never installs anything."""
import hashlib
from pathlib import Path
import platform
import shlex
import stat
import subprocess
import xml.etree.ElementTree as ET

STAGING = '/Library/PrivilegedHelperTools/dev.vpnt.staging'
COMPONENT = 'Component.pkg'


def identifier(summary):
    return f"dev.vpnt.component.{summary['uid']}"


def inventory(payload, exact=False):
    result = {'.': (stat.S_IFDIR | ((payload.stat().st_mode & 0o7777) if exact else 0o700), None)}
    for path in sorted(payload.rglob('*')):
        meta = path.lstat()
        name = path.relative_to(payload).as_posix()
        if stat.S_ISDIR(meta.st_mode):
            result[name] = (stat.S_IFDIR | ((meta.st_mode & 0o7777) if exact else 0o755), None)
        elif stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1:
            mode = (meta.st_mode & 0o7777) if exact else (0o555 if meta.st_mode & 0o100 else 0o444)
            result[name] = (stat.S_IFREG | mode, hashlib.sha256(path.read_bytes()).hexdigest())
        else:
            raise RuntimeError('Package input contains a link or special file')
    return result


def scripts(summary, expected):
    stage = STAGING + '/' + summary['id']
    guard = '#!/bin/sh\nset -eu\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\n'
    # Package scripts receive the target volume in argument 3. Check it before
    # looking at fixed paths on the running system, including for postinstall.
    guard += '[ "$#" -ge 3 ] && [ "$3" = / ] || exit 64\n'
    guard += '[ "$(/usr/bin/id -ru)" = 0 ] && [ "$(/usr/bin/id -u)" = 0 ] || exit 77\n'
    pre = guard + '''check_dir() {
    if [ -e "$1" ] || [ -L "$1" ]; then
        [ -d "$1" ] && [ ! -L "$1" ] || exit 1
        [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$1")" = "0:0:$2" ] || exit 1
    fi
}
check_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || exit 1
    [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$1")" = "0:0:$2:1" ] || exit 1
    actual=$(/usr/bin/shasum -a 256 "$1") || exit 1
    [ "${actual%% *}" = "$3" ] || exit 1
}
'''
    for directory, mode in [('/Library', '755'), ('/Library/PrivilegedHelperTools', '755'), (STAGING, '755'), (stage, '700')]:
        pre += f'check_dir {shlex.quote(directory)} {mode}\n'
    pre += f'if [ -d {shlex.quote(stage)} ]; then\n'
    for name, (mode, digest) in expected.items():
        if name == '.':
            continue
        path = shlex.quote(stage + '/' + name)
        if stat.S_ISDIR(mode):
            pre += f'    [ -d {path} ] || exit 1\n    check_dir {path} 755\n'
        else:
            pre += f'    check_file {path} {mode & 0o777:o} {digest}\n'
    pre += f'    count=$(/usr/bin/find {shlex.quote(stage)} -print0 | /usr/bin/tr -cd \'\\0\' | /usr/bin/wc -c)\n'
    pre += f'    [ "$count" -eq {len(expected)} ] || exit 1\nfi\n'
    post = guard + f'exec {shlex.quote(stage + "/adapters/installer")} activate\n'
    return {'preinstall': pre.encode(), 'postinstall': post.encode()}


def distribution(summary):
    root = ET.Element('installer-gui-script', minSpecVersion='2')
    ET.SubElement(root, 'title').text = 'vpnt'
    ET.SubElement(root, 'options', customize='never', **{'require-scripts': 'false', 'allow-external-scripts': 'false', 'rootVolumeOnly': 'true', 'hostArchitectures': platform.machine()})
    ET.SubElement(root, 'domains', enable_anywhere='false', enable_currentUserHome='false', enable_localSystem='true')
    versions = ET.SubElement(ET.SubElement(root, 'volume-check'), 'allowed-os-versions')
    ET.SubElement(versions, 'os-version', min=summary['minimumMacOS'])
    ET.SubElement(ET.SubElement(root, 'choices-outline'), 'line', choice=identifier(summary))
    choice = ET.SubElement(root, 'choice', id=identifier(summary), visible='false', enabled='true', selected='true')
    ET.SubElement(choice, 'pkg-ref', id=identifier(summary))
    ET.SubElement(root, 'pkg-ref', id=identifier(summary), version=summary['appVersion'], onConclusion='none').text = COMPONENT
    ET.indent(root)
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


def normalized(element):
    return (element.tag, dict(element.attrib), (element.text or '').strip(), [normalized(child) for child in element])


def audit(package, extraction, summary, expected):
    if package.is_symlink() or not package.is_file() or package.stat().st_nlink != 1 or package.stat().st_size > 300 * 1024 * 1024:
        raise RuntimeError('Untrusted package file')
    signature = subprocess.run(['/usr/sbin/pkgutil', '--check-signature', str(package)], capture_output=True, timeout=10, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    lines = signature.stdout.splitlines()
    if signature.returncode != 1 or len(lines) != 2 or lines[1].strip() != b'Status: no signature':
        raise RuntimeError('Expected an unsigned development package')
    subprocess.run(['/usr/sbin/pkgutil', '--expand-full', str(package), str(extraction)], check=True, capture_output=True, timeout=45)
    if {p.name for p in extraction.iterdir()} != {'Distribution', COMPONENT}:
        raise RuntimeError('Unexpected product entries')
    for path in extraction.rglob('*'):
        meta = path.lstat()
        if not (stat.S_ISDIR(meta.st_mode) or stat.S_ISREG(meta.st_mode)) or (stat.S_ISREG(meta.st_mode) and meta.st_nlink != 1):
            raise RuntimeError('Linked or special package entry')
    root = ET.parse(extraction / 'Distribution').getroot()
    # Native productbuild embeds a local reference and an empty bundle-version
    # record, plus calculated sizes. Normalize only those exact additions.
    generated = [ref for ref in root.findall('pkg-ref') if normalized(ref) == ('pkg-ref', {'id': identifier(summary)}, '', [('bundle-version', {}, '', [])])]
    if len(generated) != 1:
        raise RuntimeError('Unexpected generated bundle reference')
    root.remove(generated[0])
    for ref in root.findall('pkg-ref'):
        size = ref.attrib.pop('installKBytes', None)
        update = ref.attrib.pop('updateKBytes', None)
        if size is None or not size.isdigit() or int(size) > 300 * 1024 or update != '0':
            raise RuntimeError('Invalid component size')
        if ref.text == '#' + COMPONENT:
            ref.text = COMPONENT
    if normalized(root) != normalized(ET.fromstring(distribution(summary))):
        raise RuntimeError('Distribution changed the installation contract')
    component = extraction / COMPONENT
    if {p.name for p in component.iterdir()} != {'Bom', 'Payload', 'Scripts', 'PackageInfo'}:
        raise RuntimeError('Unexpected component entries')
    info = ET.parse(component / 'PackageInfo').getroot()
    attributes = {'identifier': identifier(summary), 'version': summary['appVersion'], 'install-location': STAGING + '/' + summary['id'], 'auth': 'root', 'relocatable': 'false', 'overwrite-permissions': 'true', 'format-version': '2', 'postinstall-action': 'none'}
    if info.tag != 'pkg-info' or set(info.attrib) != set(attributes) | {'generator-version'}:
        raise RuntimeError('Unknown component metadata')
    for key, wanted in attributes.items():
        if info.get(key) != wanted:
            raise RuntimeError('Component destination or authority changed')
    required_tags = {'payload', 'bundle-version', 'upgrade-bundle', 'update-bundle', 'atomic-update-bundle', 'strict-identifier', 'relocate', 'scripts'}
    if len(info) != len(required_tags) or {child.tag for child in info} != required_tags:
        raise RuntimeError('Unexpected component actions')
    for child in info:
        if child.tag == 'payload':
            if set(child.attrib) != {'numberOfFiles', 'installKBytes'} or any(not value.isdigit() or int(value) > 300 * 1024 for value in child.attrib.values()) or len(child):
                raise RuntimeError('Invalid payload metadata')
        elif child.tag == 'scripts':
            expected_actions = [('preinstall', {'file': './preinstall', 'timeout': '600'}, '', []), ('postinstall', {'file': './postinstall', 'timeout': '600'}, '', [])]
            if child.attrib or [normalized(action) for action in child] != expected_actions:
                raise RuntimeError('Unexpected script action')
        elif child.attrib or len(child) or (child.text or '').strip():
            raise RuntimeError('Relocation or bundle actions are forbidden')
    expected_scripts = scripts(summary, expected)
    scripts_dir = component / 'Scripts'
    if {p.name for p in scripts_dir.iterdir()} != set(expected_scripts):
        raise RuntimeError('Unknown package script')
    for name, content in expected_scripts.items():
        path = scripts_dir / name
        if path.is_symlink() or path.read_bytes() != content or path.stat().st_mode & 0o7777 != 0o755:
            raise RuntimeError('Package script changed')
    if inventory(component / 'Payload', exact=True) != expected:
        raise RuntimeError('Extracted payload differs from admitted input')
    records = subprocess.check_output(['/usr/bin/lsbom', '-p', 'fmug', str(component / 'Bom')], text=True, timeout=10)
    seen = set()
    metadata = 0
    for line in records.splitlines():
        name, mode, uid, gid = line.split('\t')
        name = name.removeprefix('./')
        key = str(Path(name).with_name(Path(name).name[2:])) if Path(name).name.startswith('._') else name
        if key not in expected or (int(mode, 8), int(uid), int(gid)) != (expected[key][0], 0, 0) or name in seen:
            raise RuntimeError('BOM path, mode or ownership changed')
        seen.add(name)
        metadata += key != name
    if not set(expected).issubset(seen):
        raise RuntimeError('BOM inventory is incomplete')
    return {'bomEntries': len(seen), 'metadataEntries': metadata, 'payloadFiles': sum(digest is not None for _, digest in expected.values()), 'scripts': sorted(expected_scripts), 'extracted': str(component / 'Payload')}
