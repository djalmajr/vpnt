"""Build well-formed but altered fictional packages. Never run package scripts."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

repository, package, summary, kind, destination = sys.argv[1:]
repository = Path(repository)
summary = json.loads(summary)
sys.path.insert(0, str(repository / 'scripts/macos'))
from installation_package import COMPONENT, STAGING, distribution, identifier

with tempfile.TemporaryDirectory(prefix='forged-pkg-', dir=repository) as temporary:
    work = Path(temporary)
    expanded = work / 'expanded'
    subprocess.run(['/usr/sbin/pkgutil', '--expand-full', package, str(expanded)], check=True, capture_output=True)
    payload = expanded / COMPONENT / 'Payload'
    scripts = expanded / COMPONENT / 'Scripts'
    if kind == 'script-bytes':
        with (scripts / 'postinstall').open('ab') as file:
            file.write(b'# altered fixture script\n')
    elif kind == 'payload-bytes':
        path = payload / 'adapters/helper'
        path.chmod(0o755)
        with path.open('ab') as file:
            file.write(b'changed fixture payload')
        path.chmod(0o555)
    elif kind == 'payload-mode':
        (payload / 'adapters/helper').chmod(0o755)
    elif kind == 'extra-file':
        (payload / 'unlisted.txt').write_bytes(b'unlisted fixture')
    else:
        raise RuntimeError('Unknown fixture variant')
    component = work / COMPONENT
    subprocess.run(['/usr/bin/pkgbuild', '--root', str(payload), '--scripts', str(scripts), '--ownership', 'recommended', '--install-location', STAGING + '/' + summary['id'], '--identifier', identifier(summary), '--version', summary['appVersion'], str(component)], check=True, capture_output=True)
    dist = work / 'Distribution'
    dist.write_bytes(distribution(summary))
    subprocess.run(['/usr/bin/productbuild', '--distribution', str(dist), '--package-path', str(work), destination], check=True, capture_output=True)
