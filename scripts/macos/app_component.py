"""Include only an admitted component package in a development app bundle."""
import importlib.util
import json
import os
from pathlib import Path
import sys


def include(payload, resources, executable):
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise RuntimeError('Prepare the app component as an ordinary user')
    # Load the same native package auditor used by the standalone packager.
    scripts = Path(__file__).resolve().parent
    sys.path.insert(0, str(scripts))
    spec = importlib.util.spec_from_file_location('component_builder', scripts / 'package-installation.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    result = builder.build(payload, builder.ROOT / 'target/vpnt-packages')
    if result['uid'] != os.getuid() or result['installationPerformed'] or result['signed']:
        raise RuntimeError('Component is not the admitted local development build')
    manifest = json.loads((payload / 'payload.json').read_text())
    minimum = max(['13.0', result['minimumMacOS']], key=lambda value: tuple(map(int, value.split('.'))))
    component = resources / 'Component'
    component.mkdir(mode=0o755)
    builder.preparer.copy_file(Path(result['package']), component / 'component.pkg')
    if builder.preparer.digest(component / 'component.pkg') != result['packageSha256']:
        raise RuntimeError('Component package changed during copying')
    metadata = {
        'format': 1,
        'appVersion': result['appVersion'],
        'uid': result['uid'],
        'build': result['id'],
        'minimumMacOS': minimum,
        'hostSha256': builder.preparer.digest(executable),
        'packageSha256': result['packageSha256'],
        'helperSha256': manifest['files']['adapters/helper'],
        'installerSha256': manifest['files']['adapters/installer'],
        'askpassSha256': manifest['files']['adapters/askpass'],
    }
    if builder.inspect(payload)['id'] != metadata['build']:
        raise RuntimeError('Component input changed during app preparation')
    path = component / 'component.json'
    path.write_text(json.dumps(metadata, sort_keys=True, separators=(',', ':')) + '\n')
    path.chmod(0o444)
    return minimum
