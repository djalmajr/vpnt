"""Channel and packaging consumers, with disposable native binaries only."""
import json
import hashlib
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
ROOT = SCRIPTS.parents[1]
SNAPSHOT = '''
import json
from pathlib import Path
from identifiers import BASE, CHANNEL, identifier, tool
from installation_package import STAGING, identifier as component, scripts
import importlib.util
spec = importlib.util.spec_from_file_location('runtime', 'scripts/macos/build-runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
suffixes = ['app', 'helper', 'install', 'runtime', 'staging', 'pppd',
            'pinentry', 'askpass', 'credentials.v1', 'component.501', 'app.preview']
summary = {'id': 'a' * 64, 'uid': 501}
print(json.dumps({'base': BASE, 'channel': CHANNEL,
 'ids': [identifier(suffix) for suffix in suffixes],
 'paths': [tool(suffix) for suffix in ['helper', 'install', 'runtime', 'staging', 'pppd', 'pinentry', 'askpass']],
 'runtime': str(runtime.PREFIX), 'staging': STAGING, 'component': component(summary),
 'postinstall': scripts(summary, {})['postinstall'].decode(),
 'policy': BASE.replace('.', '_').replace('-', '_') + '_501'}))
'''


def env(channel):
    result = dict(os.environ, PYTHONPATH=str(SCRIPTS))
    result.pop('VPNT_CHANNEL', None)
    if channel is not None:
        result['VPNT_CHANNEL'] = channel
    return result


class Channels(unittest.TestCase):
    def snapshot(self, channel):
        return json.loads(subprocess.check_output([sys.executable, '-c', SNAPSHOT],
                          cwd=ROOT, env=env(channel)))

    def test_defaults_bases_consumers_and_channel_separation(self):
        dev, prd = self.snapshot('dev'), self.snapshot('prd')
        self.assertEqual(self.snapshot(None), dev)
        self.assertEqual(dev['base'], 'dev.djalmajr.vpnt-dev')
        self.assertEqual(prd['base'], 'dev.djalmajr.vpnt')
        for document in [dev, prd]:
            base = document['base']
            self.assertTrue(all(value.startswith(base + '.') for value in document['ids']))
            self.assertTrue(all(Path(value).name.startswith(base + '.') for value in document['paths']))
            self.assertEqual(document['component'], base + '.component.501')
            self.assertIn(document['staging'] + '/', document['postinstall'])
            self.assertEqual(Path(document['runtime']).parent.name, base + '.runtime')
            # sudoers ignores filenames with dots: normalize the whole base.
            self.assertNotIn('.', document['policy'])
            self.assertNotIn('-', document['policy'])
        self.assertTrue(set(dev['ids']).isdisjoint(prd['ids']))
        self.assertTrue(set(dev['paths']).isdisjoint(prd['paths']))
        self.assertNotEqual(dev['policy'], prd['policy'])

    def test_unknown_or_empty_channel_is_rejected(self):
        for channel in ['', 'prod', 'DEV', '../prd']:
            result = subprocess.run([sys.executable, '-c', 'import identifiers'],
                                    env=env(channel), capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'VPNT_CHANNEL must be dev or prd', result.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'Apple PPP consumer is macOS only')
    def test_pinned_ppp_consumer_compiles_with_each_generated_channel_path(self):
        archive = ROOT / 'target/runtime-sources/openfortivpn-1.24.1.tar.gz'
        if not archive.is_file():
            self.skipTest('Pinned source archive is absent; no download')
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                         'c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465')
        with tempfile.TemporaryDirectory(prefix='vpnt-ppp-channel-') as temporary:
            directory = Path(temporary)
            (directory / 'src').mkdir()
            with tarfile.open(archive) as source:
                tunnel = source.extractfile('openfortivpn-1.24.1/src/tunnel.c').read().decode()
            (directory / 'src/tunnel.c').write_text(tunnel)
            subprocess.run(['/usr/bin/patch', '-t', '-p1', '-i',
                            str(SCRIPTS / 'patches/openfortivpn-ppp-supervisor.patch')],
                           cwd=directory, check=True, capture_output=True)
            tunnel = (directory / 'src/tunnel.c').read_text()
            builder = tunnel[tunnel.index('struct ofv_varr {'):tunnel.index('static int on_ppp_if_up(')]
            ppp = tunnel[tunnel.index('static int pppd_run('):tunnel.index('static const char * const ppp_message[]')]
            fixture = ROOT / 'tests/fixtures/pppd'
            source = directory / 'consumer.c'
            source.write_text((fixture / 'client-head.c').read_text() + builder + ppp +
                              (fixture / 'client-tail.c').read_text())
            for channel in ['dev', 'prd']:
                header = directory / 'vpnt-channel.h'
                subprocess.run([sys.executable, '-c',
                                'from pathlib import Path; from runtime_sources import supervisor_header; '
                                'import sys; supervisor_header(Path(sys.argv[1]))', str(header)],
                               env=env(channel), check=True, capture_output=True)
                expected = self.snapshot(channel)['base']
                self.assertEqual(header.read_text(),
                                 f'#define VPNT_PPP_SUPERVISOR "/Library/PrivilegedHelperTools/{expected}.pppd"\n')
                binary = directory / channel
                subprocess.run(['/usr/bin/cc', '-Wall', '-Wextra', '-Werror', '-include', str(header),
                                '-DPPP_PATH="/usr/sbin/pppd"', str(source), '-o', str(binary)],
                               check=True, capture_output=True)
                self.assertIn(f'/Library/PrivilegedHelperTools/{expected}.pppd'.encode(), binary.read_bytes())
                # Compile only: neither the consumer nor PPP is executed.

    @unittest.skipUnless(sys.platform == 'darwin', 'Mach-O packaging is macOS only')
    def test_native_marker_accepts_only_matching_channel_without_execution(self):
        check = 'from identifiers import require_binary_channel; import sys; require_binary_channel(sys.argv[1])'
        with tempfile.TemporaryDirectory(prefix='vpnt-channel-test-') as temporary:
            directory = Path(temporary)
            source = directory / 'never-run.c'
            source.write_text('int main(void) { return 99; }\n')
            for channel, base in [('dev', 'dev.djalmajr.vpnt-dev'), ('prd', 'dev.djalmajr.vpnt')]:
                marker = directory / 'marker'
                marker.write_bytes(f'vpnt-channel:{channel}:{base}\0'.encode())
                binary = directory / channel
                subprocess.run(['/usr/bin/cc', str(source),
                                f'-Wl,-sectcreate,__TEXT,__vpnt_channel,{marker}',
                                '-o', str(binary)], check=True, capture_output=True)
                for selected in ['dev', 'prd']:
                    result = subprocess.run([sys.executable, '-c', check, str(binary)],
                                            env=env(selected), capture_output=True)
                    self.assertEqual(result.returncode == 0, channel == selected, result.stderr)
            # Exercise the actual app packager; never launch its executable.
            bundle = directory / 'vpnt.app'
            def package(channel, binary):
                return subprocess.run([sys.executable, str(SCRIPTS / 'package-app.py'),
                                       '--binary', str(directory / binary),
                                       '--output', str(bundle), '--replace'],
                                      env=env(channel), capture_output=True)
            self.assertEqual(package('dev', 'dev').returncode, 0)
            info = bundle / 'Contents/Info.plist'
            original = info.read_bytes()
            self.assertEqual(plistlib.loads(original)['CFBundleIdentifier'], 'dev.djalmajr.vpnt-dev.app')
            self.assertEqual(plistlib.loads(original)['CFBundleIconFile'], 'AppIcon')
            self.assertEqual((bundle / 'Contents/Resources/AppIcon.icns').read_bytes(),
                             (ROOT / 'assets/macos/AppIcon.icns').read_bytes())
            self.assertNotEqual(package('prd', 'dev').returncode, 0)
            self.assertEqual(info.read_bytes(), original)
            self.assertNotEqual(package('prd', 'prd').returncode, 0)
            self.assertEqual(info.read_bytes(), original)
            missing = directory / 'missing'
            subprocess.run(['/usr/bin/cc', str(source), '-o', str(missing)], check=True, capture_output=True)
            result = subprocess.run([sys.executable, '-c', check, str(missing)],
                                    env=env('dev'), capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
