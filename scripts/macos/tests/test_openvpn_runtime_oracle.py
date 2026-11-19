"""Check that the OpenVPN runtime oracle rejects incompatible executables."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ORACLE = Path(__file__).resolve().parent.parent / "check-openvpn-runtime.py"
spec = importlib.util.spec_from_file_location("openvpn_runtime_oracle", ORACLE)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class VersionChecks(unittest.TestCase):
    def test_wrong_version_and_disabled_management_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="vpnt-oracle-fake-") as temporary:
            program = Path(temporary) / "openvpn"
            for label, output, expected in [
                ("wrong version", "OpenVPN 0.0", "unexpected OpenVPN version"),
                ("no management", "OpenVPN 2.7.9 fake\\nCompile time defines: enable_management=no enable_plugins=no enable_pkcs11=no enable_dco=no", "enable_management=yes"),
            ]:
                with self.subTest(label=label):
                    program.write_text("#!/bin/sh\nprintf '" + output + "\\n'\n")
                    program.chmod(0o700)
                    original = oracle.BINARY
                    try:
                        oracle.BINARY = program
                        with self.assertRaisesRegex(RuntimeError, expected):
                            oracle.main()
                    finally:
                        oracle.BINARY = original

    def test_management_rejects_unframed_hold_and_missing_ack(self):
        with tempfile.TemporaryDirectory(prefix="vpnt-oracle-fake-") as temporary:
            program = Path(temporary) / "openvpn"
            original = oracle.BINARY
            try:
                oracle.BINARY = program
                for message, expected in [
                    (">INFO: misleading >HOLD: inside", "management hold"),
                    (">HOLD: real", "acknowledge SIGTERM"),
                ]:
                    with self.subTest(message=message):
                        program.write_text("#!/usr/bin/python3\n" + """import socket, sys, time
if '--version' in sys.argv:
    print('OpenVPN 2.7.9 fixture')
    print('Compile time defines: enable_management=yes enable_plugins=no enable_pkcs11=no enable_dco=no')
else:
    s = socket.socket(socket.AF_UNIX)
    s.connect(sys.argv[sys.argv.index('--management') + 1])
    s.sendall(%r)
    time.sleep(0.2)
    s.close()
""" % (message.encode() + b"\n",))
                        program.chmod(0o700)
                        with self.assertRaisesRegex(RuntimeError, expected):
                            oracle.main()
            finally:
                oracle.BINARY = original


if __name__ == "__main__":
    unittest.main()
