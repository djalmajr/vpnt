#!/usr/bin/env python3
"""Focused recovery tests for build-runtime.py's configure retry.

Set VPNT_BUILD_RUNTIME to a private copy of build-runtime.py to run a named
mutation; the default is the real script. `run` is injected and temporary
directories are isolated, so no configure/make, runtime, or target tree is used.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
DEFAULT = HERE.parent / "build-runtime.py"
MODULE = Path(os.environ.get("VPNT_BUILD_RUNTIME", DEFAULT))
sys.path.insert(0, str(MODULE.parent))
spec = importlib.util.spec_from_file_location("build_runtime_under_test", MODULE)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

SIGNATURE = (
    '{"backend":"kernel-libipsec","configure":["/src/configure"],'
    '"openssl":"/opt/openssl","patches":{}}'
)
CONFIGURE = ["/src/configure", "--enable-kernel-libipsec"]
ENV = {"PATH": "/usr/bin:/bin"}
LOG = "unused.log"


class RuntimeInventoryTest(unittest.TestCase):
    def test_missing_openvpn_file_and_inventory_entry_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="vpnt-runtime-inventory-") as temporary:
            root = Path(temporary) / "target/vpnt-runtime"
            root.mkdir(parents=True)
            manifest = {
                "format": 1, "appVersion": builder.VERSION, "prefix": str(builder.PREFIX),
                "strongswan": {"backend": builder.SWAN_BACKEND, "patches": builder.expected_swan_patches()},
                "openfortivpn": {"patches": {patch.name: builder.digest(patch) for patch in [builder.FORTI_PATCH, builder.TRANSPORT_PATCH, builder.SUPERVISOR_PATCH, builder.SPLIT_PATCH, builder.DNS_PATCH]}},
                "openvpn": {"version": builder.OVPN_VERSION, "source": builder.OVPN_URL, "sha256": builder.OVPN_SHA},
                "files": {},
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            with patch.object(builder, "ROOT", Path(temporary)), patch.object(sys, "argv", ["build-runtime.py", "--verify-only"]):
                try:
                    builder.main()
                except Exception as error:
                    self.assertIsInstance(error, RuntimeError)
                    self.assertIn("missing bin/openvpn", str(error))
                else:
                    self.fail("missing OpenVPN was accepted")

    def test_non_macho_openvpn_is_rejected_before_any_client_runs(self):
        with tempfile.TemporaryDirectory(prefix="vpnt-runtime-format-") as temporary:
            root = Path(temporary) / "target/vpnt-runtime"
            (root / "bin").mkdir(parents=True)
            # Real Mach-O stand-ins for the two existing clients, so only the
            # OpenVPN entry has the wrong format.
            for program in ("charon", "openfortivpn"):
                (root / "bin" / program).write_bytes(Path("/usr/bin/true").read_bytes())
            script = root / "bin/openvpn"
            script.write_text("#!/bin/sh\necho 'OpenVPN 0.0.0 fake'\n")
            script.chmod(0o755)
            files = {f"bin/{name}": builder.digest(root / "bin" / name) for name in ("charon", "openfortivpn", "openvpn")}
            manifest = {
                "format": 1, "appVersion": builder.VERSION, "prefix": str(builder.PREFIX),
                "strongswan": {"backend": builder.SWAN_BACKEND, "patches": builder.expected_swan_patches()},
                "openfortivpn": {"patches": {patch.name: builder.digest(patch) for patch in [builder.FORTI_PATCH, builder.TRANSPORT_PATCH, builder.SUPERVISOR_PATCH, builder.SPLIT_PATCH, builder.DNS_PATCH]}},
                "openvpn": {"version": builder.OVPN_VERSION, "source": builder.OVPN_URL, "sha256": builder.OVPN_SHA},
                "files": files,
                # Correct metadata for the stand-ins, so that without the format
                # check the verifier proceeds to run a tool instead of stopping here.
                "minimumMacOS": ".".join(map(str, max(builder.minimum_macos(root / "bin" / name) for name in ("charon", "openfortivpn")))),
            }
            (root / "manifest.json").write_text(json.dumps(manifest))

            def refuse(*args, **kwargs):
                raise AssertionError(f"a subprocess ran before the format check: {args[0]}")

            with patch.object(builder.subprocess, "run", side_effect=refuse):
                with self.assertRaises(RuntimeError) as raised:
                    builder.verify_runtime(root)
            self.assertEqual(str(raised.exception), "Runtime clients are not Mach-O executables: bin/openvpn")


class Run:
    """Injected builder step: records calls and can fail the first N times."""

    def __init__(self, failures=0):
        self.calls = []
        self.failures = failures

    def __call__(self, args, cwd, env, log):
        self.calls.append((list(args), Path(cwd), dict(env), Path(log)))
        if self.failures:
            self.failures -= 1
            raise RuntimeError("configure failed")


class ConfigureRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vpnt-configure-recovery-")
        self.root = Path(self.temporary.name)
        self.build = self.root / "strongswan"

    def tearDown(self):
        self.temporary.cleanup()

    def configure(self, run, build=None):
        return builder.configure_build(
            build or self.build, SIGNATURE, CONFIGURE, ENV, LOG, run
        )

    def marker(self, build=None):
        return (build or self.build) / ".vpnt-build.json"

    def started(self, build=None):
        return (build or self.build) / ".vpnt-configure-started.json"

    def test_failed_configure_retries_and_matching_final_marker_does_not_repeat(self):
        first = Run(failures=1)
        with self.assertRaisesRegex(RuntimeError, "configure failed"):
            self.configure(first)
        self.assertEqual(len(first.calls), 1)
        self.assertEqual(first.calls[0][0], CONFIGURE)
        self.assertTrue(self.started().is_file())
        self.assertFalse(self.marker().exists())

        second = Run()
        self.configure(second)
        self.assertEqual(len(second.calls), 1)
        self.assertEqual(self.marker().read_text(), SIGNATURE)
        self.assertFalse(self.started().exists())

        third = Run()
        self.configure(third)
        self.assertEqual(third.calls, [])
        self.assertEqual(self.marker().read_text(), SIGNATURE)
        self.assertFalse(self.started().exists())

    def test_matching_final_marker_does_not_repeat_configure(self):
        self.build.mkdir()
        self.marker().write_text(SIGNATURE)
        self.started().write_text(json.dumps({"format": 1, "signature": "old"}))
        run = Run()
        self.configure(run)
        self.assertEqual(run.calls, [])
        self.assertFalse(self.started().exists())

    def test_unrecognized_directory_is_preserved_byte_identical(self):
        self.build.mkdir()
        foreign = self.build / "foreign.bin"
        foreign.write_bytes(b"\x00foreign-build-tree\xff")
        before = {path.name: path.read_bytes() for path in self.build.iterdir()}
        with self.assertRaisesRegex(
            RuntimeError, "Refusing to replace unrecognized strongSwan build"
        ):
            self.configure(Run())
        self.assertTrue(self.build.is_dir())
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.build.iterdir()}, before
        )
        self.assertFalse(self.marker().exists())

    def test_malformed_sentinel_does_not_authorize_deletion(self):
        for content in [
            '{"format": 1,',
            "not json\n",
            '["format", 1, "signature"]',
            '{"format": true, "signature": "x"}',
            '{"format": 1.0, "signature": "x"}',
            '{"format": "1", "signature": "x"}',
            '{"format": 1, "signature": "x", "extra": 0}',
        ]:
            with self.subTest(content=content):
                build = self.root / "candidate"
                build.mkdir(exist_ok=True)
                (build / ".vpnt-configure-started.json").write_text(content)
                (build / "other.partial").write_bytes(b"partial")
                before = {path.name: path.read_bytes() for path in build.iterdir()}
                with self.assertRaisesRegex(
                    RuntimeError, "Refusing to replace unrecognized strongSwan build"
                ):
                    self.configure(Run(), build)
                self.assertEqual(
                    {path.name: path.read_bytes() for path in build.iterdir()}, before
                )

    def test_own_interrupted_sentinel_with_another_signature_is_retried(self):
        self.build.mkdir()
        self.started().write_text(json.dumps({"format": 1, "signature": "previous"}))
        (self.build / "partial.o").write_bytes(b"partial")
        run = Run()
        self.configure(run)
        self.assertEqual(len(run.calls), 1)
        self.assertEqual(self.marker().read_text(), SIGNATURE)
        self.assertFalse(self.started().exists())
        self.assertFalse((self.build / "partial.o").exists())

    def test_old_and_stale_markers_are_replaced(self):
        for name, content in [
            (".vpnt-configure.json", '["/src/configure"]'),
            (".vpnt-build.json", '{"backend":"kernel-pfkey"}'),
        ]:
            with self.subTest(name=name):
                build = self.root / name.split(".")[1]
                build.mkdir()
                (build / name).write_text(content)
                (build / "old.o").write_bytes(b"old")
                run = Run()
                self.configure(run, build)
                self.assertEqual(len(run.calls), 1)
                self.assertEqual(self.marker(build).read_text(), SIGNATURE)
                self.assertFalse((build / "old.o").exists())

    def test_symlinked_build_path_is_preserved(self):
        target = self.root / "real"
        target.mkdir()
        (target / "keep.txt").write_bytes(b"keep")
        self.build.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "non-directory strongSwan build path"):
            self.configure(Run())
        self.assertTrue(self.build.is_symlink())
        self.assertEqual((target / "keep.txt").read_bytes(), b"keep")
        self.assertFalse((target / ".vpnt-build.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
