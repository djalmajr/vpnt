#!/usr/bin/env python3
"""Focused tests for the SDK build-input helper.

The helper is imported as a sibling module. Set VPNT_RUST_BUILD_INPUTS to a
private scratch copy to run the named mutation; the default is the real helper.
No Cargo, network, privilege or repository copy is used.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
DEFAULT = HERE.parent / "rust_build_inputs.py"
MODULE = Path(os.environ.get("VPNT_RUST_BUILD_INPUTS", DEFAULT))
spec = importlib.util.spec_from_file_location("rust_build_inputs_under_test", MODULE)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class BuildInputsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vpnt-build-inputs-")
        self.root = Path(self.temporary.name) / "project"
        self.build = b"fn main() { println!(\"vpnt native build\"); }\n"
        self.top = b"/* top-level native input */\n"
        self.nested = b"/* new nested native input */\n"
        (self.root / "native" / "nested").mkdir(parents=True)
        (self.root / "build.rs").write_bytes(self.build)
        (self.root / "native" / "utun_socket.c").write_bytes(self.top)
        (self.root / "native" / "nested" / "deeper.c").write_bytes(self.nested)

    def tearDown(self):
        self.temporary.cleanup()

    def test_inventory_hashes_and_copy(self):
        hashes = helper.source_hashes(self.root)
        expected = {
            "build.rs": self.build,
            "native/utun_socket.c": self.top,
            "native/nested/deeper.c": self.nested,
        }
        for key, data in expected.items():
            self.assertIn(key, hashes)
            self.assertEqual(hashes[key], hashlib.sha256(data).hexdigest())
        self.assertTrue(any(key.endswith("rust_build_inputs.py") for key in hashes))

        destination = Path(self.temporary.name) / "copy"
        helper.copy_into(self.root, destination)
        for key, data in expected.items():
            self.assertEqual((destination / key).read_bytes(), data)
        self.assertFalse((destination / "rust_build_inputs.py").exists())
        self.assertFalse((destination / "scripts").exists())

    def test_new_nested_native_file_is_enumerated_and_copied(self):
        added = b"/* added after the first inventory */\n"
        path = self.root / "native" / "new" / "deep.c"
        path.parent.mkdir()
        path.write_bytes(added)
        hashes = helper.source_hashes(self.root)
        self.assertEqual(hashes["native/new/deep.c"], hashlib.sha256(added).hexdigest())
        destination = Path(self.temporary.name) / "copy-new"
        helper.copy_into(self.root, destination)
        self.assertEqual((destination / "native/new/deep.c").read_bytes(), added)

    def test_normal_output_destination_is_allowed(self):
        destination = self.root / "output/fixtures/vpnt-copy-test"
        helper.copy_into(self.root, destination)
        self.assertEqual((destination / "build.rs").read_bytes(), self.build)
        self.assertEqual((destination / "native/nested/deeper.c").read_bytes(), self.nested)

    def test_preexisting_targets_are_preserved(self):
        build_only = Path(self.temporary.name) / "existing-build"
        build_only.mkdir()
        (build_only / "build.rs").write_bytes(b"keep-build\n")
        with self.assertRaisesRegex(RuntimeError, "existing build.rs"):
            helper.copy_into(self.root, build_only)
        self.assertEqual((build_only / "build.rs").read_bytes(), b"keep-build\n")
        self.assertFalse((build_only / "native").exists())

        native_only = Path(self.temporary.name) / "existing-native"
        (native_only / "native").mkdir(parents=True)
        (native_only / "native" / "existing.c").write_bytes(b"keep-native\n")
        with self.assertRaisesRegex(RuntimeError, "existing native/"):
            helper.copy_into(self.root, native_only)
        self.assertEqual((native_only / "native" / "existing.c").read_bytes(), b"keep-native\n")
        self.assertFalse((native_only / "build.rs").exists())

    def test_overlapping_destinations_are_rejected(self):
        inside = self.root / "native" / "copy"
        with self.assertRaisesRegex(RuntimeError, "inside native/"):
            helper.copy_into(self.root, inside)
        self.assertFalse(inside.exists())
        with self.assertRaisesRegex(RuntimeError, "source tree or its ancestor"):
            helper.copy_into(self.root, self.root)
        with self.assertRaisesRegex(RuntimeError, "source tree or its ancestor"):
            helper.copy_into(self.root, self.root.parent)
        self.assertFalse((self.root.parent / "build.rs").exists())

    def test_missing_build_or_native_fails_before_copy(self):
        destination = Path(self.temporary.name) / "copy-missing"
        (self.root / "build.rs").unlink()
        with self.assertRaisesRegex(RuntimeError, "build.rs"):
            helper.copy_into(self.root, destination)
        self.assertFalse(destination.exists())

        (self.root / "build.rs").write_bytes(self.build)
        shutil.rmtree(self.root / "native")
        with self.assertRaisesRegex(RuntimeError, "native/"):
            helper.copy_into(self.root, destination)
        self.assertFalse(destination.exists())

        (self.root / "native").mkdir()
        with self.assertRaisesRegex(RuntimeError, "no regular files"):
            helper.copy_into(self.root, destination)
        self.assertFalse(destination.exists())

    def test_symlinked_native_input_is_rejected(self):
        target = Path(self.temporary.name) / "outside.c"
        target.write_bytes(b"outside\n")
        (self.root / "native" / "link.c").symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            helper.source_hashes(self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
