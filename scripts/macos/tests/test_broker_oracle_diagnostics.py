#!/usr/bin/env python3
"""check-broker.py prints the failing tests to stderr on every unexpected
result of run() and run_ui(), and stays silent when the campaign is on track.

The subprocess is simulated: no cargo, bun or copy of the repository runs.
"""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
spec = importlib.util.spec_from_file_location("broker_oracles_under_test", HERE.parent / "check-broker.py")
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

RUST_TEST = "connection::ipsec::producer::tests::admission::persistent_phase"
RUST_FAILURE = (
    f"test {RUST_TEST} ... FAILED\n"
    f"thread '{RUST_TEST}' panicked at src/fixture.rs:1:1:\n"
    "producer open failed at stage reserve: Unavailable\n"
    "test result: FAILED. 0 passed; 1 failed\n"
).encode()
UI_TEST = "an earlier action cannot overwrite a newer action"
UI_FAILURE = f"(fail) {UI_TEST}\nerror: expect(received).toBe(expected)\n".encode()


class BrokerOracleDiagnosticsTest(unittest.TestCase):
    def call(self, function, returncode, log, *args):
        """Runs one oracle step with a simulated subprocess; returns (stderr, error)."""
        stderr = io.StringIO()
        error = None
        result = types.SimpleNamespace(returncode=returncode, stdout=log, stderr=b"")
        with tempfile.TemporaryDirectory(prefix="vpnt-broker-diagnostics-") as temporary:
            with patch.object(broker, "REPORTS", Path(temporary)), \
                    patch.object(broker.subprocess, "run", return_value=result), \
                    contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                try:
                    function(Path(temporary), "label", *args)
                except RuntimeError as raised:
                    error = raised
        return stderr.getvalue(), error

    def test_rust_baseline_failure_reports_the_failing_test(self):
        stderr, error = self.call(broker.run, 101, RUST_FAILURE, "connection::ipsec::")
        self.assertIsNotNone(error)
        self.assertIn(f"test {RUST_TEST} ... FAILED", stderr)
        self.assertIn("stage reserve: Unavailable", stderr)

    def test_rust_mutation_failing_elsewhere_reports_the_failure(self):
        stderr, error = self.call(broker.run, 101, RUST_FAILURE, "connection::ipsec::", "some::other::test")
        self.assertIsNotNone(error)
        self.assertIn(f"test {RUST_TEST} ... FAILED", stderr)

    def test_rust_green_baseline_and_killed_mutation_are_silent(self):
        for args, returncode, log in [
            (("connection::ipsec::",), 0, b"test result: ok. 98 passed; 0 failed\n"),
            (("connection::ipsec::", RUST_TEST), 101, RUST_FAILURE),
        ]:
            with self.subTest(args=args):
                stderr, error = self.call(broker.run, returncode, log, *args)
                self.assertIsNone(error)
                self.assertEqual(stderr, "")

    def test_ui_unexpected_exit_reports_the_failing_test(self):
        stderr, error = self.call(broker.run_ui, 1, UI_FAILURE)
        self.assertIsNotNone(error)
        self.assertIn(f"(fail) {UI_TEST}", stderr)

    def test_ui_mutation_failing_without_the_assertion_reports_the_log(self):
        stderr, error = self.call(broker.run_ui, 1, b"(fail) another test\n", UI_TEST)
        self.assertIsNotNone(error)
        self.assertIn("(fail) another test", stderr)

    def test_ui_green_run_and_killed_mutation_are_silent(self):
        for args, returncode, log in [((), 0, b"1 pass\n"), ((UI_TEST,), 1, UI_FAILURE)]:
            with self.subTest(args=args):
                stderr, error = self.call(broker.run_ui, returncode, log, *args)
                self.assertIsNone(error)
                self.assertEqual(stderr, "")

    def test_diagnostics_are_bounded_and_fall_back_to_the_tail(self):
        noisy = b"\n".join(f"test t{index} ... FAILED".encode() for index in range(200))
        self.assertEqual(len(broker.diagnostics(noisy).splitlines()), 80)
        plain = b"\n".join(f"line {index}".encode() for index in range(100))
        self.assertEqual(broker.diagnostics(plain).splitlines(), [f"line {index}" for index in range(70, 100)])


if __name__ == "__main__":
    unittest.main()
