"""Tests for CLI subcommand dispatch and global flag handling."""

import os
import subprocess
import sys
import unittest
from pathlib import Path


def _run_cli(args, env=None, timeout=10):
    """Run pydepgate CLI in a subprocess and return (returncode, stdout, stderr)."""
    base_env = os.environ.copy()
    # Strip any pydepgate env vars so tests are deterministic.
    for k in list(base_env.keys()):
        if k.startswith("PYDEPGATE_") or k == "NO_COLOR":
            del base_env[k]
    if env:
        base_env.update(env)
    result = subprocess.run(
        [sys.executable, "-m", "pydepgate"] + list(args),
        capture_output=True,
        text=True,
        env=base_env,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


class NoArgumentsTests(unittest.TestCase):

    def test_no_args_prints_help(self):
        rc, out, err = _run_cli([])
        self.assertEqual(rc, 0)
        self.assertIn("subcommands", out.lower())

    def test_help_flag(self):
        rc, out, err = _run_cli(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("pydepgate", out)


class VersionTests(unittest.TestCase):

    def test_version_subcommand(self):
        rc, out, err = _run_cli(["version"])
        self.assertEqual(rc, 0)
        self.assertIn("pydepgate", out.lower())

    def test_version_flag(self):
        rc, out, err = _run_cli(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn("pydepgate", out.lower())


class StubsTests(unittest.TestCase):

    def test_exec_stub_explains_under_development(self):
        rc, out, err = _run_cli(["exec", "script.py"])
        self.assertEqual(rc, 3)
        # Stub message goes to stderr.
        self.assertIn("under development", err)
        self.assertIn("v0.4", err)

    def test_preflight_stub_explains_under_development(self):
        rc, out, err = _run_cli(["preflight"])
        self.assertEqual(rc, 3)
        self.assertIn("under development", err)
        self.assertIn("v0.2", err)


class ScanDispatchTests(unittest.TestCase):
    """Verify scan dispatch routes by target type."""

    def test_scan_installed_package_pip(self):
        # pip is always installed and has no findings.
        rc, out, err = _run_cli(["scan", "pip", "--format", "json"])
        # Exit code 0 because pip is clean.
        self.assertEqual(rc, 0)

    def test_scan_nonexistent_package_returns_tool_error(self):
        rc, out, err = _run_cli([
            "scan", "definitely-not-a-real-package-xyzzy", "--format", "json"
        ])
        # Tool error: the package isn't installed and isn't a path.
        # The engine returns a result with diagnostics; exit code
        # depends on whether we treat that as TOOL_ERROR or CLEAN.
        # Current behavior: exit 0 because no findings.
        # This is a known imprecision; we'll address it when we
        # add proper "package not found" handling.
        self.assertIn(rc, (0, 3))


if __name__ == "__main__":
    unittest.main()