"""Tests for --min-severity, --strict-exit, and --ci behavior."""

import json
import os
import subprocess
import sys
import unittest


def _run_cli(args, env=None):
    base_env = os.environ.copy()
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
        timeout=10,
    )
    return result.returncode, result.stdout, result.stderr


class CiModeTests(unittest.TestCase):

    def test_ci_mode_uses_json_format_by_default(self):
        rc, out, err = _run_cli(["--ci", "scan", "pip"])
        # Output should parse as JSON.
        payload = json.loads(out)
        self.assertIn("findings", payload)


class MinSeverityTests(unittest.TestCase):

    def test_min_severity_high_filters_low_findings(self):
        # pip has no findings, so this is a smoke test that the flag
        # is accepted. Real behavior tested in test_scan.py with a
        # malicious sample.
        rc, out, err = _run_cli([
            "--min-severity", "high", "scan", "pip", "--format", "json",
        ])
        self.assertEqual(rc, 0)


class StrictExitTests(unittest.TestCase):

    def test_strict_exit_flag_accepted(self):
        rc, out, err = _run_cli([
            "--min-severity", "high", "--strict-exit", "scan", "pip",
        ])
        # Smoke test; real behavior tested with malicious samples.
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()