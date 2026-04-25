"""Tests for environment variable handling and precedence."""

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


class EnvVarTests(unittest.TestCase):

    def test_pydepgate_format_env_var(self):
        rc, out, err = _run_cli(
            ["scan", "pip"],
            env={"PYDEPGATE_FORMAT": "json"},
        )
        # Output should be JSON because of env var.
        payload = json.loads(out)
        self.assertIn("findings", payload)

    def test_pydepgate_ci_env_var(self):
        rc, out, err = _run_cli(
            ["scan", "pip"],
            env={"PYDEPGATE_CI": "1"},
        )
        # CI mode implies JSON format.
        payload = json.loads(out)
        self.assertIn("findings", payload)

    def test_no_color_env_var_respected(self):
        # Smoke test: with NO_COLOR set, no ANSI codes should appear.
        rc, out, err = _run_cli(
            ["scan", "pip", "--format", "human"],
            env={"NO_COLOR": "1"},
        )
        self.assertNotIn("\033[", out)

    def test_explicit_flag_overrides_env_var(self):
        # PYDEPGATE_FORMAT says json, but --format human should win.
        rc, out, err = _run_cli(
            ["scan", "pip", "--format", "human", "--no-color"],
            env={"PYDEPGATE_FORMAT": "json"},
        )
        # Output should be human format, not JSON.
        # Human format starts with "No findings" for a clean scan.
        self.assertIn("No findings", out)


if __name__ == "__main__":
    unittest.main()