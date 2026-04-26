"""Tests for the explain subcommand."""

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


class ExplainSignalTests(unittest.TestCase):

    def test_explain_known_signal(self):
        rc, out, err = _run_cli(["explain", "DYN002"])
        self.assertEqual(rc, 0)
        self.assertIn("DYN002", out)
        self.assertIn("Why it matters", out)

    def test_explain_unknown_topic(self):
        rc, out, err = _run_cli(["explain", "NONEXISTENT"])
        self.assertEqual(rc, 3)


class ExplainRuleTests(unittest.TestCase):

    def test_explain_default_rule(self):
        rc, out, err = _run_cli([
            "explain", "default_dyn002_in_setup_py"
        ])
        self.assertEqual(rc, 0)
        self.assertIn("Rule:", out)


class ExplainListTests(unittest.TestCase):

    def test_list_shows_signals_and_rules(self):
        rc, out, err = _run_cli(["explain", "--list"])
        self.assertEqual(rc, 0)
        self.assertIn("Signal IDs", out)
        self.assertIn("Rule IDs", out)
        self.assertIn("DYN002", out)


if __name__ == "__main__":
    unittest.main()