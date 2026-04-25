"""Tests for output format rendering."""

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


class JsonFormatTests(unittest.TestCase):

    def test_scan_pip_json_output_is_valid_json(self):
        rc, out, err = _run_cli(["scan", "pip", "--format", "json"])
        # Output must parse as JSON.
        payload = json.loads(out)
        self.assertIn("schema_version", payload)
        self.assertIn("findings", payload)
        self.assertIn("statistics", payload)

    def test_json_schema_has_expected_top_level_keys(self):
        rc, out, err = _run_cli(["scan", "pip", "--format", "json"])
        payload = json.loads(out)
        for key in ("schema_version", "artifact", "findings",
                    "skipped", "statistics", "diagnostics"):
            self.assertIn(key, payload)


class HumanFormatTests(unittest.TestCase):

    def test_human_format_clean_scan(self):
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--no-color",
        ])
        self.assertEqual(rc, 0)
        self.assertIn("No findings", out)


class SarifStubTests(unittest.TestCase):

    def test_sarif_format_emits_stub_message(self):
        rc, out, err = _run_cli(["scan", "pip", "--format", "sarif"])
        # SARIF stub returns TOOL_ERROR.
        self.assertEqual(rc, 3)
        self.assertIn("under development", out)


if __name__ == "__main__":
    unittest.main()