"""Tests for the rules loader."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from pydepgate.rules.base import RuleAction, RuleSource
from pydepgate.rules.loader import (
    GateFileError,
    discover_rules_files,
    load_rules_file,
    load_user_rules,
)


def _write_gate(content: str) -> Path:
    """Helper: write a temp .gate file with given content."""
    fd = tempfile.NamedTemporaryFile(mode="w", suffix=".gate", delete=False)
    fd.write(content)
    fd.close()
    return Path(fd.name)


class JsonFormatTests(unittest.TestCase):

    def test_load_simple_json_rule(self):
        content = json.dumps({
            "_pydepgate_format": "json",
            "_pydepgate_version": 1,
            "rules": [
                {
                    "id": "test_rule",
                    "signal_id": "DYN002",
                    "action": "set_severity",
                    "severity": "high",
                }
            ]
        })
        path = _write_gate(content)
        try:
            loaded = load_rules_file(path)
            self.assertEqual(len(loaded.rules), 1)
            self.assertEqual(loaded.rules[0].rule_id, "USER_test_rule")
            self.assertEqual(loaded.rules[0].source, RuleSource.USER)
        finally:
            path.unlink()

    def test_json_without_format_declaration_warns(self):
        content = json.dumps({
            "rules": [
                {"action": "suppress", "signal_id": "DYN002"}
            ]
        })
        path = _write_gate(content)
        try:
            loaded = load_rules_file(path)
            self.assertEqual(len(loaded.rules), 1)
            self.assertTrue(any("_pydepgate_format" in w for w in loaded.warnings))
        finally:
            path.unlink()


class TomlFormatTests(unittest.TestCase):

    def test_load_simple_toml_rule(self):
        content = """
[[rule]]
id = "my_rule"
signal_id = "DYN002"
action = "set_severity"
severity = "high"
"""
        path = _write_gate(content)
        try:
            loaded = load_rules_file(path)
            self.assertEqual(len(loaded.rules), 1)
            self.assertEqual(loaded.rules[0].rule_id, "USER_my_rule")
        finally:
            path.unlink()

    def test_load_multiple_toml_rules(self):
        content = """
[[rule]]
signal_id = "DYN001"
action = "suppress"

[[rule]]
signal_id = "DYN002"
action = "set_severity"
severity = "low"
"""
        path = _write_gate(content)
        try:
            loaded = load_rules_file(path)
            self.assertEqual(len(loaded.rules), 2)
            # Auto-numbered: USER001, USER002
            self.assertEqual(loaded.rules[0].rule_id, "USER001")
            self.assertEqual(loaded.rules[1].rule_id, "USER002")
        finally:
            path.unlink()


class ValidationTests(unittest.TestCase):

    def test_unknown_action_rejected(self):
        content = """
[[rule]]
signal_id = "DYN002"
action = "silence"
"""
        path = _write_gate(content)
        try:
            with self.assertRaises(GateFileError) as cm:
                load_rules_file(path)
            self.assertIn("unknown action", str(cm.exception).lower())
        finally:
            path.unlink()

    def test_unknown_field_with_typo_suggestion(self):
        content = """
[[rule]]
signal_id = "DYN002"
glob_path = "tests/**"
action = "suppress"
"""
        path = _write_gate(content)
        try:
            with self.assertRaises(GateFileError) as cm:
                load_rules_file(path)
            # Should suggest 'path_glob'.
            self.assertIn("path_glob", str(cm.exception))
        finally:
            path.unlink()

    def test_set_severity_without_severity_field(self):
        content = """
[[rule]]
signal_id = "DYN002"
action = "set_severity"
"""
        path = _write_gate(content)
        try:
            with self.assertRaises(GateFileError) as cm:
                load_rules_file(path)
            self.assertIn("severity", str(cm.exception).lower())
        finally:
            path.unlink()

    def test_invalid_file_kind_rejected(self):
        content = """
[[rule]]
file_kind = "setup"
action = "suppress"
"""
        path = _write_gate(content)
        try:
            with self.assertRaises(GateFileError) as cm:
                load_rules_file(path)
            self.assertIn("file_kind", str(cm.exception))
        finally:
            path.unlink()

    def test_accumulated_errors_reported(self):
        content = """
[[rule]]
action = "silence"

[[rule]]
glob_path = "tests/**"
action = "suppress"
"""
        path = _write_gate(content)
        try:
            with self.assertRaises(GateFileError) as cm:
                load_rules_file(path)
            error_msg = str(cm.exception)
            self.assertIn("validation error", error_msg)
            # Should mention both rule problems.
            self.assertIn("silence", error_msg)
            self.assertIn("path_glob", error_msg)
        finally:
            path.unlink()


class FileExtensionTests(unittest.TestCase):

    def test_non_gate_extension_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".txt") as f:
            with self.assertRaises(GateFileError):
                load_rules_file(Path(f.name))


class DiscoveryTests(unittest.TestCase):

    def test_explicit_path_returns_immediately(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "myrules.gate"
            path.write_text('{"rules": []}')
            chosen, others = discover_rules_files(
                explicit_path=str(path)
            )
            self.assertEqual(chosen, path)
            self.assertEqual(others, [])

    def test_no_file_found_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            chosen, others = discover_rules_files(cwd=Path(tmp))
            self.assertIsNone(chosen)
            self.assertEqual(others, [])


if __name__ == "__main__":
    unittest.main()