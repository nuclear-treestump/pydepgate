"""Tests that CLAUDE.md documents every critical constraint.

If a constraint section is removed or key language is tampered with,
these tests fail — ensuring the guardrails stay visible to contributors
and AI assistants.
"""

from __future__ import annotations

import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestClaudeMdConstraintSections(unittest.TestCase):
    """CLAUDE.md must document every critical constraint that these tests enforce.

    If a constraint section is removed from CLAUDE.md, the guardrail
    becomes invisible to contributors and AI assistants — the test still
    passes on the code, but nobody knows the rule exists. This class
    catches that drift.
    """

    CLAUDE_MD = (PROJECT_ROOT / "CLAUDE.md").read_text()

    REQUIRED_CONSTRAINT_SECTIONS = {
        "Never execute input": (
            "The static analyzer NEVER executes, compiles, imports, "
            "or deserializes user input"
        ),
        "Picklability contract": (
            "Inputs and outputs must be picklable"
        ),
        "Zero runtime dependencies": (
            "No third-party runtime dependencies"
        ),
        "Signal ID stability": (
            "Never rename existing IDs"
        ),
        "Exit code contract": (
            "`0` = clean"
        ),
        "Rules precedence model": (
            "User rules > system rules > defaults"
        ),
        "JSON schema_version contract": (
            "schema_version"
        ),
        "CLI argument-position invariant": (
            "Global flags work before or after the subcommand"
        ),
        "Reporter context-key handling": (
            "Underscore prefix = suppressed from JSON wire format"
        ),
        "Triage coverage boundary": (
            "traffic_control/triage.py"
        ),
    }

    REQUIRED_DENY_LIST_ITEMS = [
        "Do not add runtime dependencies",
        "Do not execute, compile, or import input during static analysis",
        "Do not rename existing signal IDs",
        "Do not repurpose exit codes",
        "Do not change JSON output shape without bumping schema_version",
        "Do not refactor rules precedence logic",
        "Do not store unpicklable state on analyzers/enrichers/rules",
        "Do not add global CLI flags without the dual-registration pattern",
        "Do not change triage coverage without explicit documentation and tests",
    ]

    def test_critical_constraint_sections_present(self):
        missing = []
        for section, key_phrase in self.REQUIRED_CONSTRAINT_SECTIONS.items():
            if f"### {section}" not in self.CLAUDE_MD:
                missing.append(f"Missing section heading: ### {section}")
            elif key_phrase not in self.CLAUDE_MD:
                missing.append(
                    f"Section '{section}' exists but missing key phrase: "
                    f"{key_phrase!r}"
                )
        if missing:
            self.fail(
                "CLAUDE.md is missing critical constraint documentation:\n"
                + "\n".join(missing)
            )

    def test_deny_list_present(self):
        self.assertIn(
            "## Deny list", self.CLAUDE_MD,
            "CLAUDE.md must contain a '## Deny list' section",
        )

    def test_deny_list_items_present(self):
        missing = [
            item for item in self.REQUIRED_DENY_LIST_ITEMS
            if item not in self.CLAUDE_MD
        ]
        if missing:
            self.fail(
                "CLAUDE.md deny list is missing required items:\n"
                + "\n".join(f"- {item}" for item in missing)
            )

    def test_scan_pipeline_documented(self):
        self.assertIn(
            "## Scan pipeline", self.CLAUDE_MD,
            "CLAUDE.md must document the scan pipeline",
        )
        for layer in [
            "Parsers", "Analyzers", "Enrichers", "Rules engine", "Reporter"
        ]:
            self.assertIn(
                layer, self.CLAUDE_MD,
                f"Scan pipeline must document the '{layer}' layer",
            )


if __name__ == "__main__":
    unittest.main()
