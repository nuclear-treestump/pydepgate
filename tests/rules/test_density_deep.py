"""
Tests for the LIBRARY_PY default rules.

Verifies that each of the 13 DENS signals receives the calibrated
severity in LIBRARY_PY context, and that LIBRARY_PY rules win
precedence over the corresponding "anywhere" fallback rules.

The pattern matches tests/rules/test_density_defaults.py: build a
Signal and a ScanContext, run evaluate_signal against the bundled
DEFAULT_RULES, assert on the resulting Finding's severity.
"""

import unittest

from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.engines.base import ArtifactKind, ScanContext, Severity
from pydepgate.parsers.pysource import SourceLocation
from pydepgate.rules.base import evaluate_signal
from pydepgate.rules.defaults import DEFAULT_RULES
from pydepgate.traffic_control.triage import FileKind


def _make_signal(
    signal_id: str,
    confidence: Confidence = Confidence.MEDIUM,
) -> Signal:
    return Signal(
        analyzer="code_density",
        signal_id=signal_id,
        confidence=confidence,
        scope=Scope.MODULE,
        location=SourceLocation(line=1, column=0),
        description="test",
        context={},
    )


def _make_library_py_context(
    internal_path: str = "mymod/util.py",
) -> ScanContext:
    return ScanContext(
        artifact_kind=ArtifactKind.WHEEL,
        artifact_identity="test.whl",
        internal_path=internal_path,
        file_kind=FileKind.LIBRARY_PY,
        triage_reason="library code (deep mode)",
    )


def _evaluate_in_library_py(signal: Signal) -> Severity | None:
    ctx = _make_library_py_context()
    result = evaluate_signal(signal, ctx, DEFAULT_RULES)
    if result.finding is None:
        return None
    return result.finding.severity


# =============================================================================
# Tier 0: Sanity check that all rules are wired in
# =============================================================================

class LibraryPyRulesPresenceTests(unittest.TestCase):
    """If these fail, the patches/defaults_library_py_block.md was not applied."""

    def test_all_thirteen_library_py_rules_present(self):
        ids = {r.rule_id for r in DEFAULT_RULES}
        for sig in (
            "001", "002", "010", "011",
            "020", "021", "030", "031",
            "040", "041", "042", "050", "051",
        ):
            with self.subTest(signal=f"DENS{sig}"):
                self.assertIn(f"default_dens{sig}_in_library_py", ids)

    def test_no_duplicate_rule_ids(self):
        density_rules = [
            r for r in DEFAULT_RULES
            if r.rule_id.startswith("default_dens")
        ]
        ids = [r.rule_id for r in density_rules]
        self.assertEqual(
            len(ids), len(set(ids)),
            f"Duplicate density rule_ids: {ids}",
        )


# =============================================================================
# Tier 1: Severity calibration per signal
# =============================================================================

class LibraryPySeverityCalibrationTests(unittest.TestCase):
    """Each signal lands at its calibrated severity in LIBRARY_PY."""

    def test_dens001_is_low(self):
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS001")),
            Severity.LOW,
        )

    def test_dens002_is_low(self):
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS002")),
            Severity.LOW,
        )

    def test_dens010_is_medium(self):
        # The LiteLLM-shape signal: in LIBRARY_PY context, MEDIUM is
        # the right severity. False positives include UUIDs and
        # embedded blobs; promotion is left to user rules for stricter
        # policies.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS010")),
            Severity.MEDIUM,
        )

    def test_dens011_is_medium(self):
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS011")),
            Severity.MEDIUM,
        )

    def test_dens020_is_info(self):
        # NumPy-style abbreviations would otherwise cause noise.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS020")),
            Severity.INFO,
        )

    def test_dens021_is_info(self):
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS021")),
            Severity.INFO,
        )

    def test_dens030_is_high(self):
        # Trojan Source: HIGH everywhere, including library code.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS030")),
            Severity.HIGH,
        )

    def test_dens031_is_high(self):
        # Homoglyphs: HIGH everywhere. Legitimate non-Latin naming is
        # the false-positive class; suppress via user rule.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS031")),
            Severity.HIGH,
        )

    def test_dens040_is_info(self):
        # AST depth false-positives heavily on Cython output.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS040")),
            Severity.INFO,
        )

    def test_dens041_is_info(self):
        # Functional Python style triggers this legitimately.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS041")),
            Severity.INFO,
        )

    def test_dens042_is_low(self):
        # Lookup tables and crypto constants trigger this.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS042")),
            Severity.LOW,
        )

    def test_dens050_is_high(self):
        # Docstring smuggling: rare in legitimate library code.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS050")),
            Severity.HIGH,
        )

    def test_dens051_is_high(self):
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS051")),
            Severity.HIGH,
        )


# =============================================================================
# Tier 2: Precedence over "anywhere" fallback rules
# =============================================================================

class LibraryPyRulePrecedenceTests(unittest.TestCase):
    """The LIBRARY_PY rule must win over the corresponding anywhere rule.

    The rule evaluator uses specificity-based precedence:
    file-kind-specific rules beat unscoped ones. These tests confirm
    that the LIBRARY_PY rule is the winner for each signal whose
    "anywhere" baseline differs from the LIBRARY_PY calibration.
    """

    def test_dens010_library_py_wins_over_anywhere(self):
        # Anywhere: LOW. LIBRARY_PY: MEDIUM.
        # If anywhere wins, this test gets LOW. We expect MEDIUM.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS010")),
            Severity.MEDIUM,
        )

    def test_dens030_library_py_wins_over_anywhere(self):
        # Both anywhere and LIBRARY_PY are HIGH for DENS030.
        # This is a sanity check that the more-specific rule
        # at least DOESN'T LOSE.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS030")),
            Severity.HIGH,
        )

    def test_dens050_library_py_wins_over_anywhere(self):
        # Anywhere: MEDIUM. LIBRARY_PY: HIGH.
        # If anywhere wins, this test gets MEDIUM. We expect HIGH.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS050")),
            Severity.HIGH,
        )

    def test_dens042_library_py_wins_over_anywhere(self):
        # Both are LOW; sanity check.
        self.assertEqual(
            _evaluate_in_library_py(_make_signal("DENS042")),
            Severity.LOW,
        )


# =============================================================================
# Tier 3: Integrity checks
# =============================================================================

class LibraryPyRuleIntegrityTests(unittest.TestCase):
    """Cross-cutting checks across the LIBRARY_PY rule block."""

    def test_every_library_py_rule_has_explain_text(self):
        library_rules = [
            r for r in DEFAULT_RULES
            if r.rule_id.endswith("_in_library_py")
        ]
        # We expect 13.
        self.assertEqual(len(library_rules), 13)
        for rule in library_rules:
            with self.subTest(rule_id=rule.rule_id):
                self.assertIsNotNone(rule.explain)
                self.assertGreater(
                    len(rule.explain), 20,
                    f"{rule.rule_id}: explain too short",
                )

    def test_no_library_py_rule_explain_contains_em_dash(self):
        library_rules = [
            r for r in DEFAULT_RULES
            if r.rule_id.endswith("_in_library_py")
        ]
        for rule in library_rules:
            with self.subTest(rule_id=rule.rule_id):
                self.assertNotIn(
                    "\u2014", rule.explain,
                    f"{rule.rule_id}: contains em-dash",
                )

    def test_every_library_py_rule_targets_library_py_file_kind(self):
        # Defensive: every rule named "in_library_py" should actually
        # match LIBRARY_PY in its RuleMatch.
        library_rules = [
            r for r in DEFAULT_RULES
            if r.rule_id.endswith("_in_library_py")
        ]
        for rule in library_rules:
            with self.subTest(rule_id=rule.rule_id):
                self.assertIs(
                    rule.match.file_kind, FileKind.LIBRARY_PY,
                    f"{rule.rule_id} doesn't actually target LIBRARY_PY",
                )

    def test_library_py_rules_cover_all_dens_signals(self):
        library_rules = [
            r for r in DEFAULT_RULES
            if r.rule_id.endswith("_in_library_py")
        ]
        signal_ids = {r.match.signal_id for r in library_rules}
        expected = {
            "DENS001", "DENS002", "DENS010", "DENS011",
            "DENS020", "DENS021", "DENS030", "DENS031",
            "DENS040", "DENS041", "DENS042", "DENS050", "DENS051",
        }
        self.assertEqual(signal_ids, expected)


if __name__ == "__main__":
    unittest.main()