"""
Tests for the context_predicates rule grammar.

Covers:
  - ContextPredicate.evaluate() across all 11 operators, including
    type-mismatch handling.
  - The context_contains -> context_predicates shim in RuleMatch
    __post_init__, including the merge case where both fields are set.
  - Loader validation of the new grammar: shape errors, unknown
    operators, multi-key inner dicts, with typo suggestions.
  - Default rules: DENS010 / DENS011 / DENS050 length escalation
    produces the correct severity at boundary lengths in each file
    kind. This is the regression test for the "magic ordering" in
    defaults.py.
"""

from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.engines.base import ScanContext, Severity, ArtifactKind
from pydepgate.parsers.pysource import SourceLocation
from pydepgate.rules.base import (
    ContextPredicate,
    Rule,
    RuleAction,
    RuleEffect,
    RuleMatch,
    RuleSource,
    VALID_OPERATORS,
    evaluate_signal,
    matches,
)
from pydepgate.rules.defaults import DEFAULT_RULES
from pydepgate.rules.loader import (
    GateFileError,
    load_rules_file,
)
from pydepgate.traffic_control.triage import FileKind


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_signal(
    signal_id: str,
    confidence: Confidence = Confidence.MEDIUM,
    context: dict | None = None,
    scope: Scope = Scope.MODULE,
) -> Signal:
    return Signal(
        analyzer="code_density",
        signal_id=signal_id,
        confidence=confidence,
        scope=scope,
        location=SourceLocation(line=1, column=0),
        description="test",
        context=context or {},
    )


def _make_context(file_kind: FileKind, internal_path: str = "test.py") -> ScanContext:
    return ScanContext(
        artifact_kind=ArtifactKind.LOOSE_FILE,
        artifact_identity="test_artifact",
        internal_path=internal_path,
        file_kind=file_kind,
        triage_reason="test fixture",
    )


def _resolve_finding_severity(
    signal: Signal,
    file_kind: FileKind,
    rules: list[Rule] = DEFAULT_RULES,
) -> tuple[Severity, str]:
    """Run a signal through the rule evaluator and return (severity, rule_id)."""
    ctx = _make_context(file_kind)
    result = evaluate_signal(signal, ctx, rules)
    assert result.finding is not None, "expected a finding"
    rule_id = result.rule_applied.rule_id if result.rule_applied else "<none>"
    return result.finding.severity, rule_id


# ===========================================================================
# ContextPredicate.evaluate (operator dispatch)
# ===========================================================================


class TestContextPredicateNumeric(unittest.TestCase):
    """Numeric and comparable operators."""

    def test_eq_matches_exact(self):
        self.assertTrue(ContextPredicate("eq", 5).evaluate(5))
        self.assertFalse(ContextPredicate("eq", 5).evaluate(6))

    def test_ne_matches_inequal(self):
        self.assertTrue(ContextPredicate("ne", 5).evaluate(6))
        self.assertFalse(ContextPredicate("ne", 5).evaluate(5))

    def test_gt_strictly_greater(self):
        self.assertTrue(ContextPredicate("gt", 100).evaluate(101))
        self.assertFalse(ContextPredicate("gt", 100).evaluate(100))
        self.assertFalse(ContextPredicate("gt", 100).evaluate(99))

    def test_gte_includes_boundary(self):
        self.assertTrue(ContextPredicate("gte", 10240).evaluate(10240))
        self.assertTrue(ContextPredicate("gte", 10240).evaluate(10241))
        self.assertFalse(ContextPredicate("gte", 10240).evaluate(10239))

    def test_lt_strictly_less(self):
        self.assertTrue(ContextPredicate("lt", 100).evaluate(99))
        self.assertFalse(ContextPredicate("lt", 100).evaluate(100))

    def test_lte_includes_boundary(self):
        self.assertTrue(ContextPredicate("lte", 100).evaluate(100))
        self.assertFalse(ContextPredicate("lte", 100).evaluate(101))

    def test_floats_work(self):
        self.assertFalse(ContextPredicate("gte", 5.5).evaluate(5.42))
        self.assertTrue(ContextPredicate("gte", 5.5).evaluate(5.5))

    def test_type_mismatch_returns_false(self):
        # Comparing a string with gte against an int returns False,
        # not raise. The whole rule fails to match silently.
        self.assertFalse(ContextPredicate("gte", 100).evaluate("not_a_number"))
        self.assertFalse(ContextPredicate("gt", "abc").evaluate(42))


class TestContextPredicateString(unittest.TestCase):
    """String-shape operators."""

    def test_contains_substring(self):
        self.assertTrue(
            ContextPredicate("contains", "pwn").evaluate("pwn3d_value")
        )
        self.assertFalse(
            ContextPredicate("contains", "pwn").evaluate("hello")
        )

    def test_contains_works_on_lists(self):
        # `in` syntax: value in actual. Lists work as iterables.
        self.assertTrue(
            ContextPredicate("contains", "x").evaluate(["x", "y", "z"])
        )
        self.assertFalse(
            ContextPredicate("contains", "q").evaluate(["x", "y", "z"])
        )

    def test_startswith(self):
        pred = ContextPredicate("startswith", "RIGHT-TO-LEFT")
        self.assertTrue(pred.evaluate("RIGHT-TO-LEFT OVERRIDE"))
        self.assertFalse(pred.evaluate("LEFT-TO-RIGHT"))

    def test_endswith(self):
        pred = ContextPredicate("endswith", "OVERRIDE")
        self.assertTrue(pred.evaluate("RIGHT-TO-LEFT OVERRIDE"))
        self.assertFalse(pred.evaluate("RIGHT-TO-LEFT EMBEDDING"))

    def test_startswith_non_string_returns_false(self):
        # Doesn't raise; just doesn't match.
        self.assertFalse(ContextPredicate("startswith", "X").evaluate(42))

    def test_endswith_non_string_returns_false(self):
        self.assertFalse(ContextPredicate("endswith", "X").evaluate(42))


class TestContextPredicateCollection(unittest.TestCase):
    """Membership operators."""

    def test_in_list(self):
        pred = ContextPredicate("in", ["base64", "hex"])
        self.assertTrue(pred.evaluate("base64"))
        self.assertFalse(pred.evaluate("base32"))

    def test_not_in_list(self):
        pred = ContextPredicate("not_in", ["kwargs", "args", "self"])
        self.assertTrue(pred.evaluate("oops"))
        self.assertFalse(pred.evaluate("kwargs"))

    def test_in_with_tuple(self):
        pred = ContextPredicate("in", ("a", "b", "c"))
        self.assertTrue(pred.evaluate("b"))

    def test_in_with_set(self):
        pred = ContextPredicate("in", {"a", "b", "c"})
        self.assertTrue(pred.evaluate("a"))


class TestContextPredicateUnknownOp(unittest.TestCase):
    """Defensive: unknown operator returns False (loader catches at parse)."""

    def test_unknown_op_returns_false(self):
        self.assertFalse(
            ContextPredicate("matches_regex", "x").evaluate("xyz")
        )


class TestValidOperatorsRegistry(unittest.TestCase):
    """The frozenset of valid operators is the source of truth."""

    def test_contains_all_operators(self):
        expected = {
            "eq", "ne", "gt", "gte", "lt", "lte",
            "contains", "startswith", "endswith",
            "in", "not_in",
        }
        self.assertEqual(set(VALID_OPERATORS), expected)

    def test_is_immutable(self):
        # Frozenset can't be mutated.
        with self.assertRaises(AttributeError):
            VALID_OPERATORS.add("foo")  # type: ignore[attr-defined]


# ===========================================================================
# context_contains -> context_predicates shim
# ===========================================================================


class TestContextContainsShim(unittest.TestCase):
    """The legacy context_contains field is normalized at construction."""

    def test_shim_creates_eq_predicates(self):
        match = RuleMatch(
            signal_id="DENS010",
            context_contains={"alphabet": "base64", "scope_name": "module"},
        )
        self.assertIsNotNone(match.context_predicates)
        self.assertEqual(len(match.context_predicates), 2)
        self.assertEqual(
            match.context_predicates["alphabet"],
            ContextPredicate(op="eq", value="base64"),
        )
        self.assertEqual(
            match.context_predicates["scope_name"],
            ContextPredicate(op="eq", value="module"),
        )

    def test_shim_preserves_original_field(self):
        # context_contains is still readable for backward inspection.
        match = RuleMatch(
            signal_id="X",
            context_contains={"key": "value"},
        )
        self.assertEqual(match.context_contains, {"key": "value"})

    def test_no_shim_when_contains_is_none(self):
        match = RuleMatch(signal_id="X")
        self.assertIsNone(match.context_predicates)

    def test_explicit_predicates_alone(self):
        match = RuleMatch(
            signal_id="X",
            context_predicates={
                "length": ContextPredicate(op="gte", value=1024),
            },
        )
        self.assertIsNone(match.context_contains)
        self.assertIsNotNone(match.context_predicates)
        self.assertIn("length", match.context_predicates)

    def test_both_fields_merge_predicates_win(self):
        # When both fields are provided, explicit predicates win on
        # key collision; non-colliding keys merge.
        match = RuleMatch(
            signal_id="X",
            context_contains={"shared_key": "old", "only_in_contains": "v1"},
            context_predicates={
                "shared_key": ContextPredicate(op="ne", value="new"),
                "only_in_predicates": ContextPredicate(op="eq", value="v2"),
            },
        )
        # All three keys present
        self.assertEqual(
            set(match.context_predicates.keys()),
            {"shared_key", "only_in_contains", "only_in_predicates"},
        )
        # shared_key uses the explicit predicate, not the eq-shim
        self.assertEqual(match.context_predicates["shared_key"].op, "ne")
        # only_in_contains is shimmed to eq
        self.assertEqual(
            match.context_predicates["only_in_contains"],
            ContextPredicate(op="eq", value="v1"),
        )

    def test_specificity_counts_shimmed_predicates(self):
        # Backward-compat: a rule with context_contains has the same
        # specificity it always did.
        match = RuleMatch(
            signal_id="X",
            context_contains={"a": 1, "b": 2, "c": 3},
        )
        # signal_id (1) + 3 predicates from shim = 4
        self.assertEqual(match.specificity(), 4)


# ===========================================================================
# matches() with new grammar
# ===========================================================================


class TestMatchesWithPredicates(unittest.TestCase):
    """The matches() function correctly applies context_predicates."""

    def _make_rule(self, predicates: dict, severity: Severity = Severity.HIGH) -> Rule:
        return Rule(
            rule_id="test",
            source=RuleSource.USER,
            match=RuleMatch(
                signal_id="DENS010",
                context_predicates=predicates,
            ),
            effect=RuleEffect(action=RuleAction.SET_SEVERITY, severity=severity),
        )

    def test_single_predicate_match(self):
        rule = self._make_rule({
            "length": ContextPredicate(op="gte", value=1024),
        })
        sig = _make_signal("DENS010", context={"length": 2000})
        ctx = _make_context(FileKind.LIBRARY_PY)
        self.assertTrue(matches(rule, sig, ctx))

    def test_predicate_below_threshold(self):
        rule = self._make_rule({
            "length": ContextPredicate(op="gte", value=1024),
        })
        sig = _make_signal("DENS010", context={"length": 500})
        ctx = _make_context(FileKind.LIBRARY_PY)
        self.assertFalse(matches(rule, sig, ctx))

    def test_predicate_with_missing_context_key_does_not_match(self):
        rule = self._make_rule({
            "missing_key": ContextPredicate(op="gte", value=1),
        })
        sig = _make_signal("DENS010", context={"length": 500})
        ctx = _make_context(FileKind.LIBRARY_PY)
        self.assertFalse(matches(rule, sig, ctx))

    def test_multiple_predicates_all_must_match(self):
        rule = self._make_rule({
            "length": ContextPredicate(op="gte", value=1024),
            "scope_name": ContextPredicate(op="eq", value="module"),
        })
        ctx = _make_context(FileKind.LIBRARY_PY)
        # Both pass
        self.assertTrue(matches(
            rule,
            _make_signal("DENS010", context={"length": 2000, "scope_name": "module"}),
            ctx,
        ))
        # length passes but scope_name fails
        self.assertFalse(matches(
            rule,
            _make_signal("DENS010", context={"length": 2000, "scope_name": "function"}),
            ctx,
        ))
        # scope_name passes but length fails
        self.assertFalse(matches(
            rule,
            _make_signal("DENS010", context={"length": 500, "scope_name": "module"}),
            ctx,
        ))


# ===========================================================================
# Loader validation of new grammar
# ===========================================================================


class TestLoaderContextPredicates(unittest.TestCase):
    """The .gate loader accepts and validates the new operator grammar."""

    def setUp(self):
        # Each test gets a fresh temp dir; tearDown removes it.
        self._tempdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tempdir.name)

    def tearDown(self):
        self._tempdir.cleanup()

    def _write_gate(self, content: str) -> Path:
        path = self.tmp_path / "test.gate"
        path.write_text(content)
        return path

    def test_loads_valid_gte_predicate_toml(self):
        path = self._write_gate(textwrap.dedent('''
            [[rule]]
            id = "block-large-base64"
            signal_id = "DENS010"
            action = "set_severity"
            severity = "critical"
            context_predicates = { length = { gte = 10240 } }
        '''))
        loaded = load_rules_file(path)
        self.assertEqual(len(loaded.rules), 1)
        rule = loaded.rules[0]
        self.assertIsNotNone(rule.match.context_predicates)
        pred = rule.match.context_predicates["length"]
        self.assertEqual(pred.op, "gte")
        self.assertEqual(pred.value, 10240)

    def test_loads_valid_in_predicate_json(self):
        path = self._write_gate(json.dumps({
            "_pydepgate_format": "json",
            "_pydepgate_version": 1,
            "rules": [{
                "id": "block-suspect-alphabets",
                "signal_id": "DENS010",
                "action": "set_severity",
                "severity": "high",
                "context_predicates": {
                    "scope_name": {"in": ["module", "function"]},
                },
            }],
        }))
        loaded = load_rules_file(path)
        rule = loaded.rules[0]
        pred = rule.match.context_predicates["scope_name"]
        self.assertEqual(pred.op, "in")
        self.assertEqual(pred.value, ["module", "function"])

    def test_unknown_operator_with_typo_suggestion(self):
        path = self._write_gate(textwrap.dedent('''
            [[rule]]
            id = "x"
            signal_id = "DENS010"
            action = "set_severity"
            severity = "high"
            context_predicates = { length = { gtee = 1024 } }
        '''))
        with self.assertRaises(GateFileError) as cm:
            load_rules_file(path)
        msg = str(cm.exception)
        self.assertIn("unknown operator 'gtee'", msg)
        self.assertIn("Did you mean 'gte'?", msg)

    def test_multiple_operators_in_one_predicate_rejected(self):
        # Each predicate dict must have exactly one operator key. To AND
        # multiple conditions on the same field, write multiple rules.
        path = self._write_gate(textwrap.dedent('''
            [[rule]]
            id = "x"
            signal_id = "DENS010"
            action = "set_severity"
            severity = "high"
            context_predicates = { length = { gte = 1024, lte = 100000 } }
        '''))
        with self.assertRaises(GateFileError) as cm:
            load_rules_file(path)
        msg = str(cm.exception)
        self.assertIn("exactly one operator", msg)
        # The error mentions the keys that were provided.
        self.assertIn("gte", msg)
        self.assertIn("lte", msg)

    def test_empty_predicate_rejected(self):
        path = self._write_gate(textwrap.dedent('''
            [[rule]]
            id = "x"
            signal_id = "DENS010"
            action = "set_severity"
            severity = "high"
            context_predicates = { length = { } }
        '''))
        with self.assertRaises(GateFileError) as cm:
            load_rules_file(path)
        self.assertIn("empty", str(cm.exception))

    def test_non_dict_predicate_rejected(self):
        # Predicate must be {op: value}, not just a value.
        path = self._write_gate(textwrap.dedent('''
            [[rule]]
            id = "x"
            signal_id = "DENS010"
            action = "set_severity"
            severity = "high"
            context_predicates = { length = 1024 }
        '''))
        with self.assertRaises(GateFileError) as cm:
            load_rules_file(path)
        self.assertIn("must be a dict", str(cm.exception))

    def test_legacy_context_contains_still_works(self):
        # Backward-compat: the old context_contains field continues
        # to work, shimmed transparently.
        path = self._write_gate(textwrap.dedent('''
            [[rule]]
            id = "legacy"
            signal_id = "DENS010"
            action = "set_severity"
            severity = "high"
            context_contains = { scope_name = "module" }
        '''))
        loaded = load_rules_file(path)
        rule = loaded.rules[0]
        # Original field preserved
        self.assertEqual(rule.match.context_contains, {"scope_name": "module"})
        # And shimmed into predicates
        self.assertIsNotNone(rule.match.context_predicates)
        self.assertEqual(
            rule.match.context_predicates["scope_name"],
            ContextPredicate(op="eq", value="module"),
        )


# ===========================================================================
# Default rules: length escalation regression
# ===========================================================================
#
# These tests pin the magic-ordering behavior in defaults.py. They will
# break if rules are reordered without preserving the precedence
# contract. See patches/defaults_length_escalation.md for the rationale.
#
# Each test class uses subTest for parametrization: one test method
# iterates over a CASES list, with each case getting its own subTest
# context so failures are reported individually.


class TestDens010LengthEscalation(unittest.TestCase):
    """DENS010 severity at boundary lengths in each file kind."""

    # (file_kind, length, expected_severity)
    CASES = [
        # Above 10240: CRITICAL everywhere
        (FileKind.PTH,            20000, Severity.CRITICAL),
        (FileKind.SETUP_PY,       20000, Severity.CRITICAL),
        (FileKind.SITECUSTOMIZE,  20000, Severity.CRITICAL),
        (FileKind.INIT_PY,        20000, Severity.CRITICAL),
        (FileKind.LIBRARY_PY,     20000, Severity.CRITICAL),

        # Boundary case: exactly 10240
        (FileKind.LIBRARY_PY,     10240, Severity.CRITICAL),

        # Between 1024 and 10240: HIGH except where baseline is already CRITICAL
        (FileKind.PTH,             2000, Severity.CRITICAL),  # baseline wins
        (FileKind.SETUP_PY,        2000, Severity.HIGH),       # baseline matches
        (FileKind.SITECUSTOMIZE,   2000, Severity.CRITICAL),
        (FileKind.INIT_PY,         2000, Severity.HIGH),       # escalates from MEDIUM
        (FileKind.LIBRARY_PY,      2000, Severity.HIGH),       # escalates from MEDIUM

        # Boundary case: exactly 1024
        (FileKind.LIBRARY_PY,      1024, Severity.HIGH),

        # Below 1024: per-file-kind baseline
        (FileKind.PTH,              500, Severity.CRITICAL),
        (FileKind.SETUP_PY,         500, Severity.HIGH),
        (FileKind.SITECUSTOMIZE,    500, Severity.CRITICAL),
        (FileKind.INIT_PY,          500, Severity.MEDIUM),
        (FileKind.LIBRARY_PY,       500, Severity.MEDIUM),

        # Just below the lower threshold
        (FileKind.LIBRARY_PY,      1023, Severity.MEDIUM),
    ]

    def test_dens010_severity_at_boundaries(self):
        for file_kind, length, expected in self.CASES:
            with self.subTest(file_kind=file_kind.value, length=length):
                sig = _make_signal("DENS010", context={
                    "length": length,
                    "entropy": 5.5,
                    "value_preview": "AAAA",
                    "scope_name": "module",
                })
                sev, _rule = _resolve_finding_severity(sig, file_kind)
                self.assertEqual(
                    sev, expected,
                    msg=(
                        f"DENS010 length={length} in {file_kind.value}: "
                        f"expected {expected.value} but got {sev.value}"
                    ),
                )


class TestDens011LengthEscalation(unittest.TestCase):
    """DENS011 severity at boundary lengths."""

    CASES = [
        # Above 10240: CRITICAL everywhere
        (FileKind.PTH,        20000, Severity.CRITICAL),
        (FileKind.SETUP_PY,   20000, Severity.CRITICAL),
        (FileKind.LIBRARY_PY, 20000, Severity.CRITICAL),
        (FileKind.INIT_PY,    20000, Severity.CRITICAL),  # via huge_anywhere

        # 1024 <= length < 10240
        (FileKind.PTH,         2000, Severity.CRITICAL),  # baseline wins
        (FileKind.SETUP_PY,    2000, Severity.HIGH),
        (FileKind.LIBRARY_PY,  2000, Severity.HIGH),       # escalates from MEDIUM
        (FileKind.INIT_PY,     2000, Severity.HIGH),       # via long_anywhere

        # Below 1024
        (FileKind.PTH,          500, Severity.CRITICAL),
        (FileKind.SETUP_PY,     500, Severity.HIGH),
        (FileKind.LIBRARY_PY,   500, Severity.MEDIUM),
        (FileKind.INIT_PY,      500, Severity.LOW),  # falls through to anywhere
    ]

    def test_dens011_severity_at_boundaries(self):
        for file_kind, length, expected in self.CASES:
            with self.subTest(file_kind=file_kind.value, length=length):
                sig = _make_signal("DENS011", context={
                    "length": length,
                    "value_preview": "AAAA",
                    "scope_name": "module",
                })
                sev, _rule = _resolve_finding_severity(sig, file_kind)
                self.assertEqual(
                    sev, expected,
                    msg=(
                        f"DENS011 length={length} in {file_kind.value}: "
                        f"expected {expected.value} but got {sev.value}"
                    ),
                )


class TestDens050LengthEscalation(unittest.TestCase):
    """DENS050 severity at boundary lengths."""

    CASES = [
        # Above 10240: CRITICAL everywhere
        (FileKind.PTH,        20000, Severity.CRITICAL),
        (FileKind.SETUP_PY,   20000, Severity.CRITICAL),
        (FileKind.LIBRARY_PY, 20000, Severity.CRITICAL),  # escalates from HIGH

        # 1024 <= length < 10240
        (FileKind.PTH,         2000, Severity.CRITICAL),
        (FileKind.SETUP_PY,    2000, Severity.CRITICAL),
        (FileKind.LIBRARY_PY,  2000, Severity.HIGH),       # baseline already HIGH
        # anywhere case (no specific in_init_py rule for DENS050):
        (FileKind.INIT_PY,     2000, Severity.HIGH),       # via long_anywhere

        # Below 1024
        (FileKind.PTH,          500, Severity.CRITICAL),
        (FileKind.SETUP_PY,     500, Severity.CRITICAL),
        (FileKind.LIBRARY_PY,   500, Severity.HIGH),
        (FileKind.INIT_PY,      500, Severity.MEDIUM),  # via anywhere baseline
    ]

    def test_dens050_severity_at_boundaries(self):
        for file_kind, length, expected in self.CASES:
            with self.subTest(file_kind=file_kind.value, length=length):
                sig = _make_signal("DENS050", context={
                    "length": length,
                    "entropy": 5.5,
                    "value_preview": "AAAA",
                    "scope_name": "module",
                })
                sev, _rule = _resolve_finding_severity(sig, file_kind)
                self.assertEqual(
                    sev, expected,
                    msg=(
                        f"DENS050 length={length} in {file_kind.value}: "
                        f"expected {expected.value} but got {sev.value}"
                    ),
                )


class TestLitellmRealWorldCases(unittest.TestCase):
    """Regression: the LiteLLM 1.82.8 second-payload should resolve
    to CRITICAL with the new escalation rules."""

    def test_proxy_server_payload_dens010(self):
        # The actual finding from litellm/proxy/proxy_server.py:130
        sig = _make_signal("DENS010", context={
            "length": 34460,
            "entropy": 5.42,
            "value_preview": "import subprocess; import tempfile; im...",
            "scope_name": "module",
        })
        sev, rule = _resolve_finding_severity(sig, FileKind.LIBRARY_PY)
        self.assertEqual(sev, Severity.CRITICAL)
        self.assertIn("huge_anywhere", rule)

    def test_proxy_server_payload_dens011(self):
        # Same finding, DENS011 perspective (b64 alphabet)
        sig = _make_signal("DENS011", context={
            "length": 34460,
            "value_preview": "AAAA",
            "scope_name": "module",
        })
        sev, rule = _resolve_finding_severity(sig, FileKind.LIBRARY_PY)
        self.assertEqual(sev, Severity.CRITICAL)
        self.assertIn("huge_anywhere", rule)

    def test_pth_backdoor_dens010(self):
        # The original .pth payload (length 34501)
        sig = _make_signal("DENS010", context={
            "length": 34501,
            "entropy": 5.42,
            "value_preview": "import subprocess",
            "scope_name": "module",
        })
        sev, _rule = _resolve_finding_severity(sig, FileKind.PTH)
        # CRITICAL via huge_anywhere (which wins by load order over in_pth)
        self.assertEqual(sev, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()