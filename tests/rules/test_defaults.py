"""Tests for the rules evaluator."""

import unittest

from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.engines.base import ArtifactKind, ScanContext, Severity
from pydepgate.parsers.pysource import SourceLocation
from pydepgate.rules.base import (
    EvaluationResult,
    Rule,
    RuleAction,
    RuleEffect,
    RuleMatch,
    RuleSource,
    evaluate_signal,
    matches,
)
from pydepgate.traffic_control.triage import FileKind


def _make_signal(
    signal_id: str = "TEST001",
    analyzer: str = "test_analyzer",
    confidence: int = Confidence.MEDIUM,
    scope: Scope = Scope.MODULE,
    description: str = "test signal",
    context: dict | None = None,
) -> Signal:
    return Signal(
        analyzer=analyzer,
        signal_id=signal_id,
        confidence=confidence,
        scope=scope,
        location=SourceLocation(line=1, column=0),
        description=description,
        context=context or {},
    )


def _make_context(
    internal_path: str = "setup.py",
    file_kind: FileKind = FileKind.SETUP_PY,
) -> ScanContext:
    return ScanContext(
        artifact_kind=ArtifactKind.LOOSE_FILE,
        artifact_identity="test",
        internal_path=internal_path,
        file_kind=file_kind,
        triage_reason="test reason",
    )


def _make_rule(
    rule_id: str = "test_rule",
    source: RuleSource = RuleSource.DEFAULT,
    signal_id: str | None = None,
    file_kind: FileKind | None = None,
    action: RuleAction = RuleAction.SET_SEVERITY,
    severity: Severity | None = Severity.HIGH,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        source=source,
        match=RuleMatch(signal_id=signal_id, file_kind=file_kind),
        effect=RuleEffect(action=action, severity=severity),
    )


# =============================================================================
# Match logic
# =============================================================================

class MatchTests(unittest.TestCase):

    def test_match_on_signal_id(self):
        rule = _make_rule(signal_id="DYN002")
        sig = _make_signal(signal_id="DYN002")
        ctx = _make_context()
        self.assertTrue(matches(rule, sig, ctx))

    def test_no_match_on_different_signal_id(self):
        rule = _make_rule(signal_id="DYN002")
        sig = _make_signal(signal_id="DYN001")
        ctx = _make_context()
        self.assertFalse(matches(rule, sig, ctx))

    def test_match_on_file_kind(self):
        rule = _make_rule(file_kind=FileKind.SETUP_PY)
        sig = _make_signal()
        ctx = _make_context(file_kind=FileKind.SETUP_PY)
        self.assertTrue(matches(rule, sig, ctx))

    def test_no_match_on_different_file_kind(self):
        rule = _make_rule(file_kind=FileKind.SETUP_PY)
        sig = _make_signal()
        ctx = _make_context(file_kind=FileKind.INIT_PY)
        self.assertFalse(matches(rule, sig, ctx))

    def test_match_requires_all_fields(self):
        rule = Rule(
            rule_id="r",
            source=RuleSource.DEFAULT,
            match=RuleMatch(
                signal_id="DYN002",
                file_kind=FileKind.SETUP_PY,
            ),
            effect=RuleEffect(action=RuleAction.SET_SEVERITY, severity=Severity.HIGH),
        )
        sig = _make_signal(signal_id="DYN002")
        ctx_match = _make_context(file_kind=FileKind.SETUP_PY)
        ctx_nomatch = _make_context(file_kind=FileKind.INIT_PY)
        self.assertTrue(matches(rule, sig, ctx_match))
        self.assertFalse(matches(rule, sig, ctx_nomatch))

    def test_match_on_path_glob(self):
        rule = Rule(
            rule_id="r",
            source=RuleSource.DEFAULT,
            match=RuleMatch(path_glob="tests/**"),
            effect=RuleEffect(action=RuleAction.SUPPRESS),
        )
        sig = _make_signal()
        ctx = _make_context(internal_path="tests/sub/foo.py")
        self.assertTrue(matches(rule, sig, ctx))

    def test_no_match_on_path_glob(self):
        rule = Rule(
            rule_id="r",
            source=RuleSource.DEFAULT,
            match=RuleMatch(path_glob="tests/**"),
            effect=RuleEffect(action=RuleAction.SUPPRESS),
        )
        sig = _make_signal()
        ctx = _make_context(internal_path="src/foo.py")
        self.assertFalse(matches(rule, sig, ctx))

    def test_match_on_context_contains(self):
        rule = Rule(
            rule_id="r",
            source=RuleSource.DEFAULT,
            match=RuleMatch(context_contains={"primitive": "eval"}),
            effect=RuleEffect(action=RuleAction.SET_SEVERITY, severity=Severity.HIGH),
        )
        sig_match = _make_signal(context={"primitive": "eval", "other": "x"})
        sig_nomatch = _make_signal(context={"primitive": "exec"})
        ctx = _make_context()
        self.assertTrue(matches(rule, sig_match, ctx))
        self.assertFalse(matches(rule, sig_nomatch, ctx))

    def test_specificity_counts(self):
        m1 = RuleMatch()
        m2 = RuleMatch(signal_id="DYN002")
        m3 = RuleMatch(signal_id="DYN002", file_kind=FileKind.SETUP_PY)
        self.assertEqual(m1.specificity(), 0)
        self.assertEqual(m2.specificity(), 1)
        self.assertEqual(m3.specificity(), 2)


# =============================================================================
# Evaluator
# =============================================================================

class EvaluatorTests(unittest.TestCase):

    def test_no_rules_falls_back_to_mechanical_mapping(self):
        sig = _make_signal(confidence=Confidence.HIGH)
        ctx = _make_context()
        result = evaluate_signal(sig, ctx, [])
        self.assertIsNotNone(result.finding)
        # HIGH confidence maps to MEDIUM severity per current mapping.
        self.assertEqual(result.finding.severity, Severity.MEDIUM)

    def test_set_severity_rule_applies(self):
        sig = _make_signal(signal_id="DYN002")
        ctx = _make_context(file_kind=FileKind.SETUP_PY)
        rule = _make_rule(
            signal_id="DYN002",
            file_kind=FileKind.SETUP_PY,
            action=RuleAction.SET_SEVERITY,
            severity=Severity.HIGH,
        )
        result = evaluate_signal(sig, ctx, [rule])
        self.assertEqual(result.finding.severity, Severity.HIGH)

    def test_suppress_rule_blocks_finding(self):
        sig = _make_signal(signal_id="DYN002")
        ctx = _make_context()
        rule = _make_rule(
            signal_id="DYN002",
            action=RuleAction.SUPPRESS,
        )
        result = evaluate_signal(sig, ctx, [rule])
        self.assertIsNone(result.finding)
        self.assertIsNotNone(result.suppressed_finding)
        self.assertIs(result.suppressing_rule, rule)


class SourcePrecedenceTests(unittest.TestCase):

    def test_user_rule_overrides_default(self):
        sig = _make_signal(signal_id="DYN002")
        ctx = _make_context(file_kind=FileKind.SETUP_PY)
        default = Rule(
            rule_id="default_rule",
            source=RuleSource.DEFAULT,
            match=RuleMatch(signal_id="DYN002", file_kind=FileKind.SETUP_PY),
            effect=RuleEffect(action=RuleAction.SET_SEVERITY, severity=Severity.HIGH),
        )
        user = Rule(
            rule_id="USER001",
            source=RuleSource.USER,
            match=RuleMatch(signal_id="DYN002"),
            effect=RuleEffect(action=RuleAction.SET_SEVERITY, severity=Severity.LOW),
        )
        # Default is more specific (2 vs 1) but user wins anyway.
        result = evaluate_signal(sig, ctx, [default, user])
        self.assertEqual(result.finding.severity, Severity.LOW)

    def test_user_suppression_records_what_default_would_have_done(self):
        sig = _make_signal(signal_id="DYN002")
        ctx = _make_context(file_kind=FileKind.SETUP_PY)
        default = Rule(
            rule_id="default_dyn002_setup_py",
            source=RuleSource.DEFAULT,
            match=RuleMatch(signal_id="DYN002", file_kind=FileKind.SETUP_PY),
            effect=RuleEffect(action=RuleAction.SET_SEVERITY, severity=Severity.HIGH),
        )
        user = Rule(
            rule_id="USER001",
            source=RuleSource.USER,
            match=RuleMatch(signal_id="DYN002"),
            effect=RuleEffect(action=RuleAction.SUPPRESS),
        )
        result = evaluate_signal(sig, ctx, [default, user])
        self.assertIsNone(result.finding)
        self.assertEqual(result.suppressing_rule.rule_id, "USER001")
        # The would-have-been should reflect the default's HIGH severity.
        self.assertEqual(result.would_have_been.severity, Severity.HIGH)

    def test_specificity_within_same_source(self):
        sig = _make_signal(signal_id="DYN002")
        ctx = _make_context(file_kind=FileKind.SETUP_PY)
        broad = Rule(
            rule_id="broad",
            source=RuleSource.DEFAULT,
            match=RuleMatch(signal_id="DYN002"),
            effect=RuleEffect(action=RuleAction.SET_SEVERITY, severity=Severity.MEDIUM),
        )
        specific = Rule(
            rule_id="specific",
            source=RuleSource.DEFAULT,
            match=RuleMatch(signal_id="DYN002", file_kind=FileKind.SETUP_PY),
            effect=RuleEffect(action=RuleAction.SET_SEVERITY, severity=Severity.HIGH),
        )
        result = evaluate_signal(sig, ctx, [broad, specific])
        # More specific wins among same-source rules.
        self.assertEqual(result.finding.severity, Severity.HIGH)


class SetDescriptionTests(unittest.TestCase):

    def test_description_override(self):
        sig = _make_signal(description="generic description")
        ctx = _make_context()
        rule = Rule(
            rule_id="test",
            source=RuleSource.DEFAULT,
            match=RuleMatch(),
            effect=RuleEffect(
                action=RuleAction.SET_DESCRIPTION,
                description="more specific message",
            ),
        )
        result = evaluate_signal(sig, ctx, [rule])
        self.assertEqual(result.finding.signal.description, "more specific message")


if __name__ == "__main__":
    unittest.main()