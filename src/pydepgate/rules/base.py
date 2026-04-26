"""
Core data structures and evaluator for the pydepgate rules engine.

This module defines:
  - RuleAction, RuleSource: enums describing what a rule does and
    where it came from.
  - RuleMatch: the match conditions a rule checks against a signal
    plus its scan context. All non-None fields must match.
  - RuleEffect: what to do when a rule matches.
  - Rule: a complete rule (match + effect + identity metadata).
  - evaluate_signal: turns a signal plus rules plus context into a
    Finding (or marks it suppressed).

The evaluator is pure: same inputs always produce the same outputs.
It does not maintain state between calls.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydepgate.analyzers.base import Scope, Signal
from pydepgate.engines.base import (
    Finding,
    ScanContext,
    Severity,
    confidence_to_severity_v01,
)
from pydepgate.traffic_control.triage import FileKind


class RuleAction(Enum):
    """What action a matching rule takes."""
    SET_SEVERITY = "set_severity"
    SUPPRESS = "suppress"
    SET_DESCRIPTION = "set_description"


class RuleSource(Enum):
    """Where a rule came from. Used for differentiating user rules
    from defaults in output and for precedence resolution."""
    DEFAULT = "default"
    SYSTEM = "system"
    USER = "user"


@dataclass(frozen=True)
class RuleMatch:
    """Conditions that must all be satisfied for a rule to match.

    All non-None fields are checked against the signal and context.
    A rule with all-None fields matches every signal (uncommon but
    useful for catch-all rules).

    Attributes:
        signal_id: Exact match against Signal.signal_id.
        analyzer: Exact match against Signal.analyzer.
        file_kind: Match against the triage decision's FileKind.
        scope: Match against Signal.scope.
        path_glob: fnmatch-style pattern matched against the file's
            internal_path. Use '/' as separator. e.g. 'tests/**/*.py'.
        context_contains: Subset match against Signal.context. Every
            key/value pair in this dict must be present in the
            signal's context with equal value.
    """
    signal_id: str | None = None
    analyzer: str | None = None
    file_kind: FileKind | None = None
    scope: Scope | None = None
    path_glob: str | None = None
    context_contains: dict[str, Any] | None = None

    def specificity(self) -> int:
        """Count of non-None match fields. More specific = higher value.

        Used as a tiebreaker among rules from the same source. Across
        sources, RuleSource ordering wins regardless of specificity.
        """
        count = 0
        if self.signal_id is not None:
            count += 1
        if self.analyzer is not None:
            count += 1
        if self.file_kind is not None:
            count += 1
        if self.scope is not None:
            count += 1
        if self.path_glob is not None:
            count += 1
        if self.context_contains is not None:
            count += len(self.context_contains)
        return count


@dataclass(frozen=True)
class RuleEffect:
    """What a matching rule does to the resulting finding."""
    action: RuleAction
    severity: Severity | None = None
    description: str | None = None


@dataclass(frozen=True)
class Rule:
    """A complete rule: match conditions plus effect plus identity.

    Attributes:
        rule_id: Identifier for this rule. Defaults are named
            descriptively; user rules are auto-numbered USER001 etc
            unless the user provides an explicit id.
        source: Where this rule came from.
        match: Conditions to evaluate.
        effect: What to do when matched.
        explain: Human-readable rationale. Optional but encouraged.
            Surfaced via 'pydepgate explain'.
    """
    rule_id: str
    source: RuleSource
    match: RuleMatch
    effect: RuleEffect
    explain: str = ""


def matches(rule: Rule, signal: Signal, context: ScanContext) -> bool:
    """Check whether a rule's match conditions are satisfied."""
    m = rule.match
    if m.signal_id is not None and signal.signal_id != m.signal_id:
        return False
    if m.analyzer is not None and signal.analyzer != m.analyzer:
        return False
    if m.file_kind is not None and context.file_kind is not m.file_kind:
        return False
    if m.scope is not None and signal.scope is not m.scope:
        return False
    if m.path_glob is not None:
        if not fnmatch.fnmatchcase(context.internal_path, m.path_glob):
            return False
    if m.context_contains is not None:
        for key, value in m.context_contains.items():
            if key not in signal.context:
                return False
            if signal.context[key] != value:
                return False
    return True


# Source precedence: user wins over system wins over default. This is
# the contract per design decision: user rules trump defaults
# regardless of specificity. Within a source, more specific rules win;
# within source-and-specificity ties, load order determines.
_SOURCE_PRIORITY = {
    RuleSource.USER: 2,
    RuleSource.SYSTEM: 1,
    RuleSource.DEFAULT: 0,
}


def _select_winning_rule(applicable: list[Rule]) -> Rule:
    """Among applicable rules, pick the winner.

    Ranking:
      1. Higher source priority wins (user > system > default).
      2. Among rules of the same source, higher specificity wins.
      3. Among ties, load order (earlier wins) is the tiebreaker.
    """
    def sort_key(rule: Rule) -> tuple:
        return (
            _SOURCE_PRIORITY[rule.source],
            rule.match.specificity(),
        )
    # max() picks the rule with the highest key; among equal keys,
    # the first one encountered wins. So we sort by load order first
    # (preserved by max's behavior on stable sequences), then take max.
    return max(applicable, key=sort_key)


@dataclass(frozen=True)
class EvaluationResult:
    """Outcome of evaluating a signal against the rule set.

    If the signal is not suppressed, finding is set and suppression
    fields are None. If the signal is suppressed, finding is None and
    suppressed_finding plus suppressing_rule and would_have_been are set.
    """
    finding: Finding | None
    suppressed_finding: Finding | None = None
    suppressing_rule: Rule | None = None
    would_have_been: Finding | None = None
    rule_applied: Rule | None = None


def evaluate_signal(
    signal: Signal,
    context: ScanContext,
    rules: list[Rule],
) -> EvaluationResult:
    """Evaluate a single signal against all rules.

    Returns an EvaluationResult that either holds an active Finding or
    a suppression record. Suppressed findings carry information about
    what they would have been without the suppression, so the reporter
    can surface this for auditability.
    """
    applicable = [r for r in rules if matches(r, signal, context)]

    if not applicable:
        # No rule matched: fall back to mechanical confidence mapping.
        return EvaluationResult(
            finding=_finding_from_signal(signal, context, severity=None),
        )

    winner = _select_winning_rule(applicable)

    if winner.effect.action is RuleAction.SUPPRESS:
        # Build the would-have-been Finding by re-running the evaluator
        # with only DEFAULT-source rules. This shows the user what they
        # are suppressing.
        default_rules = [r for r in rules if r.source is RuleSource.DEFAULT]
        if winner.source is RuleSource.DEFAULT:
            # The suppressing rule itself is a default. Edge case:
            # a default rule suppressing a finding. The "would have
            # been" is just the mechanical mapping.
            would_have_been = _finding_from_signal(signal, context, severity=None)
        else:
            default_result = evaluate_signal(signal, context, default_rules)
            would_have_been = default_result.finding
        suppressed_finding = _finding_from_signal(
            signal, context, severity=None
        )
        return EvaluationResult(
            finding=None,
            suppressed_finding=suppressed_finding,
            suppressing_rule=winner,
            would_have_been=would_have_been,
        )

    if winner.effect.action is RuleAction.SET_SEVERITY:
        return EvaluationResult(
            finding=_finding_from_signal(
                signal, context, severity=winner.effect.severity
            ),
            rule_applied=winner,
        )

    if winner.effect.action is RuleAction.SET_DESCRIPTION:
        # Severity falls back to mechanical mapping unless another
        # matching rule set it. Description is overridden.
        finding = _finding_from_signal(signal, context, severity=None)
        new_signal = _signal_with_description(signal, winner.effect.description or signal.description)
        finding = Finding(
            signal=new_signal,
            severity=finding.severity,
            context=finding.context,
        )
        return EvaluationResult(finding=finding, rule_applied=winner)

    # Should not happen; defensive fallback.
    return EvaluationResult(
        finding=_finding_from_signal(signal, context, severity=None),
    )


def _finding_from_signal(
    signal: Signal,
    context: ScanContext,
    severity: Severity | None,
) -> Finding:
    """Build a Finding from a signal, optionally with explicit severity."""
    if severity is None:
        severity = confidence_to_severity_v01(int(signal.confidence))
    return Finding(
        signal=signal,
        severity=severity,
        context=context,
    )


def _signal_with_description(signal: Signal, description: str) -> Signal:
    """Return a copy of signal with the description replaced."""
    from dataclasses import replace
    return replace(signal, description=description)