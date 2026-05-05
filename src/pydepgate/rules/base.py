"""pydepgate.rules.base

Core data structures and evaluator for the pydepgate rules engine.

This module defines:
  - RuleAction, RuleSource: enums describing what a rule does and
    where it came from.
  - ContextPredicate: a typed predicate over a single signal.context
    field (gte, lte, contains, in, etc).
  - RuleMatch: the match conditions a rule checks against a signal
    plus its scan context. All non-None fields must match.
  - RuleEffect: what to do when a rule matches.
  - Rule: a complete rule (match + effect + identity metadata).
  - evaluate_signal: turns a signal plus rules plus context into a
    Finding (or marks it suppressed).

The evaluator is pure: same inputs always produce the same outputs.
It does not maintain state between calls.

Backward-compatibility note: the legacy `RuleMatch.context_contains`
field is now a shim. At construction time it's normalized into
`context_predicates` as a dict of `eq` predicates. Both fields are
preserved on the dataclass for inspection, but only
`context_predicates` is consulted at match time.
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


# ---------------------------------------------------------------------------
# Context predicates
# ---------------------------------------------------------------------------

# Operators supported by ContextPredicate. Centralized so the loader's
# validation and the evaluator's dispatch share one source of truth.
VALID_OPERATORS = frozenset({
    # Numeric / comparable
    "eq", "ne", "gt", "gte", "lt", "lte",
    # String
    "contains", "startswith", "endswith",
    # Collection membership
    "in", "not_in",
})


@dataclass(frozen=True)
class ContextPredicate:
    """A predicate over a single field of Signal.context.

    Each predicate has an operator and a value. The operator decides
    how the actual context value is compared against `self.value`.
    Type-safety is best-effort: invalid type combinations
    (e.g. `gte` with a string actual) cause the predicate to fail
    rather than raise, so a single mistyped predicate doesn't blow
    up an entire scan.

    Operators:
      Numeric/comparable: eq, ne, gt, gte, lt, lte
      String:             eq, ne, contains, startswith, endswith
      Collection:         in, not_in

    `eq` and `ne` work for any type. `contains` works on strings
    (substring match) and on lists/tuples (membership). `in`/`not_in`
    test whether the actual value appears in `self.value`, which
    must be a list, tuple, or set.
    """
    op: str
    value: Any

    def evaluate(self, actual: Any) -> bool:
        """Apply the predicate to a signal's context value.

        Returns False on type mismatches (e.g. comparing a string
        with `gte`) rather than raising. The loader catches unknown
        operators at file-load time, so this method's "unknown
        operator" branch is defensive.
        """
        op = self.op
        try:
            if op == "eq":
                return actual == self.value
            if op == "ne":
                return actual != self.value
            if op == "gt":
                return actual > self.value
            if op == "gte":
                return actual >= self.value
            if op == "lt":
                return actual < self.value
            if op == "lte":
                return actual <= self.value
            if op == "contains":
                return self.value in actual
            if op == "startswith":
                if not isinstance(actual, str):
                    return False
                return actual.startswith(self.value)
            if op == "endswith":
                if not isinstance(actual, str):
                    return False
                return actual.endswith(self.value)
            if op == "in":
                return actual in self.value
            if op == "not_in":
                return actual not in self.value
        except (TypeError, ValueError):
            return False
        return False  # unknown operator


# ---------------------------------------------------------------------------
# Rule data model
# ---------------------------------------------------------------------------


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
        context_contains: LEGACY. Subset match against Signal.context
            with strict equality on each pair. Internally shimmed to
            context_predicates at construction; preserved on the
            dataclass for backward inspection. New code should use
            context_predicates directly.
        context_predicates: Dict mapping context-field-name to
            ContextPredicate. Each predicate is checked against the
            signal's context; all must pass for the rule to match.
    """
    signal_id: str | None = None
    analyzer: str | None = None
    file_kind: FileKind | None = None
    scope: Scope | None = None
    path_glob: str | None = None
    context_contains: dict[str, Any] | None = None
    context_predicates: dict[str, ContextPredicate] | None = None

    def __post_init__(self) -> None:
        """Shim: normalize context_contains into context_predicates.

        If both fields are provided, predicates from
        context_predicates take precedence on key collision (the
        explicit predicate wins over the implicit eq-shim).
        """
        if self.context_contains is None:
            return
        shimmed = {
            k: ContextPredicate(op="eq", value=v)
            for k, v in self.context_contains.items()
        }
        if self.context_predicates is None:
            object.__setattr__(self, "context_predicates", shimmed)
        else:
            # Merge: explicit predicates win on collision.
            merged = {**shimmed, **self.context_predicates}
            object.__setattr__(self, "context_predicates", merged)

    def specificity(self) -> int:
        """Count of non-None match fields. More specific = higher value.

        Used as a tiebreaker among rules from the same source. Across
        sources, RuleSource ordering wins regardless of specificity.

        Note: context_contains is no longer counted directly because
        it's shimmed into context_predicates by __post_init__. Each
        predicate counts as 1.
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
        if self.context_predicates is not None:
            count += len(self.context_predicates)
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
    if m.context_predicates is not None:
        for key, predicate in m.context_predicates.items():
            if key not in signal.context:
                return False
            if not predicate.evaluate(signal.context[key]):
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