"""pydpgate.rules.explanations

Human-readable explanations for pydepgate signals and rules.

The dictionaries SIGNAL_EXPLANATIONS and RULE_EXPLANATIONS surface
technical descriptions, why-it-matters context, and additional
metadata for the 'pydepgate explain' command. Their contents are
assembled per-group under pydepgate.rules.groups and aggregated by
pydepgate.rules.groups.__init__; this module re-exports them and
preserves the helper functions used by the explain CLI.

User-supplied rules with an 'explain' field get their explanations
from the rule itself, not from this module. The lookup logic falls
back to user rules when a query doesn't match a default.
"""

from __future__ import annotations

from pydepgate.rules.groups import (
    SIGNAL_EXPLANATIONS,
    RULE_EXPLANATIONS,
)


def explain_signal(signal_id: str) -> dict | None:
    """Look up a signal explanation. Returns None if not found."""
    return SIGNAL_EXPLANATIONS.get(signal_id)


def explain_rule(rule_id: str, user_rules: list | None = None) -> dict | None:
    """Look up a rule explanation.

    First checks bundled rule explanations. If not found, searches
    user_rules for a rule with matching ID and uses its 'explain'
    field if set.
    """
    bundled = RULE_EXPLANATIONS.get(rule_id)
    if bundled is not None:
        return bundled
    if user_rules:
        for rule in user_rules:
            if rule.rule_id == rule_id:
                return {
                    "description": f"User-defined rule {rule_id}",
                    "why_it_matters": (
                        rule.explain or "(no explanation provided)"
                    ),
                    "applies_to": _format_match(rule.match),
                    "effect": _format_effect(rule.effect),
                }
    return None


def _format_match(match) -> str:
    """Render a RuleMatch as a human-readable description."""
    parts = []
    if match.signal_id:
        parts.append(f"signal_id={match.signal_id}")
    if match.analyzer:
        parts.append(f"analyzer={match.analyzer}")
    if match.file_kind:
        parts.append(f"file_kind={match.file_kind.value}")
    if match.scope:
        parts.append(f"scope={match.scope.name.lower()}")
    if match.path_glob:
        parts.append(f"path={match.path_glob}")
    if match.context_contains:
        parts.append(f"context={match.context_contains}")
    return ", ".join(parts) if parts else "all signals (catch-all)"


def _format_effect(effect) -> str:
    """Render a RuleEffect as a human-readable description."""
    if effect.action.value == "set_severity":
        return f"severity = {effect.severity.value.upper()}"
    if effect.action.value == "suppress":
        return "suppress (do not report)"
    if effect.action.value == "set_description":
        return f"description = {effect.description!r}"
    return effect.action.value


def list_all_signal_ids() -> list[str]:
    """Return all signal IDs known to pydepgate."""
    return sorted(SIGNAL_EXPLANATIONS.keys())


def list_all_rule_ids(user_rules: list | None = None) -> list[str]:
    """Return all rule IDs (defaults plus any user rules)."""
    ids = list(RULE_EXPLANATIONS.keys())
    if user_rules:
        ids.extend(r.rule_id for r in user_rules)
    return sorted(set(ids))


__all__ = [
    "SIGNAL_EXPLANATIONS",
    "RULE_EXPLANATIONS",
    "explain_signal",
    "explain_rule",
    "list_all_signal_ids",
    "list_all_rule_ids",
]