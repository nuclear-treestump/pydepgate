"""
Aggregator for the per-group rules and explanations.

Each group module under pydepgate.rules.groups exposes three module-
level constants:

    RULES                  list[Rule]
    SIGNAL_EXPLANATIONS    dict[signal_id, dict]
    RULE_EXPLANATIONS      dict[rule_id, dict]

This aggregator imports each group statically (no dynamic discovery,
to preserve the picklability contract documented in CONTRIBUTING.md)
and assembles them into the public top-level constants:

    DEFAULT_RULES          list[Rule]
    SIGNAL_EXPLANATIONS    dict[signal_id, dict]
    RULE_EXPLANATIONS      dict[rule_id, dict]

The backwards-compat shims at pydepgate.rules.defaults and
pydepgate.rules.explanations re-export from here so existing imports
keep working.
"""

from __future__ import annotations

from pydepgate.rules.groups import (
    encoding,
    dynamic,
    string_ops,
    stdlib,
    density,
)


DEFAULT_RULES = (
    encoding.RULES
    + dynamic.RULES
    + string_ops.RULES
    + stdlib.RULES
    + density.RULES
)


SIGNAL_EXPLANATIONS = {
    **encoding.SIGNAL_EXPLANATIONS,
    **dynamic.SIGNAL_EXPLANATIONS,
    **string_ops.SIGNAL_EXPLANATIONS,
    **stdlib.SIGNAL_EXPLANATIONS,
    **density.SIGNAL_EXPLANATIONS,
}


RULE_EXPLANATIONS = {
    **encoding.RULE_EXPLANATIONS,
    **dynamic.RULE_EXPLANATIONS,
    **string_ops.RULE_EXPLANATIONS,
    **stdlib.RULE_EXPLANATIONS,
    **density.RULE_EXPLANATIONS,
}


__all__ = [
    "DEFAULT_RULES",
    "SIGNAL_EXPLANATIONS",
    "RULE_EXPLANATIONS",
]