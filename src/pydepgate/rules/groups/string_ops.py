"""pydepgate.rules.groups.string_ops

String-operations signal group.

Holds rules and explanations for the STR001..STR004 signals. STR001
has a signal explanation but no default rule, which means analyzer
confidence drives severity; that's intentional and preserved here.

Module-level constants:
    RULES, SIGNAL_EXPLANATIONS, RULE_EXPLANATIONS.
"""

from __future__ import annotations

from pydepgate.engines.base import Severity
from pydepgate.rules.base import (
    Rule,
    RuleAction,
    RuleEffect,
    RuleMatch,
    RuleSource,
)
from pydepgate.traffic_control.triage import FileKind


def _set_severity(severity: Severity) -> RuleEffect:
    return RuleEffect(action=RuleAction.SET_SEVERITY, severity=severity)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RULES = [
    Rule(
        rule_id="default_str002_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STR002", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Obfuscated string resolves to a sensitive name and is "
            "passed to a dangerous function inside setup.py. The "
            "obfuscation is intentional; the dangerous use is "
            "intentional. CRITICAL severity."
        ),
    ),
    Rule(
        rule_id="default_str002_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STR002"),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Obfuscated string resolves to a sensitive name and is "
            "passed to a dangerous function. The combination is rarely "
            "innocent, regardless of file context."
        ),
    ),
    Rule(
        rule_id="default_str003_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STR003"),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Variable holding obfuscated sensitive name is later used "
            "in a dangerous function. The two-step construct exists "
            "specifically to evade simpler analyzers."
        ),
    ),
    Rule(
        rule_id="default_str004_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STR004", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Heavy string obfuscation in setup.py that pydepgate could "
            "not fully resolve. Even without knowing the resolved "
            "value, this much obfuscation in setup.py is suspicious."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Signal explanations
# ---------------------------------------------------------------------------

SIGNAL_EXPLANATIONS = {
    "STR001": {
        "description": (
            "Standalone obfuscated expression resolves to a sensitive "
            "name. Not seen used in a dangerous call here, but the "
            "obfuscation is itself worth noting."
        ),
        "why_it_matters": (
            "An expression like 'ev' + 'al' that resolves to 'eval' "
            "but appears in benign code may indicate prep work for "
            "obfuscated execution elsewhere, or a remnant of attacker "
            "tooling."
        ),
    },
    "STR002": {
        "description": (
            "Obfuscated expression resolves to a sensitive name and "
            "is passed directly to a dangerous function."
        ),
        "why_it_matters": (
            "The combination of obfuscation and dangerous use is "
            "rarely innocent. Legitimate code does not assemble "
            "exec primitive names from character codes and pass them "
            "to getattr."
        ),
        "common_evasions": [
            "chr() concatenation: chr(101) + chr(118) + chr(97) + chr(108)",
            "String reversal: 'lave'[::-1]",
            "Bytes from list: bytes([101, 118, 97, 108]).decode()",
        ],
    },
    "STR003": {
        "description": (
            "Variable assigned an obfuscated sensitive name is later "
            "used as the argument to a dangerous function."
        ),
        "why_it_matters": (
            "Two-step obfuscation: build the sensitive name in one "
            "place, use it in another. The separation defeats analyzers "
            "that only look at single expressions."
        ),
    },
    "STR004": {
        "description": (
            "Heavily obfuscated expression where pydepgate could not "
            "fully resolve the value, but the expression used many "
            "obfuscation operations."
        ),
        "why_it_matters": (
            "The 'harder they hide it the stronger the signal' "
            "principle: when an expression uses many transformations "
            "to assemble a value pydepgate cannot fully resolve, the "
            "obfuscation effort itself is the signal."
        ),
    },
}


# ---------------------------------------------------------------------------
# Rule explanations
# ---------------------------------------------------------------------------

RULE_EXPLANATIONS = {
    "default_str002_in_setup_py": {
        "description": "Promotes STR002 in setup.py to CRITICAL severity.",
        "why_it_matters": (
            "Obfuscated string resolves to a sensitive name and is "
            "passed to a dangerous function inside setup.py. The "
            "obfuscation is intentional; the dangerous use is "
            "intentional. CRITICAL severity."
        ),
        "applies_to": "STR002 signals in setup.py",
        "effect": "severity = CRITICAL",
    },
    "default_str002_anywhere": {
        "description": "Sets STR002 anywhere to HIGH severity.",
        "why_it_matters": (
            "Obfuscated string resolves to a sensitive name and is "
            "passed to a dangerous function. The combination is rarely "
            "innocent, regardless of file context."
        ),
        "applies_to": "All STR002 signals",
        "effect": "severity = HIGH",
    },
    "default_str003_anywhere": {
        "description": "Sets STR003 anywhere to HIGH severity.",
        "why_it_matters": (
            "Variable holding obfuscated sensitive name is later used "
            "in a dangerous function. The two-step construct exists "
            "specifically to evade simpler analyzers."
        ),
        "applies_to": "All STR003 signals",
        "effect": "severity = HIGH",
    },
    "default_str004_in_setup_py": {
        "description": "Sets STR004 in setup.py to HIGH severity.",
        "why_it_matters": (
            "Heavy string obfuscation in setup.py that pydepgate could "
            "not fully resolve. Even without knowing the resolved "
            "value, this much obfuscation in setup.py is suspicious."
        ),
        "applies_to": "STR004 signals in setup.py",
        "effect": "severity = HIGH",
    },
}