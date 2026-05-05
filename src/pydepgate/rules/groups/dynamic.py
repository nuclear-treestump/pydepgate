"""pydepgate.rules.groups.dynamic

Dynamic-execution signal group.

Holds rules and explanations for the DYN001..DYN007 signals plus the
DYN006_PRECURSOR explanation. Note that DYN001, DYN003, DYN004 have
signal explanations but no default rules; the rules engine falls
through to whatever the analyzer assigned in those cases. This is
intentional and preserved by the refactor.

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
        rule_id="default_dyn002_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DYN002", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Module-level exec/eval/compile with non-literal argument "
            "in setup.py. setup.py runs during pip install with no "
            "user interaction. There is no legitimate reason for "
            "module-level dynamic code execution here."
        ),
    ),
    Rule(
        rule_id="default_dyn002_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DYN002", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Module-level dynamic exec inside a .pth file runs at "
            "every interpreter startup. CRITICAL: this is the LiteLLM "
            "attack pattern."
        ),
    ),
    Rule(
        rule_id="default_dyn005_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DYN005"),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Reaching into builtins via getattr/globals/locals/vars "
            "to access exec/eval/compile/__import__ by string lookup "
            "is intentional evasion. High severity regardless of "
            "context; legitimate code does not need this pattern."
        ),
    ),
    Rule(
        rule_id="default_dyn006_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DYN006"),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Compile-then-exec across a file: a compile() result is "
            "later passed to exec or eval. This two-step construct has "
            "no legitimate use that doesn't have a simpler equivalent."
        ),
    ),
    Rule(
        rule_id="default_dyn007_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DYN007", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Aliased exec shape (some_call(decode(...)) where some_call "
            "may be an aliased exec primitive) inside setup.py. The "
            "specific evasion pattern that exists to defeat naive "
            "static analysis."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Signal explanations
# ---------------------------------------------------------------------------

SIGNAL_EXPLANATIONS = {
    "DYN001": {
        "description": (
            "exec/eval/compile called at module scope with a literal "
            "string argument."
        ),
        "why_it_matters": (
            "Bare exec at module scope with a literal is unusual in "
            "legitimate code. While the literal argument means the "
            "code being executed is statically visible, the pattern is "
            "frequently a remnant of debugging code that should have "
            "been removed, or a precursor to more sophisticated "
            "obfuscation."
        ),
    },
    "DYN002": {
        "description": (
            "exec/eval/compile called at module scope with a "
            "non-literal argument."
        ),
        "why_it_matters": (
            "Module-level dynamic code execution where the argument is "
            "computed at runtime is the canonical 'arbitrary code "
            "execution' vulnerability. The code being executed is not "
            "visible in the source, and the execution happens "
            "automatically when the module loads."
        ),
        "common_evasions": [
            "Computing the exec argument via string concatenation",
            "Loading the argument from a config file or environment",
            "Using f-strings to assemble code dynamically",
        ],
    },
    "DYN003": {
        "description": (
            "exec/eval/compile called inside a function or class with "
            "a non-literal argument."
        ),
        "why_it_matters": (
            "Lower priority than module-scope dynamic execution because "
            "function bodies often have legitimate reasons to use "
            "exec (templating, plugin systems, test frameworks). Still "
            "worth flagging because the pattern's presence in untrusted "
            "code is a yellow flag."
        ),
    },
    "DYN004": {
        "description": (
            "__import__ or importlib.import_module with a non-literal "
            "module name."
        ),
        "why_it_matters": (
            "Computed module names defeat static dependency analysis. "
            "An attacker can use this to import modules whose names "
            "are themselves obfuscated or loaded from untrusted "
            "sources, evading dependency auditing tools."
        ),
    },
    "DYN005": {
        "description": (
            "Reaching into builtins via getattr/globals/locals/vars "
            "to access an exec primitive by string lookup."
        ),
        "why_it_matters": (
            "There is no legitimate reason to access exec, eval, or "
            "compile via string lookup when they are available as "
            "direct names. This pattern exists specifically to evade "
            "scanners that match on the names of dangerous builtins."
        ),
        "common_evasions": [
            "getattr(__builtins__, 'eval')",
            "globals()['exec']",
            "Constructing the attribute name via string operations",
        ],
    },
    "DYN006": {
        "description": (
            "Compile-then-exec pattern: a compile() result is later "
            "passed to exec or eval somewhere else in the file."
        ),
        "why_it_matters": (
            "Two-step dynamic execution constructs serve no purpose "
            "that single-step execution doesn't, except to confuse "
            "static analyzers. The separation between compile and exec "
            "is itself the evasion."
        ),
    },
    "DYN006_PRECURSOR": {
        "description": (
            "compile() called with mode='exec'. Even without a "
            "following exec, this creates a code object intended for "
            "execution."
        ),
        "why_it_matters": (
            "compile-with-exec-mode creates a code object that can be "
            "executed later. There is no legitimate reason to compile "
            "code with mode='exec' and not execute it; the pattern is "
            "either a precursor to dynamic execution or vestigial code."
        ),
    },
    "DYN007": {
        "description": (
            "Aliased exec shape: a call to an unresolvable name whose "
            "first argument is itself a decode call."
        ),
        "why_it_matters": (
            "Catches the 'e = exec; e(b64decode(...))' evasion. We "
            "cannot resolve what 'e' refers to, but the call shape "
            "(unknown_name(decode_call(...))) is suspicious enough to "
            "flag on its own."
        ),
    },
}


# ---------------------------------------------------------------------------
# Rule explanations
# ---------------------------------------------------------------------------

RULE_EXPLANATIONS = {
    "default_dyn002_in_setup_py": {
        "description": "Sets DYN002 in setup.py to HIGH severity.",
        "why_it_matters": (
            "Module-level exec/eval/compile with non-literal argument "
            "in setup.py. setup.py runs during 'pip install' with no "
            "user interaction. There is no legitimate reason for "
            "module-level dynamic code execution there."
        ),
        "applies_to": "DYN002 signals in setup.py",
        "effect": "severity = HIGH",
    },
    "default_dyn002_in_pth": {
        "description": "Promotes DYN002 in .pth files to CRITICAL.",
        "why_it_matters": (
            "Module-level dynamic exec inside a .pth file runs at "
            "every interpreter startup. CRITICAL: this is the LiteLLM "
            "attack pattern."
        ),
        "applies_to": "DYN002 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_dyn005_anywhere": {
        "description": "Sets DYN005 anywhere to HIGH severity.",
        "why_it_matters": (
            "Reaching into builtins via getattr/globals/locals/vars to "
            "access exec/eval/compile/__import__ by string lookup is "
            "intentional evasion. High severity regardless of context; "
            "legitimate code does not need this pattern."
        ),
        "applies_to": "All DYN005 signals",
        "effect": "severity = HIGH",
    },
    "default_dyn006_anywhere": {
        "description": "Sets DYN006 anywhere to HIGH severity.",
        "why_it_matters": (
            "Compile-then-exec across a file: a compile() result is "
            "later passed to exec or eval. This two-step construct has "
            "no legitimate use that doesn't have a simpler equivalent."
        ),
        "applies_to": "All DYN006 signals",
        "effect": "severity = HIGH",
    },
    "default_dyn007_in_setup_py": {
        "description": "Sets DYN007 in setup.py to HIGH severity.",
        "why_it_matters": (
            "Aliased exec shape inside setup.py. The specific evasion "
            "pattern that exists to defeat naive static analysis."
        ),
        "applies_to": "DYN007 signals in setup.py",
        "effect": "severity = HIGH",
    },
}