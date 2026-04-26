"""
Bundled default rules for pydepgate.

These rules encode pydepgate's baseline policy: what severity to assign
to each signal in each context. Users override these via .gate files;
defaults are starting points, not policy.

Each rule has a descriptive snake_case ID and an explain string that
is surfaced via 'pydepgate explain'.
"""

from __future__ import annotations

from pydepgate.analyzers.base import Scope
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


# -----------------------------------------------------------------------------
# encoding_abuse rules
# -----------------------------------------------------------------------------

DEFAULT_RULES = [
    Rule(
        rule_id="default_enc001_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="ENC001", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Encoded payload then exec/eval/compile inside setup.py is "
            "the canonical pip-install supply-chain attack pattern. "
            "setup.py runs automatically during 'pip install'; encoded "
            "payloads exist to evade scanners. CRITICAL severity is "
            "the right baseline."
        ),
    ),
    Rule(
        rule_id="default_enc001_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="ENC001", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Encoded payload then exec inside a .pth file is the "
            "LiteLLM 1.82.8 attack pattern. .pth files execute at every "
            "Python interpreter startup. There is no legitimate reason "
            "for a .pth file to use base64-decode-then-exec."
        ),
    ),
    Rule(
        rule_id="default_enc001_in_init_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="ENC001", file_kind=FileKind.INIT_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Encoded payload then exec at __init__.py module scope "
            "runs on every import of the package. High severity: "
            "imports are common, executions are silent."
        ),
    ),
    Rule(
        rule_id="default_enc001_in_sitecustomize",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="ENC001", file_kind=FileKind.SITECUSTOMIZE),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "sitecustomize.py runs at every interpreter startup. "
            "Encoded payloads here are essentially indistinguishable "
            "from malware. CRITICAL severity."
        ),
    ),

    # -----------------------------------------------------------------------------
    # dynamic_execution rules
    # -----------------------------------------------------------------------------

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

    # -----------------------------------------------------------------------------
    # string_ops rules
    # -----------------------------------------------------------------------------

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