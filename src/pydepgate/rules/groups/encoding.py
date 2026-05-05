"""pydepgate.rules.groups.encoding

Encoding-abuse signal group.

Holds rules and explanations for the ENC001 (decode-then-execute) and
ENC002 (deeply-nested encoded payload) signals.

This module exposes three module-level constants:

    RULES                  list[Rule]: default rules for the ENC family.
    SIGNAL_EXPLANATIONS    dict[signal_id, dict]: human-readable
                           descriptions for each signal in the family.
    RULE_EXPLANATIONS      dict[rule_id, dict]: human-readable
                           descriptions for each rule in this module.

The aggregator in pydepgate.rules.groups.__init__ assembles these
into the public DEFAULT_RULES / SIGNAL_EXPLANATIONS / RULE_EXPLANATIONS
that the rest of the codebase consumes via rules.defaults and
rules.explanations.
"""

from __future__ import annotations

from pydepgate.engines.base import Severity
from pydepgate.rules.base import (
    ContextPredicate,
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
# Rules: ENC001 (decode-then-execute)
# ---------------------------------------------------------------------------

RULES = [
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

    # -----------------------------------------------------------------------
    # Rules: ENC002 (deeply-nested encoded payload)
    #
    # Emitted by the payload_peek enricher when the unwrap chain reaches
    # 2+ transformations or exhausts the configured depth limit. The
    # analyzer-side confidence reflects depth (AMBIGUOUS at 2,
    # MEDIUM at 3, HIGH on exhaustion); these rules promote to severity
    # based on file kind.
    # -----------------------------------------------------------------------

    Rule(
        rule_id="default_enc002_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="ENC002", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Any encoded payload in a .pth file is the LiteLLM 1.82.8 "
            "shape; nesting it 2+ deep is gratuitous obfuscation on top "
            "of an already-illegitimate use of the .pth vector. "
            "CRITICAL regardless of unwrap depth or terminal kind."
        ),
    ),
    Rule(
        rule_id="default_enc002_in_sitecustomize",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="ENC002", file_kind=FileKind.SITECUSTOMIZE,
        ),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "sitecustomize.py runs at every interpreter startup. "
            "Encoded content of any kind is illegitimate here; nested "
            "encoding is decisively malicious."
        ),
    ),
    Rule(
        rule_id="default_enc002_in_usercustomize",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="ENC002", file_kind=FileKind.USERCUSTOMIZE,
        ),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "usercustomize.py shares sitecustomize's auto-execute "
            "vector at user scope. Same reasoning."
        ),
    ),
    Rule(
        rule_id="default_enc002_in_setup_py_exhausted",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="ENC002",
            file_kind=FileKind.SETUP_PY,
            context_predicates={
                "unwrap_status": ContextPredicate(
                    op="eq", value="exhausted_depth",
                ),
            },
        ),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "An encoded payload in setup.py that exceeded the configured "
            "unwrap depth limit is the strongest possible signal short of "
            "actual decoded content: legitimate setup.py code never wraps "
            "anything more than once."
        ),
    ),
    Rule(
        rule_id="default_enc002_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="ENC002", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Two or more layers of encoding around a payload in setup.py "
            "is rarely innocent. Even when the unwrap loop completed "
            "cleanly, the obfuscation pattern is a strong signal."
        ),
    ),
    Rule(
        rule_id="default_enc002_in_init_py_python_source",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="ENC002",
            file_kind=FileKind.INIT_PY,
            context_predicates={
                "final_kind": ContextPredicate(
                    op="eq", value="python_source",
                ),
            },
        ),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Nested encoding in __init__.py whose final form is Python "
            "source has no benign interpretation: the package is hiding "
            "executable code behind multiple decode steps."
        ),
    ),
    Rule(
        rule_id="default_enc002_in_init_py_exhausted",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="ENC002",
            file_kind=FileKind.INIT_PY,
            context_predicates={
                "unwrap_status": ContextPredicate(
                    op="eq", value="exhausted_depth",
                ),
            },
        ),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Encoded content in __init__.py that wanted to chain past "
            "the unwrap depth limit. HIGH because some packages legitimately "
            "ship deeply-nested encoded assets, but the pattern is "
            "uncommon enough to surface."
        ),
    ),
    Rule(
        rule_id="default_enc002_in_init_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="ENC002", file_kind=FileKind.INIT_PY),
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "Two or more encoding layers around content in __init__.py. "
            "Some packages legitimately ship encoded assets this deep; "
            "MEDIUM surfaces the observation without overstating it."
        ),
    ),
    Rule(
        rule_id="default_enc002_exhausted_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="ENC002",
            context_predicates={
                "unwrap_status": ContextPredicate(
                    op="eq", value="exhausted_depth",
                ),
            },
        ),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "An encoded payload that chained past the configured unwrap "
            "depth limit. The chain would have continued; we stopped. "
            "HIGH everywhere because this pattern essentially never "
            "appears in legitimate code."
        ),
    ),
    Rule(
        rule_id="default_enc002_python_source_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="ENC002",
            context_predicates={
                "final_kind": ContextPredicate(
                    op="eq", value="python_source",
                ),
            },
        ),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Nested encoding around a Python source payload is the "
            "exact obfuscation pattern used to defeat string-match "
            "scanners. HIGH regardless of file kind."
        ),
    ),
    Rule(
        rule_id="default_enc002_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="ENC002"),
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "Two or more encoding layers around a payload. MEDIUM "
            "baseline; rule precedence promotes specific shapes (Python "
            "source terminal, exhausted depth, certain file kinds) to "
            "HIGH or CRITICAL above this."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Signal explanations
# ---------------------------------------------------------------------------

SIGNAL_EXPLANATIONS = {
    "ENC001": {
        "description": (
            "Decode-then-execute pattern: encoded content (base64, hex, "
            "compressed bytes) is decoded and immediately passed to "
            "exec, eval, compile, or __import__."
        ),
        "why_it_matters": (
            "This is the most common pattern in Python supply-chain "
            "malware. The encoding exists to evade static scanners that "
            "match string contents. The exec primitive then executes "
            "whatever was encoded, making the package's runtime "
            "behavior fundamentally hidden from inspection. The LiteLLM "
            "1.82.8 attack used exactly this pattern in a .pth file."
        ),
        "common_evasions": [
            "Aliasing the exec primitive (e = exec; e(b64decode(...)))",
            "Chaining multiple decoders (zlib + base64)",
            "Splitting the payload across multiple variables",
        ],
    },
    "ENC002": {
        "description": (
            "Deeply-nested encoded payload: a string literal that, when "
            "passed through the unwrap loop, required 2+ transformations "
            "to reach a terminal form (or exhausted the depth limit "
            "with more decoding still possible)."
        ),
        "why_it_matters": (
            "Single-layer encoding (base64-then-exec) is the LiteLLM "
            "1.82.8 attack pattern; one decode step is enough to defeat "
            "naive string-match scanners. Nested encoding (b64 of zlib "
            "of b64 of source) exists specifically to defeat the next "
            "layer of static analysis: a scanner that sees and decodes "
            "the outer base64 still has to decompress and decode again "
            "to reach the actual payload. Each additional layer is "
            "evidence of intent to evade. Three or more layers, or any "
            "chain that wanted to keep going past the unwrap depth "
            "limit, has no benign interpretation we have ever observed."
        ),
        "common_evasions": [
            "Splitting the encoded payload across multiple variables ",
            "and concatenating before decode (string_ops STR-class "
            "signals catch the assembly).",
            "Using uncommon encoding combinations (lzma + b85, etc.) ",
            "to fall outside the unwrap loop's recognized transforms.",
            "Encoding the inner payload as a Python int array then ",
            "rebuilding it via a list comprehension (DENS042 catches ",
            "the array shape).",
        ],
    },
}


# ---------------------------------------------------------------------------
# Rule explanations
# ---------------------------------------------------------------------------

RULE_EXPLANATIONS = {
    "default_enc001_in_setup_py": {
        "description": "Promotes ENC001 in setup.py to CRITICAL severity.",
        "why_it_matters": (
            "Encoded payload then exec inside setup.py is the canonical "
            "pip-install supply-chain attack pattern. setup.py runs "
            "automatically during 'pip install'; encoded payloads in "
            "setup.py exist solely to evade scanners. CRITICAL severity "
            "is the right baseline."
        ),
        "applies_to": "ENC001 signals in files classified as setup.py",
        "effect": "severity = CRITICAL",
    },
    "default_enc001_in_pth": {
        "description": "Promotes ENC001 in .pth files to CRITICAL severity.",
        "why_it_matters": (
            "Encoded payload then exec inside a .pth file is the LiteLLM "
            "1.82.8 attack pattern. .pth files execute at every Python "
            "interpreter startup. There is no legitimate reason for a "
            ".pth file to use base64-decode-then-exec."
        ),
        "applies_to": "ENC001 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_enc001_in_init_py": {
        "description": "Sets ENC001 in __init__.py to HIGH severity.",
        "why_it_matters": (
            "Encoded payload then exec at __init__.py module scope runs "
            "on every import of the package. High severity: imports are "
            "common, executions are silent."
        ),
        "applies_to": "ENC001 signals in package __init__.py files",
        "effect": "severity = HIGH",
    },
"default_enc001_in_sitecustomize": {
        "description": "Promotes ENC001 in sitecustomize.py to CRITICAL.",
        "why_it_matters": (
            "sitecustomize.py runs at every interpreter startup. "
            "Encoded payloads here are essentially indistinguishable "
            "from malware."
        ),
        "applies_to": "ENC001 signals in sitecustomize.py",
        "effect": "severity = CRITICAL",
    },

    # -----------------------------------------------------------------------
    # ENC002 rule explanations
    #
    # Order matches the rule definitions in RULES above so that
    # readers comparing the two halves of the file can scan in
    # parallel.
    # -----------------------------------------------------------------------

    "default_enc002_in_pth": {
        "description": "Promotes ENC002 in .pth files to CRITICAL severity.",
        "why_it_matters": (
            "Any encoded payload in a .pth file is the LiteLLM 1.82.8 "
            "shape: an encoded payload carried by an auto-execute vector "
            "that runs at every interpreter startup. Nesting that "
            "payload across two or more decode layers is gratuitous "
            "obfuscation on top of an already-illegitimate use of the "
            ".pth vector. CRITICAL applies regardless of unwrap depth "
            "or the kind of content the chain ultimately produces."
        ),
        "applies_to": "ENC002 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_enc002_in_sitecustomize": {
        "description": (
            "Promotes ENC002 in sitecustomize.py to CRITICAL severity."
        ),
        "why_it_matters": (
            "sitecustomize.py runs at every interpreter startup with "
            "the user's privileges. Encoded content of any kind is "
            "illegitimate in this file; nested encoding (two or more "
            "decode layers around the same payload) is decisively "
            "malicious."
        ),
        "applies_to": "ENC002 signals in sitecustomize.py",
        "effect": "severity = CRITICAL",
    },
    "default_enc002_in_usercustomize": {
        "description": (
            "Promotes ENC002 in usercustomize.py to CRITICAL severity."
        ),
        "why_it_matters": (
            "usercustomize.py shares sitecustomize.py's auto-execute "
            "vector at the user-site scope. The reasoning that makes "
            "ENC002 in sitecustomize.py CRITICAL applies identically "
            "here. Treating both files the same way prevents an "
            "attacker from preferring whichever vector a less-strict "
            "policy happens to have left open."
        ),
        "applies_to": "ENC002 signals in usercustomize.py",
        "effect": "severity = CRITICAL",
    },
    "default_enc002_in_setup_py_exhausted": {
        "description": (
            "Promotes ENC002 in setup.py to CRITICAL severity when the "
            "unwrap loop exhausted its configured depth limit."
        ),
        "why_it_matters": (
            "An encoded payload in setup.py whose unwrap chain wanted "
            "to keep going past the configured depth limit is the "
            "strongest possible signal short of actual decoded content. "
            "Legitimate setup.py code never wraps anything more than "
            "once; a chain that exhausted depth has no benign "
            "interpretation."
        ),
        "applies_to": (
            "ENC002 signals in setup.py where context predicate "
            "unwrap_status == 'exhausted_depth'"
        ),
        "effect": "severity = CRITICAL",
    },
    "default_enc002_in_setup_py": {
        "description": "Sets ENC002 in setup.py to HIGH severity.",
        "why_it_matters": (
            "Two or more layers of encoding around a payload in "
            "setup.py is rarely innocent. Even when the unwrap loop "
            "completed cleanly (the chain reached a terminal form "
            "rather than exhausting depth), the obfuscation pattern "
            "is a strong signal that the package is hiding something."
        ),
        "applies_to": (
            "ENC002 signals in setup.py without a more-specific "
            "predicate-bearing rule (the exhausted-depth variant "
            "promotes to CRITICAL above this baseline)"
        ),
        "effect": "severity = HIGH",
    },
    "default_enc002_in_init_py_python_source": {
        "description": (
            "Promotes ENC002 in __init__.py to CRITICAL when the "
            "unwrapped final form is Python source."
        ),
        "why_it_matters": (
            "Nested encoding in __init__.py whose chain ultimately "
            "decodes to Python source has no benign interpretation: "
            "the package is hiding executable code behind multiple "
            "decode steps. Legitimate embedded assets unwrap to "
            "binary blobs (certificates, fonts, model weights), not "
            "to Python source."
        ),
        "applies_to": (
            "ENC002 signals in __init__.py where context predicate "
            "final_kind == 'python_source'"
        ),
        "effect": "severity = CRITICAL",
    },
    "default_enc002_in_init_py_exhausted": {
        "description": (
            "Sets ENC002 in __init__.py to HIGH when the unwrap loop "
            "exhausted its configured depth limit."
        ),
        "why_it_matters": (
            "Encoded content in __init__.py that wanted to chain past "
            "the unwrap depth limit. HIGH rather than CRITICAL "
            "because some packages legitimately ship deeply-nested "
            "encoded assets in __init__.py (compressed lookup tables, "
            "embedded model parameters), but the pattern is uncommon "
            "enough to surface for review."
        ),
        "applies_to": (
            "ENC002 signals in __init__.py where context predicate "
            "unwrap_status == 'exhausted_depth' and the final-kind "
            "predicate did not also match (Python-source terminal "
            "promotes to CRITICAL via a different rule)"
        ),
        "effect": "severity = HIGH",
    },
    "default_enc002_in_init_py": {
        "description": "Sets ENC002 in __init__.py to MEDIUM severity.",
        "why_it_matters": (
            "Two or more encoding layers around content in __init__.py "
            "as a baseline. Some packages legitimately ship encoded "
            "assets this deep; MEDIUM surfaces the observation without "
            "overstating it. More-specific predicate-bearing rules "
            "(Python source terminal, exhausted depth) promote above "
            "this baseline."
        ),
        "applies_to": (
            "ENC002 signals in __init__.py without a more-specific "
            "predicate-bearing rule"
        ),
        "effect": "severity = MEDIUM",
    },
    "default_enc002_exhausted_anywhere": {
        "description": (
            "Sets ENC002 to HIGH severity anywhere when the unwrap "
            "loop exhausted its configured depth limit."
        ),
        "why_it_matters": (
            "An encoded payload that chained past the configured "
            "unwrap depth limit. The chain would have continued; the "
            "unwrap loop stopped. HIGH everywhere because this "
            "pattern essentially never appears in legitimate code, "
            "regardless of which file kind contains it. More-specific "
            "file-kind rules promote to CRITICAL where the file kind "
            "is itself a startup-vector or auto-execute path."
        ),
        "applies_to": (
            "ENC002 signals in any file kind where context predicate "
            "unwrap_status == 'exhausted_depth' (catch-all baseline; "
            "specific file kinds may promote further)"
        ),
        "effect": "severity = HIGH",
    },
    "default_enc002_python_source_anywhere": {
        "description": (
            "Sets ENC002 to HIGH severity anywhere when the unwrap "
            "chain decoded to Python source."
        ),
        "why_it_matters": (
            "Nested encoding around a Python source payload is the "
            "exact obfuscation pattern used to defeat string-match "
            "scanners. HIGH everywhere because the combination of "
            "nesting and Python-source terminal has no benign use, "
            "regardless of file kind. Specific file-kind rules "
            "promote to CRITICAL for startup-vector files."
        ),
        "applies_to": (
            "ENC002 signals in any file kind where context predicate "
            "final_kind == 'python_source' (catch-all baseline)"
        ),
        "effect": "severity = HIGH",
    },
    "default_enc002_anywhere": {
        "description": "Sets ENC002 to MEDIUM severity as a baseline.",
        "why_it_matters": (
            "Two or more encoding layers around a payload at the "
            "lowest specificity. MEDIUM is the floor; rule precedence "
            "promotes specific shapes (Python source terminal, "
            "exhausted depth, certain file kinds) to HIGH or CRITICAL "
            "above this. This baseline ensures every ENC002 finding "
            "lands at MEDIUM at minimum, even when no more-specific "
            "rule matches."
        ),
        "applies_to": "All ENC002 signals (catch-all baseline)",
        "effect": "severity = MEDIUM",
    },
}