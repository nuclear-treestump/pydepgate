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
    ContextPredicate
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
    # -----------------------------------------------------------------------------
    # suspicious_stdlib rules
    # -----------------------------------------------------------------------------

    Rule(
        rule_id="default_stdlib001_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STDLIB001", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Spawning a subprocess inside setup.py runs arbitrary "
            "commands during 'pip install'. There is no legitimate "
            "use case for setup.py to invoke shell commands or "
            "subprocesses; build systems use proper hooks instead. "
            "CRITICAL severity."
        ),
    ),
    Rule(
        rule_id="default_stdlib001_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STDLIB001", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Spawning a subprocess from a .pth file runs at every "
            "interpreter startup. Combined with .pth's automatic "
            "execution, this is essentially indistinguishable from "
            "malware. CRITICAL severity."
        ),
    ),
    Rule(
        rule_id="default_stdlib001_in_init_py_module_scope",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="STDLIB001",
            file_kind=FileKind.INIT_PY,
            scope=Scope.MODULE,
        ),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Subprocess spawning at __init__.py module scope runs on "
            "every import of the package. While some legitimate "
            "packages do this (build helpers, conditional native "
            "library loading), it warrants close inspection."
        ),
    ),
    Rule(
        rule_id="default_stdlib001_in_sitecustomize",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="STDLIB001",
            file_kind=FileKind.SITECUSTOMIZE,
        ),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Subprocess spawning from sitecustomize.py runs at every "
            "interpreter startup with the user's privileges. CRITICAL "
            "severity."
        ),
    ),
    Rule(
        rule_id="default_stdlib002_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STDLIB002", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Network access from setup.py during pip install can be "
            "used to download additional payloads or exfiltrate "
            "environment data (env vars, credentials, machine details). "
            "There is rarely a legitimate reason for setup.py to make "
            "network calls."
        ),
    ),
    Rule(
        rule_id="default_stdlib002_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STDLIB002", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Network access from .pth files runs at every interpreter "
            "startup. There is no legitimate use case."
        ),
    ),
    Rule(
        rule_id="default_stdlib002_in_init_py_module_scope",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="STDLIB002",
            file_kind=FileKind.INIT_PY,
            scope=Scope.MODULE,
        ),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Network access at __init__.py module scope runs on every "
            "import. Legitimate packages defer network access until a "
            "function is called; module-scope network access in an "
            "__init__.py is unusual."
        ),
    ),
    Rule(
        rule_id="default_stdlib003_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STDLIB003", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Loading a native library from setup.py is a strong attack "
            "indicator. Native code loaded during pip install can do "
            "anything, including escape any sandbox the installer "
            "might apply. CRITICAL severity."
        ),
    ),
    Rule(
        rule_id="default_stdlib003_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STDLIB003", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Loading a native library from a .pth file runs at every "
            "interpreter startup. CRITICAL severity."
        ),
    ),
    Rule(
        rule_id="default_stdlib003_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="STDLIB003"),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Loading native libraries via ctypes is uncommon in "
            "pure-Python packages. Packages that legitimately wrap "
            "native libraries (numpy, scipy, cryptography, etc.) do so "
            "via compiled extensions, not runtime ctypes loads. HIGH "
            "severity unless the package is known to use ctypes "
            "deliberately; users can suppress via a user rule."
        ),
    ),

    # -----------------------------------------------------------------------------
    # code_density rules
    # -----------------------------------------------------------------------------
    
    # DENS001: single-line token compression
    Rule(
        rule_id="default_dens001_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS001", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Token-dense single lines in a .pth file have no legitimate "
            "use. Real .pth files contain path strings or short import "
            "statements; minified-looking content is always suspicious."
        ),
    ),
    Rule(
        rule_id="default_dens001_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS001", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Minification in setup.py is a strong attack indicator. "
            "Build systems generate readable setup.py; deliberate "
            "compression exists to evade scanners and reviewers."
        ),
    ),
    Rule(
        rule_id="default_dens001_in_sitecustomize",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS001", file_kind=FileKind.SITECUSTOMIZE),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "sitecustomize.py runs at every interpreter startup. "
            "Compressed lines there have no defensible use case."
        ),
    ),
    Rule(
        rule_id="default_dens001_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS001"),
        effect=_set_severity(Severity.LOW),
        explain=(
            "Token-dense lines in arbitrary code can be legitimate "
            "(generated parsers, machine-emitted configuration). LOW "
            "severity: surfaces the observation without crying wolf."
        ),
    ),
    
    # DENS002: semicolon chaining
    Rule(
        rule_id="default_dens002_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS002", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Semicolon-chained statements in .pth exec lines are a "
            "classic packing technique. Legitimate .pth files do not "
            "need them."
        ),
    ),
    Rule(
        rule_id="default_dens002_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS002", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Multiple statements joined by semicolons on one line in "
            "setup.py is rarely innocent. Build configurations are "
            "written one statement per line."
        ),
    ),
    Rule(
        rule_id="default_dens002_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS002"),
        effect=_set_severity(Severity.LOW),
        explain=(
            "Semicolon chaining outside startup vectors can be a stylistic "
            "choice (one-liners, doctests). LOW severity by default; "
            "stricter rules can promote it."
        ),
    ),
    
# DENS010: high-entropy string literal
    Rule(
        rule_id="default_dens010_huge_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="DENS010",
            context_predicates={
                "length": ContextPredicate(op="gte", value=10240),
            },
        ),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "High-entropy string literal of 10KB or more. No legitimate "
            "use of base64-or-similar encoded content in Python source "
            "extends to this length; the band above 10KB is essentially "
            "always a payload. CRITICAL regardless of file kind."
        ),
    ),
    Rule(
        rule_id="default_dens010_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS010", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "High-entropy string in a .pth file is the LiteLLM 1.82.8 "
            "shape: an encoded payload carried by an auto-execute vector. "
            "Even at AMBIGUOUS confidence, the file kind makes this "
            "CRITICAL: legitimate .pth files contain only paths and short "
            "imports."
        ),
    ),
    Rule(
        rule_id="default_dens010_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS010", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "High-entropy strings in setup.py frequently turn out to be "
            "encoded payloads decoded later in the same file. HIGH "
            "severity even at AMBIGUOUS confidence catches the "
            "b64-encoded-source pattern that lands at entropy ~5.3."
        ),
    ),
    Rule(
        rule_id="default_dens010_in_sitecustomize",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS010", file_kind=FileKind.SITECUSTOMIZE),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Encoded-looking strings in sitecustomize.py have no "
            "legitimate use; the file runs at every interpreter startup."
        ),
    ),
    Rule(
        rule_id="default_dens010_long_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="DENS010",
            context_predicates={
                "length": ContextPredicate(op="gte", value=1024),
            },
        ),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "High-entropy string literal of 1KB or more. Past the "
            "embedded-test-cert / embedded-icon size band, but below the "
            "definitively-payload threshold. HIGH baseline; user rules "
            "can suppress for packages that legitimately ship larger "
            "encoded blobs."
        ),
    ),
    Rule(
        rule_id="default_dens010_in_init_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS010", file_kind=FileKind.INIT_PY),
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "Some packages ship binary blobs as base64 strings in "
            "__init__.py (legitimate but uncommon). MEDIUM severity "
            "surfaces the observation; users with intentional embedded "
            "blobs can suppress with a user rule."
        ),
    ),
    Rule(
        rule_id="default_dens010_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS010"),
        effect=_set_severity(Severity.LOW),
        explain=(
            "High-entropy strings outside startup vectors are common "
            "(UUIDs, hashes, fixture data). LOW severity baseline."
        ),
    ),
# DENS011: base64-alphabet string literal
    Rule(
        rule_id="default_dens011_huge_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="DENS011",
            context_predicates={
                "length": ContextPredicate(op="gte", value=10240),
            },
        ),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Base64-shaped string literal of 10KB or more. No legitimate "
            "case I've ever seen in Python packaging extends a base64 "
            "literal to this length; it's a payload. CRITICAL regardless "
            "of file kind."
        ),
    ),
    Rule(
        rule_id="default_dens011_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS011", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "A base64-shaped string in a .pth file is an encoded payload "
            "in an auto-execute vector. CRITICAL regardless of whether "
            "an accompanying decode call is visible."
        ),
    ),
    Rule(
        rule_id="default_dens011_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS011", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Long base64-alphabet strings in setup.py are rarely innocent "
            "and are often paired with a delayed decode-and-exec."
        ),
    ),
    Rule(
        rule_id="default_dens011_long_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="DENS011",
            context_predicates={
                "length": ContextPredicate(op="gte", value=1024),
            },
        ),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Base64-shaped string literal of 1KB or more. Past the "
            "embedded-cert / embedded-asset band where most legitimate "
            "uses live. HIGH baseline; user rules can suppress for "
            "packages with intentional larger blobs."
        ),
    ),
    Rule(
        rule_id="default_dens011_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS011"),
        effect=_set_severity(Severity.LOW),
        explain=(
            "Base64 strings outside startup vectors can be legitimate "
            "(embedded assets, certificates, test fixtures). LOW baseline."
        ),
    ),
    
    # DENS020: low-vowel-ratio identifier
    Rule(
        rule_id="default_dens020_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS020"),
        effect=_set_severity(Severity.LOW),
        explain=(
            "Vowel-poor identifiers correlate with machine-generated or "
            "deliberately mangled names but produce many false positives "
            "(legitimate abbreviations, non-English domains). LOW severity "
            "as a contributing signal, not a standalone alert."
        ),
    ),
    
    # DENS021: confusable single-character identifier
    Rule(
        rule_id="default_dens021_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS021"),
        effect=_set_severity(Severity.INFO),
        explain=(
            "Use of l/O/I as variable names is a PEP 8 issue, not a "
            "security one. INFO severity: surfaces it for code-review "
            "purposes without contributing to exit-code escalation."
        ),
    ),
    
    # DENS030: invisible Unicode character
    Rule(
        rule_id="default_dens030_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS030", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Invisible characters in a .pth file are weaponized hiding. "
            "CRITICAL regardless of which specific codepoint."
        ),
    ),
    Rule(
        rule_id="default_dens030_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS030", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Invisible Unicode in setup.py exists to deceive human "
            "reviewers reading the source. There is no benign reason to "
            "ship this."
        ),
    ),
    Rule(
        rule_id="default_dens030_in_sitecustomize",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS030", file_kind=FileKind.SITECUSTOMIZE),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Invisible characters in sitecustomize.py: no legitimate use, "
            "high-impact vector."
        ),
    ),
    Rule(
        rule_id="default_dens030_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS030"),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Invisible Unicode anywhere in source is suspicious. The "
            "Trojan Source attack class (CVE-2021-42574) is precisely "
            "this. HIGH baseline; specific file kinds elevate to CRITICAL."
        ),
    ),
    
    # DENS031: Unicode homoglyph in identifier
    Rule(
        rule_id="default_dens031_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS031", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Homoglyphs in a .pth file are a string-match-evasion "
            "technique on an auto-execute vector. CRITICAL."
        ),
    ),
    Rule(
        rule_id="default_dens031_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS031", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Cyrillic or Greek lookalikes in setup.py identifiers exist "
            "to evade scanners that match on 'exec', 'os.system', etc. "
            "CRITICAL."
        ),
    ),
    Rule(
        rule_id="default_dens031_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS031"),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Homoglyph characters in identifiers are almost always an "
            "attack indicator. The known false positive (legitimate "
            "non-Latin variable names in non-English codebases) does "
            "occur, so HIGH rather than CRITICAL as a baseline."
        ),
    ),
    
    # DENS040: disproportionate AST depth
    Rule(
        rule_id="default_dens040_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS040", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Deeply nested expressions in a .pth file indicate "
            "expression-compression obfuscation."
        ),
    ),
    Rule(
        rule_id="default_dens040_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS040", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Deep expression nesting in setup.py is a hallmark of "
            "minification or generator-tool output."
        ),
    ),
    Rule(
        rule_id="default_dens040_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS040"),
        effect=_set_severity(Severity.LOW),
        explain=(
            "AST depth disproportionate to line count can occur in "
            "legitimate generated code (Cython, parser tables). LOW "
            "baseline; rules promote for sensitive file kinds."
        ),
    ),
    
    # DENS041: deep lambda/comprehension nesting
    Rule(
        rule_id="default_dens041_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS041", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Deeply nested lambdas/comprehensions in setup.py are a "
            "common functional-style obfuscation."
        ),
    ),
    Rule(
        rule_id="default_dens041_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS041", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Lambda/comprehension nesting in .pth exec lines exists "
            "purely for obfuscation."
        ),
    ),
    Rule(
        rule_id="default_dens041_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS041"),
        effect=_set_severity(Severity.LOW),
        explain=(
            "Functional Python with nested comprehensions is sometimes "
            "stylistic. LOW baseline outside startup vectors."
        ),
    ),
    
    # DENS042: large integer literal array
    Rule(
        rule_id="default_dens042_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS042", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Large byte-range integer arrays in a .pth file are payload "
            "staging on an auto-execute vector."
        ),
    ),
    Rule(
        rule_id="default_dens042_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS042", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Byte-array literals in setup.py are sometimes shellcode or "
            "embedded payloads to be reassembled at install time."
        ),
    ),
    Rule(
        rule_id="default_dens042_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS042"),
        effect=_set_severity(Severity.LOW),
        explain=(
            "Byte-range integer arrays appear legitimately in "
            "cryptographic constants, lookup tables, and embedded "
            "assets. LOW baseline; review-worthy, not block-worthy."
        ),
    ),
    
# DENS050: high-entropy docstring
    Rule(
        rule_id="default_dens050_huge_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="DENS050",
            context_predicates={
                "length": ContextPredicate(op="gte", value=10240),
            },
        ),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "High-entropy docstring of 10KB or more. Legitimate "
            "docstrings of this length and entropy do not exist; "
            "this is the docstring-as-payload pattern at scale. "
            "CRITICAL regardless of file kind."
        ),
    ),
    Rule(
        rule_id="default_dens050_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS050", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Docstrings in .pth files are not even normally meaningful "
            "(.pth files are not Python modules); a high-entropy one is "
            "almost certainly a payload smuggling attempt."
        ),
    ),
    Rule(
        rule_id="default_dens050_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS050", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "High-entropy docstrings in setup.py have been used in real "
            "attacks to hide payload text from naive readers; the "
            "docstring is then read back via __doc__ and executed."
        ),
    ),
    Rule(
        rule_id="default_dens050_long_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(
            signal_id="DENS050",
            context_predicates={
                "length": ContextPredicate(op="gte", value=1024),
            },
        ),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "High-entropy docstring of 1KB or more. Past the band where "
            "examples-with-base64 in docstrings live; this is large "
            "enough to be worth flagging. HIGH baseline."
        ),
    ),
    Rule(
        rule_id="default_dens050_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS050"),
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "Docstrings hiding encoded content are a known attack "
            "pattern (docstring-as-payload). MEDIUM baseline."
        ),
    ),
    
    # DENS051: dynamic __doc__ reference passed to a callable
    Rule(
        rule_id="default_dens051_in_pth",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS051", file_kind=FileKind.PTH),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Reading __doc__ and passing it to a function in a .pth file "
            "is the docstring-payload-execute pattern; CRITICAL."
        ),
    ),
    Rule(
        rule_id="default_dens051_in_setup_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS051", file_kind=FileKind.SETUP_PY),
        effect=_set_severity(Severity.CRITICAL),
        explain=(
            "Passing __doc__ to a callable from setup.py is a known "
            "attack shape: DENS050 hides the payload, DENS051 executes it."
        ),
    ),
    Rule(
        rule_id="default_dens051_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS051"),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "__doc__ piped to a callable is unusual outside introspection "
            "tooling. HIGH baseline; users with legitimate introspection "
            "code can suppress."
        ),
    ),
    # -----------------------------------------------------------------------------
    # code_density rules: LIBRARY_PY (deep mode)
    # -----------------------------------------------------------------------------
    # Calibrated for the false-positive shapes that occur in real
    # library code. Most signals fall into two buckets: "no legitimate
    # use case" (Unicode anomalies, docstring smuggling) and "common
    # in legitimate code" (entropy from UUIDs, structural patterns
    # from generated code). Severities reflect the bucket.

    Rule(
        rule_id="default_dens001_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS001", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.LOW),
        explain=(
            "Token-dense lines in library code can be legitimate (vendored "
            "minified bundles, generated parser tables) but warrant a look. "
            "LOW severity in deep-mode library scans."
        ),
    ),
    Rule(
        rule_id="default_dens002_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS002", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.LOW),
        explain=(
            "Semicolon-chained statements appear occasionally in library "
            "code (one-liners, doctest fragments). LOW severity in deep "
            "mode; user rules can promote for stricter policies."
        ),
    ),
    Rule(
        rule_id="default_dens010_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS010", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "High-entropy strings in library code often turn out to be "
            "UUIDs, embedded certificates, or base64 image assets. They "
            "also occasionally turn out to be embedded payloads. MEDIUM "
            "surfaces the observation without escalating to blocking "
            "severity by default."
        ),
    ),
    Rule(
        rule_id="default_dens011_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS011", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "Base64-shaped strings in library code: same calibration as "
            "DENS010 in the same context. Embedded assets are the main "
            "false-positive class; payloads are the worst case."
        ),
    ),
    Rule(
        rule_id="default_dens020_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS020", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.INFO),
        explain=(
            "Vowel-poor identifiers are common in scientific Python "
            "(NumPy-style abbreviations: nd, lhs, rhs, xt). INFO surfaces "
            "the observation without contributing to exit-code escalation."
        ),
    ),
    Rule(
        rule_id="default_dens021_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS021", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.INFO),
        explain=(
            "PEP 8 confusable identifiers (l/O/I) are a style issue, not "
            "a security one. Same severity as the anywhere rule."
        ),
    ),
    Rule(
        rule_id="default_dens030_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS030", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Invisible Unicode characters in library code have no benign "
            "use case. Trojan Source / CVE-2021-42574 territory regardless "
            "of which file in the package contains them."
        ),
    ),
    Rule(
        rule_id="default_dens031_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS031", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Homoglyph identifiers in library code are almost always an "
            "attack indicator. The legitimate-non-Latin-naming false "
            "positive is suppressible via a user rule for codebases that "
            "intentionally use non-Latin variable names."
        ),
    ),
    Rule(
        rule_id="default_dens040_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS040", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.INFO),
        explain=(
            "AST depth disproportionate to line count is heavily "
            "false-positive on legitimate generated code (Cython output, "
            "parser-generator tables, regex compilations as Python "
            "literals). INFO baseline for library context."
        ),
    ),
    Rule(
        rule_id="default_dens041_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS041", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.INFO),
        explain=(
            "Deep lambda/comprehension nesting is a stylistic choice in "
            "functional Python codebases. INFO baseline for library "
            "context; surfaces the observation without escalating."
        ),
    ),
    Rule(
        rule_id="default_dens042_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS042", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.LOW),
        explain=(
            "Byte-range integer arrays in library code are usually "
            "lookup tables (Unicode categories, color palettes) or "
            "cryptographic constants (S-boxes, magic values). LOW "
            "baseline; rare malicious cases are still surfaced."
        ),
    ),
    Rule(
        rule_id="default_dens050_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS050", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "High-entropy docstrings are rare in legitimate library "
            "code; they're a known smuggling pattern (docstring carries "
            "the payload, runtime decodes via __doc__). HIGH baseline."
        ),
    ),
    Rule(
        rule_id="default_dens051_in_library_py",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS051", file_kind=FileKind.LIBRARY_PY),
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Reading __doc__ and passing it to a callable is rare in "
            "library code. Introspection tooling does this legitimately "
            "(can be suppressed via user rule); the rest is the "
            "execution half of docstring-payload smuggling."
        ),
    ),

]