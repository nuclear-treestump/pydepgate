"""pydepgate.rules.groups.density

Code-density signal group.

Holds rules and explanations for the DENS001..DENS051 signals plus
both context bands: startup-vector files (where DENS findings are
high-confidence attack indicators) and LIBRARY_PY files (where
deep-mode scans calibrate severity for legitimate-library
false-positive shapes).

This is the largest group module by far: 58 rules, 13 signal
explanations, 58 rule explanations.

Module-level constants:
    RULES, SIGNAL_EXPLANATIONS, RULE_EXPLANATIONS.
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
# Rules: startup-vector context
# ---------------------------------------------------------------------------

RULES = [
    # -----------------------------------------------------------------------
    # DENS001: single-line token compression
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS002: semicolon chaining
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS010: high-entropy string literal
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS011: base64-alphabet string literal
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS020: low-vowel-ratio identifier
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS021: confusable single-character identifier
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS030: invisible Unicode character
    # -----------------------------------------------------------------------
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
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "Invisible Unicode anywhere in source is suspicious. The "
            "Trojan Source attack class (CVE-2021-42574) is precisely "
            "this. MEDIUM baseline; specific file kinds elevate to CRITICAL."
        ),
    ),
    # -----------------------------------------------------------------------
    # DENS031: Unicode homoglyph in identifier
    # -----------------------------------------------------------------------
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
        effect=_set_severity(Severity.HIGH),
        explain=(
            "Cyrillic or Greek lookalikes in setup.py identifiers exist "
            "to evade scanners that match on 'exec', 'os.system', etc. "
            "HIGH."
        ),
    ),
    Rule(
        rule_id="default_dens031_anywhere",
        source=RuleSource.DEFAULT,
        match=RuleMatch(signal_id="DENS031"),
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "Homoglyph characters in identifiers are almost always an "
            "attack indicator. The known false positive (legitimate "
            "non-Latin variable names in non-English codebases) does "
            "occur, so MEDIUM rather than CRITICAL as a baseline."
        ),
    ),
    # -----------------------------------------------------------------------
    # DENS040: disproportionate AST depth
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS041: deep lambda/comprehension nesting
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS042: large integer literal array
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS050: high-entropy docstring
    # -----------------------------------------------------------------------
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
    # -----------------------------------------------------------------------
    # DENS051: dynamic __doc__ reference passed to a callable
    # -----------------------------------------------------------------------
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
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "__doc__ piped to a callable is unusual outside introspection "
            "tooling. MEDIUM baseline; users with legitimate introspection "
            "code can suppress."
        ),
    ),
    # -----------------------------------------------------------------------
    # Rules: LIBRARY_PY context (deep mode)
    #
    # Calibrated for the false-positive shapes that occur in real
    # library code. Most signals fall into two buckets: "no legitimate
    # use case" (Unicode anomalies, docstring smuggling) and "common
    # in legitimate code" (entropy from UUIDs, structural patterns
    # from generated code). Severities reflect the bucket.
    # -----------------------------------------------------------------------
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
        effect=_set_severity(Severity.MEDIUM),
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
        effect=_set_severity(Severity.MEDIUM),
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
        effect=_set_severity(Severity.MEDIUM),
        explain=(
            "Reading __doc__ and passing it to a callable isn't rare in "
            "library code. Introspection tooling does this legitimately "
            "(can be suppressed via user rule); the rest is the "
            "execution half of docstring-payload smuggling."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Signal explanations
# ---------------------------------------------------------------------------

SIGNAL_EXPLANATIONS = {
    "DENS001": {
        "description": (
            "A single physical line contains an anomalously high number "
            "of tokens, indicating minification or deliberate compression."
        ),
        "why_it_matters": (
            "Minified Python is rare in legitimate packages distributed "
            "via PyPI. Even densely-written Python rarely exceeds 30-35 "
            "tokens per line. 100+ tokens on one line is almost always "
            "either machine-generated (which has its own concerns in "
            "startup-vector files) or deliberately packed to evade human "
            "review and naive scanners."
        ),
        "common_evasions": [
            "Splitting a packed payload across two slightly-shorter lines ",
            "to dodge the per-line threshold",
            (
                "Embedding the payload in a string literal and exec'ing it "
                "(caught by encoding_abuse and DENS010 instead)"
            ),
        ],
    },
    "DENS002": {
        "description": (
            "Multiple Python statements joined by semicolons on a single "
            "physical line."
        ),
        "why_it_matters": (
            "Semicolon chaining is rare in idiomatic Python and is a "
            "near-universal hallmark of one-liner payloads, REPL pastes, "
            "and minified attack code. .pth exec lines that chain "
            "subprocess.Popen with sys.exit follow this exact shape."
        ),
    },
    "DENS010": {
        "description": (
            "A string literal whose Shannon entropy and length together "
            "are consistent with encoded, compressed, or encrypted data."
        ),
        "why_it_matters": (
            "High-entropy strings in source are almost never user-readable "
            "content. They are usually base64, gzip, or other encoded "
            "payloads. The thresholds are calibrated against real attacks: "
            "base64-encoded Python source lands at ~5.2-5.4 bits/char, "
            "and the AMBIGUOUS confidence tier exists specifically to "
            "catch this band. Rules promote AMBIGUOUS to MEDIUM/HIGH/"
            "CRITICAL for setup.py and .pth files."
        ),
        "common_evasions": [
            "Splitting the payload into multiple shorter literals ",
            "(STR-class signals catch the assembly)",
            "XOR-encoding the payload first to lower its entropy ",
            "(typically still high enough to fire MEDIUM)",
            "Embedding inside a docstring (caught by DENS050)",
        ],
    },
    "DENS011": {
        "description": (
            "A long string literal whose character set is restricted to "
            "the base64 alphabet."
        ),
        "why_it_matters": (
            "DENS010 measures entropy; DENS011 measures alphabet shape. "
            "A string can be clearly base64 by alphabet without quite "
            "meeting the entropy threshold (e.g. encoded text with "
            "repeated structure). DENS011 covers this gap. The two "
            "signals are intentionally complementary and may both fire "
            "on a single string."
        ),
    },
    "DENS020": {
        "description": (
            "An identifier with a very low vowel ratio (consonant-heavy), "
            "consistent with random or machine-generated naming."
        ),
        "why_it_matters": (
            "Real code uses names humans can pronounce; obfuscated or "
            "automatically-generated code often does not. This signal is "
            "noisy on its own (legitimate abbreviations exist) but "
            "valuable as one piece of evidence among many. Default rules "
            "give it LOW severity."
        ),
    },
    "DENS021": {
        "description": (
            "Single-character identifier 'l', 'O', or 'I' used as a " "variable name."
        ),
        "why_it_matters": (
            "PEP 8 explicitly prohibits these because they are visually "
            "indistinguishable from 1, 0, and 1 in many fonts. In "
            "obfuscated code they appear deliberately to confuse readers; "
            "in normal code they appear by mistake. Default rules treat "
            "this as INFO: stylistic, not security-critical, but worth "
            "surfacing in code review."
        ),
    },
    "DENS030": {
        "description": (
            "An invisible Unicode character (zero-width space, joiner, "
            "BOM, RTL override, etc.) appears in the source."
        ),
        "why_it_matters": (
            "This is the Trojan Source attack class (CVE-2021-42574). "
            "Invisible characters can hide content from human reviewers "
            "while still being executed by the parser, or reorder the "
            "visual rendering of source so that what a reader sees is "
            "not what the interpreter runs. RTL overrides specifically "
            "weaponize this; pydepgate flags those with DEFINITE "
            "confidence."
        ),
        "common_evasions": [
            "Using less-known invisible codepoints not in pydepgate's ",
            "list (the project keeps a curated set of high-impact ones)",
            "Encoding the source so the invisible character only ",
            "appears post-decode (caught by DENS010)",
        ],
    },
    "DENS031": {
        "description": (
            "A non-ASCII character that is visually identical to an "
            "ASCII letter is used in a Python identifier."
        ),
        "why_it_matters": (
            "Cyrillic and Greek letters that look exactly like Latin "
            "letters allow attackers to write identifiers that read as "
            "'exec' or 'os.system' to humans but are completely "
            "different strings to scanners that match on byte content. "
            "This bypasses every grep-based defense. Detection is "
            "DEFINITE: it is a positive identification of the codepoint."
        ),
    },
    "DENS040": {
        "description": (
            "The AST is unusually deep relative to the file's line count, "
            "indicating expression compression."
        ),
        "why_it_matters": (
            "Code that does a lot of work on a few lines must compress "
            "expressions: deeply nested calls, lambdas, comprehensions, "
            "ternaries. While generated code (Cython, parser tables) "
            "shows this pattern legitimately, in setup.py and .pth files "
            "it is a strong attack indicator."
        ),
    },
    "DENS041": {
        "description": (
            "Lambdas or comprehensions are nested beyond the configured "
            "depth threshold."
        ),
        "why_it_matters": (
            "Functional-style obfuscation chains lambdas and "
            "comprehensions to make control flow opaque. While "
            "occasionally seen in math-heavy code, three-deep nesting "
            "of lambda within comprehension within lambda is rare "
            "outside deliberately compressed code."
        ),
    },
    "DENS042": {
        "description": (
            "A list or tuple literal contains many byte-range (0-255) "
            "integers, suggesting shellcode or payload staging."
        ),
        "why_it_matters": (
            "Byte arrays embedded as integer lists are a classic way to "
            "smuggle binary payloads through string-content scanners. "
            "Real shellcode-staging packages do exactly this and call "
            "bytes(...) on the array before passing it to ctypes or "
            "compile(). Cryptographic constants and lookup tables are "
            "the main false-positive class; default rules use LOW "
            "severity outside startup vectors."
        ),
    },
    "DENS050": {
        "description": (
            "A string in docstring position has high Shannon entropy "
            "and length, suggesting encoded content disguised as "
            "documentation."
        ),
        "why_it_matters": (
            "Docstrings are an attractive hiding place for payloads: "
            "they live in __doc__ (machine-readable), are visually "
            "innocuous (humans skim past long docstrings), and are not "
            "caught by string-literal scanners that ignore docstring "
            "position. A package that does `exec(__doc__.split('---')[1])` "
            "is using the docstring as a payload carrier."
        ),
    },
    "DENS051": {
        "description": (
            "A reference to __doc__ is passed as an argument to a " "function call."
        ),
        "why_it_matters": (
            "Reading __doc__ and handing it to a callable is the "
            "execution half of the docstring-payload pattern: DENS050 "
            "smuggles the content, DENS051 invokes it. Some "
            "introspection tools legitimately read __doc__, so the "
            "default severity is HIGH (not CRITICAL) outside startup "
            "vectors."
        ),
    },
}


# ---------------------------------------------------------------------------
# Rule explanations
# ---------------------------------------------------------------------------

RULE_EXPLANATIONS = {
    # DENS001
    "default_dens001_in_pth": {
        "description": "Promotes DENS001 in .pth files to HIGH severity.",
        "why_it_matters": (
            "Token-dense lines in .pth have no legitimate use; .pth "
            "files contain paths or short imports."
        ),
        "applies_to": "DENS001 signals in .pth files",
        "effect": "severity = HIGH",
    },
    "default_dens001_in_setup_py": {
        "description": "Promotes DENS001 in setup.py to HIGH severity.",
        "why_it_matters": (
            "Minification in setup.py is an attack indicator; build "
            "tools generate readable setup.py."
        ),
        "applies_to": "DENS001 signals in setup.py",
        "effect": "severity = HIGH",
    },
    "default_dens001_in_sitecustomize": {
        "description": "Promotes DENS001 in sitecustomize.py to HIGH.",
        "why_it_matters": (
            "Compressed lines in sitecustomize.py at every interpreter "
            "startup is not a defensible pattern."
        ),
        "applies_to": "DENS001 signals in sitecustomize.py",
        "effect": "severity = HIGH",
    },
    "default_dens001_anywhere": {
        "description": "Sets DENS001 anywhere to LOW severity.",
        "why_it_matters": (
            "Token-dense lines in arbitrary code can be legitimate "
            "(generated parsers, configuration). LOW baseline."
        ),
        "applies_to": "All DENS001 signals",
        "effect": "severity = LOW",
    },
    # DENS002
    "default_dens002_in_pth": {
        "description": "Promotes DENS002 in .pth files to HIGH severity.",
        "why_it_matters": (
            "Semicolon chains in .pth exec lines are a packing pattern "
            "with no legitimate counterpart."
        ),
        "applies_to": "DENS002 signals in .pth files",
        "effect": "severity = HIGH",
    },
    "default_dens002_in_setup_py": {
        "description": "Promotes DENS002 in setup.py to HIGH severity.",
        "why_it_matters": (
            "Multiple statements per line in setup.py is unusual; "
            "build configurations are written one statement per line."
        ),
        "applies_to": "DENS002 signals in setup.py",
        "effect": "severity = HIGH",
    },
    "default_dens002_anywhere": {
        "description": "Sets DENS002 anywhere to LOW severity.",
        "why_it_matters": (
            "Semicolon chaining can be a stylistic choice in non-startup "
            "code (one-liners, doctests)."
        ),
        "applies_to": "All DENS002 signals",
        "effect": "severity = LOW",
    },
    # DENS010
    "default_dens010_in_pth": {
        "description": "Promotes DENS010 in .pth files to CRITICAL.",
        "why_it_matters": (
            "High-entropy strings in .pth files match the LiteLLM "
            "1.82.8 attack shape: encoded payload on an auto-execute "
            "vector."
        ),
        "applies_to": "DENS010 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_dens010_in_setup_py": {
        "description": "Promotes DENS010 in setup.py to HIGH severity.",
        "why_it_matters": (
            "Encoded-looking strings in setup.py frequently turn out "
            "to be payloads decoded later in the same file. The HIGH "
            "promotion catches AMBIGUOUS-confidence signals at entropy "
            "~5.3, which is where b64-encoded Python source lands."
        ),
        "applies_to": "DENS010 signals in setup.py",
        "effect": "severity = HIGH",
    },
    "default_dens010_in_sitecustomize": {
        "description": "Promotes DENS010 in sitecustomize.py to CRITICAL.",
        "why_it_matters": (
            "Encoded strings in sitecustomize.py have no legitimate "
            "use; the file runs at every interpreter startup."
        ),
        "applies_to": "DENS010 signals in sitecustomize.py",
        "effect": "severity = CRITICAL",
    },
    "default_dens010_in_init_py": {
        "description": "Sets DENS010 in __init__.py to MEDIUM severity.",
        "why_it_matters": (
            "Some packages legitimately ship binary blobs as base64 "
            "strings in __init__.py. MEDIUM severity surfaces it; "
            "users with intentional embedded blobs can suppress."
        ),
        "applies_to": "DENS010 signals in package __init__.py",
        "effect": "severity = MEDIUM",
    },
    "default_dens010_anywhere": {
        "description": "Sets DENS010 anywhere to LOW severity.",
        "why_it_matters": (
            "High-entropy strings outside startup vectors are common "
            "(UUIDs, hashes, fixture data)."
        ),
        "applies_to": "All DENS010 signals",
        "effect": "severity = LOW",
    },
    "default_dens010_huge_anywhere": {
        "description": (
            "Escalates DENS010 to CRITICAL when the high-entropy string "
            "is at least 10240 bytes long, regardless of which file "
            "contains it."
        ),
        "why_it_matters": (
            "Above 10KB, the legitimate uses of base64-or-similar encoded "
            "string literals essentially evaporate. Embedded test "
            "certificates are typically 1-3KB; embedded fonts and icons "
            "are usually ~2-8KB; legitimate fixture data is rarely this "
            "large. The 10KB-and-up band is dominated by intentionally "
            "embedded code or configuration. The LiteLLM 1.82.8 "
            "second-payload at proxy_server.py:130 is 34460 bytes; the "
            "sibling .pth payload is 34501 bytes."
        ),
        "applies_to": "DENS010 in any file kind, when length >= 10240",
        "effect": "Severity set to CRITICAL",
    },
    "default_dens010_long_anywhere": {
        "description": (
            "Escalates DENS010 to HIGH when the high-entropy string is "
            "at least 1024 bytes long, regardless of file kind."
        ),
        "why_it_matters": (
            "Above 1KB, high-entropy string literals are well past the "
            "embedded-test-cert / embedded-asset band where most "
            "legitimate uses live. Below 10KB they're not yet definitively "
            "payloads, but they're worth surfacing at HIGH severity for "
            "review. Users who ship larger encoded blobs intentionally "
            "(certificates pinned for offline use, embedded model "
            "weights) can suppress this rule with a user rule scoped to "
            "their package."
        ),
        "applies_to": (
            "DENS010 in init_py, library_py, or files without a more "
            "specific high-baseline rule, when length >= 1024. Does not "
            "downgrade rules for .pth, sitecustomize, or setup.py "
            "(those baselines are already HIGH or CRITICAL)."
        ),
        "effect": "Severity set to HIGH",
    },
    # DENS011
    "default_dens011_huge_anywhere": {
        "description": (
            "Escalates DENS011 to CRITICAL when the base64-shaped string "
            "is at least 10240 bytes long, regardless of file kind."
        ),
        "why_it_matters": (
            "A base64-alphabet string of 10KB or more in Python source "
            "is not a thing legitimate code does. Every reference case "
            "I've seen at this length is an encoded payload waiting to "
            "be decoded. The signal complements DENS010_huge_anywhere: "
            "DENS011 fires on alphabet membership without requiring "
            "high entropy, catching cases where the string is "
            "deliberately padded or chunked to look less suspicious."
        ),
        "applies_to": "DENS011 in any file kind, when length >= 10240",
        "effect": "Severity set to CRITICAL",
    },
    "default_dens011_long_anywhere": {
        "description": (
            "Escalates DENS011 to HIGH when the base64-shaped string is "
            "at least 1024 bytes long, regardless of file kind."
        ),
        "why_it_matters": (
            "Past 1KB, base64-alphabet strings are well past the band "
            "where embedded certificates and small assets live. Worth "
            "surfacing at HIGH severity even in less-suspicious file "
            "kinds. Suppress per-package via a user rule for legitimate "
            "use cases."
        ),
        "applies_to": (
            "DENS011 in init_py, library_py, or files without a more "
            "specific high-baseline rule, when length >= 1024."
        ),
        "effect": "Severity set to HIGH",
    },
    "default_dens011_in_pth": {
        "description": "Promotes DENS011 in .pth files to CRITICAL.",
        "why_it_matters": (
            "A base64-shaped string in a .pth file is an encoded "
            "payload on an auto-execute vector."
        ),
        "applies_to": "DENS011 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_dens011_in_setup_py": {
        "description": "Promotes DENS011 in setup.py to HIGH severity.",
        "why_it_matters": (
            "Long base64 strings in setup.py are rarely innocent and "
            "are often paired with a delayed decode-and-exec."
        ),
        "applies_to": "DENS011 signals in setup.py",
        "effect": "severity = HIGH",
    },
    "default_dens011_anywhere": {
        "description": "Sets DENS011 anywhere to LOW severity.",
        "why_it_matters": (
            "Base64 strings outside startup vectors can be legitimate "
            "(embedded assets, certificates, fixtures)."
        ),
        "applies_to": "All DENS011 signals",
        "effect": "severity = LOW",
    },
    # DENS020
    "default_dens020_anywhere": {
        "description": "Sets DENS020 anywhere to LOW severity.",
        "why_it_matters": (
            "Vowel-poor identifiers correlate with machine-generated "
            "or mangled names but produce false positives. LOW severity "
            "as a contributing signal, not a standalone alert."
        ),
        "applies_to": "All DENS020 signals",
        "effect": "severity = LOW",
    },
    # DENS021
    "default_dens021_anywhere": {
        "description": "Sets DENS021 anywhere to INFO severity.",
        "why_it_matters": (
            "Use of l/O/I as variable names is a PEP 8 issue rather "
            "than a security one. INFO severity surfaces it without "
            "contributing to exit-code escalation."
        ),
        "applies_to": "All DENS021 signals",
        "effect": "severity = INFO",
    },
    # DENS030
    "default_dens030_in_pth": {
        "description": "Promotes DENS030 in .pth files to CRITICAL.",
        "why_it_matters": (
            "Invisible characters in a .pth file are weaponized hiding "
            "on an auto-execute vector."
        ),
        "applies_to": "DENS030 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_dens030_in_setup_py": {
        "description": "Promotes DENS030 in setup.py to CRITICAL.",
        "why_it_matters": (
            "Invisible Unicode in setup.py exists to deceive human "
            "reviewers. There is no benign reason to ship this."
        ),
        "applies_to": "DENS030 signals in setup.py",
        "effect": "severity = CRITICAL",
    },
    "default_dens030_in_sitecustomize": {
        "description": "Promotes DENS030 in sitecustomize.py to CRITICAL.",
        "why_it_matters": (
            "Invisible characters in sitecustomize.py: no legitimate "
            "use, high-impact vector."
        ),
        "applies_to": "DENS030 signals in sitecustomize.py",
        "effect": "severity = CRITICAL",
    },
    "default_dens030_anywhere": {
        "description": "Sets DENS030 anywhere to HIGH severity.",
        "why_it_matters": (
            "Invisible Unicode anywhere in source is suspicious "
            "(Trojan Source / CVE-2021-42574). HIGH baseline."
        ),
        "applies_to": "All DENS030 signals",
        "effect": "severity = HIGH",
    },
    # DENS031
    "default_dens031_in_pth": {
        "description": "Promotes DENS031 in .pth files to CRITICAL.",
        "why_it_matters": (
            "Homoglyphs in a .pth file are a string-match-evasion "
            "technique on an auto-execute vector."
        ),
        "applies_to": "DENS031 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_dens031_in_setup_py": {
        "description": "Promotes DENS031 in setup.py to CRITICAL.",
        "why_it_matters": (
            "Cyrillic/Greek lookalikes in setup.py identifiers exist "
            "to evade scanners that match 'exec', 'os.system', etc."
        ),
        "applies_to": "DENS031 signals in setup.py",
        "effect": "severity = CRITICAL",
    },
    "default_dens031_anywhere": {
        "description": "Sets DENS031 anywhere to HIGH severity.",
        "why_it_matters": (
            "Homoglyph identifiers are almost always an attack indicator. "
            "Legitimate non-Latin variable names are the false positive "
            "class; HIGH rather than CRITICAL accommodates that."
        ),
        "applies_to": "All DENS031 signals",
        "effect": "severity = HIGH",
    },
    # DENS040
    "default_dens040_in_pth": {
        "description": "Promotes DENS040 in .pth files to HIGH.",
        "why_it_matters": (
            "Deeply nested expressions in a .pth file indicate "
            "expression-compression obfuscation."
        ),
        "applies_to": "DENS040 signals in .pth files",
        "effect": "severity = HIGH",
    },
    "default_dens040_in_setup_py": {
        "description": "Promotes DENS040 in setup.py to HIGH.",
        "why_it_matters": (
            "Deep expression nesting in setup.py is a hallmark of "
            "minification or generator output."
        ),
        "applies_to": "DENS040 signals in setup.py",
        "effect": "severity = HIGH",
    },
    "default_dens040_anywhere": {
        "description": "Sets DENS040 anywhere to LOW severity.",
        "why_it_matters": (
            "AST depth disproportionate to line count occurs in "
            "legitimate generated code (Cython, parser tables)."
        ),
        "applies_to": "All DENS040 signals",
        "effect": "severity = LOW",
    },
    # DENS041
    "default_dens041_in_setup_py": {
        "description": "Promotes DENS041 in setup.py to HIGH.",
        "why_it_matters": (
            "Deeply nested lambdas/comprehensions in setup.py are a "
            "common functional-style obfuscation."
        ),
        "applies_to": "DENS041 signals in setup.py",
        "effect": "severity = HIGH",
    },
    "default_dens041_in_pth": {
        "description": "Promotes DENS041 in .pth files to HIGH.",
        "why_it_matters": (
            "Lambda/comprehension nesting in .pth exec lines exists "
            "purely for obfuscation."
        ),
        "applies_to": "DENS041 signals in .pth files",
        "effect": "severity = HIGH",
    },
    "default_dens041_anywhere": {
        "description": "Sets DENS041 anywhere to LOW severity.",
        "why_it_matters": (
            "Functional Python with nested comprehensions is sometimes "
            "stylistic outside startup vectors."
        ),
        "applies_to": "All DENS041 signals",
        "effect": "severity = LOW",
    },
    # DENS042
    "default_dens042_in_pth": {
        "description": "Promotes DENS042 in .pth files to CRITICAL.",
        "why_it_matters": (
            "Large byte-range integer arrays in a .pth file are "
            "payload staging on an auto-execute vector."
        ),
        "applies_to": "DENS042 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_dens042_in_setup_py": {
        "description": "Promotes DENS042 in setup.py to HIGH.",
        "why_it_matters": (
            "Byte-array literals in setup.py are sometimes shellcode "
            "or embedded payloads to be reassembled at install time."
        ),
        "applies_to": "DENS042 signals in setup.py",
        "effect": "severity = HIGH",
    },
    "default_dens042_anywhere": {
        "description": "Sets DENS042 anywhere to LOW severity.",
        "why_it_matters": (
            "Byte-range integer arrays appear legitimately in "
            "cryptographic constants and lookup tables."
        ),
        "applies_to": "All DENS042 signals",
        "effect": "severity = LOW",
    },
    # DENS050
    "default_dens050_huge_anywhere": {
        "description": (
            "Escalates DENS050 to CRITICAL when the high-entropy "
            "docstring is at least 10240 bytes long."
        ),
        "why_it_matters": (
            "A docstring of 10KB or more with high entropy is the "
            "docstring-as-payload pattern at scale. Legitimate "
            "docstrings of this length tend to be technical references "
            "or examples, with entropy in the 4.0-4.5 range; high-entropy "
            "docstrings of this size are payloads. The pattern is "
            "complete via DENS051 (dynamic __doc__ reference passed to "
            "exec/eval) but the size signal alone is enough to escalate."
        ),
        "applies_to": "DENS050 in any file kind, when length >= 10240",
        "effect": "Severity set to CRITICAL",
    },
    "default_dens050_long_anywhere": {
        "description": (
            "Escalates DENS050 to HIGH when the high-entropy docstring "
            "is at least 1024 bytes long, regardless of file kind."
        ),
        "why_it_matters": (
            "Examples-with-base64 in docstrings sometimes happen "
            "legitimately, but rarely past 1KB. Above this threshold "
            "the docstring is doing more than illustrating; it's "
            "carrying content. HIGH severity surfaces these for review "
            "without requiring the full docstring-as-payload pattern "
            "(DENS051) to also be present."
        ),
        "applies_to": (
            "DENS050 in any file kind without a more-specific "
            "high-baseline rule, when length >= 1024."
        ),
        "effect": "Severity set to HIGH",
    },
    "default_dens050_in_pth": {
        "description": "Promotes DENS050 in .pth files to CRITICAL.",
        "why_it_matters": (
            ".pth files do not even normally have meaningful "
            "docstrings; a high-entropy one is almost certainly a "
            "payload smuggling attempt."
        ),
        "applies_to": "DENS050 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_dens050_in_setup_py": {
        "description": "Promotes DENS050 in setup.py to CRITICAL.",
        "why_it_matters": (
            "High-entropy docstrings in setup.py have been used in "
            "real attacks to hide payload text from naive readers; "
            "the docstring is then read back via __doc__ and executed."
        ),
        "applies_to": "DENS050 signals in setup.py",
        "effect": "severity = CRITICAL",
    },
    "default_dens050_anywhere": {
        "description": "Sets DENS050 anywhere to MEDIUM severity.",
        "why_it_matters": (
            "Docstrings hiding encoded content are a known attack "
            "pattern (docstring-as-payload)."
        ),
        "applies_to": "All DENS050 signals",
        "effect": "severity = MEDIUM",
    },
    # DENS051
    "default_dens051_in_pth": {
        "description": "Promotes DENS051 in .pth files to CRITICAL.",
        "why_it_matters": (
            "Reading __doc__ and passing it to a function in a .pth "
            "file is the docstring-payload-execute pattern."
        ),
        "applies_to": "DENS051 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_dens051_in_setup_py": {
        "description": "Promotes DENS051 in setup.py to CRITICAL.",
        "why_it_matters": (
            "Passing __doc__ to a callable from setup.py is the "
            "execution half of DENS050: docstring smuggles, this "
            "executes."
        ),
        "applies_to": "DENS051 signals in setup.py",
        "effect": "severity = CRITICAL",
    },
    "default_dens051_anywhere": {
        "description": "Sets DENS051 anywhere to HIGH severity.",
        "why_it_matters": (
            "__doc__ piped to a callable is unusual outside "
            "introspection tooling. Users with legitimate "
            "introspection code can suppress."
        ),
        "applies_to": "All DENS051 signals",
        "effect": "severity = HIGH",
    },
    # LIBRARY_PY context (deep mode)
    "default_dens001_in_library_py": {
        "description": "Sets DENS001 in library .py files (deep mode) to LOW.",
        "why_it_matters": (
            "Token-dense lines in library code can be vendored bundles "
            "or generated parser output. LOW severity surfaces the "
            "observation without crying wolf."
        ),
        "applies_to": "DENS001 signals in FileKind.LIBRARY_PY (deep mode)",
        "effect": "severity = LOW",
    },
    "default_dens002_in_library_py": {
        "description": "Sets DENS002 in library .py files (deep mode) to LOW.",
        "why_it_matters": (
            "Semicolon-chained statements appear occasionally in "
            "legitimate library code. LOW baseline."
        ),
        "applies_to": "DENS002 signals in FileKind.LIBRARY_PY",
        "effect": "severity = LOW",
    },
    "default_dens010_in_library_py": {
        "description": "Sets DENS010 in library .py files (deep mode) to MEDIUM.",
        "why_it_matters": (
            "High-entropy strings in library code are common (UUIDs, "
            "embedded certificates, base64 image assets) but occasionally "
            "indicate embedded payloads. MEDIUM surfaces them without "
            "contributing to a blocking exit code by default."
        ),
        "applies_to": "DENS010 signals in FileKind.LIBRARY_PY",
        "effect": "severity = MEDIUM",
    },
    "default_dens011_in_library_py": {
        "description": "Sets DENS011 in library .py files (deep mode) to MEDIUM.",
        "why_it_matters": (
            "Base64-shaped strings in library code: same calibration as "
            "DENS010. Embedded assets are the main false-positive class."
        ),
        "applies_to": "DENS011 signals in FileKind.LIBRARY_PY",
        "effect": "severity = MEDIUM",
    },
    "default_dens020_in_library_py": {
        "description": "Sets DENS020 in library .py files (deep mode) to INFO.",
        "why_it_matters": (
            "Vowel-poor identifiers are common in scientific Python "
            "(NumPy-style abbreviations). INFO so the signal does not "
            "contribute to exit-code escalation."
        ),
        "applies_to": "DENS020 signals in FileKind.LIBRARY_PY",
        "effect": "severity = INFO",
    },
    "default_dens021_in_library_py": {
        "description": "Sets DENS021 in library .py files (deep mode) to INFO.",
        "why_it_matters": (
            "Confusable single-character identifiers (l/O/I) are a PEP 8 "
            "issue regardless of file context. INFO baseline."
        ),
        "applies_to": "DENS021 signals in FileKind.LIBRARY_PY",
        "effect": "severity = INFO",
    },
    "default_dens030_in_library_py": {
        "description": "Sets DENS030 in library .py files (deep mode) to HIGH.",
        "why_it_matters": (
            "Invisible Unicode in any source has no benign use case. "
            "Trojan Source / CVE-2021-42574 attack class regardless of "
            "which file in the package contains it."
        ),
        "applies_to": "DENS030 signals in FileKind.LIBRARY_PY",
        "effect": "severity = HIGH",
    },
    "default_dens031_in_library_py": {
        "description": "Sets DENS031 in library .py files (deep mode) to HIGH.",
        "why_it_matters": (
            "Homoglyph identifiers in library code are almost always an "
            "attack indicator. Suppressible via user rule for codebases "
            "that intentionally use non-Latin naming."
        ),
        "applies_to": "DENS031 signals in FileKind.LIBRARY_PY",
        "effect": "severity = HIGH",
    },
    "default_dens040_in_library_py": {
        "description": "Sets DENS040 in library .py files (deep mode) to INFO.",
        "why_it_matters": (
            "AST depth disproportionate to line count is heavily false-"
            "positive on Cython output, parser-generator tables, and "
            "regex literals. INFO baseline for library context."
        ),
        "applies_to": "DENS040 signals in FileKind.LIBRARY_PY",
        "effect": "severity = INFO",
    },
    "default_dens041_in_library_py": {
        "description": "Sets DENS041 in library .py files (deep mode) to INFO.",
        "why_it_matters": (
            "Deep lambda/comprehension nesting is a stylistic choice in "
            "functional Python codebases. INFO baseline."
        ),
        "applies_to": "DENS041 signals in FileKind.LIBRARY_PY",
        "effect": "severity = INFO",
    },
    "default_dens042_in_library_py": {
        "description": "Sets DENS042 in library .py files (deep mode) to LOW.",
        "why_it_matters": (
            "Byte-range integer arrays in library code are usually "
            "lookup tables or cryptographic constants. LOW baseline; "
            "rare malicious cases are still surfaced."
        ),
        "applies_to": "DENS042 signals in FileKind.LIBRARY_PY",
        "effect": "severity = LOW",
    },
    "default_dens050_in_library_py": {
        "description": "Sets DENS050 in library .py files (deep mode) to HIGH.",
        "why_it_matters": (
            "High-entropy docstrings are rare in legitimate library code "
            "and are a known payload-smuggling pattern. HIGH baseline."
        ),
        "applies_to": "DENS050 signals in FileKind.LIBRARY_PY",
        "effect": "severity = HIGH",
    },
    "default_dens051_in_library_py": {
        "description": "Sets DENS051 in library .py files (deep mode) to HIGH.",
        "why_it_matters": (
            "Reading __doc__ and passing it to a callable in library "
            "code is rare. Legitimate introspection tools do this and "
            "can be suppressed via user rule; the rest is the execution "
            "half of docstring-payload smuggling."
        ),
        "applies_to": "DENS051 signals in FileKind.LIBRARY_PY",
        "effect": "severity = HIGH",
    },
}
