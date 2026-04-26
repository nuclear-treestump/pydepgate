"""
Human-readable explanations for pydepgate signals and rules.

Two flat dicts surface technical descriptions, why-it-matters context,
and additional metadata for the 'pydepgate explain' command. The
descriptions are written for a security engineer audience; users
learning about Python supply-chain attacks can read these to
understand both the patterns and the rationale.

User-supplied rules with an 'explain' field get their explanations
from the rule itself, not from this module. The lookup logic falls
back to user rules when a query doesn't match a default.
"""

from __future__ import annotations


# Signal explanations. Keyed by signal_id. Each entry is a dict with
# 'description', 'why_it_matters', and optionally 'common_evasions'.
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
"STDLIB001": {
        "description": (
            "Call to a stdlib function that spawns a subprocess or "
            "executes a shell command (subprocess.Popen, os.system, "
            "os.exec*, fork, etc.)."
        ),
        "why_it_matters": (
            "Process spawning during package installation or import "
            "is a common malware pattern: the attacker uses pip's "
            "execution context to run arbitrary commands on the "
            "victim's machine. Legitimate setup.py and __init__.py "
            "files almost never need to spawn subprocesses."
        ),
        "common_evasions": [
            "Aliasing the import: 'from subprocess import Popen as P'",
            "Computing the function name dynamically (caught by "
            "string_ops if the name is obfuscated)",
            "Using shell=True to hide the actual command",
        ],
    },
    "STDLIB002": {
        "description": (
            "Call to a stdlib function that initiates network "
            "communication (urllib, socket, http.client, ftplib, etc.)."
        ),
        "why_it_matters": (
            "Network access from setup.py or startup-vector files is "
            "the primary way malicious packages download additional "
            "payloads after the initial install. It is also used for "
            "data exfiltration: stealing environment variables, "
            "credentials, or machine identification info."
        ),
    },
    "STDLIB003": {
        "description": (
            "Call to ctypes to load a native library (CDLL, WinDLL, "
            "LoadLibrary, etc.)."
        ),
        "why_it_matters": (
            "Native code loaded via ctypes runs outside Python's "
            "execution model and can do anything. Legitimate packages "
            "that wrap native libraries do so via compiled extension "
            "modules, not runtime ctypes loads. ctypes calls in "
            "pure-Python packages are unusual enough to warrant "
            "investigation."
        ),
    },
}


# Rule explanations. Keyed by rule_id. Each entry is a dict with
# 'description', 'why_it_matters', 'applies_to', and 'effect'.
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
"default_stdlib001_in_setup_py": {
        "description": "Promotes STDLIB001 in setup.py to CRITICAL severity.",
        "why_it_matters": (
            "Spawning a subprocess inside setup.py runs arbitrary "
            "commands during 'pip install'. There is no legitimate "
            "use case; build systems should use proper hooks instead."
        ),
        "applies_to": "STDLIB001 signals in setup.py",
        "effect": "severity = CRITICAL",
    },
    "default_stdlib001_in_pth": {
        "description": "Promotes STDLIB001 in .pth files to CRITICAL.",
        "why_it_matters": (
            "Subprocess spawning from a .pth file runs at every "
            "interpreter startup. Essentially indistinguishable from "
            "malware."
        ),
        "applies_to": "STDLIB001 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_stdlib001_in_init_py_module_scope": {
        "description": "Sets STDLIB001 at __init__.py module scope to HIGH.",
        "why_it_matters": (
            "Subprocess spawning at __init__.py module scope runs on "
            "every import. Some legitimate packages do this, but it "
            "warrants close inspection."
        ),
        "applies_to": "STDLIB001 in __init__.py at module scope",
        "effect": "severity = HIGH",
    },
    "default_stdlib001_in_sitecustomize": {
        "description": "Promotes STDLIB001 in sitecustomize.py to CRITICAL.",
        "why_it_matters": (
            "Subprocess spawning from sitecustomize.py runs at every "
            "interpreter startup with the user's privileges."
        ),
        "applies_to": "STDLIB001 signals in sitecustomize.py",
        "effect": "severity = CRITICAL",
    },
    "default_stdlib002_in_setup_py": {
        "description": "Sets STDLIB002 in setup.py to HIGH severity.",
        "why_it_matters": (
            "Network access from setup.py is rarely legitimate and "
            "is the main way malicious packages exfiltrate data or "
            "download additional payloads."
        ),
        "applies_to": "STDLIB002 signals in setup.py",
        "effect": "severity = HIGH",
    },
    "default_stdlib002_in_pth": {
        "description": "Promotes STDLIB002 in .pth files to CRITICAL.",
        "why_it_matters": (
            "Network access from .pth files runs at every interpreter "
            "startup. No legitimate use case."
        ),
        "applies_to": "STDLIB002 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_stdlib002_in_init_py_module_scope": {
        "description": "Sets STDLIB002 at __init__.py module scope to HIGH.",
        "why_it_matters": (
            "Network access at __init__.py module scope runs on every "
            "import. Legitimate packages defer network calls to "
            "explicit functions."
        ),
        "applies_to": "STDLIB002 in __init__.py at module scope",
        "effect": "severity = HIGH",
    },
    "default_stdlib003_in_setup_py": {
        "description": "Promotes STDLIB003 in setup.py to CRITICAL.",
        "why_it_matters": (
            "Loading a native library from setup.py is a strong "
            "attack indicator. Native code can do anything during "
            "pip install."
        ),
        "applies_to": "STDLIB003 signals in setup.py",
        "effect": "severity = CRITICAL",
    },
    "default_stdlib003_in_pth": {
        "description": "Promotes STDLIB003 in .pth files to CRITICAL.",
        "why_it_matters": (
            "Loading native libraries from .pth files runs at every "
            "interpreter startup."
        ),
        "applies_to": "STDLIB003 signals in .pth files",
        "effect": "severity = CRITICAL",
    },
    "default_stdlib003_anywhere": {
        "description": "Sets STDLIB003 anywhere to HIGH severity.",
        "why_it_matters": (
            "ctypes calls in pure-Python packages are uncommon. "
            "Packages that legitimately wrap native libraries use "
            "compiled extensions, not runtime ctypes loads. Users "
            "with legitimate ctypes use can suppress via a user rule."
        ),
        "applies_to": "All STDLIB003 signals",
        "effect": "severity = HIGH",
    },
}


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