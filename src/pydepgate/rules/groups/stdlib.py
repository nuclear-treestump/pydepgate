"""
Suspicious-stdlib signal group.

Holds rules and explanations for the STDLIB001..STDLIB003 signals,
which cover process spawning, network access, and native-library
loading.

Module-level constants:
    RULES, SIGNAL_EXPLANATIONS, RULE_EXPLANATIONS.
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


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RULES = [
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
]


# ---------------------------------------------------------------------------
# Signal explanations
# ---------------------------------------------------------------------------

SIGNAL_EXPLANATIONS = {
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


# ---------------------------------------------------------------------------
# Rule explanations
# ---------------------------------------------------------------------------

RULE_EXPLANATIONS = {
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