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
            "Single-character identifier 'l', 'O', or 'I' used as a "
            "variable name."
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
            "A reference to __doc__ is passed as an argument to a "
            "function call."
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
 
    # DENS011
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
    # DENS rules in LIBRARY_PY context (deep mode)
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