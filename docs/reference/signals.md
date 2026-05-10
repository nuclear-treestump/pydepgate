---
title: Signals
parent: Reference
nav_order: 5
---
# Signals Reference

pydepgate emits 30 signals across five analyzer namespaces. Each signal
represents a specific detection pattern.

## How severity is assigned

The rules engine evaluates each signal against the active rule set. When one
or more rules match, the most-specific rule from the highest-priority source
wins (user > system > default; within a source, more match conditions wins;
within a tie, load order wins). The winning rule's `SET_SEVERITY` effect
determines the finding's severity.

When **no rule matches**, the rules engine falls back to a mechanical mapping
from the analyzer's `Confidence` value to a `Severity` value. The mapping is
defined in `confidence_to_severity_v01()` in `src/pydepgate/engines/base.py`:

| Analyzer confidence | Resulting severity |
|---|---|
| `DEFINITE` (90) | HIGH |
| `HIGH` (70) | MEDIUM |
| `MEDIUM` (50) | LOW |
| `LOW` (30) | INFO |
| `AMBIGUOUS` (10) | INFO |

A signal with no matching rule still produces a finding; it just does so at
the conservative confidence-based severity.

The tables in each entry below list explicit default rules first, then a
"Fallback (no rule)" row where applicable, showing the severity the signal
would carry from the mechanical mapping based on the analyzer's confidence
for that signal.

Use `pydepgate explain <SIGNAL_ID>` at the command line to see all rules
(default and user) that apply to a signal.

---

## ENC: Encoding Abuse

Emitted by the `encoding_abuse` analyzer.

### ENC001

**Decode-then-execute pattern.** Encoded content (base64, hex, compressed
bytes) is decoded and immediately passed to `exec`, `eval`, `compile`, or
`__import__`.

The analyzer emits ENC001 at `DEFINITE` confidence when the inner argument
is a literal-looking payload string, and at `HIGH` confidence otherwise.

This is the most common pattern in Python supply-chain malware. The LiteLLM
1.82.8 attack used exactly this pattern in a `.pth` file.

Common evasions: aliasing the exec primitive (`e = exec; e(b64decode(...))`),
chaining multiple decoders (`zlib` + `base64`), splitting the payload across
multiple variables.

| File kind | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | CRITICAL |
| `sitecustomize` | CRITICAL |
| `init_py` | HIGH |
| Fallback (no rule, e.g. `usercustomize`, `library_py`) | HIGH (literal) or MEDIUM |

### ENC002

**Deeply-nested encoded payload.** A string literal that required 2 or more
transformations to decode (or exhausted the `--peek-depth` limit with more
layers still possible). Emitted by the payload-peek enricher; requires
`--peek`.

The enricher emits ENC002 at `AMBIGUOUS` confidence at depth 2,
`MEDIUM` confidence at depth 3, and `HIGH` confidence on depth exhaustion.

| Condition | Severity |
|---|---|
| `pth` | CRITICAL |
| `sitecustomize` | CRITICAL |
| `usercustomize` | CRITICAL |
| `setup_py` with `unwrap_status == "exhausted_depth"` | CRITICAL |
| `setup_py` (baseline) | HIGH |
| `init_py` with `final_kind == "python_source"` | CRITICAL |
| `init_py` with `unwrap_status == "exhausted_depth"` | HIGH |
| `init_py` (baseline) | MEDIUM |
| Any file kind with `unwrap_status == "exhausted_depth"` | HIGH |
| Fallback (no rule, e.g. `library_py` with non-exhausted chain) | INFO to MEDIUM (depends on depth) |

The `setup_py` exhausted-depth rule has higher specificity than the
`setup_py` baseline rule and wins when its predicate matches. Same for
the `init_py` python-source and exhausted-depth variants.

---

## DYN: Dynamic Execution

Emitted by the `dynamic_execution` analyzer.

### DYN001

**exec/eval/compile at module scope with a literal argument.** The argument
is a statically-visible string constant.

Analyzer emits at `MEDIUM` confidence. No default rule exists, so DYN001
findings always come through the mechanical-mapping fallback.

| Condition | Severity |
|---|---|
| Fallback (no rule, any file kind) | LOW |

### DYN002

**exec/eval/compile at module scope with a non-literal argument.** The
argument is computed at runtime; the executed code is not visible in the
source.

Analyzer emits at `HIGH` confidence.

| File kind | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | HIGH |
| Fallback (no rule, other file kinds) | MEDIUM |

### DYN003

**exec/eval/compile inside a function or class body with a non-literal
argument.** Lower priority than module-scope because function bodies often
have legitimate reasons to use `exec`.

Analyzer emits at `MEDIUM` confidence. No default rule.

| Condition | Severity |
|---|---|
| Fallback (no rule, any file kind) | LOW |

### DYN004

**`__import__` or `importlib.import_module` with a non-literal module name.**
Computed module names defeat static dependency analysis.

Analyzer emits at `HIGH` confidence. No default rule.

| Condition | Severity |
|---|---|
| Fallback (no rule, any file kind) | MEDIUM |

### DYN005

**Reaching into builtins via `getattr`, `globals()`, `locals()`, or `vars()`
to access an exec primitive by string lookup.** For example:
`getattr(__builtins__, 'eval')` or `globals()['exec']`.

There is no legitimate reason to access `exec`, `eval`, or `compile` via
string lookup. This pattern exists specifically to evade scanners that match
on the names of dangerous builtins.

| File kind | Severity |
|---|---|
| All file kinds (anywhere rule) | HIGH |

### DYN006

**Compile-then-exec pattern.** A `compile()` result is stored in a variable
and later passed to `exec` or `eval` somewhere else in the file.

| File kind | Severity |
|---|---|
| All file kinds (anywhere rule) | HIGH |

### DYN006_PRECURSOR

**`compile()` called with `mode='exec'`.** Creates a code object intended for
execution even without a following `exec`.

Analyzer emits at `MEDIUM` confidence. No default rule.

| Condition | Severity |
|---|---|
| Fallback (no rule, any file kind) | LOW |

### DYN007

**Aliased exec shape.** A call to an unresolvable name whose first argument
is itself a decode call, for example `e(base64.b64decode(...))` where `e`
cannot be resolved.

Analyzer emits at `HIGH` confidence.

| File kind | Severity |
|---|---|
| `setup_py` | HIGH |
| Fallback (no rule, other file kinds) | MEDIUM |

---

## STR: String Obfuscation

Emitted by the `string_ops` analyzer. Uses a safe partial evaluator to
statically compute what obfuscated string expressions would produce.

### STR001

**Standalone obfuscated expression that resolves to a sensitive name.** Not
seen passed to a dangerous function at this point, but the obfuscation is
worth noting.

Analyzer emits at `MEDIUM` confidence. No default rule.

| Condition | Severity |
|---|---|
| Fallback (no rule, any file kind) | LOW |

### STR002

**Obfuscated expression resolves to a sensitive name and is passed directly
to a dangerous function.**

Analyzer emits at `DEFINITE` confidence when the obfuscation score is 2 or
more, and at `HIGH` confidence at score 1.

Common evasions: `chr()` concatenation, string reversal (`'lave'[::-1]`),
bytes from list (`bytes([101, 118, 97, 108]).decode()`).

| File kind | Severity |
|---|---|
| `setup_py` | CRITICAL |
| All other file kinds (anywhere rule) | HIGH |

### STR003

**Variable assigned an obfuscated sensitive name is later used as the
argument to a dangerous function.** Two-step obfuscation that defeats
single-expression analyzers.

| File kind | Severity |
|---|---|
| All file kinds (anywhere rule) | HIGH |

### STR004

**Heavily obfuscated expression that pydepgate could not fully resolve, but
that used many obfuscation operations.** The obfuscation effort itself is
the signal.

Analyzer emits at `HIGH` confidence when a `func_name` is known, otherwise
at `MEDIUM` confidence.

| File kind | Severity |
|---|---|
| `setup_py` | HIGH |
| Fallback (no rule, other file kinds, with `func_name`) | MEDIUM |
| Fallback (no rule, other file kinds, without `func_name`) | LOW |

---

## STDLIB: Suspicious Standard Library

Emitted by the `suspicious_stdlib` analyzer. All three STDLIB signals fire
at `HIGH` confidence.

Note: aliased imports are a documented gap. `from subprocess import Popen as
P` followed by `P(['ls'])` does not currently fire because the qualified
name resolves to `P`, not `subprocess.Popen`.

### STDLIB001

**Call to a stdlib function that spawns a subprocess or executes a shell
command.** Covered functions include the full `subprocess.*`, `os.system`,
`os.popen`, `os.spawn*`, `os.exec*`, `os.fork`, `os.forkpty`, `pty.spawn`,
`pty.fork`, and `platform.popen` families.

| File kind | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | CRITICAL |
| `sitecustomize` | CRITICAL |
| `init_py` (module scope only) | HIGH |
| Fallback (no rule, e.g. `init_py` function scope, `usercustomize`, `library_py`) | MEDIUM |

### STDLIB002

**Call to a stdlib function that initiates network communication.** Covered
functions include `urllib.request.urlopen`, `urllib.request.urlretrieve`,
`urllib.request.Request`, `socket.socket`, `socket.create_connection`,
`http.client.HTTPConnection`, `http.client.HTTPSConnection`, `ftplib.FTP`,
`ftplib.FTP_TLS`, `smtplib.SMTP`, `smtplib.SMTP_SSL`, `imaplib.IMAP4`,
`imaplib.IMAP4_SSL`, and others.

| File kind | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | HIGH |
| `init_py` (module scope only) | HIGH |
| Fallback (no rule, e.g. `init_py` function scope, `sitecustomize`, `usercustomize`, `library_py`) | MEDIUM |

### STDLIB003

**Call to a stdlib function that loads native code via ctypes.** Covered
functions include `ctypes.CDLL`, `ctypes.WinDLL`, `ctypes.OleDLL`,
`ctypes.PyDLL`, and all `LoadLibrary` variants.

Native code loaded via ctypes runs outside Python's execution model.
Legitimate packages that wrap native libraries do so via compiled extension
modules, not runtime ctypes loads.

| File kind | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | CRITICAL |
| All other file kinds (anywhere rule) | HIGH |

---

## DENS: Code Density

Emitted by the `code_density` analyzer. Covers statistical and structural
fingerprints of intentionally obfuscated code. This is the only analyzer
that runs on ordinary library `.py` files in `--deep` mode.

None of these signals are individually conclusive. Context, particularly
file kind, is what makes them meaningful. Every DENS signal has an
`*_anywhere` default rule, so the mechanical-mapping fallback never applies
to DENS signals.

### DENS001

**Single-line token compression.** A physical line contains an anomalously
high number of tokens, indicating minification or deliberate packing. Fires
at MEDIUM at 50+ tokens, HIGH at 100+ tokens.

| File kind | Severity |
|---|---|
| `pth` | HIGH |
| `setup_py` | HIGH |
| `sitecustomize` | HIGH |
| `library_py` (deep mode) | LOW |
| All other file kinds (anywhere rule) | LOW |

### DENS002

**Semicolon statement chaining.** Multiple statements joined by semicolons
on one physical line. Fires at MEDIUM at 2+ semicolons, HIGH at 4+
semicolons.

| File kind | Severity |
|---|---|
| `pth` | HIGH |
| `setup_py` | HIGH |
| `library_py` (deep mode) | LOW |
| All other file kinds (anywhere rule) | LOW |

### DENS010

**High-entropy string literal.** A string constant whose Shannon entropy and
length together suggest encoded content. Calibrated to catch base64-encoded
Python source at approximately 5.2-5.4 bits/char (the entropy of the LiteLLM
1.82.8 attack payload).

| File kind / condition | Severity |
|---|---|
| `pth` | CRITICAL |
| `sitecustomize` | CRITICAL |
| Any file, length >= 10240 bytes | CRITICAL |
| `setup_py` | HIGH |
| `init_py` | MEDIUM |
| `library_py` (deep mode) | MEDIUM |
| All other file kinds (anywhere rule) | LOW |

### DENS011

**Base64-alphabet string constant.** A long string whose character set is
restricted to the base64 alphabet (`A-Za-z0-9+/=`), indicating a likely
encoded payload even without an accompanying decode call. Complements
DENS010 by firing on alphabet membership without requiring high entropy.

| File kind / condition | Severity |
|---|---|
| `pth` | CRITICAL |
| Any file, length >= 10240 bytes | CRITICAL |
| `setup_py` | HIGH |
| Length >= 1024 bytes | HIGH |
| `library_py` (deep mode) | MEDIUM |
| All other file kinds (anywhere rule) | LOW |

### DENS020

**Low-vowel-ratio identifier.** An identifier whose consonant-heavy
composition suggests machine-generated or deliberately mangled naming.

Produces false positives on legitimate generated code and scientific Python
abbreviations.

| File kind | Severity |
|---|---|
| `library_py` (deep mode) | INFO |
| All other file kinds (anywhere rule) | LOW |

### DENS021

**Confusable single-character identifier.** Use of `l`, `O`, or `I` as a
variable name. Universally INFO; a PEP 8 issue by itself.

| File kind | Severity |
|---|---|
| All file kinds (anywhere rule) | INFO |

### DENS030

**Invisible Unicode character.** A zero-width space, zero-width joiner,
byte-order mark, right-to-left override, or other invisible Unicode
codepoint found anywhere in the source. This is the Trojan Source attack
class ([CVE-2021-42574](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574)).

| File kind | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | CRITICAL |
| `sitecustomize` | CRITICAL |
| `library_py` (deep mode) | HIGH |
| All other file kinds (anywhere rule) | HIGH |

### DENS031

**Unicode homoglyph in identifier.** A non-ASCII character visually
identical to an ASCII letter (Cyrillic or Greek lookalikes) used in an
identifier. Enables steganographic evasion of string-match scanners.

| File kind | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | CRITICAL |
| `library_py` (deep mode) | HIGH |
| All other file kinds (anywhere rule) | HIGH |

### DENS040

**Disproportionate AST depth.** The AST is unusually deep relative to the
file's line count, indicating expression compression.

Produces false positives on Cython output and parser-generator tables.

| File kind | Severity |
|---|---|
| `pth` | HIGH |
| `setup_py` | HIGH |
| `library_py` (deep mode) | INFO |
| All other file kinds (anywhere rule) | LOW |

### DENS041

**Deeply nested lambdas or comprehensions.** Lambdas or comprehensions
nested beyond a configurable depth threshold.

| File kind | Severity |
|---|---|
| `pth` | HIGH |
| `setup_py` | HIGH |
| `library_py` (deep mode) | INFO |
| All other file kinds (anywhere rule) | LOW |

### DENS042

**Large byte-range integer array.** A list or tuple whose elements are
predominantly integers in the range `[0, 255]`, suggesting shellcode or
payload staging.

Cryptographic constants and lookup tables are the main false-positive
class.

| File kind | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | HIGH |
| `library_py` (deep mode) | LOW |
| All other file kinds (anywhere rule) | LOW |

### DENS050

**High-entropy docstring.** A string in docstring position with high
Shannon entropy and length suggesting encoded content disguised as
documentation. The complete attack pattern pairs DENS050 (smuggling the
payload) with DENS051 (executing it).

| File kind / condition | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | CRITICAL |
| Any file, length >= 10240 bytes | CRITICAL |
| Length >= 1024 bytes | HIGH |
| `library_py` (deep mode) | HIGH |
| All other file kinds (anywhere rule) | MEDIUM |

### DENS051

**Dynamic `__doc__` reference passed to a callable.** `__doc__` is read and
passed as an argument to a function call. This is the execution half of
the docstring-payload pattern.

Some introspection tools legitimately read `__doc__`; those cases can be
suppressed via a user rule.

| File kind | Severity |
|---|---|
| `pth` | CRITICAL |
| `setup_py` | CRITICAL |
| `library_py` (deep mode) | HIGH |
| All other file kinds (anywhere rule) | HIGH |