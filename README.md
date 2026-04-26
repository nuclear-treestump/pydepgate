# pydepgate

**A lightweight Python runner that interdicts suspicious startup behavior.**

pydepgate inspects Python packages and environments for code that executes
silently at interpreter startup. This was the attack class used by the
March 2026 LiteLLM supply-chain compromise and catalogued as
[MITRE ATT&CK T1546.018](https://attack.mitre.org/techniques/T1546/018/).

<img width="713" height="215" alt="image" src="https://github.com/user-attachments/assets/a1940e49-5f3f-4b39-8398-0961fc2b0727" />


## Status

**v0.1.1 Static analysis is functional end-to-end.**

pydepgate can statically analyze wheels, sdists, and installed packages
for the patterns used in real-world Python supply-chain attacks. The
detection covers payload encoding, dynamic code execution, and string
obfuscation, including resolution of obfuscated values back to their
intended form.

What works today:

- Static analysis of `.whl` files, sdists (`.tar.gz`/`.tgz`/etc.), and
  installed packages by name.
- Four production analyzers: `encoding_abuse`, `dynamic_execution`,
`string_ops`, and `suspicious_stdlib`.
- A rules engine that promotes severity based on file kind and signal context, fully data-driven via TOML or JSON.
- A safe partial evaluator that resolves obfuscated string expressions
  without executing user code.
- Command-line interface with `scan` and `explain` subcommands, environment variable support, configurable severity thresholds, and CI-friendly output modes.
- Three output formats: human-readable terminal, JSON, and a stub for
  SARIF (planned for v0.5).

What is in active development:

- The `comment_analysis` analyzer.
- Runtime interdiction (`exec` mode).
- Environment auditing (`preflight` mode).

[Available on PyPI as pydepgate](https://pypi.org/project/pydepgate/).

## The problem

Python's interpreter runs several kinds of code automatically at startup,
before any user script executes:

- `.pth` files in `site-packages/`. Any line beginning with `import` is
  passed to `exec()` by `site.py` during interpreter initialization.
- `sitecustomize.py` and `usercustomize.py`. Imported automatically if
  present.
- `__init__.py` top-level code in any imported package.
- `setup.py`. Executed during `pip install` for source distributions.
- Console-script entry points. Generated and executed by `pip install`.

Each of these is a legitimate Python feature. Each has been used in
real-world supply-chain attacks. Existing Python security tooling
(`pip-audit`, `safety`, `bandit`) does not inspect these startup vectors.
The `.pth` vector in particular has been acknowledged as a security gap
in [CPython issue #113659](https://github.com/python/cpython/issues/113659)
but has no patch.

## Installation

```bash
pip install pydepgate
```

Requires Python 3.11 or later. No third-party runtime dependencies.

## Installation
 
```bash
pip install pydepgate
```
 
Requires Python 3.11 or later. No third-party runtime dependencies.
 
## Usage
 
Scan a wheel:
 
```bash
pydepgate scan some-package-1.0.0-py3-none-any.whl
```
 
Scan a source distribution:
 
```bash
pydepgate scan some-package-1.0.0.tar.gz
```
 
Scan an installed package by name:
 
```bash
pydepgate scan litellm
```
 
Explain what a signal means and what triggers it:
 
```bash
pydepgate explain STDLIB001
pydepgate explain --rule litellm-pth-stdlib
pydepgate explain --list
```
 
In CI, use `--ci` for compact JSON output and proper exit codes:
 
```bash
pydepgate --ci scan some-package.whl
```
 
Filter findings by severity:
 
```bash
pydepgate scan some-package.whl --min-severity high
```
 
Apply a custom rules file:
 
```bash
pydepgate scan some-package.whl --rules-file company-rules.gate
```

### Exit codes

- `0` Clean. No findings (or no findings above `--min-severity`).
- `1` Findings present, but none HIGH or CRITICAL.
- `2` At least one HIGH or CRITICAL finding.
- `3` Tool error. pydepgate could not complete the scan.

These are stable as part of the v0.1+ contract.

### Environment variables
 
All flags can be set via environment variables. Explicit flags override environment values.
 
| Variable | Equivalent flag |
|---|---|
| `PYDEPGATE_CI` | `--ci` |
| `PYDEPGATE_FORMAT` | `--format` |
| `PYDEPGATE_NO_COLOR` (or `NO_COLOR`) | `--no-color` |
| `PYDEPGATE_MIN_SEVERITY` | `--min-severity` |
| `PYDEPGATE_STRICT_EXIT` | `--strict-exit` |
| `PYDEPGATE_RULES_FILE` | `--rules-file` |

## What pydepgate detects
 
The current analyzer set covers four major classes of suspicious behavior in startup vectors:
 
**Encoding abuse (ENC001).** Patterns where encoded content is decoded and executed in a single chain, e.g. `exec(base64.b64decode(payload))`. Catches base64, hex, codec-based, zlib, bz2, lzma, and gzip variants.
 
**Dynamic execution (DYN001-007).** Direct calls to `exec`, `eval`, `compile`, or `__import__`; access to exec primitives via `getattr`, `globals()`, `locals()`, `vars()`, or `__builtins__` subscripts; compile-then-exec across the file; and aliased call shapes that catch `e = exec; e(...)` evasions.
 
**String obfuscation (STR001-004).** Obfuscated string expressions that resolve to the names of exec primitives, dangerous stdlib functions, or sensitive module names. Uses a safe partial evaluator that statically computes what string an expression would produce, without executing user code. Catches:
 
- Concatenation: `'ev' + 'al'`
- Character codes: `chr(101) + chr(118) + chr(97) + chr(108)`
- Slicing: `'lave'[::-1]`
- `str.join` of literal pieces: `''.join(['e','v','a','l'])`
- `bytes.fromhex('6576616c').decode()`
- f-string assembly with literal interpolation
- Single-assignment variables containing obfuscated values
**Suspicious stdlib usage (STDLIB001-003).** Calls to stdlib functions that are highly unusual in startup vectors:
 
- `STDLIB001`: process spawn (`os.system`, `subprocess.Popen`, `subprocess.run`, `os.exec*`, etc.)
- `STDLIB002`: network operations (`urllib.request.urlopen`, `socket.socket`, `http.client`, etc.)
- `STDLIB003`: native code loading (`ctypes.CDLL`, `ctypes.WinDLL`, etc.)
Confidence is `HIGH` by default. The rules engine promotes these to `CRITICAL` when they appear in `setup.py` or in a `.pth` file (where they have no legitimate business existing). This is the rule that fires on LiteLLM 1.82.8.
 
The "harder they hide it the stronger the signal" model is realized through operation counting: an expression that required many obfuscation operations to assemble a sensitive name is treated as more confidently malicious than one that required few.

## The rules engine
 
Analyzers emit raw signals. The rules engine maps signals to severity-rated findings using a data-driven rule set. Default rules ship in JSON; users can override or augment them with a `pydepgate.gate` file (TOML or JSON, auto-detected) in the project root, the venv root, or specified via `--rules-file`.
 
A rule is a small structured object:
 
```json
{
  "id": "litellm-pth-stdlib",
  "match": {
    "signal_id": "STDLIB001",
    "file_kind": "pth"
  },
  "actions": [
    {"type": "set_severity", "severity": "critical"}
  ]
}
```
 
Three actions are supported: `set_severity`, `suppress`, and `set_description`. User rules always take precedence over default rules, regardless of specificity. Suppressed findings are tracked separately so users can see what would have fired and why it didn't.
 
Run `pydepgate explain --list` to see all default rules and signals, with descriptions of what they catch and how rules promote them.

## Design constraints
 
- **Zero runtime dependencies.** Standard library only. This is a load-bearing design constraint, not a stylistic preference: every additional dependency is a supply-chain attack surface for a tool whose job is to defend against supply-chain attacks.
- **Safe by construction.** Parsers and the partial evaluator never execute, compile, or import input content. Every operation modeled by the resolver is reimplemented from scratch using only Python builtins on values the resolver itself produced.
- **Self-integrity at bootstrap.** Critical stdlib references are captured into locals before any untrusted code runs (relevant when the runtime engine ships in v0.4).
- **Lightweight.** The full test suite (~375 tests) runs in roughly seven seconds on a modern laptop, including subprocess-based CLI tests against installed packages.

## Relationship to PyDepGuard

pydepgate is a narrow, single-purpose tool focused on startup-vector
interdiction. [PyDepGuard](https://github.com/nuclear-treestump/pylock-dependency-lockfile)
is a broader Python security framework covering runtime sandboxing,
cryptographic IPC, secure memory, and dependency management. The
startup-vector engine developed in pydepgate is intended to eventually
integrate with PyDepGuard as a subsystem; until then, the two projects
are developed independently.

Users who need only startup-vector protection should use pydepgate.
Users who need the full runtime security model should use PyDepGuard
directly.

## Architecture
 
The codebase is organized as a layered pipeline:
 
```
parsers/           bytes -> structured representations (pth, pysource, wheel, sdist)
introspection/     installed package enumeration via importlib.metadata
traffic_control/   path-based triage; decides what to analyze
analyzers/         structured representations -> raw signals
  _resolver.py        safe partial evaluator (shared infrastructure)
  _visitor.py         scope tracking and AST utilities (shared)
  encoding_abuse      ENC001
  dynamic_execution   DYN001-007
  string_ops          STR001-004
  suspicious_stdlib   STDLIB001-003
rules/             signals + context -> severity-rated findings
  base.py             rule data model and matching logic
  defaults.py         default rule set
  loader.py           TOML/JSON parser with validation and typo suggestions
  explanations.py     structured explain-output content
engines/           orchestration (currently: static)
cli/               argparse, dispatch, reporters, explain subcommand
```
 
Analyzers do not see raw bytes. They walk parsed representations and emit `Signal` objects. The rules engine wraps signals with severity to produce `Finding` objects, applying user and default rules in priority order. The CLI renders findings in human, JSON, or SARIF format.
 
The `_resolver.py` module is reusable infrastructure for any analyzer that needs to know what an expression evaluates to. It returns structured `ResolutionResult` objects with success/failure status, operation counts, partial values, and resolved fragment lists.
 
## Development
 
```bash
git clone https://github.com/nuclear-treestump/pydep-vector-runner
cd pydep-vector-runner
pip install -e .
python -m unittest discover tests -v
```
 
The test suite is approximately 375 tests as of v0.0.4. Tests are organized by module and include happy-path coverage, evasion batteries, false-positive batteries, robustness checks against adversarial inputs, integration tests against synthetic wheels and sdists, and CLI tests via subprocess.
 
To regenerate the binary `.pth` test fixtures after editing them:
 
```bash
python scripts/generate_fixtures.py
```
 
## Safety notes
 
This project builds tooling to defend against Python supply-chain attacks. The test fixtures in `tests/fixtures/` and the synthetic samples used in integration tests model the *structural shape* of known attacks (LiteLLM 1.82.8, others catalogued under T1546.018) but contain only inert payloads. No actual malicious code is present in this repository.
 
For regression testing against real malicious samples, use the [OSSF malicious-packages](https://github.com/ossf/malicious-packages), [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset), or [lxyeternal/pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) datasets. Do so in disposable VMs or containers, and do not commit samples to this repository.
 
## Known limitations
 
pydepgate's static analysis is honest about what it can and cannot catch. Documented gaps include:
 
**Analysis gaps:**
 
- Function return tracking. `code = make_payload()` where `make_payload()` internally calls `compile(...)` is not flagged.
- `__builtins__` as a Name subscript (rather than via a function call).
- Tuple unpacking, augmented assignment, and conditional assignments in the resolver's variable tracking.
- Lambda scope precision (lambdas count as their enclosing scope).
- Aliased stdlib imports such as `from subprocess import Popen as P`.

## Author

Ikari ([@0xIkari](https://github.com/0xIkari))

## License

Apache 2.0. See [LICENSE](LICENSE).
