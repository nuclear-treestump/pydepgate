# pydepgate

[![PyPI](https://img.shields.io/pypi/v/pydepgate.svg)](https://pypi.org/project/pydepgate/)[![Downloads](https://pepy.tech/badge/pydepgate)](https://pepy.tech/project/pydepgate)[![Unit tests](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/do_unittests.yml/badge.svg)](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/do_unittests.yml)

**A lightweight Python runner that interdicts suspicious startup behavior.**

pydepgate inspects Python packages and environments for code that executes
silently at interpreter startup. This was the attack class used by the
March 2026 LiteLLM supply-chain compromise and catalogued as
[MITRE ATT&CK T1546.018](https://attack.mitre.org/techniques/T1546/018/).

<img width="990" height="465" alt="image" src="https://github.com/user-attachments/assets/a723be7f-2a61-4de8-8758-9b87928e782f" />

## Status

**Static analysis is functional end-to-end.**

pydepgate can statically analyze wheels, sdists, installed packages, and
single loose files for the patterns used in real-world Python supply-chain
attacks. The detection covers payload encoding, dynamic code execution,
string obfuscation, suspicious stdlib usage, and a broad code-density
layer that catches obfuscation, Unicode trickery, and machine-generated
identifier patterns.

What works today:

- Static analysis of `.whl` files, sdists (`.tar.gz`/`.tgz`/etc.),
  installed packages by name, and individual loose files via `--single`.
- Five production analyzers: `encoding_abuse`, `dynamic_execution`,
  `string_ops`, `suspicious_stdlib`, and `code_density`.
- Defense in depth on real attack shapes. The LiteLLM 1.82.8 `.pth`
  payload, for example, fires across four analyzers simultaneously
  (ENC001, DYN002, DENS010, DENS011) so an attacker has to evade every
  layer to get past the scanner.
- A rules engine that promotes severity based on file kind and signal
  context, fully data-driven via TOML or JSON. The default rule set
  includes 32 rules dedicated to density-layer signals alone.
- A safe partial evaluator that resolves obfuscated string expressions
  without executing user code.
- An SSH-randomart-style finding-distribution map rendered inline with
  human-readable scan output, showing where in a file the findings
  cluster and at what severity.
- Command-line interface with `scan` (including `--single` for
  iteration on individual files) and `explain` subcommands, environment
  variable support, configurable severity thresholds, and CI-friendly
  output modes.
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

Scan a single loose file (useful for iterating on test fixtures, ad-hoc
inspection of a suspicious file, or reproducing a finding without
restructuring the file into a package):

```bash
pydepgate scan --single suspicious_module.py
pydepgate scan --single fixture.pth
pydepgate scan --single garbage.py --as init_py
```

`--single` bypasses wheel/sdist/installed-package dispatch and analyzes
the file directly. The file kind is auto-detected from the filename:
`.pth` files are treated as `pth`; files named `setup.py`,
`__init__.py`, `sitecustomize.py`, or `usercustomize.py` are classified
as their natural kind; anything else defaults to `setup_py` (the most
permissive context, ideal for surfacing every signal at realistic
attack-shape severity). Override with `--as`:
`setup_py` / `init_py` / `pth` / `sitecustomize` / `usercustomize`.

Explain what a signal means and what triggers it:

```bash
pydepgate explain STDLIB001
pydepgate explain DENS010
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

Scan an entire library archive:
> Recommend using --min-severity as this is noisy by design.
```bash
pydepgate scan --deep somefile.whl
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

The current analyzer set covers five major classes of suspicious behavior in startup vectors:

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

**Code density (DENS001-051).** A broad layer that catches the things obfuscated code looks like even when no single primitive call is suspicious on its own. Thirteen distinct signals across five sublayers:

*Lexical (line-shape):*

- `DENS001`: single-line token compression (minification or bundler-mimicry shapes)
- `DENS002`: semicolon chaining of multiple statements on one line

*String content:*

- `DENS010`: high-entropy string literals (Shannon entropy consistent with base64, compressed, or encrypted content)
- `DENS011`: literals using only base64-alphabet characters, even without an accompanying decode call

*Identifier shape:*

- `DENS020`: low-vowel-ratio identifiers (machine-generated or deliberately mangled names like `_xkjwbq`)
- `DENS021`: confusable single-character identifiers (`l`, `O`, `I`)

*Unicode:*

- `DENS030`: invisible Unicode characters in source (zero-width spaces, RTL overrides; the Trojan Source class catalogued as [CVE-2021-42574](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574))
- `DENS031`: Unicode homoglyphs in identifiers (Cyrillic and Greek lookalikes used to evade string-match scanners)

*Structural:*

- `DENS040`: AST depth disproportionate to line count (compression hidden inside expression trees)
- `DENS041`: deeply nested lambdas or comprehensions (functional-style obfuscation)
- `DENS042`: large byte-range integer arrays (122-element lists of 0-255 ints, the shellcode-staging shape)

*Docstring:*

- `DENS050`: high-entropy docstrings (the docstring-as-payload smuggling pattern)
- `DENS051`: dynamic `__doc__` reference passed to a callable (the runtime decode-and-execute half of the smuggling pattern)

The default rule set ships 32 rules covering these signals across five file kinds, calibrated so that the same content scans differently depending on where it lives. A high-entropy base64 literal in `.pth` is `CRITICAL` (no benign use case); the same literal in `__init__.py` is `MEDIUM` (some packages legitimately ship encoded blobs); the same literal anywhere else is `LOW` (UUIDs and hashes happen). `DENS021` is universally `INFO` because PEP-8-style confusables aren't a security finding by themselves; they only matter as a contributing signal when other signals fire.

## Layered detection in practice

The LiteLLM 1.82.8 `.pth` payload is a single line:

```
import base64; exec(base64.b64decode('cHJpbnQoMSkK'))
```

A scanner that grepped for `exec` would catch it. A scanner that grepped for `base64.b64decode` would catch it. But an attacker who knew about either of those evasions could trivially defeat both. pydepgate fires five separate findings on this line from four independent analyzers:

- **ENC001** (encoding_abuse): decode-then-execute pattern
- **DYN002** (dynamic_execution): `exec()` with non-literal argument at module scope
- **DENS001** (code_density): token-dense single line
- **DENS010** (code_density): high-entropy string literal
- **DENS011** (code_density): base64-alphabet string literal

Plus the rule layer promotes all of them to `CRITICAL` because the file is a `.pth`. To evade pydepgate, an attacker has to defeat every analyzer simultaneously while still producing a working `.pth` payload. Each evasion narrows what's possible; the intersection of all evasions is the empty set for any shape that could realistically execute on Python startup.

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
- **Lightweight.** The full test suite runs in roughly seven seconds on a modern laptop, including subprocess-based CLI tests against installed packages.

## Relationship to PyDepGuard

pydepgate is a narrow, single-purpose tool focused on startup-vector
interdiction. [PyDepGuard](https://github.com/nuclear-treestump/pylock-dependency-lockfile)
is a broader Python security framework covering runtime sandboxing, 
and dependency management. The startup-vector engine developed in pydepgate 
is intended to eventually integrate with PyDepGuard as a subsystem; until then,
the two projects are developed independently.

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
  density_analyzer    DENS001-051
rules/             signals + context -> severity-rated findings
  base.py             rule data model and matching logic
  defaults.py         default rule set (90+ rules across all signals)
  loader.py           TOML/JSON parser with validation and typo suggestions
  explanations.py     structured explain-output content
engines/           orchestration (currently: static)
visualizers/       inline rendering helpers for the human reporter
  density_map         SSH-randomart-style finding-distribution renderer
cli/               argparse, dispatch, reporters, explain subcommand
```

Analyzers do not see raw bytes. They walk parsed representations and emit `Signal` objects. The rules engine wraps signals with severity to produce `Finding` objects, applying user and default rules in priority order. The CLI renders findings in human, JSON, or SARIF format.

The `_resolver.py` module is reusable infrastructure for any analyzer that needs to know what an expression evaluates to. It returns structured `ResolutionResult` objects with success/failure status, operation counts, partial values, and resolved fragment lists.

The static engine exposes three entry points for single-file analysis. `scan_file(path)` reads bytes and routes through triage by filename. `scan_bytes(content, internal_path, ...)` is the per-file workhorse that artifact enumerators (wheel, sdist, installed) call once per in-scope file. `scan_loose_file_as(path, file_kind)` bypasses triage entirely and forces a file kind, preserving the real path through to finding contexts; this is the entry point used by `pydepgate scan --single`.

## Development

```bash
git clone https://github.com/nuclear-treestump/pydep-vector-runner
cd pydep-vector-runner
pip install -e .
python -m unittest discover tests -v
```

The test suite has grown to approximately 500 tests as the analyzer set has expanded. Tests are organized by module and include happy-path coverage, evasion batteries, false-positive batteries, robustness checks against adversarial inputs, integration tests against synthetic wheels and sdists, and CLI tests via subprocess.

To regenerate the binary `.pth` test fixtures after editing them:

```bash
python scripts/generate_fixtures.py
```

## Safety notes

This project builds tooling to defend against Python supply-chain attacks. The test fixtures in `tests/fixtures/` and the synthetic samples used in integration tests model the *structural shape* of known attacks (LiteLLM 1.82.8, Trojan Source CVE-2021-42574, others catalogued under T1546.018) but contain only inert payloads. No actual malicious code is present in this repository.

For regression testing against real malicious samples, use the [OSSF malicious-packages](https://github.com/ossf/malicious-packages), [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset), or [lxyeternal/pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) datasets. Do so in disposable VMs or containers, and do not commit samples to this repository.

## Known limitations

pydepgate's static analysis is honest about what it can and cannot catch. Documented gaps include:

**Analysis gaps:**

- Function return tracking. `code = make_payload()` where `make_payload()` internally calls `compile(...)` is not flagged.
- `__builtins__` as a Name subscript (rather than via a function call).
- Tuple unpacking, augmented assignment, and conditional assignments in the resolver's variable tracking.
- Lambda scope precision (lambdas count as their enclosing scope).
- Aliased stdlib imports such as `from subprocess import Popen as P`.
  - For now. I will add this soon enough.

**Density-layer caveats:**

- `DENS020` (low-vowel-ratio identifiers) and `DENS040` (AST depth) both produce false positives on legitimate machine-generated code (Cython output, parser tables, generated configuration). They ship at `LOW` severity outside startup vectors so they surface as contributing signals rather than standalone alerts.
- `DENS031` (homoglyphs) can fire on legitimate non-English variable names in non-Latin codebases. The default rule keeps it at `HIGH` rather than `CRITICAL` outside startup vectors so users with intentional non-Latin naming can suppress with a single user rule.

## Author

Ikari ([@0xIkari](https://github.com/0xIkari))

## License

Apache 2.0. See [LICENSE](LICENSE).
