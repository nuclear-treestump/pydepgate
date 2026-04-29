
# pydepgate

[![PyPI](https://img.shields.io/pypi/v/pydepgate.svg)](https://pypi.org/project/pydepgate/)[![Downloads](https://pepy.tech/badge/pydepgate)](https://pepy.tech/project/pydepgate)[![Unit tests](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/do_unittests.yml/badge.svg)](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/do_unittests.yml)[![CodeQL Advanced](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/codeql.yml/badge.svg)](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/codeql.yml)[![docker-publish](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/docker-publish.yml)[![CodeQL](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/nuclear-treestump/pydep-vector-runner/actions/workflows/github-code-scanning/codeql)

**A lightweight Python runner that interdicts suspicious startup behavior.**

pydepgate inspects Python packages and environments for code that executes
silently at interpreter startup. This was the attack class used by the
March 2026 LiteLLM supply-chain compromise and catalogued as
[MITRE ATT&CK T1546.018](https://attack.mitre.org/techniques/T1546/018/).

<img width="1086" height="720" alt="Screen Recording 2026-04-28 091139" src="https://github.com/user-attachments/assets/28a737fd-4ba0-4401-b49e-5d84703cad25" />

## Recently Added

Tab completion works!

```
usage: pydepgate completions [-h] {bash,zsh,fish}

Print a shell completion script to stdout. Running this command alone does NOT install completion; you have to do something with the output.

Quickest install (bash, current shell only):
  eval "$(pydepgate completions bash)"

Persistent install (bash, all future shells):
  pydepgate completions bash >> ~/.bashrc

Persistent install (zsh):
  pydepgate completions zsh >> ~/.zshrc

Persistent install (fish):
  pydepgate completions fish > ~/.config/fish/completions/pydepgate.fish

After installing, open a new shell or re-source your rc file, then test with:
  pydepgate <TAB><TAB>

When run interactively (output to a terminal rather than redirected), this command also prints install instructions to stderr.

positional arguments:
  {bash,zsh,fish}  Target shell. Supported: bash, zsh, fish.
```

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
- An optional payload-peek enricher (`--peek`) that safely partial-decodes
large encoded literals so you can see what's inside without executing
anything. Handles base64, hex, zlib, gzip, bzip2, and lzma chains up to
a configurable depth, classifies the terminal payload, scans for
high-signal indicator strings, and emits ENC002 when the unwrap chain
is nested. Pickle data is detected but never deserialized;
decompression bombs are bounded by an in-flight byte budget. Tunable
via `--peek-depth`, `--peek-budget`, `--peek-min-length`, and
`--peek-chain` (verbose per-layer hex dumps).
- An SSH-randomart-style finding-distribution map rendered inline with
human-readable scan output, showing where in a file the findings
cluster and at what severity.
- Command-line interface with `scan` (including `--single` for
iteration on individual files) and explain subcommands, environment
variable support, configurable severity thresholds, and CI-friendly
output modes.
- Three output formats: human-readable terminal, JSON (schema v2), and
a stub for SARIF (planned for v0.4).
- Explicit color control via `--color={auto,always,never}` (or
`PYDEPGATE_COLOR`), with `--no-color` preserved as an alias.
`--color=always` forces ANSI codes through pipes for `less -R` and
terminal-aware log viewers.
- Pre-commit hook integration. Drop pydepgate into any Python project's
`.pre-commit-config.yaml` to catch startup-vector patterns at commit
time. Two hook ids: `pydepgate` for `.py` files (defaults to
`--min-severity high` so informational findings don't block commits)
and `pydepgate-pth` for `.pth` files (no severity filter; .pth files
have no legitimate use for the patterns pydepgate detects).
- Official Docker image at `ghcr.io/nuclear-treestump/pydepgate`.
Multi-stage Alpine build under 50 MB, runs as non-root (uid 1000),
published for `linux/amd64` and `linux/arm64`, tagged per release.
Composes with any Python build pipeline that produces a wheel.

What is in active development:

- The comment_analysis analyzer.
- Runtime interdiction (`exec` mode).
- Environment auditing (`preflight` mode).
- Aliased import resolution (`from subprocess import Popen as P`).
- A pip-wrapper / transitive-dependency `audit` subcommand.
- SARIF 2.1.0 output for GitHub code scanning and similar consumers.

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

### Payload peek

Some malware compresses or base64-encodes its payload to slip past
naive string-match scanners. The payload-peek enricher attempts safe
partial decoding of large encoded literals so you can see what's
actually inside a flagged blob without ever executing it. Off by
default; opt in with `--peek`.

| Flag | Env var | Default | Notes |
|---|---|---|---|
| `--peek` | `PYDEPGATE_PEEK` | off | Enable the enricher. Runs a bounded decode pass over hint-tagged signals. |
| `--peek-depth N` | `PYDEPGATE_PEEK_DEPTH` | 3 | Max unwrap layers. Floor 1, ceiling 10. |
| `--peek-budget BYTES` | `PYDEPGATE_PEEK_BUDGET` | 524288 (512 KB) | Cumulative output cap across all layers. Floor 1024. |
| `--peek-chain` | `PYDEPGATE_PEEK_CHAIN` | off | Verbose per-layer breakdown with xxd-style hex dump in human output. |
| `--peek-min-length BYTES` | `PYDEPGATE_PEEK_MIN_LENGTH` | 1024 | Minimum literal size before unwrap is attempted. Floor 16. |

These behave as global flags accepted before or after the subcommand:

```bash
pydepgate --peek scan litellm-1.82.8-py3-none-any.whl
pydepgate scan litellm-1.82.8-py3-none-any.whl --peek --peek-chain
```

Scanning the LiteLLM 1.82.8 wheel with `--peek` surfaces the embedded
payload directly:

```
[CRITICAL] DENS010 (code_density)
  in litellm/proxy/proxy_server.py:130:14
  string literal at line 130 has Shannon entropy 5.61 bits/char (length 34460)
  decoded chain: base64 -> python_source (1 layer, 25.2 KB)
  indicators: subprocess, base64.b64decode
```

The same `decoded` block lands in JSON output under
`findings[*].context.decoded` regardless of `--peek-chain`, with the
full chain, terminal classification, indicators list, and a hex-encoded
preview of the unwrapped bytes. See `docs/json_schema_v2.md` for the
field reference.

#### Safety guarantees

The peek loop is strictly read-only. Three specific guarantees worth
stating explicitly:

**Pickle is detected, never deserialized.** When the unwrap loop hits
a Python pickle stream as a terminal layer, it sets
`pickle_warning: true` in the decoded block and stops.
`pickle.loads()` on attacker-controlled bytes is code execution by
design, that is the bug being analyzed, not a tool action. Inspect
such payloads with `pickletools.dis()` (which walks the opcode stream
without executing it) in an isolated environment.

**Decompression bombs are bounded.** Cumulative output across all
unwrap layers is capped by `--peek-budget`. A 2 KB zlib stream that
would expand to 2 GB trips the cap at 512 KB (default), records
`unwrap_status: exhausted_budget`, and stops. The cap is enforced
in-flight via incremental `decompressobj.decompress(data, max_length=N)`
calls, bytes that exceed the budget are never materialized.

**ENC002 fires on nested chains.** When the unwrap chain reaches
depth 2 or exhausts `--peek-depth` with more transformations still
possible, the enricher emits an `ENC002` signal carrying the decoded
block plus a chain summary. A single base64 layer is unremarkable,
it's the lingua franca of certificates, tokens, and config blobs.
Stacked layers (`base64 → zlib → python_source`) are intent. Default
severities for ENC002 vary by file kind and unwrap status; see
`pydepgate.rules.defaults` for the full table.

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
| `PYDEPGATE_PEEK` | `--peek` |
| `PYDEPGATE_PEEK_DEPTH` | `--peek-depth` |
| `PYDEPGATE_PEEK_BUDGET` | `--peek-budget` |
| `PYDEPGATE_PEEK_CHAIN` | `--peek-chain` |
| `PYDEPGATE_PEEK_MIN_LENGTH` | `--peek-min-length` |

## What pydepgate detects

The current analyzer set covers five major classes of suspicious behavior in startup vectors:

**Encoding abuse (ENC001, ENC002).** Patterns where encoded content is decoded and executed in a single chain, e.g. `exec(base64.b64decode(payload))`. Catches base64, hex, codec-based, zlib, bz2, lzma, and gzip variants. With `--peek` enabled, ENC002 also fires when the partial-decoder unwrap loop reaches 2+ chain layers or exhausts its configured depth, strong evidence that a literal is intentionally obfuscated rather than a benign encoded blob.

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

## Writing rules
 
Rules live in `pydepgate.gate` files. The format is either TOML or
JSON; pydepgate auto-detects from content. A rule has three parts:
identity (an `id`), a match (which signals it applies to), and an
action (what to do when matched).
 
### Discovery
 
When you run `pydepgate scan`, rules are loaded from the first match
of:
 
1. The `--rules-file` CLI flag, if given.
2. The `PYDEPGATE_RULES_FILE` environment variable.
3. `./pydepgate.gate` in the current directory.
4. `<venv>/pydepgate.gate` in the active virtualenv, if any.
If multiple files exist, only the first is loaded. The others are
listed in the scan summary so you can see what was skipped.
 
### Minimal rule (TOML)
 
```toml
[[rule]]
id = "my-package-uses-large-base64"
signal_id = "DENS010"
path_glob = "my_package/embedded/*.py"
action = "suppress"
explain = "We legitimately ship a 200KB embedded model in this dir."
```
 
The `id` is yours. `signal_id` is what to match (see
`pydepgate explain --list` for the catalogue). `path_glob` is an
fnmatch-style pattern matched against the internal path of the file.
`action` is one of `set_severity`, `suppress`, or `set_description`.
`explain` is optional but encouraged: it shows up in
`pydepgate explain --rule USER_my-package-uses-large-base64`.
 
### Match conditions
 
All non-empty match fields must be satisfied for a rule to apply.
The supported fields:
 
| Field                | Matches against                                      |
|----------------------|------------------------------------------------------|
| `signal_id`          | `Signal.signal_id` (e.g. `"DENS010"`)                |
| `analyzer`           | `Signal.analyzer` (e.g. `"code_density"`)            |
| `file_kind`          | The triage decision: `pth`, `setup_py`, `init_py`, `sitecustomize`, `library_py`, etc. |
| `scope`              | `Signal.scope`: `module`, `function`, `class`        |
| `path_glob`          | fnmatch pattern against the file's internal path     |
| `context_contains`   | Dict of `{key: value}` pairs that must appear in `Signal.context` with strict equality |
| `context_predicates` | Dict of `{key: {operator: value}}` pairs evaluated against `Signal.context` (richer than `context_contains`, see below) |
 
### Context predicates
 
`context_predicates` extends `context_contains` with comparison
operators. Each predicate takes the form `{field: {op: value}}`. The
inner dict has exactly one operator key. Multiple predicates on
different fields are AND-ed.
 
```toml
# Block any base64-shaped string of 10KB or larger anywhere
[[rule]]
id = "block-large-base64"
signal_id = "DENS010"
context_predicates = { length = { gte = 10240 } }
action = "set_severity"
severity = "critical"
 
# Suppress confusable single-char identifiers in test files only
[[rule]]
id = "ignore-confusables-in-tests"
signal_id = "DENS021"
path_glob = "tests/**/*.py"
context_predicates = { identifier = { in = ["l", "O", "I"] } }
action = "suppress"
```
 
Available operators:
 
| Category   | Operators                                  | Value type             |
|------------|--------------------------------------------|------------------------|
| Numeric    | `eq`, `ne`, `gt`, `gte`, `lt`, `lte`       | int or float           |
| String     | `eq`, `ne`, `contains`, `startswith`, `endswith` | string         |
| Collection | `in`, `not_in`                             | list, tuple, or set    |
 
Type mismatches (e.g. `gte` against a string) cause the predicate to
silently fail to match rather than error. To AND multiple conditions
on the same field, write multiple rules.
 
### Equivalent JSON
 
```json
{
  "_pydepgate_format": "json",
  "_pydepgate_version": 1,
  "rules": [
    {
      "id": "block-large-base64",
      "signal_id": "DENS010",
      "context_predicates": {"length": {"gte": 10240}},
      "action": "set_severity",
      "severity": "critical"
    }
  ]
}
```
 
### Actions
 
- **`set_severity`**: requires a `severity` field
  (`info`, `low`, `medium`, `high`, `critical`).
- **`suppress`**: drop the finding from the scan output. The
  suppression is still recorded; `pydepgate scan -v` shows what was
  suppressed and which rule did it.
- **`set_description`**: requires a `description` field; replaces the
  finding's text.
### Precedence
 
When multiple rules match a signal, pydepgate picks one winner using
this order:
 
1. Source priority: user rules win over system rules win over
   defaults, regardless of specificity.
2. Specificity: among rules of the same source, more match fields
   wins. Each `context_predicates` entry counts as one match field.
3. Load order: among ties on source and specificity, the earlier
   rule wins.
This means a user `[[rule]]` with the same shape as a default rule
always wins. If you want your rule to lose to a more-specific default,
add fewer match fields than the rule you want to override.
 
### Validation
 
Rules are validated when loaded. Errors are accumulated and reported
together; if any rule fails validation, the entire file is rejected
(no rules loaded). Common errors:
 
- Unknown field name: `Did you mean 'context_contains'?`
- Unknown operator: `Did you mean 'gte'?`
- Multiple operators in one predicate: must be exactly one per field.
- Missing `severity` for `set_severity` action.
Run `pydepgate scan --rules-file my.gate` once after editing to
confirm everything parses.

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
enrichers/         signal hints -> enriched signal context
  _magic.py           magic-byte tables and ASCII-alphabet predicates
  _unwrap.py          bounded multi-layer decode/decompress loop
  payload_peek        ENC002 emission and decoded context block
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
