# pydepgate

#### Stats
> Statistics provided by pypi and pepy.tech

[![PyPI](https://img.shields.io/pypi/v/pydepgate.svg)](https://pypi.org/project/pydepgate/)[![Downloads](https://pepy.tech/badge/pydepgate)](https://pepy.tech/project/pydepgate)
#### Tests
> Tests are performed against Python 3.11, 3.12, and 3.13

[![Unit tests](https://github.com/nuclear-treestump/pydepgate/actions/workflows/do_unittests.yml/badge.svg)](https://github.com/nuclear-treestump/pydepgate/actions/workflows/do_unittests.yml)
[![SARIF validation](https://github.com/nuclear-treestump/pydepgate/actions/workflows/do_sarif_validation.yml/badge.svg)](https://github.com/nuclear-treestump/pydepgate/actions/workflows/do_sarif_validation.yml)
[![CodeQL Advanced](https://github.com/nuclear-treestump/pydepgate/actions/workflows/codeql.yml/badge.svg)](https://github.com/nuclear-treestump/pydepgate/actions/workflows/codeql.yml)
[![CodeQL](https://github.com/nuclear-treestump/pydepgate/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/nuclear-treestump/pydepgate/actions/workflows/github-code-scanning/codeql)
#### Docker
> Container builds from 0.5.0 onward are multi-arch, digest-addressable, signed, attested, and reproducible for supported platforms.

[![docker-publish](https://github.com/nuclear-treestump/pydepgate/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/nuclear-treestump/pydepgate/actions/workflows/docker-publish.yml)
[![docker-repro-check](https://github.com/nuclear-treestump/pydepgate/actions/workflows/docker-repro.yml/badge.svg)](https://github.com/nuclear-treestump/pydepgate/actions/workflows/docker-repro.yml)

**A zero dependency lightweight static analyzer designed for adversarial-shape code in python to detect supply chain attacks before they reach your interpreter.**

pydepgate inspects Python packages and environments for code that executes
silently at interpreter startup. This was the attack class used by the
March 2026 LiteLLM supply-chain compromise and catalogued as
[MITRE ATT&CK T1546.018](https://attack.mitre.org/techniques/T1546/018/).

<img width="1091" height="784" alt="demo2" src="https://github.com/user-attachments/assets/a57ed511-8149-445a-880b-b597dc1b61c0" />

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

## Docker usage

```bash
docker pull ghcr.io/nuclear-treestump/pydepgate:latest
docker pull ghcr.io/nuclear-treestump/pydepgate:0.X.Y
docker pull ghcr.io/nuclear-treestump/pydepgate:0.X
```

The official image is published for `linux/amd64` and `linux/arm64`.
For CI and production package-intake workflows, prefer pinning by digest
rather than relying on a mutable tag.

From 0.5.0 onward, container releases are signed by digest,
GitHub-attested, emitted with BuildKit provenance and SBOM attestations,
built from verified PyPI wheel inputs, and reproducible for supported
platforms.

Container tags, digests, verification commands, runtime properties, and
local invocation patterns are documented in the
[Docker image guide](https://nuclear-treestump.github.io/pydepgate/guides/docker-image).

CI-specific examples are in the
[CI integration guide](https://nuclear-treestump.github.io/pydepgate/guides/ci-integration).

## Quickstart

```bash
# Scan a wheel
pydepgate scan some-package-1.0.0-py3-none-any.whl

# Scan an installed package by name
pydepgate scan litellm

# Scan a single file
pydepgate scan --single suspicious_module.py

# Look up what a signal means
pydepgate explain DENS010
```

Exit code `0` is clean, `2` means at least one HIGH or CRITICAL finding.
The full exit code contract is in
[docs/reference/exit-codes.md](https://nuclear-treestump.github.io/pydepgate/reference/exit-codes).

## Usage

### Scan for known vulnerable package versions

```bash
pydepgate cvedb update
pydepgate cvescan some-package.whl
pydepgate cvescan --save-to-db some-package.whl
```

`pydepgate scan` looks for suspicious startup-vector behavior.
`pydepgate cvescan` checks package identity against the local OSV-backed
CVE database. Use both when you want behavioral and known-vulnerability
coverage.

### Scan an artifact

Wheels, source distributions, and installed packages all use the same
positional `scan` invocation:

```bash
pydepgate scan some-package-1.0.0-py3-none-any.whl
pydepgate scan some-package-1.0.0.tar.gz
pydepgate scan litellm
```

The wheel and sdist paths read directly from disk. The installed-package
form is resolved via `importlib.metadata` against the active environment.

### Scan a single file

`--single` bypasses wheel/sdist/installed-package dispatch and analyzes
the file directly. Useful for iterating on test fixtures, ad-hoc
inspection of a suspicious file, or reproducing a finding without
restructuring the file into a package:

```bash
pydepgate scan --single suspicious_module.py
pydepgate scan --single fixture.pth
pydepgate scan --single garbage.py --as init_py
```

The file kind is auto-detected from the filename. `.pth` files are
treated as `pth`; files named `setup.py`, `__init__.py`,
`sitecustomize.py`, or `usercustomize.py` are classified as their natural
kind; anything else defaults to `setup_py` (the most permissive context).
Override with `--as`: `setup_py` / `init_py` / `pth` / `sitecustomize` /
`usercustomize` / `library_py`.

### Scan with payload peek

The peek enricher attempts safe partial decoding of large encoded
literals so you can see what's actually inside a flagged blob without
ever executing it:

```bash
pydepgate scan some-package.whl --peek
pydepgate scan some-package.whl --peek --peek-chain
```

Peek handles base64, hex, zlib, gzip, bzip2, and lzma chains up to a
configurable depth, classifies the terminal payload, and emits ENC002
when the unwrap chain is nested. Pickle data is detected but never
deserialized; decompression bombs are bounded by an in-flight byte
budget.

Full peek flag reference: [docs/cli/index.md](https://nuclear-treestump.github.io/pydepgate/cli/index#payload-peek).

### Scan with recursive decode

`--decode-payload-depth=N` runs a recursive re-scan over decoded
payloads, catching the multi-layer attack shape used by LiteLLM 1.82.8
(a base64 outer payload whose decoded source contains a second base64
payload).

```bash
pydepgate scan --deep some-package.whl --peek \
    --decode-payload-depth=3 \
    --decode-iocs=full \
    --decode-location ./forensics
```

Output goes to a directory chosen with `--decode-location` (default
`./decoded/`). With `--decode-iocs=full`, the run produces an encrypted
ZIP archive (default password `infected`, the malware-research
convention) plus a plaintext IOC sidecar for grep-friendly hash
extraction.

Full decode pipeline reference, including the IOC mode matrix and
end-to-end forensic example:
[docs/guides/decode-payloads.md](https://nuclear-treestump.github.io/pydepgate/guides/decode-payloads).

### Scan in CI

`--ci` forces machine-readable JSON output and disables ANSI color. It
does not change `--min-severity`; combine the two when CI should block
only on HIGH and CRITICAL findings:

```bash
pydepgate scan --ci --min-severity high some-package.whl
```

Full CI guide (GitHub Actions, GitLab CI, Docker, pre-commit hooks):
[docs/guides/ci-integration.md](https://nuclear-treestump.github.io/pydepgate/guides/ci-integration).

### Scan with custom rules

```bash
pydepgate scan some-package.whl --rules-file company-rules.gate
```

Auto-discovery checks `./pydepgate.gate` then `<venv>/pydepgate.gate`
when the flag is not set. The rule file format is TOML or JSON,
auto-detected. Full format spec:
[docs/reference/rules-file.md](https://nuclear-treestump.github.io/pydepgate/reference/rules-file).

### Preserve scan evidence

```bash
pydepgate scan --save-to-db some-package.whl
pydepgate db list-runs
pydepgate db explain --run-id <run-id>
```

pydepgate can store scan runs in a local SQLite evidence database,
including artifact hashes, active findings, finding locations, decoded
payload trees, and CVE matches. This makes findings reproducible after
the terminal session is gone.

### Look up a signal or rule

```bash
pydepgate explain STDLIB001
pydepgate explain DENS010
pydepgate explain --rule default_stdlib001_in_pth
pydepgate explain --list
```

### Scan an entire library archive

```bash
pydepgate scan --deep some-package.whl --min-severity high
```

`--deep` runs the density analyzer over ordinary library `.py` files in
addition to startup vectors. The density layer produces enough
informational signals at library scope that the `--min-severity high`
filter is strongly recommended.

### SARIF output

```bash
pydepgate scan some-package.whl --format sarif > findings.sarif
```

Emits a SARIF 2.1.0 document with codeFlows on decoded-payload findings,
24-character partial fingerprints for cross-run deduplication, and
content-blind message text (no payload bytes leak into the document).
For GitHub Code Scanning integration:
[docs/guides/sarif-integration.md](https://nuclear-treestump.github.io/pydepgate/guides/sarif-integration).

## What pydepgate detects

The current analyzer set covers five major classes of suspicious
behavior in startup vectors. Each analyzer emits raw signals; the rules
engine maps signals to severity-rated findings based on file kind and
context.

**Encoding abuse (ENC001, ENC002).** Patterns where encoded content is
decoded and executed in a single chain, for example
`exec(base64.b64decode(payload))`. Catches base64, hex, codec-based,
zlib, bz2, lzma, and gzip variants. With `--peek` enabled, ENC002 fires
when the partial-decoder unwrap loop reaches 2+ chain layers or
exhausts its configured depth, strong evidence that a literal is
intentionally obfuscated rather than a benign encoded blob.

**Dynamic execution (DYN001-007).** Direct calls to `exec`, `eval`,
`compile`, or `__import__`; access to exec primitives via `getattr`,
`globals()`, `locals()`, `vars()`, or `__builtins__` subscripts;
compile-then-exec across the file; and aliased call shapes that catch
`e = exec; e(...)` evasions.

**String obfuscation (STR001-004).** Obfuscated string expressions
that resolve to the names of exec primitives or dangerous stdlib
functions, computed by a safe partial evaluator that never executes
user code. Catches concatenation (`'ev' + 'al'`), character codes
(`chr(101) + chr(118) + chr(97) + chr(108)`), slicing (`'lave'[::-1]`),
`str.join` of literal pieces, `bytes.fromhex(...).decode()`, f-string
assembly, and single-assignment variables containing obfuscated values.
The "harder they hide it the stronger the signal" model is realized
through operation counting.

**Suspicious stdlib usage (STDLIB001-003).** Calls to stdlib functions
that are highly unusual in startup vectors: process spawn
(`STDLIB001`: `os.system`, `subprocess.Popen`, `subprocess.run`,
`os.exec*`), network operations (`STDLIB002`: `urllib.request.urlopen`,
`socket.socket`, `http.client`), and native code loading (`STDLIB003`:
`ctypes.CDLL`, `ctypes.WinDLL`). The rules engine promotes these to
CRITICAL when they appear in `setup.py` or `.pth` files.

**Code density (DENS001-051).** A broad layer covering the things
obfuscated code looks like even when no single primitive call is
suspicious on its own: high-entropy string literals, base64-alphabet
strings, machine-generated identifiers, confusable single-character
names, invisible Unicode characters, Unicode homoglyphs in identifiers,
disproportionate AST depth, deeply nested lambdas, byte-range integer
arrays, high-entropy docstrings, and dynamic `__doc__` references
passed to a callable. Calibrated so the same content scans differently
depending on file kind: a high-entropy base64 literal in `.pth` is
CRITICAL, in `__init__.py` is MEDIUM, anywhere else is LOW.

Complete signal reference with severity tables per file kind:
[docs/reference/signals.md](https://nuclear-treestump.github.io/pydepgate/reference/signals).

## Layered detection in practice

The LiteLLM 1.82.8 `.pth` payload is a single line:

```
import base64; exec(base64.b64decode('cHJpbnQoMSkK'))
```

A scanner that grepped for `exec` would catch it. A scanner that
grepped for `base64.b64decode` would catch it. But an attacker who
knew about either of those evasions could trivially defeat both.
pydepgate fires five separate findings on this line from four
independent analyzers:

- **ENC001** (encoding_abuse): decode-then-execute pattern
- **DYN002** (dynamic_execution): `exec()` with non-literal argument at module scope
- **DENS001** (code_density): token-dense single line
- **DENS010** (code_density): high-entropy string literal
- **DENS011** (code_density): base64-alphabet string literal

Plus the rule layer promotes all of them to `CRITICAL` because the
file is a `.pth`. To evade pydepgate, an attacker has to defeat every
analyzer simultaneously while still producing a working `.pth`
payload. Each evasion narrows what's possible; the intersection of all
evasions is the empty set for any shape that could realistically
execute on Python startup.

## The rules engine

Analyzers emit raw signals. The rules engine maps signals to
severity-rated findings using a data-driven rule set. Default rules
are built into pydepgate; users can override or augment them with a
`pydepgate.gate` file (TOML or JSON, auto-detected) in the project
root, the venv root, or specified via `--rules-file`.

A rule has three parts: identity, match conditions, and an effect:

```toml
[[rule]]
id = "litellm-pth-stdlib"
signal_id = "STDLIB001"
file_kind = "pth"
action = "set_severity"
severity = "critical"
explain = "subprocess calls in .pth files have no legitimate use case."
```

Three actions are supported: `set_severity`, `suppress`, and
`set_description`. User rules always take precedence over default
rules, regardless of specificity. Suppressed findings are tracked
separately so users can see what would have fired and why it didn't.

Run `pydepgate explain --list` to see all default rules and signals
with descriptions. Complete rules file specification:
[docs/reference/rules-file.md](https://nuclear-treestump.github.io/pydepgate/reference/rules-file). Worked
walkthroughs of common rule-writing tasks:
[docs/guides/custom-rules.md](https://nuclear-treestump.github.io/pydepgate/guides/custom-rules).

## Documentation

| Section | Contents |
|---|---|
| [Getting Started](https://nuclear-treestump.github.io/pydepgate/index) | First scan, reading output, using `explain` |
| [CLI Reference](https://nuclear-treestump.github.io/pydepgate/cli/index) | All subcommands, all flags, environment variables |
| [CLI Reference: db](https://nuclear-treestump.github.io/pydepgate/cli/db) | Store, query, and explain local scan evidence |
| [CLI Reference: cvedb](https://nuclear-treestump.github.io/pydepgate/cli/cvedb) | Build and inspect the local CVE database |
| [CLI Reference: cvescan](https://nuclear-treestump.github.io/pydepgate/cli/cvescan) | Match artifacts against known vulnerable versions |
| [Finding Fingerprint v1](https://nuclear-treestump.github.io/pydepgate/reference/fingerprint-v1) | Deterministic finding fingerprint specification |
| [Signals Reference](https://nuclear-treestump.github.io/pydepgate/reference/signals) | Every signal ID with severity tables per file kind |
| [Rules File](https://nuclear-treestump.github.io/pydepgate/reference/rules-file) | `pydepgate.gate` format specification |
| [Exit Codes](https://nuclear-treestump.github.io/pydepgate/reference/exit-codes) | Exit code contract and CI implications |
| [Output Formats](https://nuclear-treestump.github.io/pydepgate/reference/output-formats) | Human, JSON, SARIF schemas |
| [Guide: CI Integration](https://nuclear-treestump.github.io/pydepgate/guides/ci-integration) | GitHub Actions, GitLab CI, pre-commit, Docker-in-CI |
| [Guide: Docker Image](https://nuclear-treestump.github.io/pydepgate/guides/docker-image) | Container tags, digests, verification, runtime properties |
| [Guide: Custom Rules](https://nuclear-treestump.github.io/pydepgate/guides/custom-rules) | Suppressing false positives, scoping rules |
| [Guide: Decode Payloads](https://nuclear-treestump.github.io/pydepgate/guides/decode-payloads) | Recursive decode, IOC sidecars, encrypted archives |
| [Guide: SARIF Integration](https://nuclear-treestump.github.io/pydepgate/guides/sarif-integration) | GitHub Code Scanning ingestion |

## Design constraints

- **Zero runtime dependencies.** Standard library only. This is a
  load-bearing design constraint, not a stylistic preference: every
  additional dependency is a supply-chain attack surface for a tool
  whose job is to defend against supply-chain attacks.
- **Safe by construction.** Parsers and the partial evaluator never
  execute, compile, or import input content. Every operation modeled
  by the resolver is reimplemented from scratch using only Python
  builtins on values the resolver itself produced.
- **Self-integrity at bootstrap.** Critical stdlib references are
  captured into locals before any untrusted code runs (relevant when
  the runtime engine ships in v0.4).
- **Lightweight.** The full test suite runs in roughly twenty seconds
  on the lowest available options in Codespaces, including
  subprocess-based CLI tests against installed packages.
- **Verifiable release artifacts.** Container releases are built around
  digest identity rather than tag trust. From 0.5.0 onward, supported
  platform images are signed, attested, emitted with provenance/SBOM
  metadata, smoke-tested by digest, built from verified package inputs,
  and checked for reproducibility.

## Architecture

The codebase is organized as a layered pipeline.

Analyzers do not see raw bytes. They walk parsed representations and
emit `Signal` objects. The rules engine wraps signals with severity to
produce `Finding` objects, applying user and default rules in priority
order. The CLI renders findings in human, JSON, or SARIF format.

The `_resolver.py` module is reusable infrastructure for any analyzer
that needs to know what an expression evaluates to. It returns
structured `ResolutionResult` objects with success/failure status,
operation counts, partial values, and resolved fragment lists.

The static engine exposes three entry points for single-file analysis.
`scan_file(path)` reads bytes and routes through triage by filename.
`scan_bytes(content, internal_path, ...)` is the per-file workhorse
that artifact enumerators (wheel, sdist, installed) call once per
in-scope file. `scan_loose_file_as(path, file_kind)` bypasses triage
entirely and forces a file kind, preserving the real path through to
finding contexts; this is the entry point used by
`pydepgate scan --single`.

## Development

```bash
git clone https://github.com/nuclear-treestump/pydepgate
cd pydepgate
pip install -e .
python -m unittest discover tests -v
```

The test suite has grown to over 1600 tests as the analyzer
set has expanded. Tests are organized by module and include happy-path
coverage, evasion batteries, false-positive batteries, robustness
checks against adversarial inputs, integration tests against synthetic
wheels and sdists, and CLI tests via subprocess.

To regenerate the binary `.pth` test fixtures after editing them:

```bash
python scripts/generate_fixtures.py
```

Contributors: see [CONTRIBUTING.md](CONTRIBUTING.md) for the issue
process, sign-off requirements, and contribution scope.

## Safety notes

This project builds tooling to defend against Python supply-chain
attacks. The test fixtures in `tests/fixtures/` and the synthetic
samples used in integration tests model the *structural shape* of
known attacks (LiteLLM 1.82.8, Trojan Source CVE-2021-42574, others
catalogued under T1546.018) but contain only inert payloads. No
actual malicious code is present in this repository.

For regression testing against real malicious samples, use the
[OSSF malicious-packages](https://github.com/ossf/malicious-packages),
[Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset),
or [lxyeternal/pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry)
datasets. Do so in disposable VMs or containers, and do not commit
samples to this repository.

## Known limitations

pydepgate's static analysis is honest about what it can and cannot
catch. Documented gaps include:

**Analysis gaps:**

- Function return tracking. `code = make_payload()` where
  `make_payload()` internally calls `compile(...)` is not flagged.
- `__builtins__` as a Name subscript (rather than via a function call).
- Tuple unpacking, augmented assignment, and conditional assignments
  in the resolver's variable tracking.
- Lambda scope precision (lambdas count as their enclosing scope).
- Aliased stdlib imports such as `from subprocess import Popen as P`.

**Density-layer caveats:**

- `DENS020` (low-vowel-ratio identifiers) and `DENS040` (AST depth)
  both produce false positives on legitimate machine-generated code
  (Cython output, parser tables, generated configuration). They ship
  at `LOW` severity outside startup vectors so they surface as
  contributing signals rather than standalone alerts.
- `DENS031` (homoglyphs) can fire on legitimate non-English variable
  names in non-Latin codebases. The default rule keeps it at `HIGH`
  rather than `CRITICAL` outside startup vectors so users with
  intentional non-Latin naming can suppress with a single user rule.

## Promise

Supply-chain security is too important to be a function of corporate
goodwill. This project exists because the current state of Python
supply-chain defense is not acceptable, and it will continue to exist
on those terms.

This project will not be sold, transferred to a corporation, or made
part of any employment or work agreement that could capture or stifle
it. If a time comes when development by the current maintainer is no
longer possible, the maintainer commits to finding a successor who
will be held to the same conditions. If no such successor can be
found, the project will be archived rather than placed under corporate
control.

## Author

Built by Ikari ([@0xIkari](https://github.com/0xIkari)) - Python and 
security engineering. Available for security engineering roles; pydepgate remains independent under the terms of the Promise above.

- LinkedIn: [zmillersecengineer](https://www.linkedin.com/in/zmillersecengineer/)
- Email: ikari@nuclear-treestump.com

## License

Apache 2.0. See [LICENSE](LICENSE).
