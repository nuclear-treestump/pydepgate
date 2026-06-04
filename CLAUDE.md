# CLAUDE.md

> **Purpose:** This file provides guidance for LLM-assisted development. It is not an enforcement mechanism — tests, CI, and code review remain authoritative.

## Project overview

pydepgate is a zero-dependency static analyzer that detects supply-chain attacks in Python packages by inspecting startup vectors (.pth files, setup.py, sitecustomize.py, usercustomize.py, __init__.py, console-script entry points). It analyzes wheels, sdists, installed packages, and loose files without ever executing user input. Current version as of 2026-06-02: 0.5.0. Python 3.11+ required.

## Build and run

```bash
pip install -e .                           # editable install
python -m unittest discover tests -v       # full test suite (~1600 tests, <1 min)
pydepgate scan some-package.whl            # scan an artifact
pydepgate scan --single suspicious.py      # scan a loose file
pydepgate explain DENS010                  # look up a signal
```

Regenerate binary .pth test fixtures after editing:
```bash
python scripts/generate_fixtures.py
```

## Source layout

```
src/pydepgate/
  cli/                  # CLI entry point, argparse, subcommands, exit codes
  analyzers/            # Five production analyzers + shared infra (_resolver, _visitor, _enrichment)
  enrichers/            # Payload peek, decode, passthrough
  engines/              # StaticEngine (static.py), preflight, runtime stubs
  parsers/              # Wheel, sdist, .pth, Python source parsers
  reporters/            # Human, JSON (schema v4), SARIF 2.1.0, decoded tree (schema v2)
  rules/                # Rule engine, defaults, loader, explanations, per-analyzer groups
  traffic_control/      # Triage: decides which files get analyzed and their file kind
  dbs/                  # cvedb (OSV SQLite), pdgdb (local evidence database)
  package_tools/        # CVE scanner, dependency resolver, metadata extraction
  visualizers/          # Density map, peek render
  introspection/        # Installed package discovery
  pdgplatform/          # Platform-specific paths
  run_context.py        # Thread-safe run/scan IDs (UUIDv7)
tests/                  # Mirrors src layout: analyzers/, cli/, engines/, enrichers/, etc.
```

## Scan pipeline (how a scan flows)

CLI -> argparse -> StaticEngine(analyzers, enrichers, rules) -> triage (which files to analyze) -> per-file loop:
  1. Parsers: bytes -> AST or .pth structure (no security decisions)
  2. Analyzers: AST -> raw Signals with enrichment_hints (no severity)
  3. Enrichers: Signals + bytes -> enriched Signals (peek decoding)
  4. Rules engine: Signals -> severity-rated Findings (file-kind-aware)
  5. Reporter: Findings -> human/JSON/SARIF output
  6. Exit code from findings

Each layer has a single responsibility. Put work in the right layer. DO NOT GUESS. Ask the maintainer or open a PR discussion if unclear.

Where new work goes:
- New attack detection → analyzers + rules, possibly with a new enrichment hint
- New output format → reporter
- Rule discovery/loading changes → rules loader
- False-positive fix → prefer rule-layer fix over analyzer-layer fix (rules target specific file kinds; analyzer changes are global)

## Critical constraints

These are load-bearing. Breaking them produces silent failures, security bugs, or both.

### Never execute input

The static analyzer NEVER executes, compiles, imports, or deserializes user input. The safe partial evaluator (`analyzers/_resolver.py`) reimplements string operations from scratch using only builtins on values it produced itself. Never call runtime methods on resolved values (no `value.replace(...)`, no `getattr(resolved_value, ...)`). Model the operation instead.

The specific threat: an attacker can construct a value whose `__getattr__` or `__class__` does something the resolver isn't expecting. If the resolver delegates to the runtime (e.g. calling `.replace()` on a resolved object), the attacker controls what executes. This collapses the entire safety property into arbitrary code execution in the analyzer process.

The discipline when extending the resolver: model the operation from scratch using builtins, don't delegate to the runtime. If you need `str.replace`, write a function that takes the resolved string and literal arguments and produces the result by hand. The same applies to any new analyzer that inspects computed values — if you're writing `getattr(some_resolved_value, 'whatever')`, stop and add a new resolver operation with the same no-delegation discipline instead.

### Picklability contract

`_scan_one_file(FileScanInput) -> FileScanOutput` in `engines/static.py` is a pure function used for active `ProcessPoolExecutor` parallelism. Any changes around the scan engine must be careful not to break this. Three requirements, enforced by `tests/engines/test_deploy_the_pickle.py`:

1. **Inputs and outputs must be picklable.** `FileScanInput`, `FileScanOutput`, every analyzer, enricher, and rule must survive a pickle round-trip without losing information.
2. **No module-level mutable state.** Analyzers, enrichers, and the engine must not rely on global variables, lazy singletons, or class-level mutable attributes.
3. **No file-scoped side effects.** A scan of file A must not leave state behind that a scan of file B can observe. Same input must always produce same output.

If something is hard to pickle (compiled regex, file handle), construct it at use time inside analyzer logic, not as stored state.

### Zero runtime dependencies

No third-party runtime dependencies. This is a load-bearing security constraint, not a preference. Build/test/CI tooling can use whatever fits; runtime cannot. Tests must use `unittest` (stdlib only).

### Signal ID stability

Signal IDs (ENC001, DYN002, DENS010, etc.) are user-facing and matched in `pydepgate.gate` rule files. Never rename existing IDs. New signals get new IDs in unused ranges. Namespaced by analyzer prefix: ENC, DYN, STR, STDLIB, DENS. Deprecation requires aliasing for at least one major version.

### Exit code contract (stable since v0.1)

- `0` = clean
- `1` = findings present, none HIGH/CRITICAL
- `2` = findings present, at least one HIGH/CRITICAL
- `3` = tool error

CI pipelines depend on these. Repurposing code 2 means a pipeline configured to fail on HIGH/CRITICAL silently starts passing malicious-package scans. Repurposing code 0 means clean scans start failing builds. Both are catastrophic for a security tool. Never repurpose. New codes go above 3.

### Rules precedence model

1. User rules > system rules > defaults
2. Among same source: more match fields wins (specificity)
3. Ties: load order wins

Do not refactor this for clarity or performance without explicit discussion.

### JSON schema_version contract

Primary scan JSON output emits `schema_version: 4`. Decoded-tree JSON output emits `schema_version: 2`. Any shape change (new keys, renames, type changes, removals) requires a version bump. Additive = minor bump; breaking = major bump.

### CLI argument-position invariant

Global flags work before or after the subcommand. Mechanism: `_add_global_flags` called twice (top-level with real defaults, subparsers with `argparse.SUPPRESS`). New global flags must follow this pattern. See `cli/peek_args.py` for prior art.

### Reporter context-key handling

- Human reporter: explicit allowlist of "interesting keys" in `_render_finding`. New keys need allowlist update.
- JSON reporter: renders all context keys except underscore-prefixed ones. Underscore prefix = suppressed from JSON wire format (for pipeline-internal data like `_full_value`).

Two common mistakes: (1) Adding a context key and expecting it in human output — it won't appear unless you update the allowlist in the same PR. (2) Using underscore prefix as a naming convention — it's not a convention, it's a wire-format filter. Underscore-prefixed keys are deliberately omitted from JSON output. If you want the key in JSON, don't prefix with underscore. If you want it suppressed from JSON, do.

### Triage coverage boundary

`traffic_control/triage.py` controls which files get analyzed and their file kind. Changes have non-obvious consequences in two directions:

**Expanding the analyzed set** by routing more files through the pipeline can break picklability or surface new analyzer false positives in contexts where analyzers weren't calibrated. Deep mode (`--deep`) already opts into this trade-off explicitly; widening the default-mode set requires the same explicit trade-off and rule-layer work to avoid noise.

**Shrinking the analyzed set** is the more dangerous direction because the failure mode is silent: tests still pass, the scanner runs faster, and nothing alerts you that real attacks in that file kind became invisible.

Changes require explicit "this changes coverage in [direction] for [file kinds]" documentation and test cases for both positive (files that should be analyzed now are) and negative (files that should be skipped aren't).

## Code style

- Type hints throughout
- Descriptive docstrings on non-trivial functions
- Explicit over clever
- No auto-formatter configured; match surrounding code style
- No trailing whitespace or inconsistent indentation

## Tests

Tests are organized by module under `tests/` and include:
- Happy-path detection
- Evasion battery (obfuscated variants still caught)
- False-positive battery (benign patterns don't fire)
- Robustness (truncated files, malformed bytes, deep AST, unicode edges)
- Integration (synthetic wheels and sdists against the engine)
- CLI (subprocess invocation, output assertion)
- Picklability round-trips

New analyzers must include at minimum: happy-path detection, at least 3 evasion variants the analyzer should still catch, and at least 3 benign-pattern fixtures the analyzer should ignore. An analyzer that catches the obvious case but fires on every benign use of similar syntax is worse than no analyzer.

Additional test fixtures and fixture-generation scripts should be stored in `test_files/`.

All tests must pass before any change ships. Run: `python -m unittest discover tests -v`

## AI-generated code

AI assistance is fine; AI-as-author is not. Every line of a diff must be defensible as the contributor's own understanding. NEVER commit automatically, confirm with the contributor that they have reviewed the code before commiting. 
AI-generated tests that don't actually exercise the code path they claim to are the most common failure mode — verify tests fail when the code is wrong, not just pass when the code is right.

## Deny list

- Do not add runtime dependencies
- Do not execute, compile, or import input during static analysis
- Do not rename existing signal IDs
- Do not repurpose exit codes
- Do not change JSON output shape without bumping schema_version
- Do not refactor rules precedence logic
- Do not include working malware in fixtures (benign structural shapes only)
- Do not put analysis work in the wrong pipeline layer
- Do not store unpicklable state on analyzers/enrichers/rules
- Do not add global CLI flags without the dual-registration pattern
- Do not change triage coverage without explicit documentation and tests
- Do not change the `_scan_one_file` signature or I/O shapes without discussion with the maintainer.
- Do not submit AI-generated tests without verifying they fail when the code is wrong. 
- Do not change the rules precedence model without a major-version bump. 
