# pydepgate roadmap

This document describes the build plan for pydepgate. It is a living document;
scope and ordering may change as the project develops. The versioning scheme
matches the phased delivery: v0.1 is the first usable release, v1.0 is the
first release suitable for public recommendation.

## Current state

**v0.0.1 - Foundation**

- [x] Project skeleton and `src/` layout
- [x] `.pth` parser (`pydepgate.parsers.pth`)
- [x] Fourteen `.pth` test fixtures with generator script
- [x] Parser test harness (safety, classification, encoding, line endings,
      manifest-driven fixture validation)

Nothing else. No rules, no engines, no CLI, no runtime mode.

## v0.1.0 - Static analysis for `.pth` files

The first usable release. Goal: given a wheel, report on suspicious `.pth`
content.

- [ ] Data model (`pydepgate.model`): `Severity`, `Finding`, `ScanResult`,
      `ScanContext`
- [ ] Rule base class and registry (`pydepgate.rules`)
- [ ] First rule: PTH005 (oversized `.pth` file) — trivial, proves the pipeline
- [ ] Remaining `.pth` rules: PTH001 (subprocess), PTH002 (base64+exec),
      PTH003 (multi-exec), PTH004 (networking)
- [ ] Wheel unpacker (`pydepgate.parsers.wheel`)
- [ ] Static engine (`pydepgate.engines.static`)
- [ ] Minimal CLI (`pydepgate static <wheel>`)
- [ ] Human-readable reporter with ANSI output
- [ ] JSON reporter
- [ ] README updated with usage examples

**Acceptance criteria:** `pydepgate static <wheel>` on a wheel containing a
synthetic LiteLLM-shaped payload reports all applicable PTH findings with
accurate line numbers, severities, and rule IDs. Zero third-party
dependencies. Full test coverage on the rule engine and static engine.

## v0.2.0 - Preflight mode

Extend static analysis to installed environments.

- [ ] Sdist unpacker (`pydepgate.parsers.sdist`)
- [ ] Dist-info / egg-info reader (`pydepgate.parsers.dist_info`)
- [ ] Environment walker (`pydepgate.engines.preflight`)
- [ ] `pydepgate preflight` CLI subcommand
- [ ] Cross-check against known-bad feeds (OSV, optional)
- [ ] `--all-environments` flag to scan every Python install on the host
- [ ] Exit code differentiation: 0 clean, 1 findings, 2 blocking, 3 tool error

**Acceptance criteria:** `pydepgate preflight` on a machine with a deliberately
installed inert LiteLLM-shaped package correctly identifies the `.pth` file
and reports findings. No false positives on a clean environment with
setuptools editable installs and common packages.

## v0.3.0 - Additional startup vectors

Expand beyond `.pth` to the full startup-vector surface.

- [ ] `setup.py` parser and rules (command-overwriting, module-level exec,
      network imports)
- [ ] `__init__.py` top-level analyzer and rules
- [ ] `sitecustomize.py` / `usercustomize.py` detection and rules
- [ ] Console-script entry-point analyzer and rules
- [ ] Expanded fixture corpus covering each vector

**Acceptance criteria:** Static and preflight modes catch all five attack
classes catalogued under T1546.018. Rule documentation enumerates every
heuristic with rationale and MITRE mapping.

## v0.4.0 - Runtime mode

The differentiator. Wrap `python` itself with interdiction.

- [ ] Self-integrity subsystem (`pydepgate.integrity`)
- [ ] Build-time manifest generation (SHA256 of every file in the package)
- [ ] Bootstrap chain: re-exec with `-S -I`, verify self, freeze critical refs,
      install hooks, run instrumented `site.main()`, run user script
- [ ] PEP 578 audit hook manager (`pydepgate.engines.runtime`)
- [ ] `site.addpackage` shim with policy enforcement
- [ ] Policy modes: `--enforce` (block), `--warn` (log), `--audit` (SARIF)
- [ ] `pydepgate exec <script>` CLI subcommand
- [ ] Subprocess propagation: child Python processes inherit instrumentation
- [ ] Benchmarks: happy-path overhead must stay under 100ms

**Acceptance criteria:** `pydepgate exec --enforce target.py` in an environment
containing a synthetic LiteLLM-shaped `.pth` file prevents the payload from
executing and reports the interdiction. Clean-environment overhead is within
budget. Self-integrity check fails closed when any pydepgate file is tampered.

## v1.0.0 - Polish and public release

- [ ] SARIF 2.1.0 reporter with GitHub Advanced Security integration
- [ ] Allowlist subsystem: bundled, project-level, and session-level
- [ ] `pydepgate list-rules` and `pydepgate show-allowlist` introspection
      commands
- [ ] GitHub Action for CI integration
- [ ] Comprehensive documentation: architecture, rule catalog, allowlist
      workflow, threat model, limitations
- [ ] Public sample corpus script (`scripts/verify_against_real_corpus.sh`)
      demonstrating catches against real malicious packages in VM
- [ ] Announcement blog post
- [ ] License finalized

**Acceptance criteria:** A developer can install pydepgate from PyPI, run
`pydepgate preflight`, and get a useful report within 10 seconds on a typical
environment. A CI pipeline can integrate pydepgate via GitHub Action with a
single YAML block. The rule catalog page lists every heuristic with clear
rationale.

## Beyond v1.0

Not committed to ordering or scope. These are candidates, not promises.

- **Rust-accelerated hot paths.** Audit hook dispatch and manifest
  verification are the performance-sensitive components; porting them to a
  C extension or Rust module could reduce overhead further. Violates
  zero-dependency for users unless the extension is optional.

- **Stronger self-integrity.** Move the trust anchor from a Python constant
  to a compiled C extension to raise the cost of evasion. Same tradeoff.

- **Pickle, torch, and ML-model vectors.** Extend the static engine to cover
  pickle-based attack surfaces (overlapping with picklescan's scope, but
  integrated into pydepgate's pipeline).

- **PyDepGuard integration.** Refactor pydepgate's engines into loadable
  modules that PyDepGuard can consume directly, making pydepgate a
  reference implementation of the startup-vector subsystem.

- **Windows-specific hardening.** `.pth` files behave slightly differently
  on Windows (file locking, path separators); dedicated testing and rules.

- **IDE integration.** Language-server mode for real-time feedback in
  editors when a `.pth` file is opened.

- **Threat intelligence feed.** A published, signed, regularly-updated feed
  of known-bad package hashes for the preflight known-bad check.

## Principles

Decisions about scope, features, and tradeoffs should be evaluated against:

1. **Does this preserve zero runtime dependencies for users?** If not, it
   goes in a separate optional package or gets rejected.
2. **Does this preserve the under-100ms overhead budget for `exec` mode?**
   Benchmark before merging anything that touches the hot path.
3. **Does this improve the structural robustness of the tool?** A feature
   that catches more attacks at the cost of being easier to evade is a net
   loss.
4. **Is this independently testable?** Features that require elaborate
   end-to-end setup to verify tend to rot. Prefer capabilities expressible
   as pure-function rules over those that require orchestration.
5. **Does this match the product story?** pydepgate is a lightweight runner
   that interdicts suspicious startup behavior. Features that don't serve
   that story belong in PyDepGuard, not here.
