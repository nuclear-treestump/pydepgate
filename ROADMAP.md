# pydepgate roadmap

This document describes the forward trajectory of pydepgate. For what has
already shipped, see [CHANGELOG.md](CHANGELOG.md).

The version numbers in this document are targets, not commitments.
Pre-1.0 versions reserve the right to make breaking changes to the public
API surface (CLI flags, JSON schema, SARIF schema, exit codes, rule
schema) within minor version bumps. After 1.0, breaking changes go
through a formal deprecation cycle.

## Where this document came from

The previous version of this file was written before any code existed. It
described a five-version build plan with neat phase boundaries, intended
features per version, and acceptance criteria. Reality outpaced the plan
within weeks.

The original plan said v0.4.0 would deliver runtime mode (PEP 578 audit
hooks, build-time manifests, policy enforcement). v0.4.0 is shipping
SARIF 2.1.0 instead. The original plan said SARIF was a v1.0.0 feature.
The original plan said the density layer (32 rules across DENS001-051)
did not exist; it does. The original plan did not anticipate recursive
payload decoding, encrypted-archive output, pre-commit hooks, the rules
engine with TOML/JSON loading and predicate operators, or the
content-blind SARIF emission. All of those shipped.

This rewrite reflects where the project actually is, what is queued, and
what slipped. It is meant to be coherent against today's source rather
than a clean projection from a starting point that no longer applies.

## Current state: v0.4.0

The static analysis pipeline is functional end-to-end against wheels,
sdists, installed packages, and loose files. The output formats are
human-readable terminal, JSON v3, and SARIF 2.1.0. The recursive payload
decoder reconstructs multi-layer attack chains. The rules engine
supports user-supplied TOML or JSON rule files with predicate operators
and typo suggestions. Five production analyzers cover encoding abuse,
dynamic execution, string obfuscation, suspicious stdlib usage, and the
density layer. The default rule set ships 32 rules dedicated to density
signals.

For the full feature list see the README "What works today" section. For
the chronological account of how things landed see CHANGELOG.

## Versioning

- **0.4.x** patches and minor performance work. No breaking changes.
- **0.5.0 onward** new feature surfaces. Pre-1.0 still reserves
  breaking-change rights but in practice these have been confined to
  schema field additions and CLI flag additions, both backwards-
  compatible for sane consumers.
- **1.0.0** the API-stability inflection point. CLI flags, JSON schema,
  SARIF schema, exit codes, and the rule-engine schema all become
  formally stable with deprecation-cycle requirements before any
  breaking change.

## v0.4.x: stabilization and parallelism

- [x] Engine parallelism. No later than v0.4.5. The picklability
      contract for `FileScanInput`/`FileScanOutput` has been preserved
      since v0.1, so the per-file scan phase can move to a process pool
      without engine refactoring. Target is meaningful speedup on
      multi-megabyte wheels with thousands of internal files. No CLI
      changes; opt-in via a flag with conservative default worker
      count.
- Routine bug fixes, documentation refinements, dependency-free minor
  performance work.

## v0.5.0: SIEM emission

- [ ] SIEM emission layer. First-class HEC integration for Splunk with
      CIM-compliant data models so findings populate Enterprise Security
      correctly rather than appearing as raw JSON. Elastic, Datadog, and
      Sentinel emission planned alongside.

The SIEM work is bounded; once shipped it should not need significant
expansion until customers ask for additional vendor backends.

## v0.6.0: analyzer expansion and dependency-graph awareness

The exact contents of this version are not yet pinned. The candidate
pool, drawn from items currently flagged "in active development" in the
README:

- [ ] `comment_analysis` analyzer. Detection of payloads hidden in
      comments and docstrings beyond what DENS050/DENS051 already cover.
- [ ] Aliased import resolution. Catches `from subprocess import Popen
      as P` and similar evasions that currently slip past the dynamic-
      execution analyzer.
- [ ] Preflight mode. Environment-walking variant of the static engine
      that scans every importable package in a Python install. Different
      engine path from the artifact-scanning entry points; reuses the
      analyzer set unchanged.
- [ ] Transitive-dependency audit subcommand. Pip-wrapper or standalone
      `audit` subcommand that resolves a dependency graph and scans each
      reachable package.

These items do not all need to land in 0.6.0. Some may slip to 0.6.x
patches or to 0.7.x once runtime mode lands. The slot is a candidate
pool, not a commitment.

## v0.7.0: runtime mode

The marquee feature originally targeted for v0.4.0. The slip from v0.4
to v0.7 was deliberate: getting the output formats, rules engine, and
analyzer set right matters more than getting runtime interdiction
shipped fast, because runtime mode depends on a stable data-shape and
pluggability story to be useful. May land earlier than v0.7.0 if the
intermediate work falls into place faster than expected.

- [ ] Self-integrity subsystem. Critical stdlib references captured into
      locals before any untrusted code runs.
- [ ] Build-time manifest generation. SHA256 of every file in the
      package, signed, embedded.
- [ ] Bootstrap chain. Re-exec with `-S -I`, verify self, freeze
      critical refs, install hooks, run instrumented `site.main()`,
      then user script.
- [ ] PEP 578 audit hook manager.
- [ ] `site.addpackage` shim with policy enforcement.
- [ ] Policy modes: `--enforce` (block), `--warn` (log), `--audit`
      (SARIF emission of would-block events).
- [ ] `pydepgate exec <script>` CLI subcommand.
- [ ] Subprocess propagation. Child Python processes inherit
      instrumentation.
- [ ] Performance budget. Happy-path overhead under 100ms;
      benchmarked before merge.

Runtime mode requires the picklability contract that v0.4.x parallelism
will validate, the SARIF emission that v0.4.0 ships (for `--audit`
output), and the rules engine that v0.3.0 shipped. The dependency chain
is why runtime mode lives at v0.7 rather than v0.4.

## v1.0.0: API stability

The transition from "moves fast and breaks things on minor version
bumps" to "deprecation-cycle-bound stability."

- [ ] Stability promises for CLI flags, JSON schema, SARIF schema,
      exit codes, rule-engine schema. Breaking changes only via
      deprecation cycle.
- [ ] Comprehensive documentation: architecture document, formal threat
      model, complete rule catalog with rationale and MITRE mapping,
      consumer guide for downstream tooling.
- [ ] Public sample corpus script demonstrating catches against real
      malicious packages in a disposable VM.
- [ ] Announcement post.
- [ ] License finalized (currently Apache 2.0; no anticipated change).

Acceptance criterion: a downstream tool consuming pydepgate's JSON or
SARIF output can rely on the schema for the duration of the 1.x line.

## Beyond v1.0

Not committed. PyDepGuard integration remains a long-term direction.
Other directions will surface as the project matures and as user demand
makes priorities clearer.

## Principles

Decisions about scope, features, and tradeoffs are evaluated against
these criteria. They are derived from the constraints that have shaped
the project to date, rewritten to match where it is rather than where
the original plan thought it would be.

1. **Zero runtime dependencies for users.** The standard library only.
   This is a load-bearing constraint, not a stylistic preference: every
   additional dependency is a supply-chain attack surface for a tool
   whose job is to defend against supply-chain attacks. CI, build, and
   test dependencies are not constrained; runtime is.

2. **Safe by construction.** Parsers, the partial evaluator, and the
   payload-peek and decode loops never execute, compile, or import
   input content. Every operation modeled by the resolver is
   reimplemented from scratch using only Python builtins on values the
   resolver itself produced. Pickle data is detected, never
   deserialized.

3. **Content-blind output.** SARIF and JSON output describe what was
   detected behaviorally, not what content was matched. Argument
   values, URLs, command lines, and literal payload bytes never appear
   in output that flows into CI logs or public artifact uploads. A
   defender can publish output without re-leaking the underlying
   attack content.

4. **Performance budgets are per-mode and benchmarked.** Static
   analysis runs in roughly twenty seconds for the full test suite on a
   2 core 8 GB Github Codespace. SARIF validation against the Microsoft Multitool
   adds CI cost but not user-facing cost. Runtime mode (v0.7.0
   target) carries a happy-path overhead budget under 100ms;
   benchmarks land before any feature that touches that hot path.

5. **Independently testable.** Features that require elaborate
   end-to-end orchestration to verify tend to rot. Capabilities
   expressible as pure-function rules over parsed representations are
   strongly preferred over those that require integration setup.

6. **Structural robustness over feature breadth.** A feature that
   catches more attacks at the cost of being easier to evade is a net
   loss. The "harder they hide it the stronger the signal" model
   stays load-bearing.

7. **Match the product story.** pydepgate is a static and (in v0.7+) a
   runtime analyzer for the Python startup-vector attack surface.
   Features that don't serve that story belong in PyDepGuard, not
   here. PyDepGuard's broader runtime-sandboxing and dependency-
   management scope is a deliberate separation, not a tracking
   inadequacy.
