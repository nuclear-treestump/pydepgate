# Changelog

All notable changes to pydepgate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 versions reserve the right to make breaking changes to the
public API surface (CLI flags, JSON schema, exit codes) within minor
version bumps. After 1.0, the contracts in [CONTRIBUTING.md](CONTRIBUTING.md)
become binding stability promises with formal deprecation cycles.

## [Unreleased]

(no changes yet)

## [0.4.0] - 2026-05-10

### Added

- **SARIF 2.1.0 output.** `--format sarif` now emits real
  SARIF 2.1.0 documents instead of the under-development stub
  that shipped through 0.3.x. Each scan run produces a single
  document with the full rules catalog under
  `tool.driver.rules`, per-finding results with severity-mapped
  levels (critical/high to `error`, medium to `warning`, low/info
  to `note`), GitHub-compatible `security-severity` numeric
  scores, 24-character partial fingerprints for cross-run alert
  deduplication, and `automationDetails.id` of the form
  `pydepgate/{artifact_kind}/` for cross-run grouping. Deep
  scans suffix `_deep` to the artifact kind so deep and non-deep
  runs of the same artifact group separately. Compatible with
  GitHub Code Scanning, Azure DevOps, and any consumer that
  follows the OASIS SARIF 2.1.0 spec.
- **Decoded-payload codeFlows.** Findings reached through the
  recursive decode pipeline are surfaced as SARIF results with
  `codeFlows` describing the decode chain. Each `threadFlow`
  walks from the outer high-entropy literal through each decode
  layer to the innermost detection, surfacing the attack path
  in consumer UI like GitHub's "Show paths". Multi-layer
  payloads (the LiteLLM 1.82.8 attack pattern) produce nested
  threadFlow encoding with `nestingLevel` reflecting decode
  depth.
- **`--sarif-srcroot PATH` flag and `PYDEPGATE_SARIF_SRCROOT`
  environment variable.** Populates
  `originalUriBaseIds.PROJECTROOT` in the emitted document and
  tags on-disk artifact locations with `uriBaseId: "PROJECTROOT"`
  so SARIF consumers resolve paths against a known source root.
  Required when ingesting into GitHub Code Scanning for in-repo
  source navigation. The flag has CLI-over-env precedence
  matching the existing flag conventions, treats empty string
  as unset, and emits a soft warning to stderr when set without
  `--format sarif`.
- **Content-blind SARIF emission.** The document describes what
  was called (`subprocess.run()`, `urllib.request.urlopen()`)
  without including arguments, URLs, or literal payload bytes.
  This is by design: SARIF documents flow into CI logs, code
  scanning UIs, and artifact downloads, and embedding payload
  content there would replicate the exact threat the analyzer
  is detecting. A defender can publish a SARIF document
  publicly without re-leaking the underlying attack content.
  Verified against a real LiteLLM 1.82.8 sample before release.
- **`pydepgate.reporters.sarif` package.** New reporter package
  with submodules for severity mapping, URI scheme decisions,
  partial fingerprints, rule descriptor catalog generation,
  per-finding result construction, and full document assembly.
  The package is imported automatically when `--format sarif`
  is selected and is not part of the public API surface.
- **`pydepgate.cli.sarif_args` module.** Argparse helpers and
  validation for the new SARIF flag family, mirroring the
  `decode_args` and `peek_args` patterns. Exposes
  `add_sarif_arguments`, `sarif_srcroot` query helper, and
  `validate_sarif_args` soft-warning function.
- **`scripts/build_sarif_fixtures.py`.** Stdlib-only fixture
  builder that produces three benign wheels for SARIF
  validation: a clean package, a package with high-entropy
  literals that trigger DENS010/DENS011, and a package with a
  2-layer base64 chain whose innermost layer contains a
  benign `subprocess.run(['echo', 'hello-from-fixture'], ...)`
  call. The fixtures pattern-match as suspicious to the
  analyzer but contain no real malicious behavior, keeping CI
  artifacts safe to share and reproducible from a reviewable
  Python script. No binary fixtures committed to the
  repository.
- **`scripts/validate_sarif.sh`.** Local equivalent of the CI
  validation workflow. Builds the fixtures, scans each, runs
  `sarif validate` on the output. Useful for catching SARIF
  regressions on a developer machine before pushing to CI.
  Requires .NET SDK 8.0 or later for the Microsoft SARIF
  Multitool. Accepts an optional target argument to scan a
  specific file instead of the synthesized fixtures.
- **`.github/workflows/do_sarif_validation.yml`.** New CI
  workflow that validates pydepgate's SARIF emission against
  the Microsoft SARIF Multitool on every PR to main. The
  Multitool is the authoritative SARIF 2.1.0 validator and is
  what GitHub Code Scanning's ingestion uses internally.
  Validation hard-fails on warnings and errors. Accepts a
  `workflow_dispatch` `target` input for manual validation
  against arbitrary artifacts. Uploads emitted SARIF documents
  as a 7-day artifact regardless of pass/fail for debugging.

### Changed

- **`--format sarif` exit code semantics.** Previously returned
  exit code 3 (TOOL_ERROR) regardless of findings, signaling
  the under-development stub. Now computes the same exit code
  as the JSON and human formats: 0 for clean, 1 for findings
  below blocking severity, 2 for HIGH or CRITICAL findings, 3
  only for actual tool errors. CI that relied on the always-
  error behavior to detect "SARIF is not implemented yet" needs
  updating; that detection mechanism was never documented as a
  contract.
- **CLI scan flow restructured for SARIF and decode
  integration.** When `--format sarif` and
  `--decode-payload-depth` are both set, the decoded tree is
  now computed before the format dispatch and threaded into
  the SARIF renderer so codeFlows appear in the output. The
  same tree is then reused by the file-writing decode pass
  instead of running the decode driver twice. Users running
  both SARIF and decode in the same scan now get all expected
  outputs (SARIF document plus text/JSON report, IOC sidecar,
  optional encrypted archive) from one decode pass. Previously,
  SARIF format suppressed the file-writing decode pass; users
  who wanted both outputs had to run two scans.
- **Documentation.** README updated with a new SARIF output
  section under Usage, a Recently Added entry leading the
  section, and additions to the flag and environment-variable
  tables. The Status section now lists SARIF under "What works
  today" with the codeFlow encoding, severity mapping, and
  content-blindness properties called out. CHANGELOG, this
  document, gets the present entry.

### Security

The SARIF emission was audited against a real LiteLLM 1.82.8
sample before release. The document describes findings
behaviorally without including arguments to dangerous calls,
URLs, command lines, or literal payload bytes. This property
is structural rather than incidental: the per-finding message
text is constructed from analyzer signal IDs and rule
descriptions, not from the matched content. A future change
that introduced content into the message text would violate
this design constraint and is the kind of regression the CI
validation catches.

No security advisories in this release.

### Coming in 0.5.0

The following are planned for the next minor release. Tracking
issues will land in [ROADMAP.md](ROADMAP.md):

- **SIEM emission layer.** First-class HEC integration for
  Splunk, with CIM-compliant data models so findings populate
  Enterprise Security correctly rather than appearing as raw
  JSON. Elastic, Datadog and Sentinel emission planned
  alongside. Carried forward from the 0.3.0 changelog's
  "Coming in 0.4.0" list; SARIF was the headline item that
  landed in 0.4.0.
- **Engine parallelism.** The picklability contract documented
  in CONTRIBUTING.md is preserved through 0.4.0; 0.5.0 will
  enable a process pool for the per-file scan phase, targeting
  meaningful speedups on multi-megabyte wheels with thousands
  of files. Carried forward from the 0.3.0 list.

## [0.3.3] - 2026-05-05

### Changed

- **Reporters refactor.** Improved reporter module organization and structure for enhanced maintainability.
- **Location field added to all source files.** Every file in `src/pydepgate` now includes location metadata in the docstring. Example: `pydepgate.cli.subcommands.scan`.

## [0.3.2] - 2026-05-02

### Added

- **Tests for PEM detection and DER classification.** Comprehensive test coverage for PEM format recognition and DER structure classification to ensure robust certificate and payload analysis.

### Changed

- **Code structure refactoring.** Improved code organization and readability across core modules for better maintainability and clearer responsibility boundaries.

## [0.3.1] - 2026-05-01

### Fixed

- **JSON output patch.** Resolved issues with JSON output formatting and serialization to ensure consistent and valid JSON emission across all report modes.

## [0.3.0] - 2026-04-30

### Added

- **Artifact-level provenance hashes.** Scan results now include
  SHA256 and SHA512 of the scanned artifact (the wheel, sdist, or
  loose file). These appear in the JSON output's top-level
  `artifact` block as nullable `sha256` and `sha512` fields, in the
  decoded-payload tree's `artifact_sha256`/`artifact_sha512` fields,
  and in the IOC sidecar header. Installed-package scans report
  null because there is no single-file representation. The full
  forensic chain from artifact to decoded payload is now captured.
- **File-level hashes per finding.** Each finding in the JSON
  output gains nullable top-level `file_sha256` and `file_sha512`
  fields, sourced from the file's `ScanContext`. These let
  consumers correlate a finding to the specific file inside an
  artifact, which matters for wheels with hundreds of internal
  files where multiple findings might fire across different ones.
- **Containing-file hashes in decoded payload tree.** Each
  `DecodedNode` carries `containing_file_sha256` and
  `containing_file_sha512` fields when populated. The
  `render_iocs` and `render_sources` outputs include a "containing
  file" line per IOC block when the file hash differs from the
  artifact hash. For loose-file `--single` scans where the
  artifact and the file are the same bytes, the redundant line is
  suppressed.
- **Tristate `--decode-iocs` flag.** Three modes: `off` (single
  plaintext report file, default), `hashes` (plaintext report plus
  plaintext `.iocs.txt` sidecar with hash records), `full`
  (encrypted ZIP archive containing report.txt, sources.txt, and
  iocs.txt, plus a plaintext `.iocs.txt` sidecar next to the
  archive). The `full` mode always produces output, including a
  NOFINDINGS stub archive when nothing is found, so downstream
  tooling can rely on archive presence as a signal.
- **Encrypted archive output for `--decode-iocs=full`.** ZipCrypto-
  encrypted ZIP files using the malware-research convention
  password "infected" by default (configurable via
  `--decode-archive-password`). UTC timestamp in filename. Status
  prefix (`FINDINGS_` or `NOFINDINGS_`) makes downstream filtering
  trivial. Compression mode selectable via
  `--decode-archive-compression` (deflated by default; STORED
  available for forensic-grade preservation).
- **`--decode-location` flag.** Specifies where decode output
  should land. Accepts a directory path; the actual filename is
  generated from the artifact identity, timestamp, and status.
- **`--decode-payload-depth` flag.** Maximum recursion depth for
  the decoded-payload pass. Defaults to 0 (decoding off); set to a
  positive integer to enable.
- **Min-severity filter for decoded trees.** When
  `--min-severity` is set on a scan that runs the decode pass, the
  filter applies to the decoded tree as a presentation step.
  Decoding itself runs over every payload-bearing finding
  regardless of severity, so a low-severity outer finding that
  decodes to a critical inner one is still captured. The filter
  preserves chain context: a low-severity ancestor with a
  high-severity descendant is kept so the chain remains visible.
- **Engine `_hashes.py` module.** New helper module with a single
  `hash_pair(content) -> (sha256, sha512)` function. Centralizes
  hash computation across the engine, enumerators, and decode
  driver to ensure consistent format (lowercase hex, no
  separators) for downstream consumers.
- **Pre-commit hook configuration.** Two hook IDs exposed via
  `.pre-commit-hooks.yaml`: `pydepgate` (runs against staged `.py`
  files with `--min-severity high` to avoid blocking commits on
  low-severity informational signals) and `pydepgate-pth` (runs
  against staged `.pth` files at the strictest threshold since
  `.pth` files have no legitimate use case for the patterns
  pydepgate detects). Both honor `PYDEPGATE_*` environment
  variables for CI configuration.
- **`PYDEPGATE_DECODE_*` environment variables.** Five new vars
  for configuring decode behavior without changing the command
  line: `PYDEPGATE_DECODE_PAYLOAD_DEPTH`, `PYDEPGATE_DECODE_IOCS`,
  `PYDEPGATE_DECODE_LOCATION`, `PYDEPGATE_DECODE_ARCHIVE_PASSWORD`,
  `PYDEPGATE_DECODE_ARCHIVE_COMPRESSION`. CLI flags take
  precedence when both are set.

### Changed

- **JSON schema_version bumped from 2 to 3.** The change is purely
  additive: the top-level `artifact` block gains nullable `sha256`
  and `sha512` fields, and each entry in `findings` gains nullable
  top-level `file_sha256` and `file_sha512` fields. Consumers
  built against schema_version 2 continue to work without
  modification because their unknown-field handling treats the
  new keys as ignorable. Consumers should branch on the
  `schema_version` field as the canonical signal rather than
  testing for field presence.
- **Decoded-tree JSON output gains a `schema_version` field.**
  The output of `render_json` in `enrichers.decode_payloads` now
  includes `schema_version: 1`. Earlier versions emitted the same
  shape without a version field; consumers built against the
  schema-versionless output continue to work because the new
  field is additive and existing keys are unchanged. Future
  changes to this schema will bump the version.
- **`.pth` file dispatch now tries Python source path first.**
  When a `.pth` file's content is valid Python (the common case
  for malicious `.pth` payloads, where the entire file is a
  single-line `import...exec()` expression), the engine routes it
  through the standard Python source analysis path. This gives
  these files full enricher integration (peek, decode, and
  others) where previously they routed through the `.pth`-
  specific path that did not integrate with enrichers. The
  `.pth`-specific path remains the fallback for legitimately
  mixed-format files containing path-addition lines that aren't
  valid Python.
- **`decode_payloads` module moved.** Relocated from
  `pydepgate.cli.decode_payloads` to
  `pydepgate.enrichers.decode_payloads`. The module operates on
  findings as a post-scan enricher, not as CLI plumbing, and the
  new location reflects that. External callers importing from the
  old path need to update imports. No CLI behavior changes.
- **Inner archive directory uses underscores instead of dots.**
  When the decode pass produces an encrypted archive containing
  report.txt/sources.txt/iocs.txt under a target-named
  subdirectory, the subdirectory name now has dots replaced with
  underscores (`litellm_init_pth/` instead of `litellm_init.pth/`).
  Windows treats folders with file extensions inconsistently;
  Explorer may attempt to open such a folder as a file, and some
  unzip utilities refuse to create the directory. The archive
  filename itself keeps the extension since it's a real `.zip`
  file. The IOC sidecar file path is unaffected.
- **IOC sidecar format gains an artifact-identity header.** The
  plaintext `.iocs.txt` sidecar (and the `iocs.txt` inside the
  encrypted archive) now begin with an artifact-identity header
  block when artifact hashes are populated. The header uses the
  same two-token shape as existing hash lines
  (`artifact_sha256 <hex>`), so `grep '^artifact_sha256'` works
  unchanged for the new field. Existing consumers that grep for
  `decoded_sha256` or `original_sha256` continue to work because
  those lines are unchanged.

### Fixed

- **Decode pass on `.pth` files now produces real output.**
  Previously, scanning a single-line malicious `.pth` file with
  `--decode-iocs=full` produced a NOFINDINGS stub archive even
  when the file clearly contained an encoded payload (the
  LiteLLM 1.82.8 attack pattern). Root cause was a multi-layer
  interaction: the `.pth` analysis path did not integrate with
  the peek enricher, peek's unwrap loop classified subprocess-
  wrapped Python source as a terminal kind with no transforms,
  and the decode driver gated recursion on peek producing a
  decoded block. The fix combines three changes: `.pth` files
  with valid Python content now route through the Python source
  path (which integrates with peek), peek now emits decoded
  blocks for `python_source` terminals so the decode driver can
  recurse into the embedded source to find inner payloads, and
  the decode driver's recursion logic correctly handles the
  multi-layer chain. The full forensic chain from outer Python
  source to inner base64 payload to decoded malicious code is
  now captured. This corrects a major detection gap for the
  `subprocess.Popen([..., 'python', '-c', '<huge>'])` malware
  pattern that wraps base64-encoded Python inside a Popen call.
- **`--decode-format=json` no longer crashes with TypeError.**
  Previously, the JSON output path raised
  `TypeError: report_render_json() missing 1 required positional
  argument: 'stream'` due to a function naming collision between
  the main scan output renderer (`report_render_json` in
  `cli.reporter`, signature `(result, stream)`) and the
  decode-tree renderer (`render_json` in
  `enrichers.decode_payloads`, signature `(tree)`). The decode
  pass now correctly calls `render_json` with the
  `DecodedTree` argument.
- **Pre-commit hook integration confirmed working.** Multiple
  test runs of `pre-commit try-repo` against the public
  pydep-vector-runner repo confirm hooks initialize, the Python
  environment installs pydepgate from PyPI, both hook IDs
  register, and they correctly skip when no matching files are
  staged. (This was never broken in code; the previous
  uncertainty was a misreading of `try-repo` output where
  "no files to check" was correctly the result of running
  against an empty target directory rather than a hook failure.)
- **Filter preserves new hash fields when rebuilding tree.**
  `filter_tree_by_severity` now correctly propagates
  `artifact_sha256`, `artifact_sha512`, `containing_file_sha256`,
  and `containing_file_sha512` through to the filtered tree.
  Previously these were silently dropped because the filter
  rebuilt nodes without copying through new fields.
- **`SyntaxWarning` from `ast.parse` no longer pollutes stderr.**
  Decoded payloads frequently contain Python source with invalid
  escape sequences and useless `is` comparisons that Python 3.12
  raises as `SyntaxWarning`. The Python source parser now
  suppresses these warnings inside a tightly-scoped
  `warnings.catch_warnings()` block during the parse call.
  Surrounding code's warning behavior is unaffected; only
  `SyntaxWarning` from this specific parse is silenced. Other
  warning categories (`DeprecationWarning`, `RuntimeWarning`)
  pass through unchanged.

### Security

(No security advisories in this release. Detection improvements
documented under "Fixed" above represent enhanced coverage of
existing attack patterns, not vulnerabilities in pydepgate itself.)

### Coming in 0.4.0

The following are planned for the next minor release. Tracking
issues will land in [ROADMAP.md](ROADMAP.md):

- **SIEM emission layer.** First-class HEC integration for
  Splunk, with CIM-compliant data models so findings populate
  Enterprise Security correctly rather than appearing as raw
  JSON. Elastic, Datadog and Sentinel emission planned alongside.
- **SARIF 2.1.0 output.** GitHub code scanning, GitLab
  vulnerability reports, and other SARIF consumers. Currently
  stubbed in the CLI with an under-development message;
  `--format sarif` will produce real output in 0.4.0.
- **Engine parallelism.** The picklability contract documented
  in CONTRIBUTING.md is preserved through 0.3.0; 0.4.0 will
  enable a process pool for the per-file scan phase, targeting
  meaningful speedups on multi-megabyte wheels with thousands
  of files.

[Unreleased]: https://github.com/nuclear-treestump/pydep-vector-runner/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/nuclear-treestump/pydep-vector-runner/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/nuclear-treestump/pydep-vector-runner/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/nuclear-treestump/pydep-vector-runner/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/nuclear-treestump/pydep-vector-runner/releases/tag/v0.3.0
