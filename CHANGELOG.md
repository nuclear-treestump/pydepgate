# Changelog

All notable changes to pydepgate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 versions reserve the right to make breaking changes to the
public API surface (CLI flags, JSON schema, exit codes) within minor
version bumps. After 1.0, the contracts in [CONTRIBUTING.md](CONTRIBUTING.md)
become binding stability promises with formal deprecation cycles.

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

[Unreleased]: https://github.com/nuclear-treestump/pydep-vector-runner/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/nuclear-treestump/pydep-vector-runner/releases/tag/v0.3.0