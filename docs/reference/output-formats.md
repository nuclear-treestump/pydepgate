# Output Formats

pydepgate produces output in three formats, selected with `--format`:
`human` (default), `json`, and `sarif`. When the decode pipeline is active,
a fourth document type is produced: the decoded-tree JSON report.

## Human format

The human format is the default. It renders to stdout with ANSI color when
stdout is a TTY. Color is controlled by `--color` and disabled by `--no-color`
or `--ci`.

A report with findings has this structure:

```
<artifact name>

  <internal file path> [<highest severity in file>]

    [<SEVERITY>] <signal_id> <analyzer> — <description>
      Line <N>: <source line>
      Rule: <rule_id>

    [<SEVERITY>] ...

  <finding-distribution map>
  <N> findings  (<counts by severity>)

Artifact SHA256: <hex>
Artifact SHA512: <hex>
```

A clean scan produces no output and exits with code `0`.

### Finding-distribution map

The map is an SSH-randomart-style rendering that shows where findings cluster
across each scanned file and at what severity. Each character in the map
represents a region of the file; the density of characters and their visual
weight indicates finding concentration. Suppress it with `--no-map`.

## JSON format

`--format json` emits a single JSON object per scan to stdout.

### Schema version

The current schema version is **3**. Consumers should branch on the
`schema_version` field rather than testing for field presence. The schema
version is bumped on any change to the shape of the object; additive changes
(new nullable fields) are considered minor bumps, structural changes are
major.

### Top-level structure

```json
{
  "report_type": "pydepgate_scan_result",
  "schema_version": 3,
  "artifact": { ... },
  "findings": [ ... ],
  "suppressed_findings": [ ... ],
  "skipped": [ ... ],
  "statistics": { ... },
  "diagnostics": [ ... ]
}
```

### `artifact` block

```json
"artifact": {
  "identity": "<string>",
  "kind": "<string>",
  "sha256": "<64-char lowercase hex string or null>",
  "sha512": "<128-char lowercase hex string or null>"
}
```

`identity` is the artifact name as passed to the scanner (wheel filename,
package name, or path). `kind` is one of `wheel`, `sdist`, `installed_env`,
`loose_file`. `sha256` and `sha512` are null for installed-package scans,
since there is no single-file representation of an installed environment.
Hashes use lowercase hex with no separators.

### `findings` array

Each entry in `findings` represents one finding:

```json
{
  "severity": "<info|low|medium|high|critical>",
  "signal_id": "<string>",
  "analyzer": "<string>",
  "confidence": <integer>,
  "scope": "<string>",
  "description": "<string>",
  "location": {
    "internal_path": "<string>",
    "line": <integer>,
    "column": <integer>
  },
  "file_sha256": "<64-char lowercase hex string or null>",
  "file_sha512": "<128-char lowercase hex string or null>",
  "context": { ... }
}
```

`file_sha256` and `file_sha512` are the hashes of the specific file within
the artifact that contained this finding. For single-file scans these are
identical to the artifact hashes. For wheel/sdist scans they identify the
specific internal file.

`context` contains signal-specific data from the analyzer. Keys beginning
with `_` are internal pipeline fields and are omitted. All other keys and
values are stable for a given `signal_id` within a schema version.

### `suppressed_findings` array

Findings that fired but were suppressed by a rule. Present when a user rules
file suppresses a signal that would otherwise have produced a finding:

```json
{
  "signal_id": "<string>",
  "internal_path": "<string>",
  "description": "<string>",
  "suppressing_rule_id": "<string>",
  "suppressing_rule_source": "<string>",
  "would_have_been_severity": "<string>"
}
```

### `skipped` array

Files in the artifact that triage excluded from analysis:

```json
{
  "path": "<string>",
  "reason": "<string>"
}
```

### `statistics` block

```json
"statistics": {
  "files_total": <integer>,
  "files_scanned": <integer>,
  "files_skipped": <integer>,
  "files_failed_to_parse": <integer>,
  "signals_emitted": <integer>,
  "analyzers_run": <integer>,
  "enrichers_run": <integer>,
  "duration_seconds": <float>
}
```

### `diagnostics` array

A list of strings describing non-fatal issues encountered during the scan:
parser failures, analyzer warnings, enricher errors. An empty array is normal.
A non-empty array does not change the exit code unless the scan could not
complete at all (which produces exit code 3 instead).

### Schema version history

| Version | Change |
|---|---|
| `1` | Initial schema |
| `2` | Added artifact-level fields |
| `3` | Added nullable `sha256` and `sha512` to `artifact` block; added nullable `file_sha256` and `file_sha512` to each finding. Purely additive; consumers built against v2 continue to work. |

## SARIF 2.1.0 format

`--format sarif` emits a SARIF 2.1.0 document to stdout. The document is
compatible with GitHub Code Scanning, Azure DevOps, and any consumer that
follows the OASIS SARIF 2.1.0 spec. It is validated on every PR in CI against
the Microsoft SARIF Multitool.

### Document structure

Each scan produces a single run inside the document. The run contains:

- `tool.driver.rules`: the full rules catalog, regardless of which rules fired.
  Every rule pydepgate could emit is present so consumers can build UI for any
  signal.
- `results`: one entry per finding.
- `invocation`: execution metadata including `executionSuccessful: true` on the
  happy path, and `toolExecutionNotifications` for any non-fatal diagnostics.
- `automationDetails.id`: of the form `pydepgate/{artifact_kind}/`, e.g.
  `pydepgate/wheel/`. Deep scans (`--deep`) suffix `_deep` to the artifact
  kind: `pydepgate/wheel_deep/`. This is used by GitHub Code Scanning to group
  results across runs of the same scan type.
- `originalUriBaseIds.PROJECTROOT`: populated from `--sarif-srcroot` when set;
  an empty placeholder URI when not set.

### Severity mapping

pydepgate's five severity levels map to SARIF as follows:

| pydepgate severity | SARIF `level` | GitHub `security-severity` | GitHub display band |
|---|---|---|---|
| `CRITICAL` | `error` | `9.5` | Critical |
| `HIGH` | `error` | `8.0` | High |
| `MEDIUM` | `warning` | `5.0` | Medium |
| `LOW` | `note` | `2.0` | Low |
| `INFO` | `note` | `0.5` | Low |

`security-severity` values are strings as required by the SARIF spec. CRITICAL
and HIGH share the SARIF level `error` because SARIF has only three useful
levels; the distinction is preserved in the numeric `security-severity` score,
which places each within its correct GitHub display band.

### Partial fingerprints

Each result carries a `primaryLocationLineHash` partial fingerprint used by
GitHub Code Scanning to deduplicate alerts across runs. Two scans of the same
artifact that find the same signal at the same location produce the same
fingerprint and are treated as the same alert. Two scans of different artifacts
produce different fingerprints.

Fingerprints are 24 characters, derived from the signal ID, internal file
path, line number, and matched content (the `_full_value` context field when
populated, falling back to the signal description).

### Per-result properties

Each result carries a `properties` block with pydepgate-specific metadata:

```json
"properties": {
  "security-severity": "<string>",
  "pydepgate.analyzer": "<string>",
  "pydepgate.confidence": "<string>",
  "pydepgate.scope": "<string>"
}
```

These are not displayed prominently in GitHub's UI but are present in the
SARIF JSON for offline analysis.

### codeFlows for decoded payloads

When `--decode-payload-depth` is active alongside `--format sarif`, findings
reached through the decode pipeline are emitted as SARIF results with
`codeFlows`. Each `threadFlow` walks from the outer high-entropy literal on
disk through each decode layer to the innermost detection. Multi-layer payloads
produce nested `threadFlow` encoding with `nestingLevel` reflecting decode
depth. In GitHub's UI this appears as "Show paths" on the finding.

### Content-blind emission

The SARIF document describes what was called, not what was passed. Message
text identifies the dangerous call (`subprocess.run()`,
`urllib.request.urlopen()`) without including arguments, URLs, command lines,
or payload bytes. The `artifacts[]` array references file locations but does
not embed source content. No CWE taxonomy mappings are present; rules carry
descriptive `tags` with the analyzer name.

This is by construction, not convention. An attacker cannot exfiltrate payload
content through pydepgate's SARIF output even if the document is published.

## Decoded-tree JSON format

When `--decode-payload-depth` is active and `--decode-format json` is set, a
separate decoded-tree JSON document is written to the decode output location.
This is distinct from the main scan JSON output.

### Schema version

The current decoded-tree schema version is **1**.

### Structure

```json
{
  "report_type": "pydepgate_decoded_tree",
  "schema_version": 1,
  "target": "<string>",
  "max_depth": <integer>,
  "artifact_sha256": "<string or null>",
  "artifact_sha512": "<string or null>",
  "nodes": [ ... ]
}
```

Each node in `nodes` represents one payload-bearing finding that was processed
by the decode pipeline, along with its decode chain and any inner findings:

```json
{
  "outer_signal_id": "<string>",
  "outer_severity": "<string>",
  "outer_location": <integer>,
  "outer_length": <integer>,
  "triggered_by": ["<string>"],
  "chain": ["<string>"],
  "unwrap_status": "<string>",
  "final_kind": "<string>",
  "final_size": <integer or null>,
  "indicators": ["<string>"],
  "pickle_warning": <boolean>,
  "depth": <integer>,
  "stop_reason": "<string or null>",
  "containing_file_sha256": "<string or null>",
  "containing_file_sha512": "<string or null>",
  "details_summary": "<string or null>",
  "details_full": "<string or null>",
  "child_findings": [ ... ],
  "children": [ ... ],
  "ioc_data": { ... }
}
```

`ioc_data` is present only when `--decode-iocs` is `hashes` or `full`:

```json
"ioc_data": {
  "original_sha256": "<string>",
  "original_sha512": "<string>",
  "decoded_sha256": "<string>",
  "decoded_sha512": "<string>",
  "decoded_source": "<string or null>",
  "extract_timestamp": "<string>"
}
```

`decoded_source` is null when `--decode-iocs` is `hashes` (hashes only, no
source). It is populated when `--decode-iocs` is `full`.