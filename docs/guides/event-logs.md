---
title: Event Logs
parent: Guides
nav_order: 6
---
# Event Logs

Event logs are for answering a different question than scan reports.

A scan report answers:

> What did pydepgate find?

An event log answers:

> What scan work was authorized, what ran, what completed, and what side
> effects were requested?

Use event logs when pydepgate is part of CI, package intake, incident notes,
local evidence capture, or any workflow where the scan lifecycle matters.

## Capture a scan lifecycle

```bash
pydepgate scan --deep suspicious-package.whl \
  --peek \
  --decode-payload-depth 5 \
  --decode-iocs hashes \
  --event-log scan.events.jsonl \
  --format sarif \
  --min-severity high > findings.sarif
```

This command produces two different machine-readable outputs:

| File | Meaning |
|---|---|
| `findings.sarif` | The finding report. Use this for GitHub Code Scanning or SARIF consumers. |
| `scan.events.jsonl` | The scan lifecycle. Use this for custody, audit, correlation, and workflow state. |

If recursive decode is enabled, pydepgate may also write decoded-payload
reports or IOC sidecars depending on `--decode-iocs` and `--decode-location`.

## Inspect the event stream

Count events:

```bash
wc -l scan.events.jsonl
```

List event types:

```bash
jq -r '.event_type' scan.events.jsonl
```

A successful decode-enabled scan should look like this:

```text
internal.scanner.scan_grant_issued
internal.scanner.engine_created
internal.scanner.scan_started
internal.scanner.scan_completed
internal.scanner.decode_started
internal.scanner.decode_completed
internal.scanner.run_completed
```

If `--save-to-db` is also set, evidence events appear before
`run_completed`:

```text
internal.evidence.write_requested
internal.evidence.write_completed
```

## Check scan result metadata

The finding report is still the source of truth for detailed findings. The
event log carries summary counts and scan lifecycle evidence.

```bash
jq 'select(.event_type == "internal.scanner.scan_completed") | .payload' \
  scan.events.jsonl
```

Typical fields include:

```json
{
  "artifact_identity": "suspicious-package.whl",
  "artifact_kind": "wheel",
  "artifact_sha256": "...",
  "artifact_sha512": "...",
  "finding_count": 43,
  "suppressed_finding_count": 0,
  "skipped_count": 889,
  "diagnostic_count": 1,
  "statistics": {
    "files_total": 2598,
    "files_scanned": 1709,
    "files_skipped": 889,
    "files_failed_to_parse": 0,
    "signals_emitted": 43,
    "analyzers_run": 5,
    "enrichers_run": 1,
    "duration_seconds": 17.05
  }
}
```

## Check decode state

```bash
jq 'select(.event_type == "internal.scanner.decode_completed") | .payload' \
  scan.events.jsonl
```

The decode-completed event tells you whether a decoded tree was available and
how many IOC-bearing nodes were produced:

```json
{
  "tree_available": true,
  "node_count": 2,
  "total_node_count": 2,
  "ioc_count": 9,
  "decode_iocs": "hashes"
}
```

`decode_iocs=hashes` means hash-only IOC records. Full decoded payload
material is not carried in the event log.

## Use an environment variable

For CI jobs or wrapper scripts, set the event log path once:

```bash
export PYDEPGATE_EVENT_LOG="$PWD/pydepgate.events.jsonl"
pydepgate scan --ci --min-severity high dist/*.whl
```

A CLI flag wins over the environment variable:

```bash
PYDEPGATE_EVENT_LOG=default.events.jsonl \
  pydepgate scan package.whl --event-log explicit.events.jsonl
```

## Use the Python API

The API stores the same event envelopes in memory and can optionally write
JSONL:

```python
import pydepgate.api as pydepgate

result = pydepgate.scan(
    "suspicious-package.whl",
    mode="static",
    deep=True,
    peek=True,
    peek_chain=True,
    decode=True,
    decode_payload_depth=5,
    decode_iocs="hashes",
    event_log="scan.events.jsonl",
)

for event in result.events:
    print(event.event_type, event.event_id)
```

Use `result.render(format="json")`, `result.render(format="sarif")`, or
`result.write_report(...)` for findings. Use `result.events` or
`event_log=...` for lifecycle records.

## Complete-run checks

A simple shell check for a completed scan:

```bash
jq -s -e '
  map(.event_type) as $types |
  ($types | index("internal.scanner.scan_completed") != null) and
  ($types | index("internal.scanner.run_completed") != null) and
  ($types | index("internal.scanner.scan_failed") == null)
' scan.events.jsonl >/dev/null
```

For a more explicit check, count event types:

```bash
jq -r '.event_type' scan.events.jsonl | sort | uniq -c
```

A failed scan emits `internal.scanner.scan_failed` with an exception summary:

```bash
jq 'select(.event_type == "internal.scanner.scan_failed") | .payload' \
  scan.events.jsonl
```

## Append behavior

The JSONL sink appends by default. If you reuse the same event-log path, events
from multiple scans may appear in one file.

For one run per file, delete the path before the scan or generate a unique
path per job:

```bash
EVENT_LOG="pydepgate-${GITHUB_RUN_ID:-local}.events.jsonl"
rm -f "$EVENT_LOG"
pydepgate scan package.whl --event-log "$EVENT_LOG"
```

Group events by `run_id` or `correlation_id` when processing files that contain
multiple runs.

## Safety boundary

Event logs are safe operational telemetry. They can identify artifacts, file
hashes, finding counts, decode counts, and ticket metadata, but they do not
carry full payload strings, decoded source text, raw decoded bytes, or payload
archives.

Use `--decode-iocs=hashes` for hash-only IOC sidecars. Use
`--decode-iocs=full` only when you intentionally want the encrypted
malware-research archive.

## Troubleshooting

| Symptom | Explanation |
|---|---|
| No event log file exists | `--event-log` was not set, `PYDEPGATE_EVENT_LOG` was not set, or the scan failed before event sink setup. |
| No decode events | The decode pipeline was not enabled. Use `--peek --decode-payload-depth N`. |
| No evidence events | `--save-to-db` was not set. |
| Event file has more than one scan | JSONL output appends by default. Group by `run_id` or use a fresh path. |
| CLI prints an event warning but still exits with scan result | CLI event sink failures are non-fatal. The scan result and exit code remain based on findings. |
| API raises on event-log failure | The public API treats sink failures as API errors so callers do not silently lose requested telemetry. |

