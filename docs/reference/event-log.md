---
title: Event Log JSONL
parent: Reference
nav_order: 7
---
# Event Log JSONL

pydepgate 0.6 adds scan lifecycle events. An event log is a JSONL sidecar
that records what scan work was authorized, when the scanner started and
finished, whether decode ran, and whether evidence was requested.

The event log is not the finding report. Use `--format json` or
`--format sarif` for findings. Use `--event-log` when you need a durable
machine-readable custody trail for the scan itself.

## Enable event logging

```bash
pydepgate scan package.whl --event-log scan.events.jsonl
```

The same default can be supplied with an environment variable:

```bash
PYDEPGATE_EVENT_LOG=scan.events.jsonl pydepgate scan package.whl
```

The Python API can also write the same JSONL event stream:

```python
import pydepgate.api as pydepgate

result = pydepgate.scan(
    "package.whl",
    mode="static",
    deep=True,
    event_log="scan.events.jsonl",
)

print([event.event_type for event in result.events])
```

## File format

The file is newline-delimited JSON. Each line is one complete event envelope.
Consumers should parse it as JSONL, not as one large JSON array.

A typical event line looks like this:

```json
{
  "schema_version": 1,
  "event_id": "019ec3e6-de01-7d8c-bd36-f88f87a786bf",
  "event_type": "internal.scanner.scan_completed",
  "producer": "pydepgate.cli.scan",
  "run_id": "019ec3e6-ddf8-70a1-abf7-6b377764d715",
  "correlation_id": "019ec3e6-ddf8-70a1-abf7-6b377764d715",
  "parent_event_id": "019ec3e6-de00-70d9-9885-d4fb72d8a287",
  "ticket_id": "sgt_019ec3e6-ddfe-7eee-bb29-3322289b8a90",
  "occurred_at": "2026-06-14T02:04:18.413284Z",
  "emitted_at": "2026-06-14T02:04:18.413286Z",
  "severity": "info",
  "payload_schema": null,
  "payload_digest": "7fc5f42bf42c7203e2f807d84a3433e8653b0b096b2a9bbde3cc6923bde6d7d0",
  "payload": {
    "artifact_identity": "package.whl",
    "artifact_kind": "wheel",
    "finding_count": 43,
    "diagnostic_count": 1
  }
}
```

## Envelope fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | integer | Event envelope schema version. Current value: `1`. |
| `event_id` | string | Unique event identifier. |
| `event_type` | string | Namespaced event type. Must start with `internal.` or `external.`. |
| `producer` | string | Component that emitted the event, for example `pydepgate.cli.scan` or `pydepgate.api`. |
| `run_id` | string | Run identifier shared by events from the same scan. |
| `correlation_id` | string | Correlation identifier. Defaults to `run_id`. |
| `parent_event_id` | string or null | Previous event in the scan lifecycle, when applicable. |
| `ticket_id` | string or null | Scan Granting Ticket ID associated with the event. |
| `occurred_at` | string | UTC timestamp for when the event occurred. |
| `emitted_at` | string | UTC timestamp for when the envelope was emitted. |
| `severity` | string | One of `debug`, `info`, `warning`, `error`, or `critical`. |
| `payload_schema` | string or null | Optional payload schema label. Reserved for future versioned payload contracts. |
| `payload_digest` | string | Stable SHA-256 digest of the JSON-safe payload. |
| `payload` | object | Event-specific JSON-safe payload. |

## Envelope guarantees

Event envelopes are built for local custody and downstream processing:

- Payloads are deep-frozen during envelope construction.
- Payloads must be JSON-safe.
- The payload digest is computed from stable JSON serialization.
- The same immutable envelope is delivered to every configured sink.
- Event logs do not include decoded payload bytes or full payload strings.
- Scan grant events remove the ticket nonce before writing to the event log.

The event log is safe operational telemetry, not a malware sample container.
Decoded payload material belongs in the explicit full-mode payload archive,
not in events.

## Scan lifecycle events

A successful static scan normally emits these events in order:

| Event type | Emitted when | Payload highlights |
|---|---|---|
| `internal.scanner.scan_grant_issued` | A local Scan Granting Ticket has been minted. | Ticket ID, run ID, target kind, scan mode, allowed actions, budget, ruleset fingerprint, ticket digest. The ticket nonce is omitted. |
| `internal.scanner.engine_created` | The static engine has been constructed. | Analyzer names, enricher count, rule count, deep mode, worker settings. |
| `internal.scanner.scan_started` | Scanner execution is about to begin. | Target kind, target identity, scan mode, allowed actions, target reference. |
| `internal.scanner.scan_completed` | Static scanner execution completed. | Artifact identity, kind, hashes, finding count, skipped count, diagnostic count, statistics. |
| `internal.scanner.decode_started` | Recursive decode pass is about to begin. | Decode depth and IOC mode. Only emitted when decode is enabled. |
| `internal.scanner.decode_completed` | Recursive decode pass finished. | Tree availability, root node count, total node count, IOC node count, IOC mode. Only emitted when decode is enabled. |
| `internal.evidence.write_requested` | Local evidence DB write is about to begin. | Artifact identity, kind, decoded-tree availability. Only emitted with `--save-to-db`. |
| `internal.evidence.write_completed` | Local evidence DB write returned. | Artifact identity and decoded-tree availability. Only emitted with `--save-to-db`. |
| `internal.scanner.run_completed` | The scan command or API call finished. | Exit code for CLI, artifact identity, artifact kind, finding count, diagnostic count. |

If scanner execution raises an exception, pydepgate emits:

| Event type | Emitted when | Payload highlights |
|---|---|---|
| `internal.scanner.scan_failed` | Static scanner execution raised before completion. | Exception type and message. |

## Event ordering

Consumers should prefer event types and IDs over file position, but the JSONL
writer appends events in emission order. A complete successful decode-enabled
scan should contain this chain:

```text
internal.scanner.scan_grant_issued
internal.scanner.engine_created
internal.scanner.scan_started
internal.scanner.scan_completed
internal.scanner.decode_started
internal.scanner.decode_completed
internal.scanner.run_completed
```

Evidence events appear between `decode_completed` and `run_completed` when
`--save-to-db` is set.

Decode events are absent when the decode pipeline is not enabled. Evidence
events are absent when `--save-to-db` is not set.

## Scan Granting Tickets

A Scan Granting Ticket is the local authorization record for scanner work.
The first public use is local scan authorization and event correlation. It is
not a remote authentication protocol.

Ticket payload fields include:

| Field | Description |
|---|---|
| `ticket_id` | Stable ticket identifier for the scan. |
| `ticket_digest` | Stable digest over the ticket fields. |
| `run_id` | Run identifier shared by the event stream. |
| `correlation_id` | Correlation ID used by the event stream. |
| `issuer` | Component that minted the ticket. |
| `actor` | Local actor label. |
| `target_kind` | Requested target kind, such as `wheel`, `sdist`, `installed_package`, or `loose_file`. |
| `target_identity` | Requested target identity. |
| `scan_mode` | Requested scan mode, such as `static.deep` or `static.single`. |
| `allowed_actions` | Actions authorized by the ticket, such as `scan`, `decode`, and `evidence.write`. |
| `issued_at` / `expires_at` | Ticket validity window. |
| `ruleset_fingerprint` | Digest of the effective rule set when available. |
| `budget` | Scan budget and mode controls, including deep mode, workers, decode settings, and IOC mode. |
| `local_invocation` | Local process and call-stack evidence. |
| `metadata` | Additional local scanner metadata. |

The ticket nonce is intentionally removed from the event-log representation.

## Sink behavior

The first event sinks are intentionally small:

| Sink | Use |
|---|---|
| `MemoryEventSink` | Tests, API results, local inspection. Stores immutable event envelopes in memory. |
| `JsonlEventSink` | Writes one event envelope per JSONL line. Used by `--event-log` and API `event_log`. |
| `TeeEventSink` | Sends the same event to multiple child sinks. |
| `NullEventSink` | Accepts events and discards them. Useful for tests or disabled paths. |

CLI scans treat event sink failures as non-fatal warnings so telemetry cannot
hide scan results. The public API is stricter and treats sink failure as an
API error by default.

## Consumer guidance

Consumers should:

- Treat `schema_version` as the envelope contract.
- Treat `event_type` as the event discriminator.
- Use `run_id` or `correlation_id` to group events.
- Use `parent_event_id` to reconstruct the lifecycle chain.
- Use `payload_digest` to detect payload mutation or deduplicate identical payloads.
- Treat unknown payload keys as additive.
- Avoid assuming event files are truncated before each run. Use a fresh path when one-run-per-file is required.

Consumers should not:

- Treat event logs as finding reports.
- Expect payload bytes, decoded source, or full encoded strings in events.
- Treat the local Scan Granting Ticket as remote authentication.
- Parse human output when JSON, SARIF, and event JSONL are available.

## Example queries

List event types:

```bash
jq -r '.event_type' scan.events.jsonl
```

Show scan counts:

```bash
jq 'select(.event_type == "internal.scanner.scan_completed") | .payload | {
  artifact_kind,
  finding_count,
  diagnostic_count,
  skipped_count,
  statistics
}' scan.events.jsonl
```

Show decode summary:

```bash
jq 'select(.event_type == "internal.scanner.decode_completed") | .payload' \
  scan.events.jsonl
```

Detect failed scans:

```bash
jq 'select(.event_type == "internal.scanner.scan_failed") | .payload' \
  scan.events.jsonl
```

