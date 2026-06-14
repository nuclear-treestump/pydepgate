---
title: Static Scan API
parent: Python API
nav_order: 1
---
# Static Scan API

`pydepgate.api.scan(...)` runs a contextless static scan from Python. It is the
API equivalent of `pydepgate scan`, but it returns a structured result object
instead of writing only to stdout.

```python
import pydepgate.api as pydepgate

result = pydepgate.scan(
    "dist/example-1.0.0-py3-none-any.whl",
    mode="static",
    deep=True,
    peek=True,
    peek_chain=True,
    decode=True,
    decode_payload_depth=5,
    decode_iocs="hashes",
    event_log="pydepgate-events.jsonl",
    min_severity="high",
    output_format="text",
)
```

Only `mode="static"` is supported in the first public API facade.

## Basic example

```python
import pydepgate.api as pydepgate

result = pydepgate.scan(
    "litellm-1.82.8-py3-none-any.whl",
    mode="static",
    deep=True,
    peek=True,
    peek_chain=True,
    decode=True,
    decode_payload_depth=5,
    decode_iocs="hashes",
    min_severity="high",
)

print(result)
print(result.finding_count)
print(result.diagnostic_count)
print(result.iocs)
```

A typical compact repr looks like this:

```text
ScanApiResult(mode='static', target='litellm-1.82.8-py3-none-any.whl', artifact_kind='wheel', finding_count=43, diagnostic_count=1, ioc_count=9, event_count=7, output_format='text', ruleset_fingerprint='db31a46...')
```

The repr is intentionally compact. It does not dump native findings, skipped
file lists, decoded payload trees, or payload-bearing analyzer context.

## Target dispatch

The API infers artifact kind from the target when `single=False`:

| Target | Dispatch |
|---|---|
| `*.whl` | Wheel scan |
| `*.tar`, `*.tar.gz`, `*.tgz`, `*.tar.bz2`, `*.tar.xz` | Source distribution scan |
| Other string | Installed package name |
| `single=True` | One loose file |

URL targets are rejected. Use a future intake/context layer for remote
artifacts.

## Guardrails

### Archive artifacts cannot use `single=True`

This is invalid:

```python
pydepgate.scan("package.whl", single=True)
```

A wheel is an artifact container, not a loose source file. Treating a wheel as
one raw loose file creates meaningless output and can explode result size.
The public API rejects this before minting a scan ticket.

Archive targets blocked with `single=True` include:

```text
.whl
.zip
.tar
.tar.gz
.tgz
.tar.bz2
.tar.xz
```

### `single=True` and `deep=True` are incompatible

`deep=True` means ordinary library files inside an artifact are included in
scope. A single loose file has no artifact tree, so the two modes cannot be
combined.

### `as_kind` only applies to single-file scans

`as_kind` mirrors the CLI `--as` flag and is valid only when `single=True`.

Example:

```python
result = pydepgate.scan(
    "payload.py",
    single=True,
    as_kind="setup_py",
    peek=True,
)
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `target` | required | Local artifact path, installed package name, or loose file path |
| `mode` | `"static"` | Scan mode. Only `"static"` is currently supported |
| `deep` | `False` | Include ordinary library `.py` files in artifact scans |
| `single` | `False` | Scan one loose file instead of dispatching as artifact/package |
| `as_kind` | `None` | Override file kind in `single=True` mode |
| `peek` | `False` | Enable payload-peek enrichment |
| `peek_chain` | `False` | Preserve verbose per-layer peek details in rendered output |
| `peek_depth` | default payload-peek depth | Maximum decode depth in the enricher pass |
| `peek_budget` | default payload-peek budget | Cumulative byte budget across unwrap layers |
| `peek_min_length` | default payload-peek minimum | Minimum literal length before attempting decode |
| `decode` | `False` | Enable recursive decoded-payload tree construction |
| `decode_payload_depth` | `3` | Maximum recursive decode depth |
| `decode_iocs` | `"off"` | IOC mode: `"off"`, `"hashes"`, or `"full"` |
| `min_severity` | `None` | Severity threshold used for rendered reports |
| `output_format` | `"text"` | Default render format: `"text"`, `"human"`, `"json"`, or `"sarif"` |
| `rules_file` | `None` | Explicit rules file path |
| `event_log` | `None` | JSONL event log path |
| `event_sinks` | `()` | Additional event sinks |
| `workers` | `None` | Worker count for per-file scan pool |
| `parallel_threshold` | `1000` | Minimum file count before parallelism is used |

`decode_iocs` requires `decode=True` when it is not `"off"`.

When `decode=True`, the API enables `peek=True` because decoded-payload
generation requires payload-bearing findings to start from.

## Output formats

Set the default render format at scan time:

```python
result = pydepgate.scan(
    "package.whl",
    deep=True,
    output_format="json",
)

print(result.render())
```

Or override it later:

```python
print(result.render(format="text"))
print(result.render(format="human"))  # alias for text
print(result.render(format="json"))
print(result.render(format="sarif"))
```

`render(...)` and `write_report(...)` reuse the existing reporter modules:

```text
pydepgate.reporters.scan_result.human
pydepgate.reporters.scan_result.json
pydepgate.reporters.sarif
```

The API does not maintain a separate renderer implementation.

Write reports to disk:

```python
result.write_report("reports/scan.txt", format="text")
result.write_report("reports/scan.json", format="json")
result.write_report("reports/scan.sarif.json", format="sarif")
```

`min_severity` filters rendered report output. `result.finding_count` remains
the raw finding count from the scan result.

## Event log

Pass `event_log` to write a JSONL event log:

```python
result = pydepgate.scan(
    "package.whl",
    deep=True,
    decode=True,
    decode_iocs="hashes",
    event_log="events.jsonl",
)
```

A successful decoded scan emits a lifecycle like this:

```text
internal.scanner.scan_grant_issued
internal.scanner.engine_created
internal.scanner.scan_started
internal.scanner.scan_completed
internal.scanner.decode_started
internal.scanner.decode_completed
internal.scanner.run_completed
```

The returned result also includes in-memory event envelopes:

```python
for event in result.events:
    print(event.event_type)
```

Events are metadata and evidence records. They do not carry raw payload bytes,
full encoded payload values, or decoded source.

## Decoded-payload IOCs

For hash-only IOC records:

```python
result = pydepgate.scan(
    "package.whl",
    deep=True,
    peek=True,
    decode=True,
    decode_payload_depth=5,
    decode_iocs="hashes",
)

for ioc in result.iocs:
    print(ioc.source, ioc.decoded_sha256)
```

Write the same sidecar shape used by the CLI:

```python
result.write_iocs("decoded/package.iocs.txt")
```

`decode_iocs="hashes"` exposes hashes, sizes, chain information, locations,
indicators, and file hashes. It does not retain decoded source in the public
result.

Use `decode_iocs="full"` only when you intend to export payload material
through the unsafe archive path. See [API Safety Model](safety.md).

## Smoke-test pattern

A useful API smoke test should verify all of these:

- A known bad wheel scans as `artifact_kind == "wheel"`.
- `.whl` plus `single=True` is blocked.
- `finding_count`, `diagnostic_count`, and `ioc_count` match expected values.
- `result.result`, `result.outcome`, and `result.decoded_tree` are blocked.
- `result.findings` contains bounded decoded preview fields when `peek=True`.
- Rendered JSON and SARIF parse successfully.
- Rendered JSON and SARIF do not contain `_full_value` or decoded source.
- Payload archive export is blocked unless `decode_iocs="full"` and the unsafe
  token is supplied.
