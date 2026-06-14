---
title: API Safety Model
parent: Python API
nav_order: 3
---
# API Safety Model

The Python API is designed to return evidence, not payload material, by default.

pydepgate scans hostile package artifacts. Encoded payloads, decoded Python
source, and reconstructed payload archives may be malware samples. The public
API keeps those materials out of normal reprs, summaries, events, JSON reports,
SARIF reports, and safe finding records unless the caller explicitly enters an
unsafe export path.

## Safe by default

Normal API output may contain:

```text
hashes
sizes
locations
signal IDs
severity
chain names
terminal classifications
bounded preview text
bounded preview hex
indicator names
artifact and file hashes
summary metadata
```

Normal API output does not contain:

```text
raw decoded bytes
full encoded payload strings
decoded source dumps
payload archives
native ScanResult objects
native StaticScanOutcome objects
internal DecodedTree objects
```

## Payload peek is allowed when requested

`peek=True` and `peek_chain=True` are intended to show limited preview material.
This is the same behavior as the CLI payload-peek output: enough to understand
what a literal unwraps into, not enough to turn the result into a payload dump.

Safe finding context may include:

```text
preview_hex
preview_text
preview_truncated
chain
final_kind
final_bytes_size
indicators
```

It must not include:

```text
_full_value
decoded_source
raw payload bytes
```

So this is allowed:

```python
for finding in result.findings:
    decoded = finding.context.get("decoded")
    if decoded:
        print(decoded.get("preview_text"))
```

This is not part of the safe API:

```python
finding.signal.context["_full_value"]
```

`ScanFinding` is a sanitized public record, not the native finding object.

## Decode IOC modes

The API accepts the same tri-state intent as the CLI:

| Mode | Public API behavior |
|---|---|
| `off` | No decoded IOC records are requested |
| `hashes` | Hash-only IOC records are exposed through `result.iocs` and `write_iocs(...)` |
| `full` | Full decoded-source retention is permitted internally for explicit unsafe archive export |

`decode_iocs` requires `decode=True` when set to `"hashes"` or `"full"`.

### `hashes` mode

`decode_iocs="hashes"` is the normal automation mode. It exposes hash records,
locations, sizes, final kinds, chain names, and indicators.

It does not retain decoded source in the public result. It also does not allow
payload archive export.

```python
result = pydepgate.scan(
    "package.whl",
    deep=True,
    decode=True,
    decode_iocs="hashes",
)

for ioc in result.iocs:
    print(ioc.decoded_sha256)
```

### `full` mode

`decode_iocs="full"` should be used only when the caller intends to create a
payload archive for malware research, incident response, or evidence transfer.
It is not required for normal CI, SARIF, JSON reporting, or IOC hash extraction.

Even with `decode_iocs="full"`, payload archive export still requires an
explicit unsafe token.

## Unsafe tokens

Unsafe operations require capability tokens from `pydepgate.api.UNSAFE`:

```python
import pydepgate.api as pydepgate

native = result.get_native_result(
    unsafe=pydepgate.UNSAFE.ALLOW_NATIVE_RESULT,
)
```

Available tokens:

| Token | Allows |
|---|---|
| `UNSAFE.ALLOW_NATIVE_RESULT` | Access to native `ScanResult` or `StaticScanOutcome` |
| `UNSAFE.ALLOW_DECODED_TREE` | Access to the internal decoded-payload tree |
| `UNSAFE.ALLOW_PAYLOAD_ARCHIVE_EXPORT` | Writing a decoded-payload archive in `decode_iocs="full"` mode |

Unsafe operations reject booleans. Passing `unsafe=True` is not accepted. The
caller must pass the specific token for the requested operation.

## Native result access

Native result access exists for advanced integrations, debugging, and migration
work. It is not the recommended API surface for normal automation.

```python
native = result.get_native_result(
    unsafe=pydepgate.UNSAFE.ALLOW_NATIVE_RESULT,
)
```

Native objects may contain payload-bearing analyzer context. Do not blindly
print, log, pickle, or serialize them.

## Decoded tree access

The internal decoded tree is blocked by default:

```python
result.decoded_tree  # raises PyDepGateApiError
```

Explicit access:

```python
tree = result.get_decoded_tree(
    unsafe=pydepgate.UNSAFE.ALLOW_DECODED_TREE,
)
```

For normal IOC handling, use `result.iocs` instead.

## Payload archive export

The API provides an unsafe archive export path instead of returning raw payload
bytes directly.

```python
result = pydepgate.scan(
    "package.whl",
    deep=True,
    peek=True,
    decode=True,
    decode_payload_depth=5,
    decode_iocs="full",
)

result.write_payload_archive(
    "decoded/payloads.zip",
    unsafe=pydepgate.UNSAFE.ALLOW_PAYLOAD_ARCHIVE_EXPORT,
    password="infected",
)
```

The archive uses the same decoded-tree renderer family as the CLI full mode and
contains:

```text
report.txt
sources.txt
iocs.txt
```

By default, `write_payload_archive(...)` also writes a plaintext hash-only
sidecar next to the archive:

```text
payloads.zip.iocs.txt
```

Archive export is blocked unless both of these are true:

- The scan used `decode_iocs="full"`.
- The caller supplied `UNSAFE.ALLOW_PAYLOAD_ARCHIVE_EXPORT`.

## Events and reports do not carry payload material

Event envelopes are safe telemetry and evidence records. They include scan
lifecycle data, artifact identity, counts, scan statistics, decode summary, and
IOC counts. They do not include raw payload bytes, full encoded payload strings,
or decoded source.

Rendered reports from the API also use safe output rules. Text reports may show
bounded payload-peek previews. JSON and SARIF reports should not contain
`_full_value` or decoded source dumps.

## Recommended rule

Use the smallest output mode that satisfies the task:

| Task | Recommended API surface |
|---|---|
| CI gate | `result.render(format="json")` or `result.render(format="sarif")` |
| Human review | `result.render(format="text")` |
| IOC matching | `result.iocs` or `result.write_iocs(...)` |
| Event ingestion | `event_log="events.jsonl"` |
| Malware-lab handoff | `decode_iocs="full"` plus `write_payload_archive(...)` with unsafe token |
| Debugging scanner internals | Unsafe native getters |

Do not use unsafe getters when a safe view exists.
