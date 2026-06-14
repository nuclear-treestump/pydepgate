---
title: Result Objects
parent: Python API
nav_order: 2
---
# Result Objects

`pydepgate.api.scan(...)` returns a `ScanApiResult`. The result is a safe public
view over a scan run. It exposes counts, summaries, safe finding records,
hash-only IOCs, events, and report rendering helpers.

It does not expose native scanner objects by default.

## `ScanApiResult`

Common properties:

| Property | Description |
|---|---|
| `mode` | API mode used for the scan. Currently `"static"` |
| `target` | Target string supplied by the caller |
| `artifact_kind` | Scanned artifact kind, such as `"wheel"`, `"sdist"`, `"installed_package"`, or `"loose_file"` |
| `artifact_sha256` | Artifact SHA-256 when available |
| `artifact_sha512` | Artifact SHA-512 when available |
| `finding_count` | Raw number of findings in the scan result |
| `diagnostic_count` | Number of diagnostics emitted by the scan |
| `findings` | Tuple of payload-safe `ScanFinding` records |
| `iocs` | Tuple of hash-only `ScanIOC` records |
| `events` | Tuple of event envelopes emitted during the run |
| `ticket` | Scan granting ticket for the run |
| `ruleset_fingerprint` | Fingerprint of the ruleset used for the scan |
| `decode_iocs` | Decode IOC mode used for the scan |

The repr is intentionally compact:

```python
print(result)
```

```text
ScanApiResult(mode='static', target='package.whl', artifact_kind='wheel', finding_count=43, diagnostic_count=1, ioc_count=9, event_count=7, output_format='text', ruleset_fingerprint='db31a46...')
```

## Summary

`to_summary()` returns a compact JSON-safe dictionary:

```python
summary = result.to_summary()
```

It includes:

- mode and target
- artifact identity, kind, and hashes
- finding, diagnostic, suppressed, skipped, IOC, and event counts
- ruleset fingerprint
- decode IOC mode
- scan statistics

Example:

```python
import json

with open("summary.json", "w", encoding="utf-8") as f:
    json.dump(result.to_summary(), f, indent=2, sort_keys=True)
```

## Safe findings

`result.findings` returns `ScanFinding` records. These are not native
`Finding` objects. They are sanitized public summaries.

Fields:

| Field | Description |
|---|---|
| `signal_id` | Signal ID, such as `DENS010` or `STDLIB001` |
| `analyzer` | Analyzer namespace |
| `severity` | Finding severity as a lowercase string |
| `internal_path` | Path inside the artifact or loose file path |
| `line` | 1-based line number |
| `column` | 0-based column |
| `description` | Finding description |
| `file_kind` | File kind used for rule evaluation |
| `triage_reason` | Why the file was in scan scope |
| `file_sha256` | Containing file SHA-256 when available |
| `file_sha512` | Containing file SHA-512 when available |
| `context` | Payload-safe signal context |

Convert a finding to a JSON-safe dictionary:

```python
for finding in result.findings:
    print(finding.to_dict())
```

### Payload peek context

When `peek=True`, safe finding context may include a bounded `decoded` block.
This is the same class of limited preview that pydepgate can show in terminal
output.

Allowed decoded preview keys include:

```text
chain
layers_count
final_kind
final_bytes_size
unwrap_status
preview_hex
preview_text
preview_truncated
indicators
pickle_warning
continues_as
der
```

Blocked keys include:

```text
_full_value
_full_value_truncated
decoded_source
raw_payload
```

The rule is simple: bounded preview is allowed when requested; full payload
material is not.

## Hash-only IOCs

`result.iocs` returns `ScanIOC` records collected from the decoded-payload
pipeline.

Fields:

| Field | Description |
|---|---|
| `source` | Source location of the outer payload-bearing finding |
| `signal_ids` | Signal IDs associated with the decoded node |
| `severity` | Outer severity |
| `chain` | Decode chain, such as `("base64", "zlib")` |
| `final_kind` | Classified terminal type, such as `python_source` |
| `final_size` | Size of the decoded terminal bytes |
| `indicators` | Static indicators seen in the decoded material |
| `file_sha256` | Containing file SHA-256 |
| `file_sha512` | Containing file SHA-512 |
| `original_sha256` | Hash of the encoded/original payload bytes |
| `original_sha512` | SHA-512 of the encoded/original payload bytes |
| `decoded_sha256` | Hash of the decoded terminal bytes |
| `decoded_sha512` | SHA-512 of the decoded terminal bytes |
| `extracted_at` | Extraction timestamp when available |

Example:

```python
for ioc in result.iocs:
    print(ioc.source)
    print(ioc.chain)
    print(ioc.decoded_sha256)
```

Convert to dictionaries:

```python
ioc_rows = [ioc.to_dict() for ioc in result.iocs]
```

Write the CLI-compatible IOC sidecar:

```python
result.write_iocs("decoded/package.iocs.txt")
```

## Rendering reports

`render(...)` returns a report string:

```python
text_report = result.render(format="text")
json_report = result.render(format="json")
sarif_report = result.render(format="sarif")
```

`human` aliases to `text`:

```python
text_report = result.render(format="human")
```

`write_report(...)` writes a report file:

```python
result.write_report("scan.txt", format="text")
result.write_report("scan.json", format="json")
result.write_report("scan.sarif.json", format="sarif")
```

The API uses the existing pydepgate reporters. It does not duplicate the CLI
rendering stack.

## Min severity and counts

`min_severity` filters rendered output. It does not change the raw scan result
or `result.finding_count`.

Example:

```python
result = pydepgate.scan(
    "package.whl",
    deep=True,
    min_severity="high",
)

print(result.finding_count)          # raw count
print(result.render(format="text"))  # filtered report
```

This mirrors CLI behavior where the terminal report can be filtered while the
underlying scan result still records all findings.

## Blocked native properties

These properties are intentionally blocked:

```python
result.result
result.outcome
result.decoded_tree
```

They raise `PyDepGateApiError` because native scanner objects can contain
payload-bearing analyzer context or decoded source material.

Use the safe views first:

```python
result.findings
result.iocs
result.to_summary()
result.render(format="json")
```

Unsafe access is documented in [API Safety Model](safety.md).
