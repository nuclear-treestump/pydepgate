---
title: Python API
nav_order: 5
has_children: true
---
# Python API

pydepgate includes a small public Python API for callers that want to run a
static scan without shelling out to the CLI or constructing argparse objects.

The API uses the same scanner runner and reporter stack as the CLI. It is not a
separate scanner implementation.

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
    min_severity="high",
    output_format="json",
)

print(result.finding_count)
print(result.diagnostic_count)
print(result.iocs)
print(result.render())
```

## Current scope

The public API currently supports contextless static scans:

| Supported | Notes |
|---|---|
| Wheel files | `.whl` artifacts on local disk |
| Source distributions | `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz` |
| Installed packages | Package names resolvable in the active Python environment |
| Single loose files | Explicit `single=True` mode |
| Text, JSON, and SARIF rendering | Uses the existing reporter modules |
| Event JSONL logging | Uses the same event envelope system as the CLI |
| Decoded-payload IOC extraction | Hash-only records by default, unsafe archive export by explicit opt-in |

The public API does not currently fetch URLs. Remote targets belong to a future
context or intake layer that can materialize artifacts under policy.

## Safety model

The API is safe by default. Normal result objects expose summaries, hash IOCs,
limited payload-peek previews, and rendered reports. They do not expose native
scanner objects, raw payload bytes, full encoded strings, decoded source, or the
internal decoded-payload tree.

Payload material is available only through explicit unsafe capability tokens.
This is deliberate. pydepgate scans hostile artifacts, and decoded payloads are
evidence. They should not be accidentally printed, serialized, logged, or sent
to a SIEM.

See [API Safety Model](safety.md).

## API pages

| Page | Contents |
|---|---|
| [Static Scan API](scan.md) | `pydepgate.api.scan(...)`, target dispatch, guardrails, event logs, examples |
| [Result Objects](result.md) | `ScanApiResult`, `ScanFinding`, `ScanIOC`, summaries, reports, IOCs |
| [API Safety Model](safety.md) | Safe defaults, payload peek behavior, unsafe tokens, decoded-payload archive export |

## Import style

Recommended import style:

```python
import pydepgate.api as pydepgate
```

This keeps API examples readable without implying that every top-level
`pydepgate` package attribute is part of the public API facade.

## Contract status

The API is new. The safe-by-default boundary is part of the intended public
contract:

- Archive artifacts cannot be scanned with `single=True`.
- Payload peek may expose bounded previews when explicitly enabled.
- Full payload values and decoded source are not exposed through normal result
  properties.
- Native scanner objects are available only through explicit unsafe tokens.
- Text, JSON, and SARIF rendering reuses the existing pydepgate reporters.

Future context, intake, and tool-runner APIs will build on this pattern rather
than replacing it.
