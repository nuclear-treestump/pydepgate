---

title: Home
layout: home
nav_order: 1
---

# pydepgate

pydepgate is a zero-runtime-dependency static analyzer for Python supply-chain malware hiding in interpreter startup paths.

It scans wheels, source distributions, installed packages, and loose Python files for code that can execute before a user script meaningfully starts: `.pth` import lines, `sitecustomize.py`, `usercustomize.py`, package `__init__.py`, `setup.py` and it scans library files too.

It is built for hostile package artifacts, forensic repeatability, and CI use, and is designed to become a package intake control system.

## Install

```bash
pip install pydepgate
```

Requires Python 3.11 or later. pydepgate uses only the Python standard library at runtime. No dependencies required.

## First scan

```bash
# Scan a wheel
pydepgate scan some-package-1.0.0-py3-none-any.whl

# Scan an installed package by name
pydepgate scan litellm

# Scan a source distribution
pydepgate scan some-package-1.0.0.tar.gz

# Scan one loose file
pydepgate scan --single suspicious_module.py
```

Exit code `0` means clean at the active threshold. Exit code `2` means at least one HIGH or CRITICAL finding. See [Exit Codes](reference/exit-codes.md) for the full contract.

## Preserve evidence

pydepgate can store scan evidence locally so a finding does not disappear into terminal scrollback.

```bash
pydepgate scan package.whl --save-to-db
pydepgate db list-runs
pydepgate db explain --run-id <run-id>
```

The evidence database records scan runs, artifact identity and hashes, static findings, decoded payload trees, and CVE findings.

Use this when you need reproducible findings, incident notes, maintainer reports, or later correlation by package name, version, or artifact hash.

See [CLI Reference: db](cli/db.md).

## Capture scan lifecycle events

pydepgate can write a JSONL event stream for each scan. The event log records
scan authorization, engine creation, scan start and completion, decode start
and completion, evidence writes, and final run completion.

```bash
pydepgate scan package.whl --event-log scan.events.jsonl
```

Use event logs when a scan is part of CI, package intake, incident notes, or
local evidence capture. The event log is not the finding report. Use JSON,
SARIF, or human output for findings, and event JSONL for lifecycle evidence.

See [Guide: Event Logs](guides/event-logs.md) and
[Event Log JSONL](reference/event-log.md).

## Check known vulnerable versions

Static analysis and vulnerability matching answer different questions.

```bash
pydepgate cvedb update
pydepgate cvescan package.whl
pydepgate cvescan package.whl --save-to-db
```

`pydepgate scan` asks: “Does this artifact contain suspicious startup behavior?”

`pydepgate cvescan` asks: “Is this package name and version known to be vulnerable or malicious in the OSV PyPI feed?”

Use both when you want broader artifact coverage.

A combined scan mode will also be available in the near future (dependent on Roadmap 0.6.0 items)

See [CLI Reference: cvedb](cli/cvedb.md) and [CLI Reference: cvescan](cli/cvescan.md).

## What pydepgate detects

pydepgate focuses on attack shapes that execute silently during package installation, interpreter startup, or import-time initialization.

It detects:

* Encoded payloads in Python source: base64, hex, zlib, gzip, bzip2, and lzma chains
* Decode-then-execute patterns such as encoded content passed to `exec`, `eval`, `compile`, or `__import__`
* Dynamic execution and import patterns
* Obfuscated string construction that resolves to execution primitives or dangerous stdlib calls
* Suspicious stdlib use in startup contexts: subprocess, shell execution, network access, and native code loading
* Code-density anomalies: high-entropy strings, homoglyphs, invisible Unicode, machine-generated identifiers, deeply nested AST shapes, and low-signal obfuscation patterns
* Embedded PEM and DER certificate material
* Multi-layer decoded payload trees through the recursive decode pipeline

The goal is to catch adversarial-shape code in places Python runs automatically.

## Why startup vectors matter

Python intentionally runs certain files and hooks during installation, interpreter startup, or package import. Those features are useful. They are also attractive to attackers.

Important startup vectors include:

* `.pth` files in `site-packages`
* `sitecustomize.py`
* `usercustomize.py`
* package `__init__.py`
* `setup.py`

The `.pth` vector is especially dangerous because import lines inside `.pth` files are executed by Python’s startup machinery. The vector is tracked in [CPython issue #113659](https://github.com/python/cpython/issues/113659), and the broader attack class maps to [MITRE ATT&CK T1546.018](https://attack.mitre.org/techniques/T1546/018/).

## Safe payload decoding

pydepgate can inspect encoded payloads without executing them.

```bash
pydepgate scan \
  --peek \
  --decode-payload-depth 4 \
  --decode-iocs full \
  package.whl
```

The decode pipeline unwraps supported encodings and compression formats, classifies the terminal content, reconstructs the payload chain, and can write IOC sidecars or encrypted malware-research archives.

It never executes decoded content. Pickle data is detected but not deserialized.

See [Guide: Decode Payloads](guides/decode-payloads.md).

## CI, SARIF, and Docker

For CI:

```bash
pydepgate scan --ci --min-severity high dist/*.whl
```

For SARIF:

```bash
pydepgate scan --format sarif --sarif-srcroot "$PWD" dist/*.whl > pydepgate.sarif
```

For Docker:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/nuclear-treestump/pydepgate:latest \
  scan --ci --min-severity high package.whl
```

The Docker image supports `linux/amd64` and `linux/arm64`, runs as a non-root user, and is designed for local scans, CI pipelines, and package-intake workflows.

See [Guide: CI Integration](guides/ci-integration.md), [Guide: SARIF Integration](guides/sarif-integration.md), and [Guide: Docker Image](guides/docker-image.md).

## Finding fingerprints

pydepgate v0.5.0 includes the Finding Fingerprint v1 specification.

A finding fingerprint is a deterministic, content-addressed identifier for what a specific pydepgate version found in a specific artifact. The goal is simple: a researcher should be able to report a finding today, and a maintainer should be able to independently reproduce it later from the artifact and tool version.

The v1 specification is available now. CLI validation support is planned for a later release.

See [Finding Fingerprint v1](reference/fingerprint-v1.md).

## Documentation

| Section                                                     | Contents                                                               |
| ----------------------------------------------------------- | ---------------------------------------------------------------------- |
| [Getting Started](getting-started.md)                       | First scan, reading output, using `explain`                            |
| [CLI Reference](cli/index.md)                               | Top-level command structure and global flags                           |
| [CLI Reference: scan](cli/scan.md)                          | Static startup-vector scanning                                         |
| [CLI Reference: cvedb](cli/cvedb.md)                        | Build and inspect the local OSV PyPI database                          |
| [CLI Reference: cvescan](cli/cvescan.md)                    | Match wheel identity against known CVE / malware records               |
| [CLI Reference: db](cli/db.md)                              | Store, query, and explain scan evidence                                |
| [CLI Reference: explain](cli/explain.md)                    | Signal and rule lookup                                                 |
| [Exit Codes](reference/exit-codes.md)                       | Public exit-code contract for CI                                       |
| [Output Formats](reference/output-formats.md)               | Human, JSON, SARIF, and decoded-tree schemas                           |
| [Event Log JSONL](reference/event-log.md)                | Event envelope schema and scan lifecycle telemetry                     |
| [Guide: Event Logs](guides/event-logs.md)                | Capturing and consuming scan lifecycle JSONL                           |
| [Environment Variables](reference/environment-variables.md) | All `PYDEPGATE_*` variables                                            |
| [Rules File](reference/rules-file.md)                       | `pydepgate.gate` format and precedence                                 |
| [Signals Reference](reference/signals.md)                   | Signal IDs, severity mapping, and detection rationale                  |
| [Finding Fingerprint v1](reference/fingerprint-v1.md)       | Deterministic finding fingerprint specification                        |
| [Guide: CI Integration](guides/ci-integration.md)           | GitHub Actions, GitLab CI, Docker, and pre-commit                      |
| [Guide: Docker Image](guides/docker-image.md)               | Container tags, digests, signatures, attestations, and reproducibility |
| [Guide: Custom Rules](guides/custom-rules.md)               | Suppressing false positives and adjusting severity                     |
| [Guide: Decode Payloads](guides/decode-payloads.md)         | Recursive decode pipeline, IOC sidecars, encrypted archives            |
| [Guide: SARIF Integration](guides/sarif-integration.md)     | GitHub Code Scanning ingestion                                         |

## Current limitations

`pydepgate exec` and `pydepgate preflight` are planned runtime and environment-auditing commands. They are documented as roadmap surfaces but are not functional yet.

`pydepgate cvescan` currently supports wheel artifacts.

## License

Apache 2.0. See [LICENSE](https://github.com/nuclear-treestump/pydepgate/blob/main/LICENSE).
