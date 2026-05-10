---
layout: home
title: pydepgate
---
# pydepgate

pydepgate is a static analyzer for Python supply-chain malware that exploits
interpreter startup vectors. It inspects wheels, source distributions,
installed packages, and individual source files for code that executes
silently before any user script runs.

## The problem

Python's interpreter runs several kinds of code automatically at startup:

- `.pth` files in `site-packages/`. Any line beginning with `import` is passed
  to `exec()` by `site.py` during interpreter initialization.
- `sitecustomize.py` and `usercustomize.py`. Imported automatically when present.
- `__init__.py` top-level code in any imported package.
- `setup.py`. Executed during `pip install` for source distributions.
- Console-script entry points. Generated and executed by `pip install`.

Each is a legitimate Python feature. Each has been used in real supply-chain
attacks. The `.pth` vector in particular is acknowledged as a security gap in
[CPython issue #113659](https://github.com/python/cpython/issues/113659) and
has no upstream patch. Existing Python security tooling (`pip-audit`, `safety`,
`bandit`) does not inspect these vectors.

This is the attack class used in the March 2026 LiteLLM supply-chain compromise,
catalogued as [MITRE ATT&CK T1546.018](https://attack.mitre.org/techniques/T1546/018/).

## Installation

```bash
pip install pydepgate
```

Requires Python 3.11 or later. No third-party runtime dependencies.

## Quick start

```bash
# Scan a wheel
pydepgate scan some-package-1.0.0-py3-none-any.whl

# Scan an installed package by name
pydepgate scan litellm

# Scan a source distribution
pydepgate scan some-package-1.0.0.tar.gz

# Scan a single file
pydepgate scan --single suspicious_module.py
```

Exit code `2` means at least one HIGH or CRITICAL finding. Exit code `0` is
clean. See [Exit Codes](reference/exit-codes.md) for the full contract.

## What pydepgate detects

- Encoded payloads in source files (base64, hex, zlib, gzip, bzip2, lzma chains)
- Dynamic execution patterns (`exec`, `eval`, `compile`, `__import__`)
- Obfuscated string construction and variable chaining leading to execution
- Suspicious stdlib use (subprocess, socket, urllib, ctypes, os) in startup contexts
- Code density anomalies: high entropy identifiers, homoglyphs, deep AST nesting,
  low-vowel-ratio names
- PEM and DER certificate material embedded in source files
- Multi-layer encoded payloads via the recursive decode pipeline

## Documentation

| Section | Contents |
|---|---|
| [Getting Started](getting-started.md) | First scan, reading output, using `explain` |
| [CLI Reference: scan](cli/scan.md) | All flags for `pydepgate scan` |
| [CLI Reference: explain](cli/explain.md) | Rule and signal lookup |
| [Exit Codes](reference/exit-codes.md) | Exit code contract and CI implications |
| [Output Formats](reference/output-formats.md) | Human, JSON, SARIF schemas |
| [Environment Variables](reference/environment-variables.md) | All `PYDEPGATE_*` variables |
| [Rules File](reference/rules-file.md) | `pydepgate.gate` format and precedence |
| [Signals Reference](reference/signals.md) | All signal IDs across all namespaces |
| [Guide: CI Integration](guides/ci-integration.md) | GitHub Actions, GitLab CI, pre-commit, Docker |
| [Guide: Custom Rules](guides/custom-rules.md) | Suppressing false positives, scoping rules |
| [Guide: Decode Payloads](guides/decode-payloads.md) | `--decode-payload-depth`, IOC sidecars, encrypted archives |
| [Guide: SARIF Integration](guides/sarif-integration.md) | GitHub Code Scanning ingestion |

## Relationship to PyDepGuard

[PyDepGuard](https://github.com/nuclear-treestump/pydepguard) is a broader
Python security framework covering runtime sandboxing and dependency management.
The startup-vector engine in pydepgate is intended to integrate with PyDepGuard
as a subsystem. Until then, the two projects are developed independently.

Use pydepgate for startup-vector static analysis. Use PyDepGuard for the full
runtime security model.

## License

Apache 2.0. See [LICENSE](https://github.com/nuclear-treestump/pydepgate/blob/main/LICENSE).
