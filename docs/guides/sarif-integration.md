---
title: SARIF Integration
parent: Guides
nav_order: 4
---
# SARIF Integration

pydepgate emits SARIF 2.1.0 documents compatible with GitHub Code Scanning,
Azure DevOps, and any SARIF consumer that follows the OASIS spec. This page
covers generating SARIF output and ingesting it into GitHub Code Scanning.

## Generating SARIF output

Pass `--format sarif` to emit a SARIF document on stdout:

```bash
pydepgate scan --format sarif some-package.whl > scan.sarif
```

The exit code is the same as for human and JSON output: `0` for clean, `1`
for findings below HIGH/CRITICAL, `2` for at least one HIGH or CRITICAL
finding, `3` for a tool error. This means the scan step will exit non-zero
when findings are present, which you need to account for in your workflow.
See the [GitHub Actions workflow](#github-actions) section below for the
standard handling.

## The SARIF document

Each scan produces a single SARIF 2.1.0 document containing:

- The full rules catalog under `tool.driver.rules`, with rule descriptions,
  help text, and common evasions for each signal pydepgate knows about.
- Per-finding results with severity mapped to SARIF levels: CRITICAL and HIGH
  map to `error`, MEDIUM maps to `warning`, LOW and INFO map to `note`.
- GitHub-compatible `security-severity` numeric scores on each result for
  correct placement in the GitHub vulnerability severity scale.
- 24-character partial fingerprints on each result for cross-run alert
  deduplication. Results for the same finding across different runs of the
  same artifact are recognized as the same alert rather than accumulating as
  new ones.
- `automationDetails.id` of the form `pydepgate/{artifact_kind}/` for
  cross-run grouping. Deep scans (`--deep`) suffix `_deep` to the artifact
  kind so deep and non-deep runs group separately.

### Content-blind emission

The SARIF document describes what was called, not what was passed. A finding
for `subprocess.Popen()` says `subprocess.Popen() called` in the message text.
It does not include the arguments, the command line, any URLs, or the payload
bytes. This is by design.

SARIF documents flow into CI logs, code scanning UIs, and artifact downloads.
Embedding payload content in the document would replicate the exact threat the
analyzer is detecting. A defender can publish a pydepgate SARIF document
publicly without re-leaking the underlying attack content.

### codeFlows for decoded payloads

When `--decode-payload-depth` is enabled alongside `--format sarif`, findings
reached through the decode pipeline are surfaced with `codeFlows` encoding the
attack chain. Each `threadFlow` walks from the outer high-entropy literal
through each decode layer to the innermost detection. Multi-layer payloads
produce nested threadFlow encoding with `nestingLevel` reflecting decode depth.

In GitHub's code scanning UI, this appears as "Show paths" on a finding. Each
step in the chain is visible.

## Source root configuration

For in-repo scans where GitHub Code Scanning needs to resolve paths relative
to the repository root, set `--sarif-srcroot`:

```bash
pydepgate scan --format sarif --sarif-srcroot /path/to/repo some-package.whl > scan.sarif
```

This populates `originalUriBaseIds.PROJECTROOT` in the document and tags
on-disk artifact locations with `uriBaseId: "PROJECTROOT"`. Without this,
GitHub Code Scanning may not be able to link findings to source lines in the
repository viewer.

The environment variable equivalent is `PYDEPGATE_SARIF_SRCROOT`.

## GitHub Actions

The standard workflow scans the built artifact, writes SARIF output, and
uploads it to GitHub Code Scanning:

```yaml
name: pydepgate SARIF scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Build wheel
        run: |
          pip install build
          python -m build --wheel

      - name: Install pydepgate
        run: pip install pydepgate

      - name: Run pydepgate scan
        run: |
          pydepgate scan \
            --format sarif \
            --sarif-srcroot "${{ github.workspace }}" \
            dist/*.whl > pydepgate.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pydepgate.sarif
          category: pydepgate
```

`continue-on-error: true` on the scan step is required because pydepgate exits
non-zero when findings are present. Without it, the upload step never runs.
GitHub Code Scanning ingests the document regardless of whether findings are
present; the alerts appear in the Security tab of the repository.

The `permissions` block requires `security-events: write` for the upload
action to function on private repositories. Public repositories do not require
the explicit permission.

### With decode pipeline

To include codeFlow encoding for multi-layer payloads:

```yaml
      - name: Run pydepgate scan
        run: |
          pydepgate scan \
            --format sarif \
            --sarif-srcroot "${{ github.workspace }}" \
            --peek \
            --decode-payload-depth 4 \
            dist/*.whl > pydepgate.sarif
        continue-on-error: true
```

This produces all expected outputs (SARIF document with codeFlows) from a
single decode pass.

## Validation

pydepgate's SARIF emission is validated on every pull request in CI using the
Microsoft SARIF Multitool. The workflow runs three synthetic fixtures: a clean
scan, a scan with findings, and a scan with multi-layer codeFlows. Validation
hard-fails on any warning or error.

To validate a SARIF document locally, install the SARIF Multitool via the
.NET SDK (8.0 or later) and run:

```bash
dotnet tool install -g Sarif.Multitool
sarif validate pydepgate.sarif
```

A local equivalent of the CI workflow is available at
`scripts/validate_sarif.sh` in the repository.