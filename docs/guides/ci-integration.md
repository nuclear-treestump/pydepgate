---
title: CI Integration
parent: Guides
nav_order: 1
render_with_liquid: false
---

# CI Integration

pydepgate is designed to run as an artifact gate in CI.

The usual pattern is:

1. Build the package artifact.
2. Scan the artifact before publishing or deploying it.
3. Fail the pipeline if pydepgate finds HIGH or CRITICAL startup-vector behavior.
4. Optionally store the scan evidence as a CI artifact for later review.

pydepgate supports CI integration through direct CLI invocation, Docker, pre-commit hooks, JSON output, SARIF output, and the local evidence database.

## Exit code contract

CI integrations should rely on pydepgate's public exit-code contract.

| Code | Meaning                                          |
| ---- | ------------------------------------------------ |
| `0`  | Clean. No findings at or above `--min-severity`. |
| `1`  | Findings present, but none HIGH or CRITICAL.     |
| `2`  | At least one HIGH or CRITICAL finding.           |
| `3`  | Tool error. The scan could not complete.         |

The standard CI pattern is to fail the build on exit code `2`.

Exit code `1` means pydepgate found lower-severity signals, but not enough to block the pipeline under the active threshold. Use `--strict-exit` when you want any finding to fail the build.

## Recommended CI policy

For most projects:

```bash
pydepgate scan --ci --min-severity high dist/*.whl
```

This blocks on HIGH and CRITICAL findings while allowing lower-severity informational signals to be reviewed separately.

`--ci` is an output-mode flag. It does not change severity behavior.

When enabled, `--ci`:

* forces JSON output unless another format is explicitly selected
* disables color unless color was explicitly configured
* preserves the normal exit-code contract

Pair `--ci` with `--min-severity high` when you want CI to block only on HIGH and CRITICAL findings.

## Direct CLI invocation

Direct CLI invocation is the simplest integration path when the CI job already has Python available.

### GitHub Actions

```yaml
name: pydepgate scan

on:
  push:
  pull_request:

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
          python -m pip install --upgrade pip
          python -m pip install build
          python -m build --wheel

      - name: Install pydepgate
        run: python -m pip install "pydepgate>=0.5,<0.6"

      - name: Scan wheel
        run: pydepgate scan --ci --min-severity high dist/*.whl
```

Use a bounded version range for CI if you want patch releases without accepting a future breaking change. Use an exact version pin when you need fully reproducible pipeline behavior.

Example:

```bash
python -m pip install "pydepgate==0.5.0"
```

### GitLab CI

```yaml
stages:
  - build
  - scan

build-wheel:
  stage: build
  image: python:3.12-slim
  script:
    - python -m pip install --upgrade pip
    - python -m pip install build
    - python -m build --wheel
  artifacts:
    paths:
      - dist/

scan-wheel:
  stage: scan
  image: python:3.12-slim
  script:
    - python -m pip install --upgrade pip
    - python -m pip install "pydepgate>=0.5,<0.6"
    - pydepgate scan --ci --min-severity high dist/*.whl
  dependencies:
    - build-wheel
```

## Scanning installed packages

Artifact scanning is preferred for packages you build yourself, because it scans the exact wheel or source distribution that would be published.

Installed-package scanning is useful when you want to inspect a third-party package already present in the environment.

```yaml
      - name: Install target package
        run: python -m pip install some-package

      - name: Scan installed package
        run: pydepgate scan --ci --min-severity high some-package
```

Use this for dependency intake or local environment review. For release gating, scan the built artifact.

## Docker image

The official Docker image is published at:

```text
ghcr.io/nuclear-treestump/pydepgate
```

The image is intended for CI pipelines that should not install pydepgate into the build environment directly.

Published tags include:

```bash
docker pull ghcr.io/nuclear-treestump/pydepgate:latest
docker pull ghcr.io/nuclear-treestump/pydepgate:0.5
docker pull ghcr.io/nuclear-treestump/pydepgate:0.5.0
```

Use `latest` for quick local testing. Use a version tag or digest pin in CI.

See [Guide: Docker Image](docker-image.md) for image properties, supported platforms, digest pinning, signatures, attestations, and reproducibility notes.

### Scan one artifact with Docker

```bash
docker run --rm \
  -v "$(pwd)/dist:/scan:ro" \
  ghcr.io/nuclear-treestump/pydepgate:0.5 \
  scan --ci --min-severity high /scan/some-package-1.0.0-py3-none-any.whl
```

The `:ro` mount is recommended for ordinary scans. pydepgate does not need write access to the scanned artifact.

### Scan multiple artifacts with Docker

Docker does not expand globs unless a shell is used inside the container. For wildcard scans, override the entrypoint and invoke `sh -c`:

```bash
docker run --rm \
  --entrypoint sh \
  -v "$(pwd)/dist:/scan:ro" \
  ghcr.io/nuclear-treestump/pydepgate:0.5 \
  -c 'pydepgate scan --ci --min-severity high /scan/*.whl'
```

This keeps glob expansion inside the container, where `/scan/*.whl` actually exists.

### GitHub Actions with Docker

```yaml
name: pydepgate docker scan

on:
  push:
  pull_request:

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
          python -m pip install --upgrade pip
          python -m pip install build
          python -m build --wheel

      - name: Scan wheel with pydepgate container
        run: |
          docker run --rm \
            --entrypoint sh \
            -v "${{ github.workspace }}/dist:/scan:ro" \
            ghcr.io/nuclear-treestump/pydepgate:0.5 \
            -c 'pydepgate scan --ci --min-severity high /scan/*.whl'
```

For locked-down pipelines, replace the version tag with an image digest.

```yaml
          docker run --rm \
            --entrypoint sh \
            -v "${{ github.workspace }}/dist:/scan:ro" \
            ghcr.io/nuclear-treestump/pydepgate@sha256:<digest> \
            -c 'pydepgate scan --ci --min-severity high /scan/*.whl'
```

### GitLab CI with Docker

```yaml
scan-wheel:
  stage: scan
  image:
    name: ghcr.io/nuclear-treestump/pydepgate:0.5
    entrypoint: [""]
  script:
    - pydepgate scan --ci --min-severity high dist/*.whl
  dependencies:
    - build-wheel
```

The `entrypoint: [""]` line overrides the image's pydepgate entrypoint so GitLab can run its normal shell wrapper before executing the `script` section.

### Multi-stage Dockerfile

For projects that already build inside Docker, use pydepgate as a scan stage.

```dockerfile
FROM python:3.12-slim AS build
WORKDIR /src
COPY . .
RUN python -m pip install --upgrade pip \
    && python -m pip install build \
    && python -m build --wheel

FROM ghcr.io/nuclear-treestump/pydepgate:0.5 AS scan
COPY --from=build /src/dist/*.whl /scan/
RUN pydepgate scan --ci --min-severity high /scan/*.whl
```

The scan stage fails if blocking findings are present, stopping the build before downstream stages receive the artifact.

## Environment variables in Docker

All `PYDEPGATE_*` environment variables work inside the container.

```bash
docker run --rm \
  -v "$(pwd)/dist:/scan:ro" \
  -e PYDEPGATE_PEEK=1 \
  -e PYDEPGATE_MIN_SEVERITY=high \
  -e PYDEPGATE_FORMAT=json \
  ghcr.io/nuclear-treestump/pydepgate:0.5 \
  scan /scan/some-package-1.0.0-py3-none-any.whl
```

Use environment variables when your CI system manages policy through job configuration rather than command-line arguments.

See [Environment Variables](../reference/environment-variables.md).

## Saving scan evidence in CI

pydepgate can store scan evidence in its local evidence database.

This is useful when you want the CI job to preserve:

* artifact identity and hashes
* active findings
* finding locations
* decoded payload trees
* CVE matches
* later `pydepgate db explain` output

Set `XDG_DATA_HOME` to a workspace directory, run the scan with `--save-to-db`, and upload that directory as a CI artifact.

### GitHub Actions evidence artifact

```yaml
      - name: Scan wheel and save evidence
        env:
          XDG_DATA_HOME: ${{ github.workspace }}/.pydepgate-data
        run: pydepgate scan --ci --min-severity high --save-to-db dist/*.whl

      - name: Upload pydepgate evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pydepgate-evidence
          path: .pydepgate-data/
```

`if: always()` ensures the evidence is uploaded even when pydepgate exits with code `2`.

### Inspecting evidence after CI

After downloading the artifact, use:

```bash
pydepgate db list-runs
pydepgate db explain --run-id <run-id>
```

See [CLI Reference: db](../cli/db.md).

## CVE scanning in CI

`pydepgate scan` and `pydepgate cvescan` answer different questions.

`pydepgate scan` asks:

> Does this artifact contain suspicious startup-vector behavior?

`pydepgate cvescan` asks:

> Does this artifact identify as a package version known to be vulnerable or malicious in the local CVE database?

A CI job can run both.

```yaml
      - name: Install pydepgate
        run: python -m pip install "pydepgate>=0.5,<0.6"

      - name: Update local CVE database
        run: pydepgate cvedb update

      - name: Static startup-vector scan
        run: pydepgate scan --ci --min-severity high dist/*.whl

      - name: Known vulnerability scan
        run: pydepgate cvescan --ci --min-severity high dist/*.whl
```

For offline or hermetic CI, build or cache the CVE database in an earlier trusted job and reuse it in the scan job.

See [CLI Reference: cvedb](../cli/cvedb.md) and [CLI Reference: cvescan](../cli/cvescan.md).

## SARIF upload

Use SARIF when you want pydepgate findings to appear in GitHub Code Scanning or another SARIF-compatible system.

```yaml
      - name: Run pydepgate SARIF scan
        run: |
          pydepgate scan \
            --format sarif \
            --sarif-srcroot "$GITHUB_WORKSPACE" \
            --min-severity low \
            dist/*.whl > pydepgate.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pydepgate.sarif
```

SARIF scans are usually run with a lower display threshold than blocking CI scans because code scanning is useful for review, not just pass/fail gating.

See [Guide: SARIF Integration](sarif-integration.md).

## pre-commit hooks

pydepgate ships two pre-commit hook IDs.

`pydepgate` runs `pydepgate scan --single` against staged `.py` files. It defaults to `--min-severity high` so commits are not blocked by informational density signals. The threshold is tunable via `args`.

`pydepgate-pth` scans staged `.pth` files. `.pth` files are startup-vector files, so any finding there warrants review.

### Add pydepgate to pre-commit

In `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/nuclear-treestump/pydepgate
    rev: v0.5.0
    hooks:
      - id: pydepgate
      - id: pydepgate-pth
```

Install and run the hooks:

```bash
pre-commit install
pre-commit run --all-files
```

### Tune the hook threshold

Catch MEDIUM and above:

```yaml
      - id: pydepgate
        args: [--min-severity, medium, --no-color]
```

Enable payload peeking:

```yaml
      - id: pydepgate
        args: [--min-severity, high, --no-color, --peek]
```

Exclude generated or vendored directories:

```yaml
      - id: pydepgate
        exclude: ^(generated/|vendor/|third_party/)
```

### pre-commit in CI

The same hook configuration works in CI.

GitHub Actions:

```yaml
      - uses: pre-commit/action@v3.0.1
```

GitLab CI:

```yaml
pre-commit:
  image: python:3.12-slim
  script:
    - python -m pip install pre-commit
    - pre-commit run --all-files
```

pre-commit is best used as a commit-time safety net. Release pipelines should still scan built artifacts.

## Recommended thresholds

| Context                   | Recommended flag                    | Rationale                                                 |
| ------------------------- | ----------------------------------- | --------------------------------------------------------- |
| CI artifact gate          | `--ci --min-severity high`          | Blocks on HIGH/CRITICAL findings only.                    |
| Strict CI artifact gate   | `--ci --strict-exit`                | Blocks on any finding.                                    |
| SARIF review scan         | `--format sarif --min-severity low` | Emits lower-severity context for review surfaces.         |
| pre-commit `.py` hook     | `--min-severity high`               | Avoids blocking commits on informational density signals. |
| pre-commit `.pth` hook    | no severity filter                  | Any finding in a `.pth` file warrants review.             |
| Interactive investigation | `--min-severity low` or no filter   | Preserves full signal visibility.                         |
| Evidence-producing scan   | `--save-to-db`                      | Stores reproducible scan records for later explanation.   |

## JSON output for downstream processing

Use JSON when a later CI step needs to apply custom policy.

Do not use `|| true` if you need the original pydepgate exit code. Capture it explicitly.

```bash
set +e
pydepgate scan --format json --min-severity low dist/*.whl > scan-results.json
status=$?
set -e

python scripts/evaluate-pydepgate-results.py scan-results.json

exit "$status"
```

This preserves pydepgate's exit code while still allowing custom processing.

If your custom policy fully replaces pydepgate's exit-code behavior, exit with your policy result instead:

```bash
set +e
pydepgate scan --format json --min-severity low dist/*.whl > scan-results.json
scan_status=$?
set -e

python scripts/evaluate-pydepgate-results.py scan-results.json
policy_status=$?

if [ "$scan_status" -eq 3 ]; then
  exit 3
fi

exit "$policy_status"
```

See [Output Formats](../reference/output-formats.md) for the JSON schema.

## Minimal copy-paste recipes

### Block HIGH/CRITICAL findings on built wheels

```bash
python -m pip install "pydepgate>=0.5,<0.6"
pydepgate scan --ci --min-severity high dist/*.whl
```

### Strict zero-finding gate

```bash
python -m pip install "pydepgate>=0.5,<0.6"
pydepgate scan --ci --strict-exit dist/*.whl
```

### Containerized scan

```bash
docker run --rm \
  --entrypoint sh \
  -v "$(pwd)/dist:/scan:ro" \
  ghcr.io/nuclear-treestump/pydepgate:0.5 \
  -c 'pydepgate scan --ci --min-severity high /scan/*.whl'
```

### Static scan plus CVE scan

```bash
python -m pip install "pydepgate>=0.5,<0.6"
pydepgate cvedb update
pydepgate scan --ci --min-severity high dist/*.whl
pydepgate cvescan --ci --min-severity high dist/*.whl
```

### Save evidence for later explanation

```bash
export XDG_DATA_HOME="$PWD/.pydepgate-data"
pydepgate scan --ci --min-severity high --save-to-db dist/*.whl
pydepgate db list-runs
```
