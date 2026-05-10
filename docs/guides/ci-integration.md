# CI Integration

pydepgate integrates with CI pipelines in three ways: direct invocation via
the CLI, the Docker image for containerized pipelines, and pre-commit hooks
for commit-time scanning. This page covers all three.

## Exit code contract

All three integration paths depend on pydepgate's exit codes:

| Code | Meaning |
|---|---|
| `0` | Clean. No findings at or above `--min-severity`. |
| `1` | Findings present, none HIGH or CRITICAL. |
| `2` | At least one HIGH or CRITICAL finding. |
| `3` | Tool error. Scan could not complete. |

The standard CI pattern is to fail the build on exit code `2`. Exit code `1`
represents findings below the blocking threshold and does not fail the build
unless you use `--strict-exit`, which treats any finding as blocking regardless
of severity.

## Direct CLI invocation

### GitHub Actions

```yaml
name: pydepgate scan

on: [push, pull_request]

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

      - name: Scan wheel
        run: pydepgate scan --ci dist/*.whl
```

`--ci` is equivalent to `--min-severity high --no-color`. It filters out
informational and low-severity signals that are too noisy for automated blocking
while still catching everything HIGH and CRITICAL. Adjust `--min-severity` if
your threshold differs.

To scan an installed package instead of a wheel:

```yaml
      - name: Install target package
        run: pip install some-package

      - name: Scan installed package
        run: pydepgate scan --ci some-package
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
    - pip install build
    - python -m build --wheel
  artifacts:
    paths:
      - dist/

scan-wheel:
  stage: scan
  image: python:3.12-slim
  script:
    - pip install pydepgate
    - pydepgate scan --ci dist/*.whl
  dependencies:
    - build-wheel
```

## Docker image

The official Docker image is at `ghcr.io/nuclear-treestump/pydepgate`. It is a
multi-stage Alpine build under 50 MB, runs as non-root (uid 1000), and is
published for `linux/amd64` and `linux/arm64`.

```bash
docker pull ghcr.io/nuclear-treestump/pydepgate:latest
docker pull ghcr.io/nuclear-treestump/pydepgate:0.4.0
docker pull ghcr.io/nuclear-treestump/pydepgate:0.4
```

Scan a wheel from the host filesystem:

```bash
docker run --rm \
    -v "$(pwd):/scan" \
    ghcr.io/nuclear-treestump/pydepgate:latest \
    scan --ci some-package.whl
```

The container's working directory is `/scan`, so paths are resolved against
the bind-mounted directory.

### GitHub Actions with Docker

```yaml
      - name: Scan wheel with pydepgate
        run: |
          docker run --rm \
            -v "${{ github.workspace }}/dist:/scan" \
            ghcr.io/nuclear-treestump/pydepgate:0.4 \
            scan --ci /scan/*.whl
```

Or using the container directive:

```yaml
      - name: Scan wheel with pydepgate
        uses: docker://ghcr.io/nuclear-treestump/pydepgate:0.4
        with:
          args: scan --ci dist/*.whl
```

### GitLab CI with Docker

```yaml
scan-wheel:
  stage: scan
  image:
    name: ghcr.io/nuclear-treestump/pydepgate:0.4
    entrypoint: [""]
  script:
    - pydepgate scan --ci dist/*.whl
  dependencies:
    - build-wheel
```

The `entrypoint: [""]` line overrides the image's pydepgate entrypoint so
GitLab can run its own shell wrapper before the `script` section executes.

### Multi-stage Dockerfile

For projects that already containerize their build, reference the pydepgate
image as a build stage:

```dockerfile
FROM python:3.12-slim AS build
WORKDIR /src
COPY . .
RUN pip install build && python -m build --wheel

FROM ghcr.io/nuclear-treestump/pydepgate:0.4 AS scan
COPY --from=build /src/dist/*.whl /scan/
RUN pydepgate scan --ci /scan/*.whl
```

The pydepgate stage fails the build if blocking findings are present, stopping
the pipeline before any downstream stage receives the artifact.

### Environment variables in Docker

All `PYDEPGATE_*` variables work inside the container:

```bash
docker run --rm \
    -v "$(pwd):/scan" \
    -e PYDEPGATE_PEEK=1 \
    -e PYDEPGATE_MIN_SEVERITY=high \
    -e PYDEPGATE_FORMAT=json \
    ghcr.io/nuclear-treestump/pydepgate:latest \
    scan some-package.whl
```

## pre-commit hooks

pydepgate ships two pre-commit hook IDs that integrate with
[pre-commit](https://pre-commit.com).

### Hook IDs

`pydepgate` runs `pydepgate scan --single` against every staged `.py` file.
It defaults to `--min-severity high` so commits are not blocked by
informational findings. The threshold is tunable via `args`.

`pydepgate-pth` runs the same scanner against staged `.pth` files with no
severity filter. `.pth` files have no legitimate use case for any pattern
pydepgate detects, so even an INFO finding there warrants a human look.

### Adding to your project

In your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/nuclear-treestump/pydepgate
    rev: v0.4.0
    hooks:
      - id: pydepgate
      - id: pydepgate-pth
```

Install and run an initial scan:

```bash
pre-commit install
pre-commit run --all-files
```

### Tuning

Lower the threshold to catch MEDIUM and above:

```yaml
      - id: pydepgate
        args: [--min-severity, medium, --no-color]
```

Enable payload peeking during the hook run:

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

The hook configuration also works under `pre-commit run --all-files` in CI:

**GitHub Actions:**

```yaml
      - uses: pre-commit/action@v3.0.1
```

**GitLab CI:**

```yaml
pre-commit:
  image: python:3.12-slim
  script:
    - pip install pre-commit
    - pre-commit run --all-files
```

## Recommended thresholds

| Context | Recommended flag | Rationale |
|---|---|---|
| CI artifact scan | `--min-severity high` or `--ci` | Blocks on the patterns that indicate real malware |
| pre-commit `.py` hook | `--min-severity high` | Avoids blocking commits on density informational signals |
| pre-commit `.pth` hook | (none) | All findings on `.pth` files warrant review |
| Interactive investigation | `--min-severity low` or no filter | Full signal visibility |
| Strict CI (zero tolerance) | `--strict-exit` | Any finding blocks the build |

## JSON output for downstream processing

To consume pydepgate output in a downstream step rather than failing
the pipeline directly:

```bash
pydepgate scan --format json dist/*.whl > scan-results.json || true
```

The `|| true` prevents the shell from stopping on a non-zero exit.
Parse `scan-results.json` to apply custom logic. Exit code is still set
correctly; use `$?` if you need it after the redirect.

See [Output Formats](../reference/output-formats.md) for the JSON schema.