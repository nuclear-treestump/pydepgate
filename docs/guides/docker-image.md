---

title: Docker Image
parent: Guides
nav_order: 5
render_with_liquid: false
-------------------------

# Docker Image

pydepgate publishes an official Docker image at:

```text
ghcr.io/nuclear-treestump/pydepgate
```

The image is intended for local containerized scans, CI pipelines,
package-intake workflows, and future mirror/guarded-install use cases.
For CI-specific examples, see the
[CI Integration guide](ci-integration.md).

## Tags and platforms

The image is published for:

* `linux/amd64`
* `linux/arm64`

Common tags:

```bash
docker pull ghcr.io/nuclear-treestump/pydepgate:latest
docker pull ghcr.io/nuclear-treestump/pydepgate:0.X.Y
docker pull ghcr.io/nuclear-treestump/pydepgate:0.X
```

For CI and production package-intake workflows, prefer pinning the image
by digest:

```bash
docker pull ghcr.io/nuclear-treestump/pydepgate@sha256:<digest>
```

Tags are convenient pointers. Digests identify the actual immutable
image artifact.

## Quick local scan

Bind-mount the directory containing the artifact to `/scan`:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/nuclear-treestump/pydepgate:latest \
  scan some-package.whl
```

The image working directory is `/scan`, so relative paths are resolved
against the mounted directory.

With CI-style output and a blocking threshold:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/nuclear-treestump/pydepgate:latest \
  scan --ci --min-severity high some-package.whl
```

With payload peek enabled:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/nuclear-treestump/pydepgate:latest \
  scan --peek some-package.whl
```

## Runtime properties

The image:

* runs as a non-root user (`uid 1000`);
* uses `/scan` as its working directory;
* exposes `pydepgate` as the entrypoint;
* keeps `python` and `pip` available at runtime;
* installs pydepgate from a verified PyPI wheel during image build;
* avoids using a pydepgate virtual environment in the runtime image;
* supports both `linux/amd64` and `linux/arm64`.

`pip` remains available because dependency resolution and future guarded
install features require pip-compatible behavior. pydepgate itself is
still a zero-runtime-dependency tool.

## Release integrity

New image releases are designed around digest identity and verifiable
release metadata.

The container publishing workflow:

* resolves the pydepgate PyPI wheel filename, URL, and SHA256;
* verifies the wheel hash during the Docker build;
* resolves the Python base image to a digest;
* builds a multi-arch image;
* emits BuildKit provenance;
* emits a BuildKit SBOM attestation;
* signs the pushed image digest with keyless Sigstore/cosign using
  GitHub Actions OIDC;
* attaches a GitHub artifact attestation to the pushed digest;
* smoke-tests the exact pushed digest before the workflow exits.

This means the release chain is built around the immutable image digest,
not around trust in a mutable tag.

## Verifying the image signature

Install `cosign`, then verify the digest:

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/nuclear-treestump/pydepgate/.github/workflows/docker-publish.yml@refs/(tags/v.*|heads/.*)" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/nuclear-treestump/pydepgate@sha256:<digest>
```

Use the digest for the image release you intend to run.

## Verifying the GitHub artifact attestation

Install the GitHub CLI, then run:

```bash
gh attestation verify \
  oci://ghcr.io/nuclear-treestump/pydepgate:0.X.Y \
  -R nuclear-treestump/pydepgate
```

For strict workflows, verify the digest-addressed image rather than
only the version tag.

## Reproducibility status

pydepgate tracks container reproducibility separately from signing and
attestation.

* **Signing** proves that the trusted release workflow signed a specific
  image digest.
* **Attestation** records where and how the image was built.
* **Reproducibility** checks whether the same declared inputs rebuild to
  the same image result.

The reproducibility workflow performs per-platform rebuild checks for
`linux/amd64` and `linux/arm64`. Until those checks are consistently
green for a release, treat pydepgate images as signed and attested, not
as fully reproducible.

## Custom rules file

Mount a rules file read-only and pass its in-container path:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  -v "$(pwd)/company-rules.gate:/etc/pydepgate.gate:ro" \
  ghcr.io/nuclear-treestump/pydepgate:latest \
  scan --rules-file /etc/pydepgate.gate some-package.whl
```

## Environment variables

All documented `PYDEPGATE_*` environment variables work inside the
container.

Example:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  -e PYDEPGATE_PEEK=1 \
  -e PYDEPGATE_MIN_SEVERITY=high \
  -e PYDEPGATE_FORMAT=json \
  ghcr.io/nuclear-treestump/pydepgate:latest \
  scan some-package.whl
```

See the [CLI reference](../cli/index.md) for the full environment
variable surface.

## SARIF output

Write SARIF output to the mounted directory:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/nuclear-treestump/pydepgate:latest \
  scan --format sarif some-package.whl > findings.sarif
```

For GitHub Code Scanning ingestion, see the
[SARIF Integration guide](sarif-integration.md).

## Permissions and bind mounts

The container runs as `uid 1000`. On most Linux developer machines,
user-owned files are readable by this UID. If a bind-mounted directory
cannot be read, either adjust the host permissions or run the container
with a matching user:

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$(pwd):/scan" \
  ghcr.io/nuclear-treestump/pydepgate:latest \
  scan some-package.whl
```

## Interactive inspection

To inspect the image manually:

```bash
docker run --rm -it \
  --entrypoint sh \
  ghcr.io/nuclear-treestump/pydepgate:latest
```

Then:

```bash
pydepgate --version
python -m pip --version
```

## Relationship to CI integration

This page describes the Docker image itself: tags, digests, verification,
runtime properties, and local invocation.

For full CI recipes, use the
[CI Integration guide](ci-integration.md), which covers GitHub Actions,
GitLab CI, Docker-in-CI, and pre-commit workflows.



