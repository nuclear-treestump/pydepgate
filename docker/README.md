# Docker image

pydepgate ships an Alpine-based Docker image for use in CI pipelines
and local containerized scans. The image is published to GitHub
Container Registry on every release tag.

## Pulling

    docker pull ghcr.io/nuclear-treestump/pydepgate:latest
    docker pull ghcr.io/nuclear-treestump/pydepgate:0.4.0
    docker pull ghcr.io/nuclear-treestump/pydepgate:0.4

The image supports both `linux/amd64` and `linux/arm64`, so it works
on Intel CI runners, GitHub-hosted runners, and Apple Silicon
developer machines without explicit platform flags.

## Image properties

The image is built FROM `python:3.12-alpine` with pydepgate
installed into an isolated venv at `/opt/pydepgate-venv`. Working
directory is `/scan` and the entrypoint is `pydepgate`, so the
container can be invoked exactly like the local CLI:

    docker run --rm -v "$(pwd):/scan" ghcr.io/nuclear-treestump/pydepgate:latest \
        scan some-package.whl

The container runs as a non-root user (`uid 1000`) and contains no
build toolchain or package manager. It is strictly a runtime image
for the pydepgate CLI. Image size is under 50 MB.

## Composition with build pipelines

pydepgate intentionally does not bundle a Python build tool. The
image scans wheels, sdists, installed packages, and loose source
files, but it doesn't produce them. That's the user's build
pipeline's job. Two common composition shapes:

### Two-stage CI: build, then scan

The most direct pattern is two distinct CI stages. The first stage
runs whatever build tool produces your wheel (`python -m build`,
`uv build`, `hatch build`, `poetry build`, `pip wheel .`, etc.) and
emits the artifact. The second stage runs pydepgate against the
artifact.

### Multi-stage Dockerfile in user projects

Users who already containerize their build can reference the
pydepgate image as a stage in their own Dockerfile:

    FROM python:3.12-slim AS build
    WORKDIR /src
    COPY . .
    RUN pip install build && python -m build --wheel

    FROM ghcr.io/nuclear-treestump/pydepgate:0.2 AS scan
    COPY --from=build /src/dist/*.whl /scan/
    RUN pydepgate scan --ci /scan/*.whl

This produces a scan result during image build; failure of the
pydepgate stage fails the build entirely, so a malicious-pattern
match blocks the pipeline before any downstream stage sees the
artifact.

## Example workflows

### GitHub Actions

    name: scan
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

          - name: Scan wheel with pydepgate
            run: |
              docker run --rm \
                -v "${{ github.workspace }}/dist:/scan" \
                ghcr.io/nuclear-treestump/pydepgate:0.2 \
                scan --ci --min-severity high /scan/*.whl

For repos that prefer the action-style invocation, the same step can
be rewritten using the container directive:

          - name: Scan wheel with pydepgate
            uses: docker://ghcr.io/nuclear-treestump/pydepgate:0.2
            with:
              args: scan --ci --min-severity high dist/*.whl

### GitLab CI

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
      image:
        name: ghcr.io/nuclear-treestump/pydepgate:0.2
        entrypoint: [""]
      script:
        - pydepgate scan --ci --min-severity high dist/*.whl
      dependencies:
        - build-wheel

The `entrypoint: [""]` line overrides the image's pydepgate
entrypoint so GitLab can run its own shell wrapper; the actual
pydepgate invocation goes in the script section.

### Jenkins

    pipeline {
      agent any
      stages {
        stage('Build') {
          agent { docker { image 'python:3.12-slim' } }
          steps {
            sh 'pip install build && python -m build --wheel'
            stash includes: 'dist/*.whl', name: 'wheel'
          }
        }
        stage('Scan') {
          agent { docker { image 'ghcr.io/nuclear-treestump/pydepgate:0.2' } }
          steps {
            unstash 'wheel'
            sh 'pydepgate scan --ci --min-severity high dist/*.whl'
          }
        }
      }
    }

## Invocation patterns

### Scanning a wheel from the host filesystem

    docker run --rm -v "$(pwd):/scan" \
        ghcr.io/nuclear-treestump/pydepgate:latest \
        scan --peek some-package.whl

Bind-mount your working directory to `/scan`. The pydepgate working
directory inside the container is `/scan`, so any path argument is
resolved against it.

### Running with environment-variable configuration

    docker run --rm \
        -v "$(pwd):/scan" \
        -e PYDEPGATE_PEEK=1 \
        -e PYDEPGATE_MIN_SEVERITY=high \
        -e PYDEPGATE_FORMAT=json \
        ghcr.io/nuclear-treestump/pydepgate:latest \
        scan some-package.whl

All `PYDEPGATE_*` environment variables documented in the main
README work inside the container exactly as they do locally.

### Using a custom rules file

    docker run --rm \
        -v "$(pwd):/scan" \
        -v "$(pwd)/company-rules.gate:/etc/pydepgate.gate:ro" \
        ghcr.io/nuclear-treestump/pydepgate:latest \
        scan --rules-file /etc/pydepgate.gate some-package.whl

Mount the rules file read-only into the container; pass the
in-container path to `--rules-file`. Read-only mount is good
hygiene since the container shouldn't modify the host's rules
file.

### Interactive debugging

To poke around inside the image (e.g., to verify which pydepgate
version is installed):

    docker run --rm -it --entrypoint sh \
        ghcr.io/nuclear-treestump/pydepgate:latest

This drops you into an Alpine shell with the pydepgate venv on
PATH; `pydepgate --version` confirms the installed version.

## Security notes

The image runs as non-root by design. Users who bind-mount host
directories should ensure the mount points are readable by uid 1000.
On most Linux hosts this is the default for user-owned files; on
machines where the host user has a different uid, adjust mount
permissions with `chown` or use the `--user` flag on `docker run` to
remap the container user to match the host.

The image contains no shell beyond Alpine's busybox `sh`, no package
manager, and no Python build toolchain. The attack surface is
essentially the pydepgate CLI plus the standard library it depends
on.

The image's source-of-truth Dockerfile is at `docker/Dockerfile` in
the pydepgate repo. Builds are reproducible from that file plus a
pinned pydepgate version; the build workflow is at
`.github/workflows/docker-publish.yml`.
