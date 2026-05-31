# pydepgate Docker image.
#
# Multi-stage build:
#   - builder stage installs pydepgate from PyPI into a virtual
#     environment, isolated from the Alpine system Python so the
#     copy-out step has a clean target to lift.
#   - runtime stage copies just the venv into a minimal base, runs
#     as a non-root user, and exposes pydepgate as the entrypoint.
#
# The runtime image is sub-50MB and has no Python build toolchain
# present. Users compose this image with their own build pipeline
# rather than building artifacts inside it; see the README in this
# directory for example workflows.
#
# Reproducibility-oriented build properties:
#   - Base image may be pinned by digest through PYTHON_BASE_IMAGE.
#   - PyPI wheel filename and SHA256 are supplied by the workflow.
#   - The downloaded wheel is verified before installation.
#   - pip cache and bytecode generation are disabled.
#   - SOURCE_DATE_EPOCH is used to normalize copied runtime mtimes.
#
# Build:
#   docker build \
#     --build-arg PYDEPGATE_VERSION=0.5.0 \
#     --build-arg PYDEPGATE_WHEEL_FILENAME=pydepgate-0.5.0-py3-none-any.whl \
#     --build-arg PYDEPGATE_WHEEL_SHA256=<sha256> \
#     -t pydepgate:0.5.0 \
#     ./docker
#
# Use:
#   docker run --rm -v $(pwd):/scan pydepgate:0.5.0 scan some.whl
#   docker run --rm -v $(pwd):/scan pydepgate:0.5.0 scan --peek some.whl

# ============================================================================
# Shared build arguments
# ============================================================================

# Workflows should pass this as python:3.12-alpine@sha256:<digest>.
# The tag default keeps local ad-hoc builds ergonomic, but release and
# reproducibility workflows must pass a digest-pinned value.
ARG PYTHON_BASE_IMAGE=python:3.12-alpine

# ============================================================================
# Stage 1: builder
#
# Install pydepgate into an isolated venv. Pin the version explicitly
# rather than installing latest; the image tag is the source of truth
# for which pydepgate version is shipped.
# ============================================================================

FROM ${PYTHON_BASE_IMAGE} AS builder

# pydepgate has no third-party runtime dependencies, so we don't need
# build-base or libffi-dev or any of the usual Alpine compile packages.
# The pure-Python install completes against the standard library only.

ARG PYDEPGATE_VERSION=0.5.0
ARG PYDEPGATE_WHEEL_FILENAME
ARG PYDEPGATE_WHEEL_SHA256
ARG SOURCE_DATE_EPOCH=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Create the venv, download the exact PyPI wheel, verify its SHA256,
# then install from the verified local wheelhouse.
#
# Do not upgrade pip here. The base image digest pins the bundled pip
# version; upgrading pip would reintroduce moving-network-state into
# the build.
RUN test -n "${PYDEPGATE_VERSION}" \
    && test -n "${PYDEPGATE_WHEEL_FILENAME}" \
    && test -n "${PYDEPGATE_WHEEL_SHA256}" \
    && python -m venv /opt/pydepgate-venv \
    && /opt/pydepgate-venv/bin/python -m pip download \
        --only-binary=:all: \
        --no-deps \
        --dest /tmp/wheelhouse \
        "pydepgate==${PYDEPGATE_VERSION}" \
    && test -f "/tmp/wheelhouse/${PYDEPGATE_WHEEL_FILENAME}" \
    && echo "${PYDEPGATE_WHEEL_SHA256}  /tmp/wheelhouse/${PYDEPGATE_WHEEL_FILENAME}" | sha256sum -c - \
    && /opt/pydepgate-venv/bin/python -m pip install \
        --no-index \
        --find-links=/tmp/wheelhouse \
        --no-deps \
        --no-compile \
        "pydepgate==${PYDEPGATE_VERSION}" \
    && rm -rf /tmp/wheelhouse /root/.cache/pip

# Normalize mtimes inside the venv so layer contents are less sensitive
# to wall-clock build time. Use Python instead of touch flags because
# BusyBox/coreutils behavior differs across minimal images.
RUN SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python - <<'PY'
import os

epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
roots = ("/opt/pydepgate-venv",)

for root in roots:
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            try:
                os.utime(path, (epoch, epoch), follow_symlinks=False)
            except OSError:
                pass
    try:
        os.utime(root, (epoch, epoch), follow_symlinks=False)
    except OSError:
        pass
PY

# Sanity-check the install before promoting to the runtime stage. If
# the version we asked for didn't actually land, fail the build here
# rather than shipping a broken image.
RUN /opt/pydepgate-venv/bin/pydepgate --version

# ============================================================================
# Stage 2: runtime
#
# Minimal base, copy the venv from the builder, set up a non-root
# user, and expose pydepgate as the entrypoint.
# ============================================================================

FROM ${PYTHON_BASE_IMAGE}

# Standard OCI labels so registries and tooling can extract metadata
# without parsing the README. Version label is filled in by the build
# arg so it stays in sync with the installed pydepgate.
ARG PYDEPGATE_VERSION=0.5.0
ARG SOURCE_DATE_EPOCH=0

LABEL org.opencontainers.image.title="pydepgate" \
      org.opencontainers.image.description="Static analyzer for Python supply-chain malware patterns" \
      org.opencontainers.image.version="${PYDEPGATE_VERSION}" \
      org.opencontainers.image.source="https://github.com/nuclear-treestump/pydepgate" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Ikari <ikari@nuclear-treestump.com>"

# Make pydepgate the only thing on PATH that matters. We deliberately
# don't activate the venv via a shell wrapper; just put its bin
# directory at the front of PATH so the entrypoint resolves cleanly.
ENV PATH="/opt/pydepgate-venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Copy the prebuilt venv from the builder stage. This keeps the
# runtime image free of build tools and package caches.
COPY --from=builder /opt/pydepgate-venv /opt/pydepgate-venv

# Non-root user. Shipping a security tool that runs as root is a bad
# look. uid/gid 1000 matches the conventional first-non-system user
# on most Linux hosts, which makes bind-mount permissions work without
# the user having to configure anything.
RUN addgroup -g 1000 -S pydepgate \
    && adduser -u 1000 -S -G pydepgate -h /home/pydepgate pydepgate \
    && mkdir -p /scan \
    && chown pydepgate:pydepgate /scan /home/pydepgate

# Normalize runtime mtimes for copied/generated paths.
RUN SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python - <<'PY'
import os

epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
roots = (
    "/opt/pydepgate-venv",
    "/home/pydepgate",
    "/scan",
)

for root in roots:
    if not os.path.exists(root):
        continue
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            try:
                os.utime(path, (epoch, epoch), follow_symlinks=False)
            except OSError:
                pass
    try:
        os.utime(root, (epoch, epoch), follow_symlinks=False)
    except OSError:
        pass
PY

# Working directory for scans. Users bind-mount their artifact
# directory to /scan; pydepgate runs against paths inside that mount.
WORKDIR /scan

USER pydepgate

# Direct entrypoint into the pydepgate CLI. The user supplies the
# subcommand and arguments at `docker run` time:
#
#   docker run --rm -v $(pwd):/scan pydepgate:0.5.0 scan some.whl
#   docker run --rm -v $(pwd):/scan pydepgate:0.5.0 scan --peek some.whl
#   docker run --rm -v $(pwd):/scan pydepgate:0.5.0 explain DENS010
ENTRYPOINT ["pydepgate"]
CMD ["--help"]
