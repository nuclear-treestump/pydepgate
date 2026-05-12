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
# Build:
#   docker build -t pydepgate:0.4.0 .
#
# Use:
#   docker run --rm -v $(pwd):/scan pydepgate:0.2.0 scan some.whl
#   docker run --rm -v $(pwd):/scan pydepgate:0.2.0 scan --peek some.whl

# ============================================================================
# Stage 1: builder
#
# Install pydepgate into an isolated venv. Pin the version explicitly
# rather than installing latest; the image tag is the source of truth
# for which pydepgate version is shipped.
# ============================================================================

FROM python:3.12-alpine AS builder

# pydepgate has no third-party runtime dependencies, so we don't need
# build-base or libffi-dev or any of the usual Alpine compile packages.
# The pure-Python install completes against the standard library only.

ARG PYDEPGATE_VERSION=0.4.0

RUN python -m venv /opt/pydepgate-venv \
    && /opt/pydepgate-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/pydepgate-venv/bin/pip install --no-cache-dir \
        "pydepgate==${PYDEPGATE_VERSION}"

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

FROM python:3.12-alpine

# Standard OCI labels so registries and tooling can extract metadata
# without parsing the README. Version label is filled in by the build
# arg so it stays in sync with the installed pydepgate.
ARG PYDEPGATE_VERSION=0.4.0

LABEL org.opencontainers.image.title="pydepgate" \
      org.opencontainers.image.description="Static analyzer for Python supply-chain malware patterns" \
      org.opencontainers.image.version="${PYDEPGATE_VERSION}" \
      org.opencontainers.image.source="https://github.com/nuclear-treestump/pydepgate" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Ikari <ikari@nuclear-treestump.com>"

# Copy the prebuilt venv from the builder stage. This keeps the
# runtime image free of pip, build tools, and package caches.
COPY --from=builder /opt/pydepgate-venv /opt/pydepgate-venv

# Make pydepgate the only thing on PATH that matters. We deliberately
# don't activate the venv via a shell wrapper; just put its bin
# directory at the front of PATH so the entrypoint resolves cleanly.
ENV PATH="/opt/pydepgate-venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root user. Shipping a security tool that runs as root is a bad
# look. uid/gid 1000 matches the conventional first-non-system user
# on most Linux hosts, which makes bind-mount permissions work without
# the user having to configure anything.
RUN addgroup -g 1000 -S pydepgate \
    && adduser -u 1000 -S -G pydepgate -h /home/pydepgate pydepgate

# Working directory for scans. Users bind-mount their artifact
# directory to /scan; pydepgate runs against paths inside that mount.
WORKDIR /scan
RUN chown pydepgate:pydepgate /scan

USER pydepgate

# Direct entrypoint into the pydepgate CLI. The user supplies the
# subcommand and arguments at `docker run` time:
#
#   docker run --rm -v $(pwd):/scan pydepgate:0.2.0 scan some.whl
#   docker run --rm -v $(pwd):/scan pydepgate:0.2.0 scan --peek some.whl
#   docker run --rm -v $(pwd):/scan pydepgate:0.2.0 explain DENS010
ENTRYPOINT ["pydepgate"]
CMD ["--help"]
