# syntax=docker/dockerfile:1.7

# pydepgate Docker image.
#
# Multi-stage build:
#   - builder stage installs pydepgate from PyPI into a virtual
#     environment, isolated from the Alpine system Python so the
#     copy-out step has a clean target to lift.
#   - runtime stage copies just the venv into a minimal base, runs
#     as a non-root user, and exposes pydepgate as the entrypoint.
#
# Reproducibility-oriented build properties:
#   - Base image may be pinned by digest through PYTHON_BASE_IMAGE.
#   - PyPI wheel filename and SHA256 are supplied by the workflow.
#   - The downloaded wheel is verified before installation.
#   - pip cache and bytecode generation are disabled.
#   - SOURCE_DATE_EPOCH is used to normalize mtimes in the same layer
#     where mutable filesystem state is created whenever possible.

ARG PYTHON_BASE_IMAGE=python:3.12-alpine

# ============================================================================
# Stage 1: builder
# ============================================================================

FROM ${PYTHON_BASE_IMAGE} AS builder

ARG PYDEPGATE_VERSION=0.5.0
ARG PYDEPGATE_WHEEL_FILENAME
ARG PYDEPGATE_WHEEL_SHA256
ARG SOURCE_DATE_EPOCH=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Create the venv, download the exact PyPI wheel, verify its SHA256,
# install from the verified local wheelhouse, remove transient state,
# normalize mtimes, and sanity-check the install in one layer.
#
# Keeping normalization in the same layer matters. A later normalization
# RUN would only add a corrective layer; it would not make the original
# layer deterministic.
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
    && rm -rf /tmp/wheelhouse /root/.cache/pip \
    && SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" /opt/pydepgate-venv/bin/python - <<'PY' \
    && /opt/pydepgate-venv/bin/pydepgate --version
import os

epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
roots = ("/opt/pydepgate-venv",)

for root in roots:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
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

# ============================================================================
# Stage 2: runtime
# ============================================================================

FROM ${PYTHON_BASE_IMAGE}

ARG PYDEPGATE_VERSION=0.5.0
ARG SOURCE_DATE_EPOCH=0

LABEL org.opencontainers.image.title="pydepgate" \
      org.opencontainers.image.description="Static analyzer for Python supply-chain malware patterns" \
      org.opencontainers.image.version="${PYDEPGATE_VERSION}" \
      org.opencontainers.image.source="https://github.com/nuclear-treestump/pydepgate" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Ikari <ikari@nuclear-treestump.com>"

ENV PATH="/opt/pydepgate-venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Copy the prebuilt venv from the builder stage. COPY is its own layer,
# so the source venv must already be normalized before this point.
COPY --link --from=builder /opt/pydepgate-venv /opt/pydepgate-venv

# Create runtime user, scan directory, ownership, and normalized mtimes
# in the same layer. Do not normalize in a later RUN; that would leave
# this layer's original nondeterministic metadata in the image.
RUN addgroup -g 1000 -S pydepgate \
    && adduser -u 1000 -S -G pydepgate -h /home/pydepgate pydepgate \
    && mkdir -p /scan \
    && chown -R pydepgate:pydepgate /scan /home/pydepgate /opt/pydepgate-venv \
    && SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python - <<'PY'
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
        dirnames.sort()
        filenames.sort()
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

WORKDIR /scan

USER pydepgate

ENTRYPOINT ["pydepgate"]
CMD ["--help"]
