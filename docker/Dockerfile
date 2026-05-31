# syntax=docker/dockerfile:1.7

# pydepgate Docker image.
#
# Reproducibility-oriented runtime image:
#   - Base image may be pinned by digest through PYTHON_BASE_IMAGE.
#   - pip remains installed from the Python base image.
#   - pydepgate itself is not installed through pip or a venv.
#   - PyPI wheel URL, filename, and SHA256 are supplied by the workflow.
#   - The downloaded wheel is verified before extraction.
#   - The wheel is extracted directly with Python stdlib zipfile.
#   - The console entrypoint is generated from wheel metadata.
#   - Runtime user/group files are written deterministically.
#   - SOURCE_DATE_EPOCH is used to normalize mtimes in the same layer
#     where mutable filesystem state is created.
#
# Why no venv:
#   Virtual environments and pip install metadata can introduce
#   nondeterministic filesystem state. pydepgate has zero runtime
#   dependencies, so extracting the verified wheel directly is simpler,
#   smaller, and more reproducible.
#
# Why pip stays:
#   Dependency resolution and future guarded install features need pip
#   available at runtime. The base python image provides pip; this image
#   keeps it.

ARG PYTHON_BASE_IMAGE=python:3.12-alpine

FROM ${PYTHON_BASE_IMAGE}

ARG PYDEPGATE_VERSION=0.5.0
ARG PYDEPGATE_WHEEL_URL
ARG PYDEPGATE_WHEEL_FILENAME
ARG PYDEPGATE_WHEEL_SHA256
ARG SOURCE_DATE_EPOCH=0

LABEL org.opencontainers.image.title="pydepgate" \
      org.opencontainers.image.description="Static analyzer for Python supply-chain malware patterns" \
      org.opencontainers.image.version="${PYDEPGATE_VERSION}" \
      org.opencontainers.image.source="https://github.com/nuclear-treestump/pydepgate" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Ikari <ikari@nuclear-treestump.com>"

ENV PYTHONPATH="/opt/pydepgate" \
    PATH="/usr/local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Download the exact PyPI wheel, verify SHA256, extract it with stdlib
# zipfile, generate a deterministic console entrypoint, create the
# runtime user/group deterministically, and normalize mtimes in the
# same filesystem layer.
#
# pip remains installed from the Python base image, but pydepgate is
# installed by verified wheel extraction rather than pip install.
RUN test -n "${PYDEPGATE_VERSION}" \
    && test -n "${PYDEPGATE_WHEEL_URL}" \
    && test -n "${PYDEPGATE_WHEEL_FILENAME}" \
    && test -n "${PYDEPGATE_WHEEL_SHA256}" \
    && mkdir -p /opt/pydepgate /tmp/wheelhouse /home/pydepgate /scan \
    && PYDEPGATE_VERSION="${PYDEPGATE_VERSION}" \
       PYDEPGATE_WHEEL_URL="${PYDEPGATE_WHEEL_URL}" \
       PYDEPGATE_WHEEL_FILENAME="${PYDEPGATE_WHEEL_FILENAME}" \
       PYDEPGATE_WHEEL_SHA256="${PYDEPGATE_WHEEL_SHA256}" \
       SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
       python - <<'PY' \
    && echo 'pydepgate:x:1000:' >> /etc/group \
    && echo 'pydepgate:x:1000:1000:pydepgate:/home/pydepgate:/sbin/nologin' >> /etc/passwd \
    && chown -R 1000:1000 /home/pydepgate /scan /opt/pydepgate \
    && chown 0:0 /usr/local/bin/pydepgate \
    && SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python - <<'PY' \
    && pydepgate --version \
    && python -m pip --version
import configparser
import hashlib
import os
import urllib.request
import zipfile

wheel_url = os.environ["PYDEPGATE_WHEEL_URL"]
wheel_filename = os.environ["PYDEPGATE_WHEEL_FILENAME"]
expected_sha256 = os.environ["PYDEPGATE_WHEEL_SHA256"].lower()
epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))

wheel_path = os.path.join("/tmp/wheelhouse", wheel_filename)
target_root = "/opt/pydepgate"
entrypoint_path = "/usr/local/bin/pydepgate"

with urllib.request.urlopen(wheel_url, timeout=60) as response:
    data = response.read()

actual_sha256 = hashlib.sha256(data).hexdigest().lower()
if actual_sha256 != expected_sha256:
    raise SystemExit(
        f"wheel sha256 mismatch for {wheel_filename}: "
        f"expected {expected_sha256}, got {actual_sha256}"
    )

with open(wheel_path, "wb") as handle:
    handle.write(data)

with zipfile.ZipFile(wheel_path) as wheel:
    wheel.extractall(target_root)

entrypoint_target = "pydepgate.cli.main:main"

for dirpath, dirnames, filenames in os.walk(target_root):
    dirnames.sort()
    filenames.sort()
    for filename in filenames:
        if filename == "entry_points.txt" and dirpath.endswith(".dist-info"):
            parser = configparser.ConfigParser()
            parser.read(os.path.join(dirpath, filename))
            if parser.has_section("console_scripts") and parser.has_option("console_scripts", "pydepgate"):
                entrypoint_target = parser.get("console_scripts", "pydepgate").strip()
            break

if ":" not in entrypoint_target:
    raise SystemExit(f"unsupported pydepgate entrypoint target: {entrypoint_target!r}")

module_name, function_name = entrypoint_target.split(":", 1)

entrypoint = f"""#!/usr/local/bin/python
from {module_name} import {function_name}

if __name__ == "__main__":
    raise SystemExit({function_name}())
"""

with open(entrypoint_path, "w", encoding="utf-8", newline="\n") as handle:
    handle.write(entrypoint)

os.chmod(entrypoint_path, 0o755)

# Normalize wheel-extracted permissions. The generated entrypoint is
# the only executable pydepgate file intentionally created here.
for dirpath, dirnames, filenames in os.walk(target_root):
    dirnames.sort()
    filenames.sort()

    for dirname in dirnames:
        path = os.path.join(dirpath, dirname)
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass

    for filename in filenames:
        path = os.path.join(dirpath, filename)
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass

# Normalize mtimes for extracted pydepgate content and wrapper.
roots = (
    target_root,
    entrypoint_path,
)

for root in roots:
    if not os.path.exists(root):
        continue

    if os.path.isfile(root) or os.path.islink(root):
        try:
            os.utime(root, (epoch, epoch), follow_symlinks=False)
        except OSError:
            pass
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

try:
    os.remove(wheel_path)
except OSError:
    pass
PY
import os

epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
roots = (
    "/etc/group",
    "/etc/passwd",
    "/opt/pydepgate",
    "/usr/local/bin/pydepgate",
    "/home/pydepgate",
    "/scan",
)

for root in roots:
    if not os.path.exists(root):
        continue

    if os.path.isfile(root) or os.path.islink(root):
        try:
            os.utime(root, (epoch, epoch), follow_symlinks=False)
        except OSError:
            pass
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
