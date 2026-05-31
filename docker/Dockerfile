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
# runtime user/group deterministically, sanity-check pydepgate and pip,
# remove transient state, and normalize mtimes in the same filesystem
# layer.
#
# pip remains installed from the Python base image, but pydepgate is
# installed by verified wheel extraction rather than pip install.
RUN test -n "${PYDEPGATE_VERSION}" \
    && test -n "${PYDEPGATE_WHEEL_URL}" \
    && test -n "${PYDEPGATE_WHEEL_FILENAME}" \
    && test -n "${PYDEPGATE_WHEEL_SHA256}" \
    && PYDEPGATE_VERSION="${PYDEPGATE_VERSION}" \
       PYDEPGATE_WHEEL_URL="${PYDEPGATE_WHEEL_URL}" \
       PYDEPGATE_WHEEL_FILENAME="${PYDEPGATE_WHEEL_FILENAME}" \
       PYDEPGATE_WHEEL_SHA256="${PYDEPGATE_WHEEL_SHA256}" \
       SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
       python - <<'PY' \
    && pydepgate --version \
    && python -m pip --version \
    && SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python - <<'PY'
import configparser
import hashlib
import os
import shutil
import urllib.request
import zipfile

wheel_url = os.environ["PYDEPGATE_WHEEL_URL"]
wheel_filename = os.environ["PYDEPGATE_WHEEL_FILENAME"]
expected_sha256 = os.environ["PYDEPGATE_WHEEL_SHA256"].lower()

wheel_dir = "/tmp/pydepgate-wheelhouse"
wheel_path = os.path.join(wheel_dir, wheel_filename)
target_root = "/opt/pydepgate"
entrypoint_path = "/usr/local/bin/pydepgate"

# Create all directories up front. Parent directory mtimes are normalized
# later in this same layer.
for path in (
    target_root,
    wheel_dir,
    "/home/pydepgate",
    "/scan",
):
    os.makedirs(path, exist_ok=True)

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

# Deterministic runtime identity. Avoid adduser/addgroup helper metadata.
with open("/etc/group", "a", encoding="utf-8", newline="\n") as handle:
    handle.write("pydepgate:x:1000:\n")

with open("/etc/passwd", "a", encoding="utf-8", newline="\n") as handle:
    handle.write("pydepgate:x:1000:1000:pydepgate:/home/pydepgate:/sbin/nologin\n")

# Normalize permissions for extracted files. The generated entrypoint is
# the one executable pydepgate file intentionally created here.
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

# Ownership.
for root in (
    target_root,
    "/home/pydepgate",
    "/scan",
):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            try:
                os.chown(path, 1000, 1000)
            except OSError:
                pass
    try:
        os.chown(root, 1000, 1000)
    except OSError:
        pass

os.chown(entrypoint_path, 0, 0)

# Remove transient wheel download state before the layer closes.
shutil.rmtree(wheel_dir, ignore_errors=True)
PY
import os

epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))

recursive_roots = (
    "/opt/pydepgate",
    "/home/pydepgate",
    "/scan",
)

single_paths = (
    "/",
    "/opt",
    "/home",
    "/tmp",
    "/usr",
    "/usr/local",
    "/usr/local/bin",
    "/usr/local/bin/pydepgate",
    "/etc",
    "/etc/passwd",
    "/etc/group",
)

for root in recursive_roots:
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

for path in single_paths:
    if not os.path.exists(path):
        continue

    try:
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    except OSError:
        pass
PY

WORKDIR /scan

USER pydepgate

ENTRYPOINT ["pydepgate"]
CMD ["--help"]
