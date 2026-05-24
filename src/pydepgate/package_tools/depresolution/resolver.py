"""pydepgate.package_tools.depresolution.resolver"""

import json
import logging
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from shutil import move as shutil_move
from typing import Any

from pydepgate.pdgplatform import paths

_log = logging.getLogger(__name__)

_PEP508_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")
_PYTHON_VERSION_MARKER_RE = re.compile(
    r'python_version\s*([<>=!]+)\s*["\']?([\d\.]+)["\']?'
)

# Only major.minor is relevant for python_version markers.
_CURRENT_PYTHON: tuple[int, int] = tuple(sys.version_info[:2])  # type: ignore[assignment]

_PIP_MIN_VERSION = (23, 0)

_PIP_BASE_ARGS: tuple[str, ...] = (
    sys.executable,
    "-m",
    "pip",
    "install",
    "--dry-run",
    "--ignore-installed",
    "--only-binary=:all:",
)


def _normalize_pkg_name(name: str) -> str:
    """PEP 503 normalization: lowercase, collapse runs of [-_.] to a single hyphen."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _dep_string_to_normalized_name(dep: str) -> str:
    """Extract the normalized package name from a PEP 508 dependency string."""
    match = _PEP508_NAME_RE.match(dep.strip())
    if match:
        return _normalize_pkg_name(match.group(1))
    return _normalize_pkg_name(dep.split()[0])


def _python_version_marker_applies(marker: str) -> bool:
    """Return True if the python_version marker in *marker* applies to the running interpreter.

    Evaluates the first python_version constraint found in the marker string.
    If no python_version constraint is present or the expression cannot be parsed,
    returns True (include the dependency by default).
    """
    match = _PYTHON_VERSION_MARKER_RE.search(marker)
    if not match:
        return True
    operator, version_str = match.groups()
    try:
        candidate = tuple(int(x) for x in version_str.split("."))
    except ValueError:
        return True
    current = _CURRENT_PYTHON[: len(candidate)]
    result = {
        ">": current > candidate,
        ">=": current >= candidate,
        "<": current < candidate,
        "<=": current <= candidate,
        "==": current == candidate,
        "!=": current != candidate,
    }.get(operator)
    if result is None:
        return True
    return result


def _check_pip_version() -> None:
    """Verify pip is available and meets the minimum version requirement.

    Raises:
        RuntimeError: If pip is absent, its version output is unparseable,
            or the version is below _PIP_MIN_VERSION.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError("pip is not available via the current Python executable")
    # output is like: pip 23.1.2 from /path (python 3.12)
    raw = result.stdout.decode().split()
    if len(raw) < 2:
        raise RuntimeError(
            f"Unexpected pip --version output: {result.stdout.decode()!r}"
        )
    try:
        version_parts = tuple(int(x) for x in raw[1].split(".")[:2])
    except ValueError:
        raise RuntimeError(f"Could not parse pip version number from: {raw[1]!r}")
    if version_parts < _PIP_MIN_VERSION:
        raise RuntimeError(
            f"pip {'.'.join(str(x) for x in _PIP_MIN_VERSION)} or later required for "
            f"--report support; found {raw[1]}"
        )


def _collect_applicable_requires_dist(metadata: dict[str, Any]) -> list[str]:
    """Return Requires-Dist entries applicable to the current environment.

    Extras-gated entries are excluded. python_version markers are evaluated
    against the running interpreter. Entries with other marker types
    (sys_platform, implementation_name, etc.) are included conservatively.

    Args:
        metadata: The metadata dict from a pip report install entry.

    Returns:
        List of dep strings with markers stripped (base specifier only).
    """
    result = []
    for dep in metadata.get("requires_dist", []):
        if ";" not in dep:
            result.append(dep)
            continue
        base, marker = dep.split(";", 1)
        marker = marker.strip()
        if "extra ==" in marker:
            continue
        if "python_version" in marker and not _python_version_marker_applies(marker):
            continue
        result.append(base.strip())
    return result


def get_deps_from_pip_report(
    report: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Classify pip report entries into root, level-1, and transitive dependency tiers.

    Pip marks only the directly-requested package as is_direct=True when scanning
    a local wheel. This function uses the root package's Requires-Dist to distinguish
    its direct dependencies (tier 1) from packages pulled in by those deps (tier 2+).

    Args:
        report: Parsed contents of a pip --report JSON document.

    Returns:
        A three-tuple of (root_deps, level1_deps, transitive_deps).

        root_deps contains the directly-requested package(s) with their
        applicable Requires-Dist.

        level1_deps contains packages whose normalized name appears in the
        root's applicable Requires-Dist.

        transitive_deps contains all remaining packages in the install plan.

    Raises:
        RuntimeError: If the report is missing the expected 'install' key.
    """
    if "install" not in report:
        raise RuntimeError("Invalid pip report: missing 'install' key")

    root_deps: list[dict[str, Any]] = []
    level1_deps: list[dict[str, Any]] = []
    transitive_deps: list[dict[str, Any]] = []

    # First pass: collect root entries and their applicable Requires-Dist.
    for install_step in report["install"]:
        if not install_step.get("is_direct"):
            continue
        metadata = install_step.get("metadata", {})
        requires_dist = _collect_applicable_requires_dist(metadata)
        root_deps.append(
            {
                "name": metadata.get("name"),
                "version": metadata.get("version"),
                "is_yanked": install_step.get("is_yanked", False),
                "hash": (
                    install_step.get("download_info", {})
                    .get("archive_info", {})
                    .get("hash")
                ),
                "requires_dist": requires_dist,
                "requires_dist_normalized": list(map(str.lower, requires_dist)),
                "url": install_step.get("download_info", {}).get("url"),
            }
        )

    # Build the level-1 name set from root Requires-Dist after the first pass
    # so all root entries are present before classification begins.
    level1_names: set[str] = {
        _dep_string_to_normalized_name(dep)
        for d in root_deps
        for dep in d.get("requires_dist", [])
    }

    # Second pass: classify all non-root entries.
    for install_step in report["install"]:
        if install_step.get("is_direct"):
            continue
        metadata = install_step.get("metadata", {})
        entry: dict[str, Any] = {
            "name": metadata.get("name"),
            "normalized_name": str.lower(metadata.get("name", "")),
            "version": metadata.get("version"),
            "is_yanked": install_step.get("is_yanked", False),
            "hash": (
                install_step.get("download_info", {})
                .get("archive_info", {})
                .get("hash")
            ),
            "url": install_step.get("download_info", {}).get("url"),
        }
        if _normalize_pkg_name(metadata.get("name", "")) in level1_names:
            level1_deps.append(entry)
        else:
            transitive_deps.append(entry)

    return root_deps, level1_deps, transitive_deps


def get_pip_resolution_report(
    package_spec: str,
    package_name: str,
    package_version: str,
    timeout: int = 120,
) -> dict[str, Any]:
    """Resolve a package spec via pip dry-run and return the structured report.

    The pip --report JSON is written to a temp file, parsed, then moved to the
    package's XDG cache directory as an audit artifact named
    ``{package_name}-{package_version}_pip_report.json``. On any error the
    temp file is removed and nothing is written to the cache directory.

    Args:
        package_spec: Full pip-style package specifier, e.g. 'litellm==1.82.8'
            or a path to a local wheel.
        package_name: Normalized package name, used to locate the cache directory.
        package_version: Package version string, used in the audit artifact filename.
        timeout: Seconds before the pip subprocess is killed. Default 120.

    Returns:
        Parsed contents of the pip --report JSON output.

    Raises:
        RuntimeError: If pip is unavailable, below minimum version, the
            subprocess times out, resolution fails, or the report cannot be parsed.
    """
    _check_pip_version()
    dep_dir = paths.ensure_directory(paths.xdg_cache_home() / package_name)
    artifact_name = f"{package_name}-{package_version}_pip_report.json"

    with tempfile.NamedTemporaryFile(
        suffix="_pip_report.json", delete=False
    ) as report_file:
        report_path = Path(report_file.name)

    args = list(_PIP_BASE_ARGS) + ["--report", str(report_path), package_spec]
    _log.debug("Running pip resolution: %s", args)

    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        report_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"pip resolution timed out after {timeout}s for {package_spec!r}"
        )

    if result.returncode != 0:
        report_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"pip resolution failed for {package_spec!r}:\n{result.stderr.decode()}"
        )

    stderr_text = result.stderr.decode().strip()
    if stderr_text:
        _log.warning("pip stderr for %r:\n%s", package_spec, stderr_text)

    _moved = False
    try:
        try:
            json_report = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Failed to parse pip resolution report for {package_spec!r}: {e}"
            ) from e
        shutil_move(str(report_path), dep_dir / artifact_name)
        _moved = True
        return json_report
    finally:
        if not _moved:
            report_path.unlink(missing_ok=True)
