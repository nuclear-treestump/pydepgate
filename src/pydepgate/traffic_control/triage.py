"""
Triage module ("traffic control"): determine which files in an artifact
are in scope for pydepgate's analysis.

This module makes scope decisions based on file paths alone, without
reading any file content. That's a deliberate design choice: scope
decisions should be cheap, fast, and free of side effects. A file's
content can't make it more or less in-scope. Only its location and
name matter.

Downstream layers (parsers, analyzers, rules) only ever see files that
this module has approved.

Deep mode (deep_mode=True):
  Extends scope to include "library" .py files: ordinary Python source
  that lives inside a package but isn't on a recognized startup vector.
  Used by `pydepgate scan --deep` to surface obfuscation patterns
  anywhere in a package, not just in setup.py / __init__.py / .pth.
  Files inside excluded directories (tests/, docs/, __pycache__/, etc.)
  remain skipped even in deep mode; deep mode does NOT mean "scan
  everything indiscriminately."
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from enum import Enum


class FileKind(Enum):
    """What kind of startup vector a file represents, if any."""
    SKIP = "skip"
    PTH = "pth"
    SETUP_PY = "setup_py"
    INIT_PY = "init_py"
    SITECUSTOMIZE = "sitecustomize"
    USERCUSTOMIZE = "usercustomize"
    LIBRARY_PY = "library_py"
    """Ordinary Python source that's not on a startup vector. Only
    produced by triage when deep_mode=True. Matched by the
    DENSxxx_in_library_py default rules."""
    ENTRY_POINTS = "entry_points"


@dataclass(frozen=True)
class TriageDecision:
    """The result of triaging a single file.

    Attributes:
        kind: What the file is, or SKIP if out of scope.
        internal_path: The path as it appeared in the artifact
            (normalized to forward slashes).
        reason: Human-readable explanation of the decision, useful
            for debugging scope misses.
        depth: Directory depth from artifact root. Top-level files
            have depth 0.
    """
    kind: FileKind
    internal_path: str
    reason: str
    depth: int


# Directory names that we never descend into, regardless of what's
# inside them. All comparisons are case-insensitive on the name itself,
# but the path separator comparison is strict (we don't try to handle
# weird OS-specific paths; archive contents use forward slashes).
_EXCLUDED_DIRECTORY_NAMES = frozenset({
    "tests", "test", "testing",
    "__pycache__",
    ".git", ".hg", ".svn",
    ".tox", ".nox",
    ".pytest_cache", ".mypy_cache",
    "docs", "doc",
    "examples", "example",
    "benchmarks", "benchmark",
})

# File extensions we completely ignore.
_EXCLUDED_EXTENSIONS = frozenset({
    ".pyc", ".pyo", ".pyd",
    ".so", ".dylib", ".dll",
    ".c", ".h", ".cpp", ".hpp",
    ".rst", ".md", ".txt",
    ".json", ".yaml", ".yml", ".toml",
    ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".csv", ".tsv",
    ".whl", ".tar", ".gz", ".zip",
})


def _normalize_path(path: str) -> str:
    """Normalize a path to forward slashes and remove leading './'."""
    normalized = path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _path_contains_excluded_directory(path: str) -> str | None:
    """Return the name of the first excluded directory in the path, or None."""
    parts = path.split("/")
    # Don't check the last component (that's the filename).
    for part in parts[:-1]:
        if part.lower() in _EXCLUDED_DIRECTORY_NAMES:
            return part
    return None


def triage(
    internal_path: str,
    deep_mode: bool = False,
) -> TriageDecision:
    """Decide whether a single file is in scope for pydepgate analysis.

    Args:
        internal_path: The file's path within its containing artifact
            (or a loose-file path).
        deep_mode: When True, ordinary .py files outside startup
            vectors return FileKind.LIBRARY_PY instead of SKIP.
            Files inside excluded directories still skip; this flag
            only upgrades the "not a known startup vector" cases.

    Returns:
        A TriageDecision describing the kind, reason, and depth.
    """
    path = _normalize_path(internal_path).lstrip("/")
    parts = path.split("/")
    depth = len(parts) - 1
    filename = parts[-1] if parts else ""

    # ── INCLUSION RULES ──
    # Specific filenames and patterns that are always in scope take
    # precedence over general exclusion rules. A .txt file is normally
    # out of scope, but entry_points.txt inside a dist-info directory
    # is meaningful.

    # .pth files anywhere.
    if filename.endswith(".pth"):
        return TriageDecision(
            kind=FileKind.PTH,
            internal_path=path,
            reason=".pth file",
            depth=depth,
        )

    # sitecustomize.py / usercustomize.py anywhere. The filenames
    # themselves are the signal.
    if filename == "sitecustomize.py":
        return TriageDecision(
            kind=FileKind.SITECUSTOMIZE,
            internal_path=path,
            reason="sitecustomize.py (should never appear in a third-party package)",
            depth=depth,
        )
    if filename == "usercustomize.py":
        return TriageDecision(
            kind=FileKind.USERCUSTOMIZE,
            internal_path=path,
            reason="usercustomize.py (should never appear in a third-party package)",
            depth=depth,
        )

    # entry_points.txt inside *.dist-info or *.egg-info.
    if filename == "entry_points.txt":
        if depth >= 1 and (
            parts[-2].endswith(".dist-info")
            or parts[-2].endswith(".egg-info")
        ):
            return TriageDecision(
                kind=FileKind.ENTRY_POINTS,
                internal_path=path,
                reason=f"entry_points.txt in {parts[-2]}",
                depth=depth,
            )
        # entry_points.txt outside a metadata directory is just a text file.
        return TriageDecision(
            kind=FileKind.SKIP,
            internal_path=path,
            reason="entry_points.txt not in dist-info/egg-info metadata directory",
            depth=depth,
        )

    # setup.py only at artifact root.
    if filename == "setup.py":
        if depth == 0:
            return TriageDecision(
                kind=FileKind.SETUP_PY,
                internal_path=path,
                reason="top-level setup.py",
                depth=depth,
            )
        # setup.py not at root: usually vendored or an example.
        # In deep mode, treat it as library code IF it's not inside
        # an excluded directory (tests/, docs/, examples/).
        if deep_mode:
            excluded = _path_contains_excluded_directory(path)
            if excluded is None:
                return TriageDecision(
                    kind=FileKind.LIBRARY_PY,
                    internal_path=path,
                    reason="vendored setup.py treated as library code in deep mode",
                    depth=depth,
                )
        return TriageDecision(
            kind=FileKind.SKIP,
            internal_path=path,
            reason="setup.py not at artifact root (likely example or vendored)",
            depth=depth,
        )

    # __init__.py at depth 1 (top-level package).
    if filename == "__init__.py":
        if depth == 1:
            parent = parts[-2]
            if parent.endswith((".dist-info", ".egg-info")):
                return TriageDecision(
                    kind=FileKind.SKIP,
                    internal_path=path,
                    reason=f"__init__.py inside metadata directory {parent}",
                    depth=depth,
                )
            # Still need to check the excluded-directory list here in case
            # the depth-1 directory is something like 'tests/'.
            if parent.lower() in _EXCLUDED_DIRECTORY_NAMES:
                return TriageDecision(
                    kind=FileKind.SKIP,
                    internal_path=path,
                    reason=f"__init__.py inside excluded directory {parent}",
                    depth=depth,
                )
            return TriageDecision(
                kind=FileKind.INIT_PY,
                internal_path=path,
                reason=f"top-level package __init__.py ({parent}/)",
                depth=depth,
            )
        # Deeper __init__.py files: skipped in default mode, treated
        # as library code in deep mode (unless inside an excluded
        # directory, which still skips).
        excluded = _path_contains_excluded_directory(path)
        if excluded is not None:
            return TriageDecision(
                kind=FileKind.SKIP,
                internal_path=path,
                reason=f"inside excluded directory: {excluded}",
                depth=depth,
            )
        if deep_mode:
            return TriageDecision(
                kind=FileKind.LIBRARY_PY,
                internal_path=path,
                reason=(
                    f"package __init__.py at depth {depth} treated as "
                    f"library code in deep mode"
                ),
                depth=depth,
            )
        return TriageDecision(
            kind=FileKind.SKIP,
            internal_path=path,
            reason=f"__init__.py at depth {depth} (only depth 1 analyzed in v0.1)",
            depth=depth,
        )

    # EXCLUSION RULES
    # Nothing above matched, so we fall through to general exclusions.

    # Excluded directories (tests/, docs/, __pycache__/, etc.). These
    # remain skipped even in deep mode. Deep mode is "scan library
    # code" not "scan everything indiscriminately."
    excluded = _path_contains_excluded_directory(path)
    if excluded is not None:
        return TriageDecision(
            kind=FileKind.SKIP,
            internal_path=path,
            reason=f"inside excluded directory: {excluded}",
            depth=depth,
        )

    # Excluded extensions. These remain skipped in deep mode too;
    # the density analyzer expects parseable Python source.
    for ext in _EXCLUDED_EXTENSIONS:
        if filename.endswith(ext):
            return TriageDecision(
                kind=FileKind.SKIP,
                internal_path=path,
                reason=f"excluded file extension: {ext}",
                depth=depth,
            )

    # Default: unknown file.
    # In deep mode, .py files reach here legitimately and become
    # LIBRARY_PY; everything else (and all files in default mode)
    # remain SKIP.
    if deep_mode and filename.endswith(".py"):
        return TriageDecision(
            kind=FileKind.LIBRARY_PY,
            internal_path=path,
            reason="library code (deep mode)",
            depth=depth,
        )
    return TriageDecision(
        kind=FileKind.SKIP,
        internal_path=path,
        reason="not a known startup vector",
        depth=depth,
    )


def triage_many(
    paths: list[str],
    deep_mode: bool = False,
) -> list[TriageDecision]:
    """Triage a batch of paths. Convenience wrapper."""
    return [triage(p, deep_mode=deep_mode) for p in paths]