"""
The 'scan' subcommand: static analysis of a wheel, sdist, or
installed package, plus single-file iteration mode.

Auto-detection rules (when neither --single nor a special suffix is given):
  - Path ending in .whl is treated as a wheel
  - Path ending in .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar is an sdist
  - Anything else is treated as an installed package name

Single-file mode (--single PATH):
  Reads PATH directly, bypassing triage's name-based scope check, so
  arbitrary files (test fixtures, garbage data, ad-hoc snippets) can
  be analyzed without renaming them. The file's effective "kind"
  determines which analyzers run and which default rules apply; it
  is auto-detected from the filename or set explicitly with --as.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.analyzers.dynamic_execution import DynamicExecutionAnalyzer
from pydepgate.analyzers.string_ops import StringOpsAnalyzer
from pydepgate.analyzers.suspicious_stdlib import SuspiciousStdlibAnalyzer
from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.cli import exit_codes
from pydepgate.cli.reporter import (
    render_human, render_json, render_sarif_stub,
)
from pydepgate.engines.base import ArtifactKind, ScanResult, ScanStatistics, Severity
from pydepgate.engines.static import StaticEngine


_SDIST_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")


# Choices for --as. Maps the user-facing name to a synthetic
# internal_path that triage will classify as the requested FileKind.
# These paths are never written to disk; they only exist to give
# triage something to recognize.
_AS_KIND_CHOICES = ("setup_py", "init_py", "pth", "sitecustomize", "usercustomize")

_AS_KIND_TO_INTERNAL_PATH = {
    "setup_py": "setup.py",
    # INIT_PY requires depth=1 (one directory above the file). A
    # bare "__init__.py" at depth=0 is classified as SKIP. The
    # synthetic "pkg/" prefix is invisible to the user; triage just
    # needs it to land at the right depth.
    "init_py": "pkg/__init__.py",
    "pth": "single.pth",
    "sitecustomize": "sitecustomize.py",
    "usercustomize": "usercustomize.py",
}

# Filenames that triage classifies naturally without any rewriting.
# Used by auto-detection when --as is not supplied.
_NATURAL_KIND_FILENAMES = {
    "setup.py": "setup.py",
    "__init__.py": "pkg/__init__.py",  # depth fix, same reason as above
    "sitecustomize.py": "sitecustomize.py",
    "usercustomize.py": "usercustomize.py",
}


def register(subparsers) -> None:
    """Register the scan subcommand on the given subparsers object."""
    parser = subparsers.add_parser(
        "scan",
        help="Statically analyze a wheel, sdist, installed package, or single file",
        description=(
            "Statically analyze a Python package for suspicious "
            "startup-vector behavior. Accepts a path to a wheel or "
            "sdist, the name of an installed package, or a single "
            "loose file via --single."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        help=(
            "Path to .whl/.tar.gz/etc., or name of an installed package. "
            "Omit when using --single."
        ),
    )
    parser.add_argument(
        "--single",
        metavar="PATH",
        default=None,
        help=(
            "Scan a single file directly, bypassing wheel/sdist/installed "
            "dispatch. Useful for iterating on test fixtures or garbage "
            "data. The file kind is auto-detected from the filename "
            "(.pth -> pth, setup.py/__init__.py/sitecustomize.py/"
            "usercustomize.py -> their natural kind, anything else -> "
            "setup.py). Override with --as."
        ),
    )
    parser.add_argument(
        "--as",
        dest="as_kind",  # 'as' is a Python keyword
        choices=_AS_KIND_CHOICES,
        default=None,
        help=(
            "Override the file kind for --single mode. Setup_py is the "
            "most permissive context (density rules promote to HIGH/"
            "CRITICAL there), making it the best default for iteration "
            "testing of new signals."
        ),
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the scan subcommand. Returns an exit code."""
    from pydepgate.rules.defaults import DEFAULT_RULES
    from pydepgate.rules.loader import GateFileError, load_user_rules

    # Argument validation: exactly one of target/--single must be given.
    if args.single and args.target:
        sys.stderr.write(
            "error: cannot combine a positional target with --single. "
            "Use --single PATH OR a positional target, not both.\n"
        )
        return exit_codes.TOOL_ERROR
    if not args.single and not args.target:
        sys.stderr.write(
            "error: scan requires either a positional target "
            "(wheel/sdist/installed-package-name) or --single PATH.\n"
        )
        return exit_codes.TOOL_ERROR
    if args.as_kind and not args.single:
        sys.stderr.write(
            "error: --as only applies in --single mode.\n"
        )
        return exit_codes.TOOL_ERROR

    # Load user rules.
    rules_file = getattr(args, "rules_file", None)
    try:
        loaded = load_user_rules(explicit_path=rules_file)
    except GateFileError as exc:
        sys.stderr.write(f"error loading rules: {exc}\n")
        return exit_codes.TOOL_ERROR

    # Combine defaults and user rules. Default order: defaults first,
    # then user rules. Source precedence handles conflicts.
    all_rules = list(DEFAULT_RULES) + list(loaded.rules)

    # Surface discovery information.
    if loaded.source_path:
        sys.stderr.write(
            f"note: using rules file {loaded.source_path}\n"
        )
    if loaded.also_found:
        for other in loaded.also_found:
            sys.stderr.write(
                f"note: also found {other} (not loaded; "
                f"{loaded.source_path} takes precedence)\n"
            )
    for warning in loaded.warnings:
        sys.stderr.write(f"warning: {warning}\n")

    engine = StaticEngine(
        analyzers=[
            EncodingAbuseAnalyzer(),
            DynamicExecutionAnalyzer(),
            StringOpsAnalyzer(),
            SuspiciousStdlibAnalyzer(),
            CodeDensityAnalyzer(),
        ],
        rules=all_rules,
    )

    if args.single:
        result = _dispatch_single(engine, args.single, args.as_kind)
    else:
        result = _dispatch_scan(engine, args.target)
    return _render_and_exit_code(result, args)


def _dispatch_scan(engine: StaticEngine, target: str) -> ScanResult:
    """Auto-detect target type and run the appropriate scan method."""
    path = Path(target)

    if path.suffix == ".whl" and path.is_file():
        return engine.scan_wheel(path)

    for suffix in _SDIST_SUFFIXES:
        if target.endswith(suffix):
            if path.is_file():
                return engine.scan_sdist(path)
            break

    # Fallback: treat as installed package name.
    return engine.scan_installed(target)


def _dispatch_single(
    engine: StaticEngine,
    path_str: str,
    as_kind: str | None,
) -> ScanResult:
    """Scan a single loose file, bypassing triage's name check.

    Reads the file, determines a synthetic internal_path that will
    classify under the desired FileKind, and feeds the bytes through
    engine.scan_bytes. The real filesystem path is preserved as
    artifact_identity so the report still references the right file.
    """
    path = Path(path_str)
    if not path.exists():
        return _empty_result_with_diag(
            path, f"file not found: {path}",
        )
    if not path.is_file():
        return _empty_result_with_diag(
            path, f"not a regular file: {path}",
        )
    try:
        content = path.read_bytes()
    except OSError as exc:
        return _empty_result_with_diag(
            path, f"failed to read {path}: {exc}",
        )

    internal_path = _internal_path_for_single(path, as_kind)
    return engine.scan_bytes(
        content=content,
        internal_path=internal_path,
        artifact_kind=ArtifactKind.LOOSE_FILE,
        artifact_identity=str(path),
    )


def _internal_path_for_single(path: Path, as_kind: str | None) -> str:
    """Decide what internal_path to feed triage in --single mode.

    The internal_path drives both the parser/analyzer routing AND
    which default rules apply (rules match on file_kind). For
    iteration testing, defaulting to setup.py gives the most
    aggressive rule promotion, surfacing every signal at a
    realistic-attack severity rather than the mechanical-mapping
    floor.
    """
    # Explicit override wins.
    if as_kind is not None:
        return _AS_KIND_TO_INTERNAL_PATH[as_kind]

    # .pth at any depth is classified as PTH; use the real filename.
    if path.suffix == ".pth":
        return path.name

    # Natural-kind filenames pass through with a depth fixup if needed.
    if path.name in _NATURAL_KIND_FILENAMES:
        return _NATURAL_KIND_FILENAMES[path.name]

    # Fallback: treat arbitrary content as setup.py for maximum
    # rule promotion. This is the iteration-testing default.
    return "setup.py"


def _empty_result_with_diag(path: Path, diagnostic: str) -> ScanResult:
    """Build an empty ScanResult carrying a single diagnostic message."""
    return ScanResult(
        artifact_identity=str(path),
        artifact_kind=ArtifactKind.LOOSE_FILE,
        findings=(),
        skipped=(),
        statistics=ScanStatistics(),
        diagnostics=(diagnostic,),
    )


def _render_and_exit_code(result: ScanResult, args: argparse.Namespace) -> int:
    """Render result in the requested format and compute exit code.

    Honors --min-severity for both display and exit code, unless
    --strict-exit is set, in which case the exit code uses unfiltered
    findings.
    """
    min_severity = _parse_severity(args.min_severity)
    strict_exit = args.strict_exit

    # Filter findings for display.
    display_findings = tuple(
        f for f in result.findings
        if _severity_meets_threshold(f.severity, min_severity)
    )

    # Make a filtered ScanResult for rendering.
    filtered = result.__class__(
        artifact_identity=result.artifact_identity,
        artifact_kind=result.artifact_kind,
        findings=display_findings,
        skipped=result.skipped,
        statistics=result.statistics,
        diagnostics=result.diagnostics,
    )

    # Render in the requested format.
    if args.format == "json":
        render_json(filtered, sys.stdout)
    elif args.format == "sarif":
        render_sarif_stub(sys.stdout)
        return exit_codes.TOOL_ERROR
    else:
        render_human(filtered, sys.stdout, no_color=args.no_color, ci_mode=args.ci)

    # Compute exit code from the appropriate finding set.
    findings_for_exit = (
        result.findings if strict_exit else display_findings
    )

    return _compute_exit_code(findings_for_exit)


def _parse_severity(severity_str: str | None) -> Severity:
    """Convert a severity string to a Severity enum."""
    if not severity_str:
        return Severity.INFO
    mapping = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    return mapping.get(severity_str.lower(), Severity.INFO)


# Severity ordering for threshold comparison. Higher value = more severe.
_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _severity_meets_threshold(severity: Severity, threshold: Severity) -> bool:
    """True if severity is at or above the threshold."""
    return _SEVERITY_ORDER[severity] >= _SEVERITY_ORDER[threshold]


def _compute_exit_code(findings) -> int:
    """Compute exit code from a set of findings."""
    if not findings:
        return exit_codes.CLEAN
    has_blocking = any(
        f.severity in (Severity.HIGH, Severity.CRITICAL)
        for f in findings
    )
    if has_blocking:
        return exit_codes.FINDINGS_BLOCKING
    return exit_codes.FINDINGS_BELOW_BLOCKING