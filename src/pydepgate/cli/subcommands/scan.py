"""
The 'scan' subcommand: static analysis of a wheel, sdist, or
installed package.

Auto-detection rules:
  - Path ending in .whl is treated as a wheel
  - Path ending in .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar is an sdist
  - Anything else is treated as an installed package name
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.analyzers.dynamic_execution import DynamicExecutionAnalyzer
from pydepgate.analyzers.string_ops import StringOpsAnalyzer
from pydepgate.analyzers.suspicious_stdlib import SuspiciousStdlibAnalyzer
from pydepgate.cli import exit_codes
from pydepgate.cli.reporter import (
    render_human, render_json, render_sarif_stub,
)
from pydepgate.engines.base import ScanResult, Severity
from pydepgate.engines.static import StaticEngine


_SDIST_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")


def register(subparsers) -> None:
    """Register the scan subcommand on the given subparsers object."""
    parser = subparsers.add_parser(
        "scan",
        help="Statically analyze a wheel, sdist, or installed package",
        description=(
            "Statically analyze a Python package for suspicious "
            "startup-vector behavior. Accepts a path to a wheel or "
            "sdist, or the name of an installed package."
        ),
    )
    parser.add_argument(
        "target",
        help=(
            "Path to .whl/.tar.gz/etc., or name of an installed package"
        ),
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the scan subcommand. Returns an exit code."""
    from pydepgate.rules.defaults import DEFAULT_RULES
    from pydepgate.rules.loader import GateFileError, load_user_rules

    target = args.target

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
        ],
        rules=all_rules,
    )

    result = _dispatch_scan(engine, target)
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