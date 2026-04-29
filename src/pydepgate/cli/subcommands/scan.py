"""
The 'scan' subcommand: static analysis of a wheel, sdist, or
installed package, plus single-file iteration mode.

Auto-detection rules (when neither --single nor a special suffix is given):
  - Path ending in .whl is treated as a wheel
  - Path ending in .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar is an sdist
  - Anything else is treated as an installed package name

Single-file mode (--single PATH):
  Reads PATH directly via engine.scan_loose_file_as(), which bypasses
  triage's name-based scope check. The real path is preserved in the
  resulting finding contexts, so reports reference the actual file
  rather than a synthetic stand-in. The file's effective "kind"
  determines which analyzers run and which default rules apply; it
  is auto-detected from the filename or set explicitly with --as.

Deep mode (--deep):
  Extends the artifact scan to include ordinary library .py files
  that triage would normally skip. Only the density analyzer runs
  on those files (other analyzers' signals would produce too many
  false positives without rule-layer promotion). Useful for finding
  obfuscated code anywhere in a package, not just in startup vectors.
  Incompatible with --single.
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
from pydepgate.cli.progress import make_progress_callback
from pydepgate.cli.reporter import (
    render_human, render_json, render_sarif_stub,
)
from pydepgate.engines.base import (
    ArtifactKind, ScanResult, ScanStatistics, Severity,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.traffic_control.triage import FileKind
from pydepgate.cli.peek_args import build_peek_enricher, peek_chain_enabled
from pydepgate.cli.decode_args import decode_enabled
from pydepgate.cli.decode_payloads import (
    decode_payloads,
    render_json,
    render_text,
)


_SDIST_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")


# Choices for the --as flag, mapped to the FileKind the engine will
# treat the file as. These names are user-facing; FileKind values are
# internal. Keep this dict in sync with the choices argparse exposes.
_AS_KIND_CHOICES = (
    "setup_py", "init_py", "pth",
    "sitecustomize", "usercustomize",
    "library_py",
)

_AS_KIND_TO_FILE_KIND = {
    "setup_py": FileKind.SETUP_PY,
    "init_py": FileKind.INIT_PY,
    "pth": FileKind.PTH,
    "sitecustomize": FileKind.SITECUSTOMIZE,
    "usercustomize": FileKind.USERCUSTOMIZE,
    "library_py": FileKind.LIBRARY_PY,
}

# Filenames that map naturally to a known startup-vector kind. Used
# by autodetection when --as is omitted.
_NATURAL_KIND_FILES = {
    "setup.py": FileKind.SETUP_PY,
    "__init__.py": FileKind.INIT_PY,
    "sitecustomize.py": FileKind.SITECUSTOMIZE,
    "usercustomize.py": FileKind.USERCUSTOMIZE,
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
            "dispatch. The real path is preserved in the report so "
            "findings reference the actual file. The file kind is "
            "auto-detected from the filename (.pth -> pth, "
            "setup.py/__init__.py/sitecustomize.py/usercustomize.py -> "
            "their natural kind, anything else -> setup_py for maximum "
            "rule promotion). Override with --as. Incompatible with "
            "--deep."
        ),
    )
    parser.add_argument(
        "--as",
        dest="as_kind",  # 'as' is a Python keyword
        choices=_AS_KIND_CHOICES,
        default=None,
        help=(
            "Override the file kind for --single mode. setup_py is the "
            "most permissive context (density rules promote to HIGH/"
            "CRITICAL there), making it the best default for iteration "
            "testing of new signals. library_py iterates on deep-mode "
            "calibration."
        ),
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        default=False,
        help=(
            "Deep scan: also analyze ordinary library .py files in "
            "the artifact, not just startup vectors. Only the density "
            "analyzer runs on library files (other analyzers' signals "
            "would be too noisy outside startup-vector context). "
            "Useful for finding obfuscation anywhere in a package. "
            "Files inside excluded directories (tests/, docs/, etc.) "
            "remain skipped. Incompatible with --single."
        ),
    )
    parser.add_argument(
        "--no-bar",
        action="store_true",
        default=False,
        help=(
            "Suppress the per-file progress bar shown during artifact "
            "scans. The bar is automatically suppressed when stderr is "
            "not a TTY (piped output, CI runs, redirected logs), so "
            "this flag is mainly for users who want to silence it in "
            "an interactive terminal. No effect in --single mode."
        ),
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the scan subcommand. Returns an exit code."""
    from pydepgate.rules.defaults import DEFAULT_RULES
    from pydepgate.rules.loader import GateFileError, load_user_rules

    # Argument validation.
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
    if args.deep and args.single:
        sys.stderr.write(
            "error: --deep and --single are incompatible. --deep scans "
            "entire artifacts (wheels, sdists, installed packages); "
            "--single scans one file at a time. To iterate on a single "
            "file with library-mode rules, use '--single PATH --as "
            "library_py' instead.\n"
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
    enrichers = []
    peek_enricher = build_peek_enricher(args)
    if peek_enricher is not None:
        enrichers.append(peek_enricher)
    engine = StaticEngine(
        analyzers=[
            EncodingAbuseAnalyzer(),
            DynamicExecutionAnalyzer(),
            StringOpsAnalyzer(),
            SuspiciousStdlibAnalyzer(),
            CodeDensityAnalyzer(),
        ],
        enrichers=enrichers,
        rules=all_rules,
        deep_mode=args.deep,
    )

    if args.single:
        result = _dispatch_single(engine, args.single, args.as_kind)
    else:
        # Build the progress bar callbacks. The factory returns
        # no-ops when --no-bar is set or stderr isn't a TTY, so
        # callers don't need to branch on those conditions.
        update_progress, finish_progress = make_progress_callback(
            no_bar=args.no_bar,
        )
        try:
            result = _dispatch_scan(
                engine, args.target,
                progress_callback=update_progress,
            )
        finally:
            # Always terminate the bar with a newline, even if the
            # scan raised. Otherwise an exception traceback would
            # render on the same line as the bar.
            finish_progress()
    exit_code = _render_and_exit_code(result, args)

    # Decoded-payload pass. Runs after the main scan when the user
    # opted in via --decode-payload-depth. The driver re-invokes the
    # engine on the decoded form of payload-bearing findings,
    # recursing up to the requested depth. Output goes to a file at
    # the user-specified --decode-location (or an auto-generated
    # path under <cwd>/decoded/).
    if decode_enabled(args):
        _run_decode_pass(result, engine, args)

    return exit_code


def _dispatch_scan(
    engine: StaticEngine,
    target: str,
    *,
    progress_callback=None,
) -> ScanResult:
    """Auto-detect target type and run the appropriate scan method.

    The progress_callback is threaded through to whichever engine
    method handles the target. None means no progress bar (engine
    treats it as a no-op).
    """
    path = Path(target)

    if path.suffix == ".whl" and path.is_file():
        return engine.scan_wheel(path, progress_callback=progress_callback)

    for suffix in _SDIST_SUFFIXES:
        if target.endswith(suffix):
            if path.is_file():
                return engine.scan_sdist(
                    path, progress_callback=progress_callback,
                )
            break

    # Fallback: treat as installed package name.
    return engine.scan_installed(
        target, progress_callback=progress_callback,
    )


def _dispatch_single(
    engine: StaticEngine,
    path_str: str,
    as_kind: str | None,
) -> ScanResult:
    """Scan a single loose file via the engine's bypass-triage entry point.

    Pre-checks for nonexistent paths and directories so we get clean
    diagnostic messages rather than raw OSError text. Once we know
    the file is real, hand off to engine.scan_loose_file_as which
    preserves the real path through to the report.
    """
    path = Path(path_str)
    if not path.exists():
        return _empty_result_with_diag(path, f"file not found: {path}")
    if not path.is_file():
        return _empty_result_with_diag(path, f"not a regular file: {path}")

    file_kind = _file_kind_for_single(path, as_kind)
    return engine.scan_loose_file_as(path, file_kind)


def _file_kind_for_single(path: Path, as_kind: str | None) -> FileKind:
    """Decide the FileKind for a --single-mode scan.

    The kind drives both the parser/analyzer routing AND which
    default rules apply (rules match on file_kind). For iteration
    testing, defaulting unknown content to SETUP_PY gives the most
    aggressive rule promotion, surfacing every signal at a
    realistic-attack severity.
    """
    if as_kind is not None:
        return _AS_KIND_TO_FILE_KIND[as_kind]

    if path.suffix == ".pth":
        return FileKind.PTH

    if path.name in _NATURAL_KIND_FILES:
        return _NATURAL_KIND_FILES[path.name]

    # Fallback: arbitrary content gets the setup.py treatment.
    return FileKind.SETUP_PY


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
    peek_chain = peek_chain_enabled(args)
    
    # Render in the requested format.
    if args.format == "json":
        render_json(filtered, sys.stdout)
    elif args.format == "sarif":
        render_sarif_stub(sys.stdout)
        return exit_codes.TOOL_ERROR
    else:
        render_human(filtered, sys.stdout, color=args.color, ci_mode=args.ci, peek_chain=peek_chain)

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

def _run_decode_pass(
    result: ScanResult,
    engine: StaticEngine,
    args: argparse.Namespace,
) -> None:
    """Run the decoded-payload driver and write its output to disk.

    Failures here are non-fatal: the main scan exit code already
    fired, and a problem in the decode pass should not silently
    suppress that. We log a stderr diagnostic and move on.
    """
    try:
        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=args.decode_payload_depth,
            peek_min_length=args.peek_min_length,
            peek_max_depth=args.peek_depth,
            peek_max_budget=args.peek_budget,
            extract_iocs=getattr(args, 'decode_iocs', False),
        )
    except Exception as exc:  # noqa: BLE001 — non-fatal post-scan step
        sys.stderr.write(
            f"warning: decoded-payload pass failed: "
            f"{type(exc).__name__}: {exc}\n"
        )
        return

    # Skip writing the file when there's nothing meaningful to
    # report. A file with "(no payload-bearing findings)" is more
    # confusing than no file at all when the user expected one.
    if not tree.nodes:
        sys.stderr.write(
            "note: no payload-bearing findings; "
            "no decoded-payload report written.\n"
        )
        return

    if args.decode_format == "json":
        rendered = render_json(tree)
        ext = ".json"
    else:
        include_iocs = getattr(args, 'decode_iocs', False)
        rendered = render_text(tree, include_iocs=include_iocs)
        ext = ".txt"

    output_path = _resolve_decode_location(args, ext)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(
            f"warning: could not write decoded-payload report to "
            f"{output_path}: {exc}\n"
        )
        return

    sys.stderr.write(
        f"note: decoded-payload report written to {output_path}\n"
    )


def _resolve_decode_location(
    args: argparse.Namespace,
    ext: str,
) -> Path:
    """Compute the output path for the decode-payload report.

    When --decode-location was set, use it verbatim (no extension
    munging; the user picked the path they want). Otherwise build
    <cwd>/decoded/decoded_payloads_<targetname><ext>, where
    <targetname> is derived from the scan target with directory
    components stripped and unsafe characters squashed.
    """
    explicit = getattr(args, "decode_location", None)
    if explicit:
        return Path(explicit)

    target = args.target or args.single or "scan"
    safe = _sanitize_target_for_filename(Path(target).name)
    return Path.cwd() / "decoded" / f"decoded_payloads_{safe}{ext}"


def _sanitize_target_for_filename(raw: str) -> str:
    """Make a target string safe for use in a filename."""
    out_chars: list[str] = []
    for ch in raw:
        if ch.isalnum() or ch in ("-", "_", "."):
            out_chars.append(ch)
        else:
            out_chars.append("_")
    sanitized = "".join(out_chars).strip("._-")
    return sanitized or "scan"