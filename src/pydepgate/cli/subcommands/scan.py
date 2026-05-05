"""pydepgate.cli.subcommands.scan

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
import os
import datetime
from pathlib import Path

from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.analyzers.dynamic_execution import DynamicExecutionAnalyzer
from pydepgate.analyzers.string_ops import StringOpsAnalyzer
from pydepgate.analyzers.suspicious_stdlib import SuspiciousStdlibAnalyzer
from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.cli import exit_codes
from pydepgate.cli.progress import make_progress_callback
from pydepgate.cli.reporter import render_sarif_stub
from pydepgate.reporters.scan_result import human as scan_human
from pydepgate.reporters.scan_result import json as scan_json
from pydepgate.engines.base import (
    ArtifactKind, ScanResult, ScanStatistics, Severity,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.traffic_control.triage import FileKind
from pydepgate.cli.peek_args import build_peek_enricher, peek_chain_enabled
from pydepgate.cli.decode_args import (
    DECODE_IOCS_FULL,
    DECODE_IOCS_HASHES,
    DECODE_IOCS_OFF,
    decode_archive_compression,
    decode_archive_password,
    decode_enabled,
    decode_extract_iocs,
    decode_iocs_mode,
)
from pydepgate.enrichers.decode_payloads import (
    decode_payloads,
    filter_tree_by_severity,
)
from pydepgate.reporters.decoded_tree import iocs as tree_iocs
from pydepgate.reporters.decoded_tree import json as tree_json
from pydepgate.reporters.decoded_tree import sources as tree_sources
from pydepgate.reporters.decoded_tree import text as tree_text
from pydepgate.cli._archive import write_encrypted_zip

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
        scan_json.render(filtered, sys.stdout)
    elif args.format == "sarif":
        render_sarif_stub(sys.stdout)
        return exit_codes.TOOL_ERROR
    else:
        scan_human.render(filtered, sys.stdout, color=args.color, ci_mode=args.ci, peek_chain=peek_chain)

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


def _sanitize_target_for_filename(raw: str) -> str:
    """Make a target string safe for use in a filename.

    Allowed character set: [A-Za-z0-9._-]. Anything else is replaced
    with a single underscore. Leading dots/underscores/hyphens are
    stripped (a leading dot would make the file hidden on Unix and
    rejected on Windows; the others are aesthetic). An empty result
    falls back to 'unknown_target' so we never produce a path with
    no visible filename component.
    """
    out_chars: list[str] = []
    for ch in raw:
        if ch.isalnum() or ch in ("-", "_", "."):
            out_chars.append(ch)
        else:
            out_chars.append("_")
    sanitized = "".join(out_chars).strip("._-")
    return sanitized or "unknown_target"


def _build_decode_filename(
    *,
    status: str,
    target: str,
    ext: str,
    timestamp: datetime.datetime | None = None,
) -> str:
    """Build the filename for a decoded-payload output file.

    Pattern: {STATUS}_{timestamp}_{target}{ext}, where:
      STATUS is 'FINDINGS' or 'NOFINDINGS'.
      timestamp is UTC, formatted '%Y-%m-%d_%H-%M-%S' (no Z suffix;
        the format is sortable lexicographically and unambiguous).
      target is a sanitized identifier from artifact_identity.
      ext is the file extension including the leading dot.

    The timestamp parameter is for tests; production callers pass
    None to use the current UTC time.
    """
    if timestamp is None:
        timestamp = datetime.datetime.now(datetime.timezone.utc)
    ts = timestamp.strftime("%Y-%m-%d_%H-%M-%S")
    return f"{status}_{ts}_{target}{ext}"


def _resolve_decode_location(
    args: argparse.Namespace,
    result: ScanResult,
    tree: DecodedTree,
    ext: str,
) -> Path:
    """Compute the output path for the decoded-payload report.

    --decode-location, when set, is treated as a DIRECTORY (not a
    file). The file inside follows the convention
        {STATUS}_{timestamp}_{target}{ext}
    See _build_decode_filename for the field meanings.

    When --decode-location is not set, the directory defaults to
    <cwd>/decoded/.

    The directory is not created here; the caller is responsible
    for mkdir on output_path.parent and for handling the case
    where the parent path exists as a non-directory.
    """
    explicit = getattr(args, "decode_location", None)
    if explicit:
        directory = Path(explicit)
    else:
        directory = Path.cwd() / "decoded"

    status = "FINDINGS" if tree.nodes else "NOFINDINGS"
    target_basename = os.path.basename(result.artifact_identity)
    target = _sanitize_target_for_filename(target_basename)

    filename = _build_decode_filename(
        status=status,
        target=target,
        ext=ext,
    )
    return directory / filename


def _run_decode_pass(
    result: ScanResult,
    engine: StaticEngine,
    args: argparse.Namespace,
) -> None:
    """Run the decoded-payload driver and write its output to disk.

    Branching on --decode-iocs mode:
      off    : single plaintext report file. Skip on empty tree.
      hashes : plaintext report + plaintext .iocs.txt sidecar.
               Skip on empty tree.
      full   : encrypted ZIP containing report.txt, sources.txt,
               and iocs.txt, plus a plaintext .iocs.txt sidecar
               next to the archive. ALWAYS produces output, even
               when the tree is empty (NOFINDINGS stub archive),
               so downstream tooling can rely on archive presence.

    The --min-severity flag is applied as a presentation filter
    AFTER decoding completes. Decoding itself runs over every
    payload-bearing finding regardless of severity, because a
    low-severity outer finding can decode to a critical inner one.

    Failures are non-fatal: the main scan exit code already fired,
    so a problem here just gets a stderr diagnostic.
    """
    extract_iocs = decode_extract_iocs(args)

    try:
        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=args.decode_payload_depth,
            peek_min_length=args.peek_min_length,
            peek_max_depth=args.peek_depth,
            peek_max_budget=args.peek_budget,
            extract_iocs=extract_iocs,
        )
    except Exception as exc:  # noqa: BLE001 - non-fatal post-scan step
        sys.stderr.write(
            f"warning: decoded-payload pass failed: "
            f"{type(exc).__name__}: {exc}\n"
        )
        return

    # Apply --min-severity as a post-decode presentation filter.
    # Decoding was NOT gated by this; the engine ran over every
    # payload-bearing finding so a low-severity outer that decodes
    # to a critical inner is still captured. The filter here just
    # cleans the tree up before rendering.
    min_sev = getattr(args, "min_severity", None)
    if min_sev:
        tree = filter_tree_by_severity(tree, min_sev)

    mode = decode_iocs_mode(args)

    # JSON format short-circuits the mode logic. The JSON output
    # carries ioc_data inline when extract_iocs is True, so a
    # single .json file is sufficient regardless of mode.
    if args.decode_format == "json":
        if not tree.nodes and mode != DECODE_IOCS_FULL:
            sys.stderr.write(_no_findings_msg(min_sev))
            return
        rendered = tree_json.render(tree, include_source=(decode_iocs_mode(args) == DECODE_IOCS_FULL))
        output_path = _resolve_decode_location(args, result, tree, ".json")
        if not _write_decode_text_file(output_path, rendered):
            return
        sys.stderr.write(
            f"note: decoded-payload report written to {output_path}\n"
        )
        return

    # Text format. Branch on mode.
    if mode == DECODE_IOCS_OFF:
        if not tree.nodes:
            sys.stderr.write(_no_findings_msg(min_sev))
            return
        rendered = tree_text.render(tree, include_iocs=False)
        output_path = _resolve_decode_location(args, result, tree, ".txt")
        if not _write_decode_text_file(output_path, rendered):
            return
        sys.stderr.write(
            f"note: decoded-payload report written to {output_path}\n"
        )
        return

    if mode == DECODE_IOCS_HASHES:
        if not tree.nodes:
            sys.stderr.write(_no_findings_msg(min_sev))
            return
        report_text = tree_text.render(tree, include_iocs=False)
        iocs_text = tree_iocs.render(tree)
        main_path = _resolve_decode_location(args, result, tree, ".txt")
        sidecar_path = _sidecar_iocs_path(main_path)
        if not _write_decode_text_file(main_path, report_text):
            return
        if not _write_decode_text_file(sidecar_path, iocs_text):
            return
        sys.stderr.write(
            f"note: decoded-payload report written to {main_path}\n"
            f"note: IOC hash sidecar written to {sidecar_path}\n"
        )
        return

    # mode == DECODE_IOCS_FULL: always write, even on empty.
    report_text = tree_text.render(tree, include_iocs=False)
    sources_text = tree_sources.render(tree)
    iocs_text = tree_iocs.render(tree)

    archive_path = _resolve_decode_location(args, result, tree, ".zip")
    sidecar_path = _sidecar_iocs_path(archive_path)

    # Inner subdirectory inside the archive; keeps unzip from
    # dropping loose files into the user's cwd.
    target_safe = _sanitize_target_for_filename(
        os.path.basename(result.artifact_identity)
    )
    inner_dir = target_safe or "decoded"
    inner_dir = inner_dir.replace(".", "_")  # avoid confusion with file extensions
    inner_dir = inner_dir[:50]  # keep the path short to avoid zipfile limits
    entries = [
        (f"{inner_dir}/report.txt", report_text.encode("utf-8")),
        (f"{inner_dir}/sources.txt", sources_text.encode("utf-8")),
        (f"{inner_dir}/iocs.txt", iocs_text.encode("utf-8")),
    ]

    password = decode_archive_password(args)
    compression = decode_archive_compression(args)

    parent = archive_path.parent
    if parent.exists() and not parent.is_dir():
        sys.stderr.write(
            f"error: --decode-location target {parent} exists but "
            f"is not a directory. Pass a directory path, or remove "
            f"the existing file.\n"
        )
        return

    try:
        parent.mkdir(parents=True, exist_ok=True)
        # Atomic archive write: temp file + replace, so a partial
        # write never leaves a corrupt archive at the final path.
        tmp_archive = archive_path.with_name(archive_path.name + ".tmp")
        write_encrypted_zip(
            tmp_archive,
            entries,
            password=password,
            compression=compression,
        )
        tmp_archive.replace(archive_path)
        # Sidecar: direct write, since a partial sidecar is
        # recoverable from the archive's inner iocs.txt anyway.
        sidecar_path.write_text(iocs_text, encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(
            f"warning: could not write decoded-payload archive to "
            f"{archive_path}: {exc}\n"
        )
        return

    if tree.nodes:
        sys.stderr.write(
            f"note: decoded-payload archive written to {archive_path}\n"
            f"note: IOC hash sidecar written to {sidecar_path}\n"
        )
    else:
        sys.stderr.write(
            f"note: no payload-bearing findings"
            f"{f' at or above --min-severity={min_sev}' if min_sev else ''}"
            f"; NOFINDINGS stub archive written to {archive_path}\n"
        )


def _no_findings_msg(min_sev) -> str:
    """Standard 'nothing decoded' note for the off/hashes skip path."""
    if min_sev:
        return (
            f"note: no payload-bearing findings at or above "
            f"--min-severity={min_sev}; no decoded-payload "
            f"report written.\n"
        )
    return (
        "note: no payload-bearing findings; no decoded-payload "
        "report written.\n"
    )


def _write_decode_text_file(output_path: Path, rendered: str) -> bool:
    """Write a single text file, with the same parent pre-check as the archive path.

    Returns True on success, False on failure (with a stderr
    diagnostic already emitted).
    """
    parent = output_path.parent
    if parent.exists() and not parent.is_dir():
        sys.stderr.write(
            f"error: --decode-location target {parent} exists but "
            f"is not a directory. Pass a directory path, or remove "
            f"the existing file.\n"
        )
        return False
    try:
        parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(
            f"warning: could not write decoded-payload output to "
            f"{output_path}: {exc}\n"
        )
        return False
    return True


def _sidecar_iocs_path(main_path: Path) -> Path:
    """Compute the IOC sidecar path next to the main output.

    Replaces the file's last suffix with '.iocs.txt'. So
    'FINDINGS_<ts>_litellm.whl.zip' becomes
    'FINDINGS_<ts>_litellm.whl.iocs.txt' in the same directory.
    """
    return main_path.with_name(main_path.stem + ".iocs.txt")