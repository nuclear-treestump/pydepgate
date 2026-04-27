"""
Output rendering for pydepgate scan results.

Two formats fully implemented in v0.1: human-readable terminal output
and machine-readable JSON. SARIF output is stubbed with an
under-development message.

Renderers receive a ScanResult plus rendering options and produce
text written to a stream. They never decide on exit codes; that is
the CLI's job in main.py.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from typing import TextIO

from pydepgate.engines.base import (
    Finding,
    ScanResult,
    Severity,
)

from pydepgate.visualizers.density_map import render_density_map


# ANSI color codes. Using direct codes to avoid a dependency on a
# color library. NO_COLOR support per https://no-color.org standard.
class _Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def _color_enabled(no_color_flag: bool) -> bool:
    """Decide whether ANSI color codes should be emitted.

    Disabled if:
      - The user passed --no-color (no_color_flag is True)
      - The NO_COLOR environment variable is set (any value)
      - The PYDEPGATE_NO_COLOR environment variable is set
      - stdout is not a terminal (output is being piped or redirected)
    """
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("PYDEPGATE_NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


def _severity_color(severity: Severity, color: bool) -> tuple[str, str]:
    """Return (prefix, suffix) ANSI codes for a severity. ('', '') if no color."""
    if not color:
        return ("", "")
    palette = {
        Severity.CRITICAL: _Color.RED + _Color.BOLD,
        Severity.HIGH: _Color.RED,
        Severity.MEDIUM: _Color.YELLOW,
        Severity.LOW: _Color.BLUE,
        Severity.INFO: _Color.DIM,
    }
    prefix = palette.get(severity, "")
    return (prefix, _Color.RESET if prefix else "")


def _group_findings_by_path(
    findings: list[Finding],
) -> dict[str, list[Finding]]:
    """Group findings by their internal file path, preserving order."""
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        path = getattr(finding, "internal_path", None) or "unknown"
        groups.setdefault(path, []).append(finding)
    return groups


def render_human(
    result: ScanResult,
    stream: TextIO,
    no_color: bool = False,
    ci_mode: bool = False,
) -> None:
    """Render a ScanResult as colored, human-readable terminal output."""
    color = _color_enabled(no_color)
    findings = result.findings
    suppressed = result.suppressed_findings

    if not findings and not suppressed:
        if ci_mode:
            stream.write(f"pydepgate: clean ({result.artifact_identity})\n")
        else:
            green_pre, green_post = (
                (_Color.GREEN, _Color.RESET) if color else ("", "")
            )
            stream.write(
                f"{green_pre}No findings{green_post} in "
                f"{result.artifact_identity}\n"
            )
            _render_statistics(result, stream, color)
        return

    if findings:
        groups = _group_findings_by_path(findings)
        for path, file_findings in groups.items():
            # Render all findings for this file.
            for finding in file_findings:
                _render_finding(finding, stream, color, ci_mode)

            # Render the density map for this file (no-op if color off or CI).
            if not ci_mode:
                map_str = render_density_map(
                    filename=path,
                    findings=file_findings,
                    total_lines=None,   # approximate from max finding line
                    color=color,
                )
                if map_str:
                    stream.write("\n" + map_str + "\n")

    # Suppressed findings section.
    if suppressed:
        if not ci_mode:
            dim_pre, dim_post = (_Color.DIM, _Color.RESET) if color else ("", "")
            yellow_pre, yellow_post = (
                (_Color.YELLOW, _Color.RESET) if color else ("", "")
            )
            stream.write(
                f"\n{yellow_pre}{len(suppressed)} suppressed finding"
                f"{'s' if len(suppressed) != 1 else ''}{yellow_post}\n"
            )
            stream.write("-" * 60 + "\n")
            stream.write(
                f"{dim_pre}The following findings were silenced by rules. "
                f"Review to confirm suppressions are intentional.{dim_post}\n\n"
            )

        for sup in suppressed:
            _render_suppressed_finding(sup, stream, color, ci_mode)

    if not ci_mode:
        _render_statistics(result, stream, color)


def _render_suppressed_finding(
    sup, stream: TextIO, color: bool, ci_mode: bool
) -> None:
    """Render a single suppressed finding."""
    dim_pre, dim_post = (_Color.DIM, _Color.RESET) if color else ("", "")
    sig = sup.original_finding.signal
    would_have = sup.would_have_been

    if ci_mode:
        # Compact format for CI.
        stream.write(
            f"SUPPRESSED {sig.signal_id} "
            f"{sup.original_finding.context.internal_path}: "
            f"by {sup.suppressing_rule_id} "
            f"(would have been {would_have.severity.value.upper()})\n"
        )
        return

    # Full format.
    stream.write(
        f"  {dim_pre}[SUPPRESSED]{dim_post} {sig.signal_id} "
        f"in {sup.original_finding.context.internal_path}"
    )
    if sig.location.line:
        stream.write(f":{sig.location.line}")
    stream.write("\n")
    stream.write(f"    {dim_pre}{sig.description}{dim_post}\n")
    stream.write(
        f"    {dim_pre}suppressed by: {sup.suppressing_rule_id} "
        f"(source: {sup.suppressing_rule_source}){dim_post}\n"
    )
    stream.write(
        f"    {dim_pre}would have been: "
        f"{would_have.severity.value.upper()}{dim_post}\n\n"
    )


def _render_finding(
    finding: Finding, stream: TextIO, color: bool, ci_mode: bool
) -> None:
    """Render a single finding."""
    sev_pre, sev_post = _severity_color(finding.severity, color)
    cyan_pre, cyan_post = (_Color.CYAN, _Color.RESET) if color else ("", "")
    dim_pre, dim_post = (_Color.DIM, _Color.RESET) if color else ("", "")

    sev_text = finding.severity.value.upper()
    sig = finding.signal

    if ci_mode:
        # Compact one-or-two-line format for CI logs.
        location = (
            f"{finding.context.internal_path}:{sig.location.line}"
            if sig.location.line
            else finding.context.internal_path
        )
        stream.write(
            f"{sev_text} {sig.signal_id} {location}: {sig.description}\n"
        )
        return

    # Full multi-line format for interactive use.
    stream.write(
        f"{sev_pre}[{sev_text}]{sev_post} "
        f"{cyan_pre}{sig.signal_id}{cyan_post} "
        f"({sig.analyzer})\n"
    )
    stream.write(f"  in {finding.context.internal_path}")
    if sig.location.line:
        stream.write(f":{sig.location.line}")
        if sig.location.column:
            stream.write(f":{sig.location.column}")
    stream.write("\n")
    stream.write(f"  {sig.description}\n")
    if sig.context:
        # Show a few key context fields if present, useful for diagnostics.
        interesting_keys = [
            "resolved_value", "matched_sensitive", "primitive",
            "decode_function", "namespace",
        ]
        for key in interesting_keys:
            if key in sig.context:
                stream.write(
                    f"  {dim_pre}{key}: {sig.context[key]!r}{dim_post}\n"
                )
    stream.write("\n")


def _render_statistics(result: ScanResult, stream: TextIO, color: bool) -> None:
    """Render the trailing summary of scan statistics."""
    dim_pre, dim_post = (_Color.DIM, _Color.RESET) if color else ("", "")
    stats = result.statistics
    parts = []
    if stats.files_total:
        parts.append(f"{stats.files_total} files total")
    if stats.files_scanned:
        parts.append(f"{stats.files_scanned} scanned")
    if stats.files_skipped:
        parts.append(f"{stats.files_skipped} skipped")
    parts.append(f"{stats.duration_seconds * 1000:.0f}ms")
    stream.write(f"{dim_pre}{' | '.join(parts)}{dim_post}\n")

    if result.diagnostics:
        stream.write("\n")
        for diag in result.diagnostics:
            stream.write(f"{dim_pre}note: {diag}{dim_post}\n")


def render_json(result: ScanResult, stream: TextIO) -> None:
    """Render a ScanResult as a single JSON object on stdout."""
    payload = {
        "schema_version": 1,
        "artifact": {
            "identity": result.artifact_identity,
            "kind": result.artifact_kind.value,
        },
        "findings": [_finding_to_dict(f) for f in result.findings],
        "suppressed_findings": [
            _suppressed_to_dict(s) for s in result.suppressed_findings
        ],
        "skipped": [
            {"path": s.internal_path, "reason": s.reason}
            for s in result.skipped
        ],
        "statistics": {
            "files_total": result.statistics.files_total,
            "files_scanned": result.statistics.files_scanned,
            "files_skipped": result.statistics.files_skipped,
            "files_failed_to_parse": result.statistics.files_failed_to_parse,
            "signals_emitted": result.statistics.signals_emitted,
            "analyzers_run": result.statistics.analyzers_run,
            "duration_seconds": result.statistics.duration_seconds,
        },
        "diagnostics": list(result.diagnostics),
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")


def _suppressed_to_dict(sup) -> dict:
    """Convert a SuppressedFinding to a JSON-serializable dict."""
    return {
        "signal_id": sup.original_finding.signal.signal_id,
        "internal_path": sup.original_finding.context.internal_path,
        "description": sup.original_finding.signal.description,
        "suppressing_rule_id": sup.suppressing_rule_id,
        "suppressing_rule_source": sup.suppressing_rule_source,
        "would_have_been_severity": sup.would_have_been.severity.value,
    }


def _finding_to_dict(finding: Finding) -> dict:
    """Convert a Finding to a JSON-serializable dict."""
    sig = finding.signal
    return {
        "severity": finding.severity.value,
        "signal_id": sig.signal_id,
        "analyzer": sig.analyzer,
        "confidence": int(sig.confidence),
        "scope": sig.scope.name.lower() if hasattr(sig.scope, "name") else str(sig.scope),
        "description": sig.description,
        "location": {
            "internal_path": finding.context.internal_path,
            "line": sig.location.line,
            "column": sig.location.column,
        },
        "context": _serialize_context(sig.context),
    }


def _serialize_context(context: dict) -> dict:
    """Make a context dict JSON-safe by coercing tuples to lists."""
    out = {}
    for key, value in context.items():
        if isinstance(value, tuple):
            out[key] = list(value)
        elif isinstance(value, (str, int, float, bool, type(None), list, dict)):
            out[key] = value
        else:
            # Fallback: stringify anything else.
            out[key] = str(value)
    return out


def render_sarif_stub(stream: TextIO) -> None:
    """SARIF output is under development. Emit a clear message."""
    stream.write(
        "SARIF output format is part of pydepgate's GitHub Advanced "
        "Security integration and is currently under development. It "
        "will produce SARIF 2.1.0 output suitable for GitHub code "
        "scanning, GitLab vulnerability reports, and other SARIF "
        "consumers.\n"
        "\n"
        "Planned for v0.4. Track progress in ROADMAP.md.\n"
        "\n"
        "For now, use --format json for machine-readable output.\n"
    )