"""pydepgate.cli.subcommands.cvescan

CLI subcommand: cvescan.

Runs the package-level CVE scanner against a supported Python package
artifact. This command is intentionally separate from the normal static
`scan` subcommand. Static scan inspects files inside an artifact;
cvescan reads package identity metadata, queries the local cvedb, and
reports known vulnerability matches for that package name and version.

The command owns rendering and exit-code policy for CVE results. The
storage query logic stays in package_tools.cvedb.lookup, and the
artifact-level scanner shape stays in package_tools.cvescanner.scanner.

Database behavior:

    By default, cvescan requires a readable, schema-compatible cvedb.
    That is stricter than the scanner library default because this
    command exists specifically to perform CVE lookup. Use
    --ignore-missing-db to downgrade missing or broken DB state into a
    warning and a clean no-findings result.

Formats:

    human   Compact terminal report.
    json    Machine-readable report.

SARIF is deliberately not emitted here yet. CVE findings are
package-level findings, not file findings, and need a later SARIF
mapping that does not pretend the vulnerability lives on a source line.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from pydepgate.cli import exit_codes
from pydepgate.dbs.cvedb import lookup
from pydepgate.dbs.cvedb import schema
from pydepgate.package_tools.cvescanner import scanner
from pydepgate.events import (
    EventEmitter,
    EventSinkError,
    JsonlEventSink,
    mintsgt,
)
from pydepgate.scanning import CveScanRequest, ScanTargetRef, execute_cve_scan

_SEVERITY_ORDER = {
    "UNKNOWN": 0,
    "INFO": 0,
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "MODERATE": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

_MIN_SEVERITY_ORDER = {
    None: 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}


def register(subparsers) -> None:
    """Register the cvescan subcommand."""
    parser = subparsers.add_parser(
        "cvescan",
        help="Scan a package artifact for known CVEs",
        description=(
            "Scan a supported Python package artifact for known CVEs "
            "using pydepgate's local cvedb. This is a package-level "
            "scan: it reads artifact metadata for name/version, then "
            "queries the local OSV-derived database. Run "
            "'pydepgate cvedb update' first to build the database."
        ),
    )
    parser.add_argument(
        "target",
        help="Package artifact to scan. Wheels are currently supported.",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help=(
            "Path to a pydepgate cvedb SQLite database. Defaults to "
            "pydepgate's platform cache location."
        ),
    )
    parser.add_argument(
        "--ignore-missing-db",
        action="store_true",
        default=False,
        help=(
            "Do not fail when the CVE database is missing, unreadable, "
            "or schema-incompatible. The result will contain warnings "
            "and no CVE findings."
        ),
    )
    parser.add_argument(
        "--save-to-db",
        action="store_true",
        default=False,
        help=(
            "Persist CVE scan results to the pydepgate evidence database. "
            "The database is created if it does not exist. "
            "DB write failures emit a warning but do not affect the "
            "scan exit code."
        ),
    )
    parser.add_argument(
        "--event-log",
        metavar="PATH",
        default=os.environ.get("PYDEPGATE_EVENT_LOG"),
        help=(
            "Write CVE scan lifecycle events to a JSONL file. "
            "Env: PYDEPGATE_EVENT_LOG"
        ),
    )
    parser.set_defaults(func=run)


def _build_cve_event_emitter(
    args: argparse.Namespace,
    *,
    run_id: str,
    correlation_id: str,
) -> EventEmitter:
    """Build the event emitter used by cvescan.run."""
    injected = getattr(args, "_event_emitter", None)
    if injected is not None:
        return injected

    sinks = list(getattr(args, "_event_sinks", ()) or ())
    event_log = getattr(args, "event_log", None)
    if event_log:
        sinks.append(JsonlEventSink(event_log))

    return EventEmitter(
        producer="pydepgate.cli.cvescan",
        sinks=tuple(sinks),
        run_id=run_id,
        correlation_id=correlation_id,
    )


def _emit_cve_event(
    emitter: EventEmitter,
    event_type: str,
    payload: dict | None = None,
    *,
    ticket_id: str | None = None,
    parent_event_id: str | None = None,
    severity: str = "info",
):
    """Emit a CVE scan event without letting sink failures hide results."""
    try:
        return emitter.emit(
            event_type,
            payload or {},
            ticket_id=ticket_id,
            parent_event_id=parent_event_id,
            severity=severity,
        )
    except EventSinkError as exc:
        sys.stderr.write(
            f"warning: could not emit {event_type}: " f"{type(exc).__name__}: {exc}\n"
        )
        return None


def _ticket_event_payload(ticket) -> dict:
    """Return ticket fields safe for event logs."""
    payload = ticket.to_dict()
    payload.pop("ticket_nonce", None)
    return payload


def _requested_target_identity(args: argparse.Namespace) -> str:
    """Return the target value requested by the user."""
    return str(args.target)


def _requested_target_kind(args: argparse.Namespace) -> str:
    """Return the requested CVE scan target kind."""
    target = str(getattr(args, "target", "") or "")
    if target.lower().endswith(".whl"):
        return "wheel"
    return "package_artifact"


def _target_ref_for_args(args: argparse.Namespace) -> ScanTargetRef:
    """Return an internal target reference for a CLI CVE scan request."""
    target = str(args.target)
    return ScanTargetRef(
        kind=_requested_target_kind(args),
        identity=target,
        location=target,
        metadata={"source": "cli", "command": "cvescan"},
    )


def _allowed_actions_for_args(args: argparse.Namespace) -> tuple[str, ...]:
    """Return actions needed to satisfy the requested CVE scan."""
    actions = ["cve.scan"]
    if getattr(args, "save_to_db", False):
        actions.append("evidence.write")
    return tuple(actions)


def _cve_scan_budget_for_args(args: argparse.Namespace) -> dict:
    """Return local resource expectations for the CVE scan grant."""
    return {
        "db_path": (
            str(getattr(args, "db_path", None))
            if getattr(args, "db_path", None) is not None
            else None
        ),
        "require_database": not bool(getattr(args, "ignore_missing_db", False)),
        "ignore_missing_db": bool(getattr(args, "ignore_missing_db", False)),
    }


def _cve_scan_context_event_payload(args: argparse.Namespace) -> dict[str, Any]:
    """Return target context fields shared by CVE scan lifecycle events."""
    target_ref = _target_ref_for_args(args)
    return {
        "scan_mode": "cve.artifact",
        "target_kind": _requested_target_kind(args),
        "target_identity": _requested_target_identity(args),
        "target_ref": target_ref.to_dict(),
    }


def _cve_result_event_payload(
    result: scanner.CveScanResult,
    *,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Return a JSON-safe summary of a CVE scan result."""
    return {
        **_cve_scan_context_event_payload(args),
        "result_kind": "cve",
        "package_name": result.package_name,
        "normalized_package_name": result.normalized_package_name,
        "package_version": result.package_version,
        "finding_count": len(result.findings),
        "warning_count": len(result.warnings),
        "unevaluated_range_count": len(result.unevaluated_ranges),
        "database_path": (
            str(result.database_path) if result.database_path is not None else None
        ),
    }


def run(args: argparse.Namespace) -> int:
    """Execute the cvescan subcommand and return a CLI exit code."""
    if args.format == "sarif":
        sys.stderr.write(
            "error: cvescan does not support SARIF output yet. "
            "Use --format human or --format json.\n"
        )
        return exit_codes.TOOL_ERROR

    ticket = mintsgt(
        target_kind=_requested_target_kind(args),
        target_identity=_requested_target_identity(args),
        scan_mode="cve.artifact",
        allowed_actions=_allowed_actions_for_args(args),
        budget=_cve_scan_budget_for_args(args),
        metadata={
            "command": "cvescan",
            "format": getattr(args, "format", None),
        },
        require_cli_stack=True,
    )
    if not ticket.allows_action("cve.scan") or ticket.is_expired():
        sys.stderr.write("error: scanner could not obtain a valid CVE scan grant.\n")
        return exit_codes.TOOL_ERROR

    emitter = _build_cve_event_emitter(
        args,
        run_id=ticket.run_id,
        correlation_id=ticket.correlation_id,
    )
    grant_event = _emit_cve_event(
        emitter,
        "internal.scanner.scan_grant_issued",
        _ticket_event_payload(ticket),
        ticket_id=ticket.ticket_id,
    )

    if getattr(args, "save_to_db", False) and not ticket.allows_action(
        "evidence.write"
    ):
        sys.stderr.write("error: CVE scan grant does not authorize evidence write.\n")
        return exit_codes.TOOL_ERROR

    try:
        request = CveScanRequest(
            ticket=ticket,
            target_ref=_target_ref_for_args(args),
            emitter=emitter,
            db_path=getattr(args, "db_path", None),
            applied_policy_result=None,
            require_database=not getattr(args, "ignore_missing_db", False),
            grant_event_id=(grant_event.event_id if grant_event else None),
            strict_event_sinks=False,
            event_warning=sys.stderr.write,
        )
        outcome = execute_cve_scan(request)
    except lookup.CveDatabaseNotFound as exc:
        sys.stderr.write(
            f"CVE database not found at {exc.path}\n"
            "Run 'pydepgate cvedb update' to download and import.\n"
        )
        return exit_codes.TOOL_ERROR
    except schema.SchemaVersionMismatch as exc:
        sys.stderr.write(
            f"CVE database has incompatible schema: {exc}\n"
            "Run 'pydepgate cvedb update' to rebuild.\n"
        )
        return exit_codes.TOOL_ERROR
    except lookup.CveLookupError as exc:
        sys.stderr.write(f"error: CVE lookup failed: {exc}\n")
        return exit_codes.TOOL_ERROR
    except Exception as exc:  # noqa: BLE001 - CLI boundary converts to tool error
        sys.stderr.write(f"error: cvescan failed: {type(exc).__name__}: {exc}\n")
        return exit_codes.TOOL_ERROR

    result = outcome.result
    display_findings = _filter_findings(result.findings, args.min_severity)
    display_result = _filtered_result(result, display_findings)

    if args.format == "json":
        _render_json(display_result, result, sys.stdout)
    else:
        _render_human(display_result, result, sys.stdout)

    findings_for_exit = result.findings if args.strict_exit else display_findings
    exit_code = _compute_exit_code(findings_for_exit)

    evidence_completed_event = None
    if getattr(args, "save_to_db", False):
        evidence_event = _emit_cve_event(
            emitter,
            "internal.evidence.write_requested",
            _cve_result_event_payload(result, args=args),
            ticket_id=ticket.ticket_id,
            parent_event_id=outcome.scan_completed_event_id,
        )
        _save_to_db(result)
        evidence_completed_event = _emit_cve_event(
            emitter,
            "internal.evidence.write_completed",
            _cve_result_event_payload(result, args=args),
            ticket_id=ticket.ticket_id,
            parent_event_id=(evidence_event.event_id if evidence_event else None),
        )

    _emit_cve_event(
        emitter,
        "internal.scanner.run_completed",
        {
            **_cve_scan_context_event_payload(args),
            "result_kind": "cve",
            "command": "cvescan",
            "exit_code": exit_code,
            "package_name": result.package_name,
            "normalized_package_name": result.normalized_package_name,
            "package_version": result.package_version,
            "finding_count": len(result.findings),
            "displayed_finding_count": len(display_findings),
            "warning_count": len(result.warnings),
            "unevaluated_range_count": len(result.unevaluated_ranges),
        },
        ticket_id=ticket.ticket_id,
        parent_event_id=(
            evidence_completed_event.event_id
            if evidence_completed_event
            else outcome.scan_completed_event_id
        ),
    )
    return exit_code


def _save_to_db(result) -> None:
    """Persist CVE scan result to the evidence DB.

    Non-fatal: any failure emits a warning to stderr and returns.
    The scan exit code is never affected by DB write failures.
    """
    from pydepgate.dbs.pdgdb import schema
    from pydepgate.dbs.pdgdb.writer import write_cve_scan_result
    from pydepgate.pdgplatform.paths import ensure_directory, pydepgate_data_dir

    db_path = pydepgate_data_dir() / "pdgdb" / "evidence.db"
    try:
        ensure_directory(db_path.parent)
        conn = schema.connect(db_path)
        try:
            schema.initialize_schema(conn)
            write_cve_scan_result(
                conn,
                result,
                producer_id="cli0",
            )
        finally:
            conn.close()
    except Exception as exc:
        sys.stderr.write(
            f"warning: could not save CVE scan result to DB: "
            f"{type(exc).__name__}: {exc}\n"
        )


def _filter_findings(
    findings: tuple[scanner.CveFinding, ...],
    min_severity: str | None,
) -> tuple[scanner.CveFinding, ...]:
    """Apply --min-severity style filtering to CVE findings."""
    threshold = _MIN_SEVERITY_ORDER.get(min_severity, 0)
    return tuple(
        finding for finding in findings if _severity_rank(finding.severity) >= threshold
    )


def _filtered_result(
    result: scanner.CveScanResult,
    findings: tuple[scanner.CveFinding, ...],
) -> scanner.CveScanResult:
    """Return a result with findings replaced for display."""
    return scanner.CveScanResult(
        package_name=result.package_name,
        normalized_package_name=result.normalized_package_name,
        package_version=result.package_version,
        package_metadata=result.package_metadata,
        findings=findings,
        unevaluated_ranges=result.unevaluated_ranges,
        warnings=result.warnings,
        attribution=result.attribution,
        database_path=result.database_path,
        applied_policy_result=result.applied_policy_result,
    )


def _render_human(
    display_result: scanner.CveScanResult,
    full_result: scanner.CveScanResult,
    out,
) -> None:
    """Render a compact human-readable CVE scan report."""
    identity = _identity_line(full_result)
    out.write(f"CVE scan: {identity}\n")
    if full_result.database_path is not None:
        out.write(f"Database: {full_result.database_path}\n")

    if full_result.warnings:
        out.write("\nWarnings:\n")
        for warning in full_result.warnings:
            out.write(f"  - {warning}\n")

    if display_result.findings:
        hidden = len(full_result.findings) - len(display_result.findings)
        out.write(f"\nFindings: {len(display_result.findings)}")
        if hidden > 0:
            out.write(f" ({hidden} hidden by --min-severity)")
        out.write("\n")
        for finding in display_result.findings:
            _render_human_finding(finding, out)
    else:
        if full_result.findings:
            out.write("\nNo CVE findings matched the current severity filter.\n")
        else:
            out.write("\nNo known CVE findings for this package identity.\n")

    if full_result.unevaluated_ranges:
        out.write(
            f"\nUnevaluated advisory ranges: {len(full_result.unevaluated_ranges)}\n"
        )
        for row in full_result.unevaluated_ranges:
            out.write(
                f"  - {row.canonical_id} [{row.range_type}] "
                f"introduced={row.introduced or '<empty>'} "
                f"fixed={row.fixed or '<empty>'} "
                f"last_affected={row.last_affected or '<empty>'} "
                f"reason={row.reason or '<unspecified>'}\n"
            )

    if full_result.attribution:
        out.write(f"\n{full_result.attribution}\n")


def _render_human_finding(finding: scanner.CveFinding, out) -> None:
    """Render one human-readable CVE finding."""
    out.write(f"\n  {finding.canonical_id} [{finding.severity}]\n")
    if finding.aliases:
        out.write(f"    Aliases: {', '.join(finding.aliases)}\n")
    out.write(f"    Match: {finding.match_type}\n")
    if finding.summary:
        out.write(f"    Summary: {finding.summary}\n")
    if finding.cvss_v3:
        out.write(f"    CVSS v3: {finding.cvss_v3}\n")
    if finding.cvss_v4:
        out.write(f"    CVSS v4: {finding.cvss_v4}\n")
    if finding.range_type:
        out.write(
            "    Range: "
            f"{finding.range_type} introduced={finding.introduced or '<empty>'} "
            f"fixed={finding.fixed or '<empty>'} "
            f"last_affected={finding.last_affected or '<empty>'}\n"
        )


def _render_json(
    display_result: scanner.CveScanResult,
    full_result: scanner.CveScanResult,
    out,
) -> None:
    """Render a JSON CVE scan report."""
    payload = {
        "schema": "pydepgate.cvescan.v1",
        "package_name": full_result.package_name,
        "normalized_package_name": full_result.normalized_package_name,
        "package_version": full_result.package_version,
        "database_path": (
            str(full_result.database_path) if full_result.database_path else None
        ),
        "findings": [_finding_to_json(finding) for finding in display_result.findings],
        "total_findings": len(full_result.findings),
        "displayed_findings": len(display_result.findings),
        "unevaluated_ranges": [
            _unevaluated_range_to_json(row) for row in full_result.unevaluated_ranges
        ],
        "warnings": list(full_result.warnings),
        "attribution": full_result.attribution,
        "artifact_metadata": _metadata_to_json(full_result.package_metadata),
    }
    json.dump(payload, out, indent=2, sort_keys=True)
    out.write("\n")


def _finding_to_json(finding: scanner.CveFinding) -> dict[str, Any]:
    """Convert a CveFinding into JSON-safe primitives."""
    return {
        "canonical_id": finding.canonical_id,
        "aliases": list(finding.aliases),
        "package_name": finding.package_name,
        "normalized_package_name": finding.normalized_package_name,
        "package_version": finding.package_version,
        "database_package_name": finding.database_package_name,
        "database_version": finding.database_version,
        "match_type": finding.match_type,
        "summary": finding.summary,
        "details": finding.details,
        "published": finding.published,
        "modified": finding.modified,
        "cvss_v3": finding.cvss_v3,
        "cvss_v4": finding.cvss_v4,
        "severity": finding.severity,
        "raw_severity": finding.raw_severity,
        "versions_complete": finding.versions_complete,
        "range_type": finding.range_type,
        "introduced": finding.introduced,
        "fixed": finding.fixed,
        "last_affected": finding.last_affected,
    }


def _unevaluated_range_to_json(
    row: scanner.CveUnevaluatedRange,
) -> dict[str, str]:
    """Convert a CveUnevaluatedRange into JSON-safe primitives."""
    return {
        "canonical_id": row.canonical_id,
        "package_name": row.package_name,
        "range_type": row.range_type,
        "introduced": row.introduced,
        "fixed": row.fixed,
        "last_affected": row.last_affected,
        "reason": row.reason,
    }


def _metadata_to_json(metadata) -> dict[str, Any] | None:
    """Convert PackageMetadata into a small JSON-safe block."""
    if metadata is None:
        return None
    return {
        "artifact_type": metadata.artifact_type,
        "artifact_path": str(metadata.artifact_path),
        "identity_source": metadata.identity_source,
        "metadata_name": metadata.metadata_name,
        "metadata_version": metadata.metadata_version,
        "filename_name": metadata.filename_name,
        "filename_version": metadata.filename_version,
        "dist_info_dir": metadata.dist_info_dir,
        "metadata_path": metadata.metadata_path,
        "wheel_metadata_path": metadata.wheel_metadata_path,
        "wheel_version": metadata.wheel_version,
        "wheel_generator": metadata.wheel_generator,
        "root_is_purelib": metadata.root_is_purelib,
        "wheel_tags": list(metadata.wheel_tags),
        "requires_python": metadata.requires_python,
        "requires_dist": list(metadata.requires_dist),
        "provides_extra": list(metadata.provides_extra),
        "project_urls": list(metadata.project_urls),
        "summary": metadata.summary,
        "warnings": list(metadata.warnings),
    }


def _identity_line(result: scanner.CveScanResult) -> str:
    """Return the package identity displayed in human output."""
    name = result.package_name or "<unknown-name>"
    version = result.package_version or "<unknown-version>"
    if result.normalized_package_name and result.normalized_package_name != name:
        return f"{name} {version} ({result.normalized_package_name})"
    return f"{name} {version}"


def _compute_exit_code(findings: tuple[scanner.CveFinding, ...]) -> int:
    """Compute cvescan exit code from displayed or full findings."""
    if not findings:
        return exit_codes.CLEAN
    if any(finding.severity in _BLOCKING_SEVERITIES for finding in findings):
        return exit_codes.FINDINGS_BLOCKING
    return exit_codes.FINDINGS_BELOW_BLOCKING


def _severity_rank(severity: str | None) -> int:
    """Return an ordering rank for CVE severity labels."""
    if severity is None:
        return 0
    return _SEVERITY_ORDER.get(str(severity).strip().upper(), 0)
