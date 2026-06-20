"""pydepgate.scanning.cve_runner

CVE scanner runner for granted scan requests.

This module executes the package-level CVE scanner from internal API objects.
It does not read argparse namespaces and it treats the Scan Granting Ticket as
its authorization boundary. The returned result remains CVE-native so a future
combined report model can aggregate package-level CVE findings without forcing
them into the static file-finding shape.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydepgate.events import EventEmitter, EventSinkError, ScanGrantingTicket
from pydepgate.package_tools.cvescanner import scanner
from pydepgate.scanning.api import ScanApiContractError, ScanTargetRef

_SUPPORTED_TARGET_REF_KINDS = frozenset(
    ("auto", "local_path", "package_artifact", "wheel")
)
_SUPPORTED_TICKET_TARGET_KINDS = frozenset(
    ("auto", "local_path", "package_artifact", "wheel", "unknown")
)
_NON_WHEEL_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".zip")


class CveScanError(RuntimeError):
    """Raised when a granted CVE scan cannot be executed."""


@dataclass(frozen=True, slots=True)
class CveScanRequest:
    """Granted request for package-level CVE scanner execution."""

    ticket: ScanGrantingTicket
    target_ref: ScanTargetRef
    emitter: EventEmitter
    db_path: str | Path | None = None
    applied_policy_result: object | None = None
    require_database: bool = False
    grant_event_id: str | None = None
    strict_event_sinks: bool = False
    event_warning: Callable[[str], None] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ticket, ScanGrantingTicket):
            raise ScanApiContractError("ticket must be a ScanGrantingTicket")
        if not isinstance(self.target_ref, ScanTargetRef):
            raise ScanApiContractError("target_ref must be a ScanTargetRef")
        if not isinstance(self.emitter, EventEmitter):
            raise ScanApiContractError("emitter must be an EventEmitter")
        if not isinstance(self.require_database, bool):
            raise ScanApiContractError("require_database must be a bool")
        if not isinstance(self.strict_event_sinks, bool):
            raise ScanApiContractError("strict_event_sinks must be a bool")
        if self.db_path is not None and not isinstance(self.db_path, (str, Path)):
            raise ScanApiContractError("db_path must be a string, Path, or None")
        if self.event_warning is not None and not callable(self.event_warning):
            raise ScanApiContractError("event_warning must be callable or None")


@dataclass(frozen=True, slots=True)
class CveScanOutcome:
    """Result of a granted package-level CVE scanner execution."""

    result: scanner.CveScanResult = field(repr=False)
    scan_started_event_id: str | None = None
    scan_completed_event_id: str | None = None

    def __repr__(self) -> str:
        return (
            "CveScanOutcome("
            f"package_name={self.result.package_name!r}, "
            f"package_version={self.result.package_version!r}, "
            f"finding_count={len(self.result.findings)}, "
            f"warning_count={len(self.result.warnings)}, "
            f"unevaluated_range_count={len(self.result.unevaluated_ranges)}, "
            f"scan_completed_event_id={self.scan_completed_event_id!r}"
            ")"
        )


def execute_cve_scan(request: CveScanRequest) -> CveScanOutcome:
    """Execute a package-level CVE scan from an internal request object."""
    _validate_ticket_for_cve_scan(request)

    scan_started_event = _emit_event(
        request,
        "internal.scanner.cve_scan_started",
        {
            "target_kind": request.ticket.target_kind,
            "target_identity": request.ticket.target_identity,
            "scan_mode": request.ticket.scan_mode,
            "allowed_actions": list(request.ticket.allowed_actions),
            "target_ref": request.target_ref.to_dict(),
            "require_database": request.require_database,
            "db_path": str(request.db_path) if request.db_path is not None else None,
        },
        parent_event_id=request.grant_event_id,
    )

    try:
        result = scanner.scan_artifact(
            request.target_ref.access_location,
            db_path=request.db_path,
            applied_policy_result=request.applied_policy_result,
            require_database=request.require_database,
        )
    except Exception as exc:
        _emit_event(
            request,
            "internal.scanner.cve_scan_failed",
            _exception_event_payload(exc, request=request),
            parent_event_id=(
                scan_started_event.event_id if scan_started_event else None
            ),
            severity="error",
        )
        raise

    scan_completed_event = _emit_event(
        request,
        "internal.scanner.cve_scan_completed",
        _cve_scan_result_event_payload(result, request=request),
        parent_event_id=(scan_started_event.event_id if scan_started_event else None),
    )

    return CveScanOutcome(
        result=result,
        scan_started_event_id=(
            scan_started_event.event_id if scan_started_event else None
        ),
        scan_completed_event_id=(
            scan_completed_event.event_id if scan_completed_event else None
        ),
    )


def _validate_ticket_for_cve_scan(request: CveScanRequest) -> None:
    ticket = request.ticket
    if ticket.is_expired():
        raise CveScanError("scan ticket is expired")
    if not _ticket_allows_cve_scan(ticket):
        raise CveScanError("scan ticket does not authorize CVE scan work")
    if ticket.target_identity and ticket.target_identity != request.target_ref.identity:
        if request.target_ref.location != ticket.target_identity:
            raise CveScanError("target reference does not match scan ticket")
    if ticket.target_kind not in _SUPPORTED_TICKET_TARGET_KINDS:
        raise CveScanError(
            f"CVE scanner cannot use ticket target kind {ticket.target_kind!r}"
        )
    if request.target_ref.kind not in _SUPPORTED_TARGET_REF_KINDS:
        raise CveScanError(
            f"CVE runner cannot scan target ref kind {request.target_ref.kind!r}"
        )
    if ticket.target_kind == "wheel" and request.target_ref.kind not in (
        "auto",
        "local_path",
        "package_artifact",
        "wheel",
    ):
        raise CveScanError("wheel ticket requires a wheel-compatible target ref")

    target = request.target_ref.access_location
    if _looks_like_non_wheel_archive(target):
        raise CveScanError("CVE scanner currently supports wheel artifacts only")
    if request.target_ref.kind == "wheel" and not _looks_like_wheel(target):
        raise CveScanError("wheel target ref requires a .whl access location")
    if ticket.target_kind == "wheel" and not _looks_like_wheel(target):
        raise CveScanError("wheel ticket requires a .whl access location")


def _ticket_allows_cve_scan(ticket: ScanGrantingTicket) -> bool:
    return ticket.allows_action("scan") or ticket.allows_action("cve.scan")


def _looks_like_wheel(target: str) -> bool:
    return target.lower().endswith(".whl")


def _looks_like_non_wheel_archive(target: str) -> bool:
    lowered = target.lower()
    return any(lowered.endswith(suffix) for suffix in _NON_WHEEL_ARCHIVE_SUFFIXES)


def _emit_event(
    request: CveScanRequest,
    event_type: str,
    payload: dict | None = None,
    *,
    parent_event_id: str | None = None,
    severity: str = "info",
):
    try:
        return request.emitter.emit(
            event_type,
            payload or {},
            ticket_id=request.ticket.ticket_id,
            parent_event_id=parent_event_id,
            severity=severity,
        )
    except EventSinkError as exc:
        if request.strict_event_sinks:
            raise
        _warn(
            request,
            f"warning: could not emit {event_type}: {type(exc).__name__}: {exc}\n",
        )
        return None


def _warn(request: CveScanRequest, message: str) -> None:
    if request.event_warning is not None:
        request.event_warning(message)


def _scan_context_event_payload(request: CveScanRequest) -> dict[str, Any]:
    return {
        "scan_mode": request.ticket.scan_mode,
        "target_kind": request.ticket.target_kind,
        "target_identity": request.ticket.target_identity,
        "target_ref": request.target_ref.to_dict(),
    }


def _cve_scan_result_event_payload(
    result: scanner.CveScanResult,
    *,
    request: CveScanRequest,
) -> dict[str, Any]:
    metadata = result.package_metadata
    return {
        **_scan_context_event_payload(request),
        "result_kind": "cve",
        "package_name": result.package_name,
        "normalized_package_name": result.normalized_package_name,
        "package_version": result.package_version,
        "finding_count": len(result.findings),
        "unevaluated_range_count": len(result.unevaluated_ranges),
        "warning_count": len(result.warnings),
        "database_path": str(result.database_path) if result.database_path else None,
        "artifact_type": metadata.artifact_type if metadata is not None else None,
        "artifact_path": str(metadata.artifact_path) if metadata is not None else None,
        "identity_source": metadata.identity_source if metadata is not None else None,
        "applied_policy": result.applied_policy_result is not None,
    }


def _exception_event_payload(
    exc: BaseException,
    *,
    request: CveScanRequest,
) -> dict[str, Any]:
    return {
        **_scan_context_event_payload(request),
        "result_kind": "cve",
        "exception_type": type(exc).__name__,
        "message": str(exc),
    }


__all__ = [
    "CveScanError",
    "CveScanOutcome",
    "CveScanRequest",
    "execute_cve_scan",
]
