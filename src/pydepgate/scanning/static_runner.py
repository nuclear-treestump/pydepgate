"""pydepgate.scanning.static_runner

Static scanner runner for granted scan requests.

This module executes the static scanner from internal API objects. It does not
read argparse namespaces and it treats the Scan Granting Ticket as the authority
for scanner work.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.analyzers.dynamic_execution import DynamicExecutionAnalyzer
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.analyzers.string_ops import StringOpsAnalyzer
from pydepgate.analyzers.suspicious_stdlib import SuspiciousStdlibAnalyzer
from pydepgate.engines.base import ArtifactKind, ScanResult, ScanStatistics
from pydepgate.engines.static import StaticEngine
from pydepgate.enrichers.decode_payloads import decode_payloads, filter_tree_by_severity
from pydepgate.enrichers.payload_peek import (
    DEFAULT_MAX_BUDGET,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MIN_LENGTH,
)
from pydepgate.events import EventEmitter, EventSinkError, ScanGrantingTicket
from pydepgate.scanning.api import ScanApiContractError, ScanTargetRef
from pydepgate.traffic_control.triage import FileKind

_SDIST_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")
_ARCHIVE_SUFFIXES = (".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")

_AS_KIND_TO_FILE_KIND = {
    "setup_py": FileKind.SETUP_PY,
    "init_py": FileKind.INIT_PY,
    "pth": FileKind.PTH,
    "sitecustomize": FileKind.SITECUSTOMIZE,
    "usercustomize": FileKind.USERCUSTOMIZE,
    "library_py": FileKind.LIBRARY_PY,
}

_NATURAL_KIND_FILES = {
    "setup.py": FileKind.SETUP_PY,
    "__init__.py": FileKind.INIT_PY,
    "sitecustomize.py": FileKind.SITECUSTOMIZE,
    "usercustomize.py": FileKind.USERCUSTOMIZE,
}


class StaticScanError(RuntimeError):
    """Raised when a granted static scan cannot be executed."""


@dataclass(frozen=True, slots=True)
class StaticDecodeOptions:
    """Options needed by the decoded-payload pass."""

    peek_min_length: int = DEFAULT_MIN_LENGTH
    peek_depth: int = DEFAULT_MAX_DEPTH
    peek_budget: int = DEFAULT_MAX_BUDGET
    min_severity: str | None = None


@dataclass(frozen=True, slots=True)
class StaticScanRequest:
    """Granted request for static scanner execution."""

    ticket: ScanGrantingTicket
    target_ref: ScanTargetRef
    rules: Sequence[Any]
    emitter: EventEmitter
    ruleset_fingerprint: str | None = None
    enrichers: Sequence[Any] = field(default_factory=tuple)
    as_kind: str | None = None
    initial_diagnostics: Sequence[str] = field(default_factory=tuple)
    progress_callback: Callable[[int, int], None] | None = None
    grant_event_id: str | None = None
    decode_options: StaticDecodeOptions = field(default_factory=StaticDecodeOptions)
    strict_event_sinks: bool = False
    event_warning: Callable[[str], None] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ticket, ScanGrantingTicket):
            raise ScanApiContractError("ticket must be a ScanGrantingTicket")
        if not isinstance(self.target_ref, ScanTargetRef):
            raise ScanApiContractError("target_ref must be a ScanTargetRef")
        if not isinstance(self.emitter, EventEmitter):
            raise ScanApiContractError("emitter must be an EventEmitter")
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(self, "enrichers", tuple(self.enrichers))
        object.__setattr__(self, "initial_diagnostics", tuple(self.initial_diagnostics))
        if self.as_kind is not None and self.as_kind not in _AS_KIND_TO_FILE_KIND:
            raise ScanApiContractError(
                f"unknown static single-file kind: {self.as_kind}"
            )


@dataclass(frozen=True, slots=True)
class StaticScanOutcome:
    """Result of a granted static scanner execution."""

    result: ScanResult = field(repr=False)
    engine: StaticEngine = field(repr=False)
    decoded_tree: Any | None = field(default=None, repr=False)
    engine_event_id: str | None = None
    scan_started_event_id: str | None = None
    scan_completed_event_id: str | None = None
    decode_started_event_id: str | None = None
    decode_completed_event_id: str | None = None

    def __repr__(self) -> str:
        return (
            "StaticScanOutcome("
            f"artifact_kind={self.result.artifact_kind.value!r}, "
            f"finding_count={len(self.result.findings)}, "
            f"diagnostic_count={len(self.result.diagnostics)}, "
            f"decoded_tree_available={self.decoded_tree is not None}, "
            f"scan_completed_event_id={self.scan_completed_event_id!r}"
            ")"
        )


def execute_static_scan(request: StaticScanRequest) -> StaticScanOutcome:
    """Execute a static scan from an internal request object."""
    ticket = request.ticket
    _validate_ticket_for_static_scan(request)

    budget = _ticket_budget(ticket)
    deep_mode = bool(budget.get("deep", False))
    workers = budget.get("workers")
    parallel_threshold = int(budget.get("parallel_threshold", 1000))

    engine = StaticEngine(
        analyzers=(
            EncodingAbuseAnalyzer(),
            DynamicExecutionAnalyzer(),
            StringOpsAnalyzer(),
            SuspiciousStdlibAnalyzer(),
            CodeDensityAnalyzer(),
        ),
        enrichers=request.enrichers,
        rules=request.rules,
        deep_mode=deep_mode,
        workers=workers,
        parallel_threshold=parallel_threshold,
        initial_diagnostics=request.initial_diagnostics,
    )

    engine_event = _emit_event(
        request,
        "internal.scanner.engine_created",
        {
            "analyzers": [analyzer.__class__.__name__ for analyzer in engine.analyzers],
            "enricher_count": len(request.enrichers),
            "rule_count": len(request.rules),
            "deep_mode": deep_mode,
            "workers": workers,
            "parallel_threshold": parallel_threshold,
        },
        parent_event_id=request.grant_event_id,
    )

    scan_started_event = _emit_event(
        request,
        "internal.scanner.scan_started",
        {
            "target_kind": ticket.target_kind,
            "target_identity": ticket.target_identity,
            "scan_mode": ticket.scan_mode,
            "allowed_actions": list(ticket.allowed_actions),
            "target_ref": request.target_ref.to_dict(),
        },
        parent_event_id=(engine_event.event_id if engine_event else None),
    )

    try:
        result = _dispatch_static_scan(engine, request)
    except Exception as exc:
        _emit_event(
            request,
            "internal.scanner.scan_failed",
            _exception_event_payload(exc),
            parent_event_id=(
                scan_started_event.event_id if scan_started_event else None
            ),
            severity="error",
        )
        raise

    scan_completed_event = _emit_event(
        request,
        "internal.scanner.scan_completed",
        _scan_result_event_payload(result),
        parent_event_id=(scan_started_event.event_id if scan_started_event else None),
    )

    decoded_tree = None
    decode_started_event = None
    decode_completed_event = None
    if _ticket_allows_decode(ticket):
        decode_started_event = _emit_event(
            request,
            "internal.scanner.decode_started",
            {
                "decode_payload_depth": budget.get("decode_payload_depth"),
                "decode_iocs": budget.get("decode_iocs"),
            },
            parent_event_id=(
                scan_completed_event.event_id if scan_completed_event else None
            ),
        )
        decoded_tree = _compute_decoded_tree(request, result, engine)
        decode_completed_event = _emit_event(
            request,
            "internal.scanner.decode_completed",
            {
                "tree_available": decoded_tree is not None,
                "node_count": (
                    len(decoded_tree.nodes) if decoded_tree is not None else 0
                ),
                "total_node_count": _count_decoded_nodes(decoded_tree),
                "ioc_count": _count_ioc_nodes(decoded_tree),
                "decode_iocs": budget.get("decode_iocs"),
            },
            parent_event_id=(
                decode_started_event.event_id if decode_started_event else None
            ),
            severity="info" if decoded_tree is not None else "warning",
        )

    return StaticScanOutcome(
        result=result,
        engine=engine,
        decoded_tree=decoded_tree,
        engine_event_id=engine_event.event_id if engine_event else None,
        scan_started_event_id=(
            scan_started_event.event_id if scan_started_event else None
        ),
        scan_completed_event_id=(
            scan_completed_event.event_id if scan_completed_event else None
        ),
        decode_started_event_id=(
            decode_started_event.event_id if decode_started_event else None
        ),
        decode_completed_event_id=(
            decode_completed_event.event_id if decode_completed_event else None
        ),
    )


def _validate_ticket_for_static_scan(request: StaticScanRequest) -> None:
    ticket = request.ticket
    if ticket.is_expired():
        raise StaticScanError("scan ticket is expired")
    if not _ticket_allows_scan(ticket):
        raise StaticScanError("scan ticket does not authorize static scan work")
    if ticket.ruleset_fingerprint and request.ruleset_fingerprint:
        if ticket.ruleset_fingerprint != request.ruleset_fingerprint:
            raise StaticScanError("ruleset fingerprint does not match scan ticket")
    if ticket.target_identity and ticket.target_identity != request.target_ref.identity:
        if request.target_ref.location != ticket.target_identity:
            raise StaticScanError("target reference does not match scan ticket")
    single_budget = bool(ticket.budget.get("single", False))
    target_path = request.target_ref.access_location

    if single_budget and ticket.target_kind != "loose_file":
        raise StaticScanError("single-file budget requires a loose-file ticket")
    if request.target_ref.kind == "loose_file" and ticket.target_kind != "loose_file":
        raise StaticScanError("loose-file target ref cannot satisfy an artifact ticket")
    if ticket.target_kind == "loose_file" and request.target_ref.kind not in (
        "loose_file",
        "local_path",
    ):
        raise StaticScanError("loose-file ticket requires a loose-file target ref")
    if ticket.target_kind == "loose_file" and _looks_like_archive_target(target_path):
        raise StaticScanError("archive artifacts cannot be scanned as loose files")
    if request.target_ref.kind == "loose_file" and _looks_like_archive_target(
        target_path
    ):
        raise StaticScanError("archive artifacts cannot be scanned as loose files")
    if ticket.target_kind == "wheel" and request.target_ref.kind not in (
        "wheel",
        "auto",
        "local_path",
    ):
        raise StaticScanError("wheel ticket requires a wheel-compatible target ref")
    if ticket.target_kind == "sdist" and request.target_ref.kind not in (
        "sdist",
        "auto",
        "local_path",
    ):
        raise StaticScanError("sdist ticket requires an sdist-compatible target ref")


def _looks_like_archive_target(target: str) -> bool:
    return target.lower().endswith(_ARCHIVE_SUFFIXES)


def _count_decoded_nodes(decoded_tree) -> int:
    if decoded_tree is None:
        return 0

    def visit(node) -> int:
        return 1 + sum(visit(child) for child in getattr(node, "children", ()))

    return sum(visit(node) for node in getattr(decoded_tree, "nodes", ()))


def _count_ioc_nodes(decoded_tree) -> int:
    if decoded_tree is None:
        return 0

    def visit(node) -> int:
        count = 1 if getattr(node, "ioc_data", None) is not None else 0
        return count + sum(visit(child) for child in getattr(node, "children", ()))

    return sum(visit(node) for node in getattr(decoded_tree, "nodes", ()))


def _ticket_allows_scan(ticket: ScanGrantingTicket) -> bool:
    return ticket.allows_action("scan") or ticket.allows_action("static.scan")


def _ticket_allows_decode(ticket: ScanGrantingTicket) -> bool:
    budget = _ticket_budget(ticket)
    return bool(budget.get("decode_enabled", False)) and (
        ticket.allows_action("decode") or ticket.allows_action("static.decode")
    )


def _ticket_budget(ticket: ScanGrantingTicket) -> Mapping[str, Any]:
    return ticket.budget


def _dispatch_static_scan(
    engine: StaticEngine, request: StaticScanRequest
) -> ScanResult:
    ticket = request.ticket
    target = request.target_ref.access_location

    if ticket.target_kind == "loose_file" or request.target_ref.kind == "loose_file":
        return _dispatch_single(
            engine,
            target,
            request.as_kind,
            initial_diagnostics=tuple(request.initial_diagnostics),
        )

    if request.target_ref.kind == "wheel":
        return engine.scan_wheel(
            Path(target), progress_callback=request.progress_callback
        )
    if request.target_ref.kind == "sdist":
        return engine.scan_sdist(
            Path(target), progress_callback=request.progress_callback
        )
    if request.target_ref.kind == "installed_package":
        return engine.scan_installed(
            target, progress_callback=request.progress_callback
        )
    if request.target_ref.kind in ("local_path", "auto"):
        return _dispatch_scan(
            engine, target, progress_callback=request.progress_callback
        )

    raise StaticScanError(
        f"static runner cannot scan target ref kind {request.target_ref.kind!r}"
    )


def _dispatch_scan(
    engine: StaticEngine,
    target: str,
    *,
    progress_callback=None,
) -> ScanResult:
    path = Path(target)

    if path.suffix == ".whl" and path.is_file():
        return engine.scan_wheel(path, progress_callback=progress_callback)

    lowered = target.lower()
    for suffix in _SDIST_SUFFIXES:
        if lowered.endswith(suffix):
            if path.is_file():
                return engine.scan_sdist(path, progress_callback=progress_callback)
            break

    return engine.scan_installed(target, progress_callback=progress_callback)


def _dispatch_single(
    engine: StaticEngine,
    path_str: str,
    as_kind: str | None,
    initial_diagnostics: tuple[str, ...] = (),
) -> ScanResult:
    path = Path(path_str)
    if not path.exists():
        return _empty_result_with_diag(
            path, f"file not found: {path}", initial_diagnostics
        )
    if not path.is_file():
        return _empty_result_with_diag(
            path, f"not a regular file: {path}", initial_diagnostics
        )

    file_kind = _file_kind_for_single(path, as_kind)
    return engine.scan_loose_file_as(path, file_kind)


def _file_kind_for_single(path: Path, as_kind: str | None) -> FileKind:
    if as_kind is not None:
        return _AS_KIND_TO_FILE_KIND[as_kind]
    if path.suffix == ".pth":
        return FileKind.PTH
    if path.name in _NATURAL_KIND_FILES:
        return _NATURAL_KIND_FILES[path.name]
    return FileKind.SETUP_PY


def _empty_result_with_diag(
    path: Path,
    diagnostic: str,
    initial_diagnostics: tuple[str, ...] = (),
) -> ScanResult:
    return ScanResult(
        artifact_identity=str(path),
        artifact_kind=ArtifactKind.LOOSE_FILE,
        findings=(),
        skipped=(),
        statistics=ScanStatistics(),
        diagnostics=tuple(initial_diagnostics) + (diagnostic,),
    )


def _compute_decoded_tree(
    request: StaticScanRequest,
    result: ScanResult,
    engine: StaticEngine,
):
    budget = _ticket_budget(request.ticket)
    decode_iocs_mode = str(budget.get("decode_iocs", "off"))
    extract_iocs = decode_iocs_mode in ("hashes", "full")
    include_decoded_source = decode_iocs_mode == "full"
    max_depth = budget.get("decode_payload_depth")
    if max_depth is None:
        max_depth = 3

    try:
        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=int(max_depth),
            peek_min_length=request.decode_options.peek_min_length,
            peek_max_depth=request.decode_options.peek_depth,
            peek_max_budget=request.decode_options.peek_budget,
            extract_iocs=extract_iocs,
            include_decoded_source=include_decoded_source,
        )
    except Exception as exc:
        _warn(
            request,
            f"warning: decoded-payload pass failed: {type(exc).__name__}: {exc}\n",
        )
        return None

    if request.decode_options.min_severity:
        tree = filter_tree_by_severity(tree, request.decode_options.min_severity)
    return tree


def _emit_event(
    request: StaticScanRequest,
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


def _warn(request: StaticScanRequest, message: str) -> None:
    if request.event_warning is not None:
        request.event_warning(message)


def _scan_result_event_payload(result: ScanResult) -> dict:
    stats = result.statistics
    return {
        "artifact_identity": result.artifact_identity,
        "artifact_kind": result.artifact_kind.value,
        "artifact_sha256": result.artifact_sha256,
        "artifact_sha512": result.artifact_sha512,
        "scan_id": result.scan_id,
        "finding_count": len(result.findings),
        "suppressed_finding_count": len(result.suppressed_findings),
        "skipped_count": len(result.skipped),
        "diagnostic_count": len(result.diagnostics),
        "statistics": {
            "files_total": stats.files_total,
            "files_scanned": stats.files_scanned,
            "files_skipped": stats.files_skipped,
            "files_failed_to_parse": stats.files_failed_to_parse,
            "signals_emitted": stats.signals_emitted,
            "analyzers_run": stats.analyzers_run,
            "enrichers_run": stats.enrichers_run,
            "duration_seconds": stats.duration_seconds,
        },
    }


def _exception_event_payload(exc: BaseException) -> dict:
    return {
        "exception_type": type(exc).__name__,
        "message": str(exc),
    }


__all__ = [
    "StaticDecodeOptions",
    "StaticScanError",
    "StaticScanOutcome",
    "StaticScanRequest",
    "execute_static_scan",
]
