"""pydepgate.engines.base

Shared types for pydepgate engines.

This module contains data structures that engines produce and consume.
It deliberately has no dependencies on parsers, analyzers, or triage
so that the type contracts are stable even as those subsystems evolve.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydepgate.analyzers.base import Signal
from pydepgate.traffic_control.triage import FileKind, TriageDecision
from pydepgate import run_context


class ArtifactKind(Enum):
    """What kind of artifact is being scanned.

    The engine uses this to decide which entry point applies and to
    label findings for downstream reporting. It is not used to make
    triage decisions; that is the triage module's job based on paths
    within the artifact.
    """

    WHEEL = "wheel"
    SDIST = "sdist"
    INSTALLED_ENV = "installed_env"
    LOOSE_FILE = "loose_file"


class Severity(Enum):
    """Severity of a finding.

    For v0.1, severity is derived mechanically from a signal's
    confidence because the rule layer does not exist yet. When rules
    land, they will assign severity based on signal plus context, and
    this mechanical mapping will be replaced.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ScanContext:
    """Context passed to analyzers for a single file within an artifact.

    Attributes:
        artifact_kind: What the outer artifact is.
        artifact_identity: A string identifying the artifact (path,
            package name, environment root, etc.). Used in findings.
        internal_path: Path of this file within the artifact.
        file_kind: What the triage module decided this file is.
        triage_reason: The human-readable triage decision, useful for
            downstream debugging.
        file_sha256: SHA256 hex digest of the file's bytes, if
            computed by the enumerator. None when the scan path
            did not compute hashes (decode-driver synthetic inputs,
            tests). Analyzers MAY read this for forensic context
            but should not rely on it being populated.
        file_sha512: SHA512 hex digest of the file's bytes. Same
            semantics as file_sha256.
    """

    artifact_kind: ArtifactKind
    artifact_identity: str
    internal_path: str
    file_kind: FileKind
    triage_reason: str
    file_sha256: str | None = None
    file_sha512: str | None = None


@dataclass(frozen=True)
class Finding:
    """A finding produced by the engine.

    For v0.1, findings wrap signals directly. When rules land, findings
    will be produced by rules evaluating signals plus context, and this
    structure may change.

    Attributes:
        signal: The underlying signal.
        severity: Severity assigned to this finding.
        context: The scan context in which the signal was observed.
    """

    signal: Signal
    severity: Severity
    context: ScanContext


@dataclass(frozen=True)
class SuppressedFinding:
    """A finding that was suppressed by a rule.

    Captured for audit visibility: users should be able to see what
    suppression rules silenced, including what severity the finding
    would have had without the suppression. This prevents accidentally
    hiding real issues with overly broad suppression rules.

    Attributes:
        original_finding: The Finding that would have been emitted
            without the suppression rule.
        suppressing_rule_id: ID of the rule that suppressed this
            finding.
        suppressing_rule_source: Source category of the suppressing
            rule (default/system/user). Useful for distinguishing
            user-intentional suppressions from default-behavior ones.
        would_have_been: Finding showing what default rules would
            have produced. Same as original_finding when the
            suppressing rule was itself a default; different when
            user/system rules overrode a stronger default.
    """

    original_finding: "Finding"
    suppressing_rule_id: str
    suppressing_rule_source: str
    would_have_been: "Finding"


@dataclass(frozen=True)
class SkippedFile:
    """A file that was not analyzed and why.

    Kept in the ScanResult for debugging and auditing. Users who want
    to understand why pydepgate missed a file can inspect this list.
    """

    internal_path: str
    reason: str


@dataclass
class ScanStatistics:
    """Quick counts and timing for a scan.

    Mutable during a scan, frozen by convention after the engine
    finalizes the result. Kept as a plain dataclass rather than frozen
    so the engine can update it incrementally.
    """

    files_total: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    files_failed_to_parse: int = 0
    signals_emitted: int = 0
    analyzers_run: int = 0
    enrichers_run: int = 0
    duration_seconds: float = 0.0


@dataclass(frozen=True)
class ScanResult:
    artifact_identity: str
    artifact_kind: ArtifactKind
    findings: tuple[Finding, ...]
    skipped: tuple[SkippedFile, ...]
    statistics: ScanStatistics
    diagnostics: tuple[str, ...] = field(default_factory=tuple)
    suppressed_findings: tuple[SuppressedFinding, ...] = field(default_factory=tuple)
    per_file_statistics: tuple[FileStatsEntry, ...] = ()
    """Per-file stats for multi-file scans. Empty for single-file
    scans (scan_file, scan_bytes, scan_loose_file_as), populated
    for artifact scans (scan_wheel, scan_sdist, scan_installed).
    """
    artifact_sha256: str | None = None
    artifact_sha512: str | None = None
    scan_id: str = field(default_factory=lambda: run_context.get_current_run_uuid())


@dataclass(frozen=True)
class FileScanInput:
    """Input for a single per-file scan invocation.

    Designed as a pickle-safe boundary type. All fields are either
    primitive values or immutable enum values, so an instance can
    be sent to a worker process by a future parallel executor
    without further marshaling.

    Attributes:
        content: The file's raw bytes.
        internal_path: The file's path within its containing
            artifact (or the loose-file path for single-file mode).
            Used by triage when forced_file_kind is None.
        artifact_kind: What kind of outer artifact this file came
            from. Surfaced in finding contexts.
        artifact_identity: Identifier for the outer artifact
            (wheel path, sdist path, package name, or loose file
            path). Surfaced in finding contexts.
        forced_file_kind: If set, bypass triage and treat the file
            as this kind. Used by `scan_loose_file_as` for
            `pydepgate scan --single` mode. Must not be
            FileKind.SKIP at the public API boundary; callers
            handle that case before constructing this input.
    """

    content: bytes
    internal_path: str
    artifact_kind: ArtifactKind
    artifact_identity: str
    forced_file_kind: FileKind | None = None
    file_sha256: str | None = None
    file_sha512: str | None = None


@dataclass(frozen=True)
class FileScanOutput:
    """Output from a single per-file scan invocation.

    Designed as a pickle-safe boundary type. Aggregated by the
    artifact-level scan methods (scan_wheel, scan_sdist,
    scan_installed) into a ScanResult.

    Attributes:
        internal_path: The file's path as supplied in the input.
            Echoed back so aggregators can build per-file stats
            entries without retaining the input.
        findings: Findings produced by this file's analyzers and
            rule evaluation.
        skipped: SkippedFile entries produced when this file was
            triaged out (zero or one entries).
        diagnostics: Per-file diagnostic messages from analyzers
            or parsers that failed.
        suppressed_findings: Findings that would have fired but
            were suppressed by user rules.
        statistics: Per-file ScanStatistics. files_total is
            always 1; files_scanned is 1 if the file was
            analyzed, 0 if it was triaged out; files_skipped is
            the inverse; signals_emitted is the count of raw
            signals before rule evaluation.
    """

    internal_path: str
    findings: tuple[Finding, ...]
    skipped: tuple[SkippedFile, ...]
    diagnostics: tuple[str, ...]
    suppressed_findings: tuple[SuppressedFinding, ...]
    statistics: ScanStatistics
    file_sha256: str | None = None
    file_sha512: str | None = None


@dataclass(frozen=True)
class FileStatsEntry:
    """Per-file timing and output statistics for a multi-file scan.

    Populated for wheel, sdist, and installed-package scans where
    multiple files contribute to a single ScanResult. Useful for
    diagnosing slow files in large scans (numpy, tensorflow) and
    for the planned --deep mode where ten thousand files might
    contribute to one result.

    Attributes:
        internal_path: The file's path within the artifact.
        duration_seconds: Wall-clock time spent scanning this
            file alone (parser + all analyzers + rule evaluation).
        signals_emitted: Number of raw signals from analyzers,
            before rule evaluation.
        findings_count: Number of findings retained after rule
            evaluation. Suppressed findings are not counted here.
    """

    internal_path: str
    duration_seconds: float
    signals_emitted: int
    findings_count: int


def confidence_to_severity_v01(confidence: int) -> Severity:
    """Map a Signal's confidence (IntEnum value) to a default severity.

    This is a temporary bridge for v0.1. It is intentionally conservative:
    even a DEFINITE signal only becomes HIGH (not CRITICAL) because the
    engine does not yet know the scope context well enough to justify
    CRITICAL. Rules will make that judgment properly.
    """
    if confidence >= 90:
        return Severity.HIGH
    if confidence >= 70:
        return Severity.MEDIUM
    if confidence >= 50:
        return Severity.LOW
    return Severity.INFO
