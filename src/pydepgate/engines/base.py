"""
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
    """
    artifact_kind: ArtifactKind
    artifact_identity: str
    internal_path: str
    file_kind: FileKind
    triage_reason: str


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