"""pydepgate.package_tools.cvescanner.scanner

Artifact-level CVE scanner.

This module is the policy boundary between package metadata and the
cvedb storage layer. It reads or accepts package identity, delegates
vulnerability matching to cvedb.lookup, and returns scanner-shaped
records that can later be rendered by a CLI command, combined with the
normal static scan, or filtered by run policies.

The scanner deliberately does not inspect files inside an artifact. It
is not a StaticEngine analyzer and it does not create file findings.
CVE matches are package-level findings derived from the artifact's
claimed package identity.

Policy ingestion:

    Each public scan function accepts applied_policy_result. The value
    is preserved on CveScanResult but is not interpreted yet. This gives
    the future policy subsystem a stable ingestion point without making
    this first scanner pass invent policy behavior before the policy
    contract exists.

Public surface:

    scan_artifact(path, *, db_path=None, applied_policy_result=None,
                  require_database=False) -> CveScanResult
        Read PackageMetadata from a supported package artifact and scan
        its package identity.

    scan_metadata(metadata, *, db_path=None, applied_policy_result=None,
                  require_database=False) -> CveScanResult
        Scan an existing PackageMetadata object.

    scan_identity(package_name, version, *, db_path=None,
                  applied_policy_result=None, require_database=False)
                  -> CveScanResult
        Scan a raw package name and version.

    CveFinding, CveUnevaluatedRange, CveScanResult
        Frozen, pickle-safe scanner records.

Error behavior:

    Missing or incompatible cvedb files are warnings by default so a
    future combined scan can continue file analysis. Pass
    require_database=True to raise lookup or schema exceptions instead,
    which is the stricter behavior a dedicated cvescan CLI may want.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydepgate.package_tools import metadata as metadata_module
from pydepgate.dbs.cvedb import constants
from pydepgate.dbs.cvedb import lookup
from pydepgate.dbs.cvedb import schema
from pydepgate.pdgplatform import paths

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_UNKNOWN = "UNKNOWN"

WARNING_MISSING_PACKAGE_NAME = "missing-package-name"
WARNING_MISSING_PACKAGE_VERSION = "missing-package-version"
WARNING_CVE_DATABASE_NOT_FOUND = "cve-database-not-found"
WARNING_CVE_DATABASE_LOOKUP_FAILED = "cve-database-lookup-failed"
WARNING_CVE_DATABASE_SCHEMA_MISMATCH = "cve-database-schema-mismatch"
WARNING_CVE_RANGES_UNEVALUATED = "cve-ranges-unevaluated"


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CveFinding:
    """A definite package-level vulnerability match.

    Attributes:
        canonical_id: Canonical vulnerability identifier selected by
            cvedb import logic.
        aliases: All known identifiers for the vulnerability, including
            the canonical ID.
        package_name: Package name supplied to the scanner.
        normalized_package_name: PEP 503 style package name used for
            lookup comparisons.
        package_version: Package version supplied to the scanner.
        database_package_name: Package name stored in the matching DB
            row. This may differ in casing or separators from
            package_name.
        database_version: affected_versions version for exact and ALL
            matches. Empty for range matches.
        match_type: Stable cvedb match-type string.
        summary, details, published, modified, cvss_v3, cvss_v4:
            Vulnerability fields copied from cvedb.
        severity: Scanner-normalized severity string. Empty, missing,
            zero, and placeholder values become UNKNOWN.
        raw_severity: Severity value exactly as cvedb returned it.
        versions_complete: Boolean projection of the DB row's
            versions_complete flag.
        range_type, introduced, fixed, last_affected: Range evidence
            for range matches. Empty for affected_versions matches.
    """

    canonical_id: str
    aliases: tuple[str, ...]
    package_name: str
    normalized_package_name: str
    package_version: str
    database_package_name: str
    database_version: str
    match_type: str
    summary: str | None
    details: str | None
    published: str | None
    modified: str | None
    cvss_v3: str | None
    cvss_v4: str | None
    severity: str
    raw_severity: str | None
    versions_complete: bool
    range_type: str = ""
    introduced: str = ""
    fixed: str = ""
    last_affected: str = ""


@dataclass(frozen=True)
class CveUnevaluatedRange:
    """Advisory range evidence that was not evaluated safely.

    Unevaluated ranges are not findings. They tell callers that cvedb
    contains advisory range data for the package, but that lookup could
    not compare the row against the queried package version without
    guessing. Typical reasons are unsupported OSV range types such as
    GIT, or ECOSYSTEM ranges that contain versions outside the private
    PEP 440 helper's supported subset.
    """

    canonical_id: str
    package_name: str
    range_type: str
    introduced: str
    fixed: str
    last_affected: str
    reason: str


@dataclass(frozen=True)
class CveScanResult:
    """Result of artifact-level CVE scanning.

    Attributes:
        package_name: Package name scanned, if known.
        normalized_package_name: PEP 503 style package name, if known.
        package_version: Package version scanned, if known.
        package_metadata: PackageMetadata used for this scan, if the
            scan came from an artifact or metadata object.
        findings: Definite CVE matches.
        unevaluated_ranges: Range rows that could not be compared
            safely.
        warnings: Non-fatal scanner, metadata, and lookup warnings.
        attribution: Vulnerability data attribution line. Reporters
            should surface this when findings are shown.
        database_path: cvedb path used or intended for lookup.
        applied_policy_result: Optional future AppliedPolicyResult. It
            is accepted and preserved but not interpreted in this pass.
    """

    package_name: str | None
    normalized_package_name: str | None
    package_version: str | None
    package_metadata: metadata_module.PackageMetadata | None
    findings: tuple[CveFinding, ...]
    unevaluated_ranges: tuple[CveUnevaluatedRange, ...]
    warnings: tuple[str, ...]
    attribution: str
    database_path: Path | None
    applied_policy_result: object | None = None

    @property
    def has_findings(self) -> bool:
        """Return True when at least one vulnerability was found."""
        return bool(self.findings)

    @property
    def has_warnings(self) -> bool:
        """Return True when the scan returned non-fatal warnings."""
        return bool(self.warnings)

    @property
    def has_unevaluated_ranges(self) -> bool:
        """Return True when advisory ranges could not be evaluated."""
        return bool(self.unevaluated_ranges)


# ---------------------------------------------------------------------------
# Public scanner API
# ---------------------------------------------------------------------------


def scan_artifact(
    path: str | Path,
    *,
    db_path: str | Path | None = None,
    applied_policy_result: object | None = None,
    require_database: bool = False,
) -> CveScanResult:
    """Scan a package artifact for known vulnerabilities.

    The artifact is read only through package_tools.metadata. The CVE
    scanner does not enumerate or inspect files inside the artifact.

    Args:
        path: Supported package artifact path. Wheels are currently the
            only supported artifact type.
        db_path: Optional cvedb SQLite path. Defaults to pydepgate's
            platform cache path.
        applied_policy_result: Optional future AppliedPolicyResult. It
            is preserved on the result but not interpreted yet.
        require_database: When True, missing, incompatible, or failed
            database lookups raise instead of becoming warnings.

    Returns:
        CveScanResult with metadata, findings, warnings, attribution,
        and policy context.

    Raises:
        ValueError, OSError, zipfile.BadZipFile: Propagated from
            package_tools.metadata when artifact metadata cannot be
            read.
        lookup.CveLookupError: When require_database is True and cvedb
            lookup fails.
        schema.SchemaVersionMismatch: When require_database is True and
            the cvedb schema is incompatible.
    """
    meta = metadata_module.read_package_metadata(Path(path))
    return scan_metadata(
        meta,
        db_path=db_path,
        applied_policy_result=applied_policy_result,
        require_database=require_database,
    )


def scan_metadata(
    metadata: metadata_module.PackageMetadata,
    *,
    db_path: str | Path | None = None,
    applied_policy_result: object | None = None,
    require_database: bool = False,
) -> CveScanResult:
    """Scan an existing PackageMetadata object for known vulnerabilities.

    Metadata warnings are preserved in CveScanResult.warnings so callers
    can display artifact identity problems next to CVE lookup state.
    """
    return scan_identity(
        metadata.name,
        metadata.version,
        normalized_package_name=metadata.normalized_name,
        metadata=metadata,
        db_path=db_path,
        applied_policy_result=applied_policy_result,
        require_database=require_database,
    )


def scan_identity(
    package_name: str | None,
    version: str | None,
    *,
    normalized_package_name: str | None = None,
    metadata: metadata_module.PackageMetadata | None = None,
    db_path: str | Path | None = None,
    applied_policy_result: object | None = None,
    require_database: bool = False,
) -> CveScanResult:
    """Scan a raw package name and version for known vulnerabilities.

    This function is the scanner's testable core. It accepts a raw
    identity and optional metadata context, checks whether the identity
    is complete enough for cvedb lookup, and converts lookup results
    into scanner records.
    """
    clean_name = _clean_optional(package_name)
    clean_version = _clean_optional(version)
    normalized_name = _clean_optional(normalized_package_name)
    if clean_name and not normalized_name:
        normalized_name = metadata_module.normalize_package_name(clean_name)

    resolved_db_path = _resolve_db_path(db_path)
    warnings = list(metadata.warnings if metadata else ())

    if not clean_name:
        warnings.append(WARNING_MISSING_PACKAGE_NAME)
    if not clean_version:
        warnings.append(WARNING_MISSING_PACKAGE_VERSION)

    if not clean_name or not clean_version:
        return _empty_result(
            package_name=clean_name,
            normalized_package_name=normalized_name,
            package_version=clean_version,
            metadata=metadata,
            warnings=warnings,
            db_path=resolved_db_path,
            applied_policy_result=applied_policy_result,
        )

    try:
        lookup_result = lookup.lookup_package_in_db(
            resolved_db_path,
            clean_name,
            clean_version,
        )
    except lookup.CveDatabaseNotFound as exc:
        if require_database:
            raise
        warnings.append(f"{WARNING_CVE_DATABASE_NOT_FOUND}: {exc.path}")
        return _empty_result(
            package_name=clean_name,
            normalized_package_name=normalized_name,
            package_version=clean_version,
            metadata=metadata,
            warnings=warnings,
            db_path=resolved_db_path,
            applied_policy_result=applied_policy_result,
        )
    except schema.SchemaVersionMismatch as exc:
        if require_database:
            raise
        warnings.append(f"{WARNING_CVE_DATABASE_SCHEMA_MISMATCH}: {exc}")
        return _empty_result(
            package_name=clean_name,
            normalized_package_name=normalized_name,
            package_version=clean_version,
            metadata=metadata,
            warnings=warnings,
            db_path=resolved_db_path,
            applied_policy_result=applied_policy_result,
        )
    except lookup.CveLookupError as exc:
        if require_database:
            raise
        warnings.append(f"{WARNING_CVE_DATABASE_LOOKUP_FAILED}: {exc}")
        return _empty_result(
            package_name=clean_name,
            normalized_package_name=normalized_name,
            package_version=clean_version,
            metadata=metadata,
            warnings=warnings,
            db_path=resolved_db_path,
            applied_policy_result=applied_policy_result,
        )

    findings = tuple(_finding_from_match(match) for match in lookup_result.matches)
    unevaluated_ranges = tuple(
        _unevaluated_range_from_lookup(row) for row in lookup_result.unevaluated_ranges
    )
    warnings.extend(lookup_result.warnings)
    if unevaluated_ranges and WARNING_CVE_RANGES_UNEVALUATED not in warnings:
        warnings.append(WARNING_CVE_RANGES_UNEVALUATED)

    return CveScanResult(
        package_name=lookup_result.package_name,
        normalized_package_name=lookup_result.normalized_package_name,
        package_version=lookup_result.package_version,
        package_metadata=metadata,
        findings=tuple(sorted(findings, key=_finding_sort_key)),
        unevaluated_ranges=tuple(
            sorted(unevaluated_ranges, key=_unevaluated_range_sort_key)
        ),
        warnings=tuple(warnings),
        attribution=lookup_result.attribution,
        database_path=resolved_db_path,
        applied_policy_result=applied_policy_result,
    )


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------


def _resolve_db_path(db_path: str | Path | None) -> Path:
    """Resolve the cvedb path used by a scanner call."""
    if db_path is not None:
        return Path(db_path)
    return paths.pydepgate_cache_dir() / "cvedb" / constants.CVE_DB_FILENAME


def _clean_optional(value: object | None) -> str | None:
    """Strip a value defensively and return None for empty values."""
    if value is None:
        return None
    clean = str(value).strip()
    return clean or None


def _empty_result(
    *,
    package_name: str | None,
    normalized_package_name: str | None,
    package_version: str | None,
    metadata: metadata_module.PackageMetadata | None,
    warnings: list[str],
    db_path: Path | None,
    applied_policy_result: object | None,
) -> CveScanResult:
    """Build an empty scanner result for skipped or degraded scans."""
    return CveScanResult(
        package_name=package_name,
        normalized_package_name=normalized_package_name,
        package_version=package_version,
        package_metadata=metadata,
        findings=(),
        unevaluated_ranges=(),
        warnings=tuple(warnings),
        attribution=constants.OSV_DATA_ATTRIBUTION_LINE,
        database_path=db_path,
        applied_policy_result=applied_policy_result,
    )


def _finding_from_match(match: lookup.VulnerabilityMatch) -> CveFinding:
    """Convert a cvedb lookup match into a scanner finding."""
    return CveFinding(
        canonical_id=match.canonical_id,
        aliases=match.aliases,
        package_name=match.queried_name,
        normalized_package_name=match.normalized_queried_name,
        package_version=match.queried_version,
        database_package_name=match.database_package_name,
        database_version=match.database_version,
        match_type=match.match_type,
        summary=match.summary,
        details=match.details,
        published=match.published,
        modified=match.modified,
        cvss_v3=match.cvss_v3,
        cvss_v4=match.cvss_v4,
        severity=_normalize_severity(match.severity),
        raw_severity=match.severity,
        versions_complete=match.versions_complete,
        range_type=match.range_type,
        introduced=match.introduced,
        fixed=match.fixed,
        last_affected=match.last_affected,
    )


def _unevaluated_range_from_lookup(
    row: lookup.UnevaluatedRange,
) -> CveUnevaluatedRange:
    """Convert lookup's unevaluated range record into scanner shape."""
    return CveUnevaluatedRange(
        canonical_id=row.canonical_id,
        package_name=row.package_name,
        range_type=row.range_type,
        introduced=row.introduced,
        fixed=row.fixed,
        last_affected=row.last_affected,
        reason=row.reason,
    )


def _normalize_severity(value: object | None) -> str:
    """Return a stable scanner severity string."""
    if value is None:
        return SEVERITY_UNKNOWN
    clean = str(value).strip().upper()
    if clean in {"", "0", "NONE", "N/A", "NA", "NULL"}:
        return SEVERITY_UNKNOWN
    return clean


def _finding_sort_key(finding: CveFinding) -> tuple[Any, ...]:
    """Return deterministic ordering for scanner findings."""
    return (
        finding.canonical_id,
        finding.match_type,
        finding.database_package_name,
        finding.database_version,
        finding.range_type,
        finding.introduced,
        finding.fixed,
        finding.last_affected,
    )


def _unevaluated_range_sort_key(row: CveUnevaluatedRange) -> tuple[str, ...]:
    """Return deterministic ordering for unevaluated range evidence."""
    return (
        row.canonical_id,
        row.package_name,
        row.range_type,
        row.introduced,
        row.fixed,
        row.last_affected,
        row.reason,
    )
