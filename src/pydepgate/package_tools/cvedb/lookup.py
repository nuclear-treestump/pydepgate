"""pydepgate.package_tools.cvedb.lookup

SQLite query layer for the local PyPI CVE database.

This module is intentionally storage-focused. It knows how to query
cvedb tables and how to turn those rows into frozen, pickle-safe
records. It does not know about wheels, sdists, StaticEngine, CLI
rendering, or artifact scan policy. Those callers should supply a
package name and version, then decide how to display or merge the
result.

The first lookup generation handles only exact affected-version rows
and the importer's ALL sentinel. affected_ranges rows are surfaced as
unevaluated range hints and as warnings, but they are not evaluated
against the supplied version yet. That is deliberate: Python package
version comparison needs a careful stdlib-only implementation before
range matching can be trusted.

Public surface:

    lookup_package(conn, package_name, version) -> LookupResult
        Query an already-open sqlite3.Connection.

    lookup_package_in_db(db_path, package_name, version) -> LookupResult
        Open a cvedb SQLite file, query it, and close it.

    normalize_package_name(name) -> str
        PEP 503 style package-name normalization used by lookup.

    VulnerabilityMatch, UnevaluatedRange, LookupResult
        Frozen result records suitable for tests, callers, and future
        package_tools scanners.

    CveLookupError, CveDatabaseNotFound
        lookup.py specific exception hierarchy.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from pydepgate.package_tools.cvedb import constants
from pydepgate.package_tools.cvedb import importer
from pydepgate.package_tools.cvedb import schema

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MATCH_TYPE_EXACT_VERSION = "exact-version"
MATCH_TYPE_ALL_VERSIONS = "all-versions"

WARNING_RANGE_ROWS_UNEVALUATED = "range-rows-unevaluated"
WARNING_EMPTY_PACKAGE_NAME = "empty-package-name"
WARNING_EMPTY_PACKAGE_VERSION = "empty-package-version"

_SQL_NORMALIZE_PACKAGE = "pydepgate_normalize_package"
_NAME_NORMALIZER = re.compile(r"[-_.]+")


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VulnerabilityMatch:
    """A vulnerability row that matched a package identity.

    Attributes:
        canonical_id: Canonical vulnerability identifier chosen at
            import time.
        aliases: All known identifiers for the vulnerability, sorted
            deterministically. The canonical ID is included even if the
            aliases table was missing that row.
        queried_name: Package name supplied by the caller, after
            surrounding whitespace was stripped.
        normalized_queried_name: PEP 503 style normalized package name
            used for lookup.
        queried_version: Version supplied by the caller, after
            surrounding whitespace was stripped.
        database_package_name: Package name stored in cvedb for the
            matched row.
        database_version: Version stored in affected_versions. This is
            either the queried version for exact matches or the ALL
            sentinel for universal matches.
        match_type: MATCH_TYPE_EXACT_VERSION or
            MATCH_TYPE_ALL_VERSIONS.
        summary, details, published, modified, cvss_v3, cvss_v4,
        severity: Vulnerability attributes copied from the
            vulnerabilities table.
        versions_complete: Boolean projection of the DB row's
            versions_complete flag.
    """

    canonical_id: str
    aliases: tuple[str, ...]
    queried_name: str
    normalized_queried_name: str
    queried_version: str
    database_package_name: str
    database_version: str
    match_type: str
    summary: str | None
    details: str | None
    published: str | None
    modified: str | None
    cvss_v3: str | None
    cvss_v4: str | None
    severity: str | None
    versions_complete: bool


@dataclass(frozen=True)
class UnevaluatedRange:
    """affected_ranges row that belongs to the queried package.

    Range rows are useful evidence but are not findings in this first
    lookup generation. They are returned so cvescan can warn users that
    a package has range-based advisory data that lookup.py could not
    yet evaluate.
    """

    canonical_id: str
    package_name: str
    range_type: str
    introduced: str
    fixed: str
    last_affected: str


@dataclass(frozen=True)
class LookupResult:
    """Result of querying cvedb for one package name and version.

    Attributes:
        package_name: Caller supplied package name after stripping
            whitespace, or an empty string when the input was empty.
        normalized_package_name: PEP 503 style package name, or an
            empty string when package_name is empty.
        package_version: Caller supplied package version after
            stripping whitespace, or an empty string when the input was
            empty.
        matches: Definite exact-version or ALL-sentinel matches.
        unevaluated_ranges: Range rows for this package that were not
            evaluated against the supplied version.
        warnings: Non-fatal lookup warnings.
        attribution: Attribution line for the vulnerability data
            source. Reporters should surface this when vulnerability
            data appears in user-visible output.
    """

    package_name: str
    normalized_package_name: str
    package_version: str
    matches: tuple[VulnerabilityMatch, ...]
    unevaluated_ranges: tuple[UnevaluatedRange, ...]
    warnings: tuple[str, ...]
    attribution: str

    @property
    def has_matches(self) -> bool:
        """Return True when at least one definite match was found."""
        return bool(self.matches)

    @property
    def has_unevaluated_ranges(self) -> bool:
        """Return True when range rows were found but not evaluated."""
        return bool(self.unevaluated_ranges)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CveLookupError(Exception):
    """Base class for cvedb lookup failures."""


class CveDatabaseNotFound(CveLookupError):
    """The requested cvedb SQLite file does not exist.

    Attributes:
        path: Filesystem path that was requested.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        super().__init__(f"CVE database not found at {self.path}")


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def normalize_package_name(name: str) -> str:
    """Normalize a Python package name for lookup comparisons.

    This follows the PEP 503 comparison rule used throughout Python
    packaging: runs of hyphen, underscore, and dot collapse to a single
    hyphen, then the result is lowercased.
    """
    return _NAME_NORMALIZER.sub("-", name).lower()


# ---------------------------------------------------------------------------
# Public lookup API
# ---------------------------------------------------------------------------


def lookup_package_in_db(
    db_path: str | Path,
    package_name: str,
    version: str,
) -> LookupResult:
    """Open a cvedb SQLite file and query one package identity.

    Args:
        db_path: Path to the cvedb SQLite file.
        package_name: Package name to query. The lookup normalizes this
            for comparison, but the original stripped value is preserved
            in the result.
        version: Package version to query. Version strings are matched
            exactly in this generation.

    Returns:
        LookupResult with definite matches, unevaluated range hints,
        warnings, and attribution.

    Raises:
        CveDatabaseNotFound: The path does not exist.
        CveLookupError: sqlite3 raised while opening or querying the DB.
        schema.SchemaVersionMismatch: The DB schema version is not
            compatible with this build.
    """
    path = Path(db_path)
    if not path.exists():
        raise CveDatabaseNotFound(path)

    try:
        conn = schema.connect(path)
    except sqlite3.Error as exc:
        raise CveLookupError(f"could not open CVE database {path}: {exc}") from exc

    try:
        return lookup_package(conn, package_name, version)
    finally:
        conn.close()


def lookup_package(
    conn: sqlite3.Connection,
    package_name: str,
    version: str,
) -> LookupResult:
    """Query an open cvedb connection for one package identity.

    This function is the testable core of lookup.py. It validates the
    supplied identity, verifies schema compatibility, installs a small
    SQLite normalization function on the connection, then queries exact
    affected_versions rows, ALL-sentinel rows, and unevaluated
    affected_ranges rows.

    Args:
        conn: Open sqlite3.Connection to a cvedb database.
        package_name: Package name to query.
        version: Package version to query.

    Returns:
        LookupResult. Empty or incomplete identity inputs return an
        empty result with warnings and do not require a compatible DB.

    Raises:
        CveLookupError: sqlite3 raised while querying the DB.
        schema.SchemaVersionMismatch: The DB schema version is not
            compatible with this build.
    """
    clean_name = _clean_value(package_name)
    clean_version = _clean_value(version)
    warnings: list[str] = []

    if not clean_name:
        warnings.append(WARNING_EMPTY_PACKAGE_NAME)
    if not clean_version:
        warnings.append(WARNING_EMPTY_PACKAGE_VERSION)

    if warnings:
        normalized = normalize_package_name(clean_name) if clean_name else ""
        return LookupResult(
            package_name=clean_name,
            normalized_package_name=normalized,
            package_version=clean_version,
            matches=(),
            unevaluated_ranges=(),
            warnings=tuple(warnings),
            attribution=constants.OSV_DATA_ATTRIBUTION_LINE,
        )

    normalized_name = normalize_package_name(clean_name)

    try:
        schema.check_schema_compatibility(conn)
        _install_sql_functions(conn)
        match_rows = _fetch_match_rows(
            conn,
            package_name=clean_name,
            normalized_package_name=normalized_name,
            version=clean_version,
        )
        range_rows = _fetch_range_rows(
            conn,
            package_name=clean_name,
            normalized_package_name=normalized_name,
        )
        aliases = _fetch_aliases(
            conn,
            _canonical_ids(match_rows, range_rows),
        )
        attribution = _read_attribution(conn)
    except schema.SchemaVersionMismatch:
        raise
    except sqlite3.Error as exc:
        raise CveLookupError(f"cvedb lookup failed: {exc}") from exc

    ranges = tuple(_range_from_row(row) for row in range_rows)
    if ranges:
        warnings.append(WARNING_RANGE_ROWS_UNEVALUATED)

    matches = _build_matches(
        rows=match_rows,
        aliases=aliases,
        queried_name=clean_name,
        normalized_queried_name=normalized_name,
        queried_version=clean_version,
    )

    return LookupResult(
        package_name=clean_name,
        normalized_package_name=normalized_name,
        package_version=clean_version,
        matches=matches,
        unevaluated_ranges=ranges,
        warnings=tuple(warnings),
        attribution=attribution,
    )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def _clean_value(value: str) -> str:
    """Return a stripped string, accepting defensive non-str inputs."""
    if value is None:  # type: ignore[unreachable]
        return ""
    return str(value).strip()


def _install_sql_functions(conn: sqlite3.Connection) -> None:
    """Install lookup.py's package-name normalizer on a connection."""
    try:
        conn.create_function(
            _SQL_NORMALIZE_PACKAGE,
            1,
            _sqlite_normalize_package_name,
            deterministic=True,
        )
    except TypeError:
        # Python versions before deterministic= support are not a
        # target for pydepgate today, but this fallback keeps the helper
        # harmless if embedded in an older interpreter during tests.
        conn.create_function(
            _SQL_NORMALIZE_PACKAGE,
            1,
            _sqlite_normalize_package_name,
        )


def _sqlite_normalize_package_name(value: object) -> str:
    """SQLite UDF adapter for normalize_package_name."""
    if not isinstance(value, str):
        return ""
    return normalize_package_name(value)


def _fetch_match_rows(
    conn: sqlite3.Connection,
    *,
    package_name: str,
    normalized_package_name: str,
    version: str,
) -> list[tuple]:
    """Fetch exact-version and ALL-sentinel affected_versions rows."""
    exact_rows = conn.execute(
        "SELECT v.canonical_id, v.summary, v.details, v.published, "
        "v.modified, v.cvss_v3, v.cvss_v4, v.severity, "
        "v.versions_complete, av.package_name, av.version "
        "FROM affected_versions av "
        "JOIN vulnerabilities v ON v.canonical_id = av.canonical_id "
        "WHERE av.package_name IN (?, ?) "
        "AND av.version IN (?, ?) "
        "ORDER BY v.canonical_id, av.package_name, av.version",
        (
            package_name,
            normalized_package_name,
            version,
            importer.ALL_VERSIONS_SENTINEL,
        ),
    ).fetchall()

    normalized_rows = conn.execute(
        "SELECT v.canonical_id, v.summary, v.details, v.published, "
        "v.modified, v.cvss_v3, v.cvss_v4, v.severity, "
        "v.versions_complete, av.package_name, av.version "
        "FROM affected_versions av "
        "JOIN vulnerabilities v ON v.canonical_id = av.canonical_id "
        f"WHERE {_SQL_NORMALIZE_PACKAGE}(av.package_name) = ? "
        "AND av.version IN (?, ?) "
        "ORDER BY v.canonical_id, av.package_name, av.version",
        (
            normalized_package_name,
            version,
            importer.ALL_VERSIONS_SENTINEL,
        ),
    ).fetchall()

    return _dedupe_rows(exact_rows, normalized_rows)


def _fetch_range_rows(
    conn: sqlite3.Connection,
    *,
    package_name: str,
    normalized_package_name: str,
) -> list[tuple]:
    """Fetch affected_ranges rows that belong to the queried package."""
    exact_rows = conn.execute(
        "SELECT canonical_id, package_name, range_type, introduced, "
        "fixed, last_affected "
        "FROM affected_ranges "
        "WHERE package_name IN (?, ?) "
        "ORDER BY canonical_id, package_name, introduced, fixed, "
        "last_affected",
        (package_name, normalized_package_name),
    ).fetchall()

    normalized_rows = conn.execute(
        "SELECT canonical_id, package_name, range_type, introduced, "
        "fixed, last_affected "
        "FROM affected_ranges "
        f"WHERE {_SQL_NORMALIZE_PACKAGE}(package_name) = ? "
        "ORDER BY canonical_id, package_name, introduced, fixed, "
        "last_affected",
        (normalized_package_name,),
    ).fetchall()

    return _dedupe_rows(exact_rows, normalized_rows)


def _dedupe_rows(*groups: Sequence[tuple]) -> list[tuple]:
    """Combine sqlite rows while preserving deterministic order."""
    seen: set[tuple] = set()
    out: list[tuple] = []
    for group in groups:
        for row in group:
            row_tuple = tuple(row)
            if row_tuple in seen:
                continue
            seen.add(row_tuple)
            out.append(row_tuple)
    out.sort()
    return out


def _canonical_ids(
    match_rows: Sequence[tuple],
    range_rows: Sequence[tuple],
) -> tuple[str, ...]:
    """Return sorted canonical IDs from match and range rows."""
    ids = {row[0] for row in match_rows}
    ids.update(row[0] for row in range_rows)
    return tuple(sorted(ids))


def _fetch_aliases(
    conn: sqlite3.Connection,
    canonical_ids: Iterable[str],
) -> dict[str, tuple[str, ...]]:
    """Fetch aliases for canonical IDs as a deterministic mapping."""
    ids = tuple(sorted(set(canonical_ids)))
    if not ids:
        return {}

    placeholders = ", ".join("?" for _ in ids)
    rows = conn.execute(
        "SELECT canonical_id, alias FROM aliases "
        f"WHERE canonical_id IN ({placeholders}) "
        "ORDER BY canonical_id, alias",
        ids,
    ).fetchall()

    by_canonical: dict[str, set[str]] = {cid: {cid} for cid in ids}
    for canonical_id, alias in rows:
        by_canonical.setdefault(canonical_id, {canonical_id}).add(alias)

    return {
        canonical_id: tuple(sorted(aliases))
        for canonical_id, aliases in sorted(by_canonical.items())
    }


def _read_attribution(conn: sqlite3.Connection) -> str:
    """Read or synthesize the vulnerability data attribution line."""
    source_name = schema.read_metadata(
        conn,
        schema.METADATA_KEY_DATA_SOURCE_NAME,
    )
    source_url = schema.read_metadata(
        conn,
        schema.METADATA_KEY_DATA_SOURCE_URL,
    )
    license_name = schema.read_metadata(
        conn,
        schema.METADATA_KEY_DATA_LICENSE,
    )

    if source_name and source_url and license_name:
        return f"Vulnerability data: {source_name} ({source_url}), {license_name}."
    return constants.OSV_DATA_ATTRIBUTION_LINE


# ---------------------------------------------------------------------------
# Row conversion helpers
# ---------------------------------------------------------------------------


def _build_matches(
    *,
    rows: Sequence[tuple],
    aliases: dict[str, tuple[str, ...]],
    queried_name: str,
    normalized_queried_name: str,
    queried_version: str,
) -> tuple[VulnerabilityMatch, ...]:
    """Convert affected_versions rows into one match per canonical ID."""
    selected: dict[str, tuple[int, tuple]] = {}
    for row in rows:
        canonical_id = row[0]
        match_rank = _match_rank(row[10], queried_version)
        current = selected.get(canonical_id)
        if current is None or match_rank > current[0]:
            selected[canonical_id] = (match_rank, row)
        elif current is not None and match_rank == current[0]:
            if tuple(row) < tuple(current[1]):
                selected[canonical_id] = (match_rank, row)

    out = []
    for canonical_id in sorted(selected):
        row = selected[canonical_id][1]
        out.append(
            VulnerabilityMatch(
                canonical_id=canonical_id,
                aliases=aliases.get(canonical_id, (canonical_id,)),
                queried_name=queried_name,
                normalized_queried_name=normalized_queried_name,
                queried_version=queried_version,
                database_package_name=row[9],
                database_version=row[10],
                match_type=_match_type(row[10], queried_version),
                summary=row[1],
                details=row[2],
                published=row[3],
                modified=row[4],
                cvss_v3=row[5],
                cvss_v4=row[6],
                severity=row[7],
                versions_complete=bool(row[8]),
            )
        )
    return tuple(out)


def _match_rank(database_version: str, queried_version: str) -> int:
    """Rank duplicate rows for the same canonical vulnerability."""
    if database_version == queried_version:
        return 2
    if database_version == importer.ALL_VERSIONS_SENTINEL:
        return 1
    return 0


def _match_type(database_version: str, queried_version: str) -> str:
    """Return a stable match-type string for a database version."""
    if database_version == queried_version:
        return MATCH_TYPE_EXACT_VERSION
    return MATCH_TYPE_ALL_VERSIONS


def _range_from_row(row: tuple) -> UnevaluatedRange:
    """Convert an affected_ranges row into UnevaluatedRange."""
    return UnevaluatedRange(
        canonical_id=row[0],
        package_name=row[1],
        range_type=row[2],
        introduced=row[3],
        fixed=row[4],
        last_affected=row[5],
    )
