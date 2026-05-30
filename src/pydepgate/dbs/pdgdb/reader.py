"""pydepgate.dbs.pdgdb.reader

Read pydepgate evidence database records.

Public surface
--------------

    get_db_status(conn) -> DbStatus
        Return summary counts and metadata for db status display.

    list_runs(conn, *, limit, offset) -> list[ScanRunRow]
        Return scan runs in reverse chronological order.

    query_by_package(conn, package_name, *,
                     package_version, limit, offset) -> list[ArtifactRow]
        Return scanned artifact records matching a package name and
        optional version.

    query_by_artifact_sha512(conn, sha512) -> list[ArtifactRow]
        Return scanned artifact records matching an artifact SHA-512.

    explain_run(conn, run_id) -> RunExplanation | None
        Return the full structured record for a run by its UUID.
        Returns None if the run_id is not found.

Data types
----------

    DbStatus
    ScanRunRow
    ArtifactRow
    FindingRow
    DecodedNodeRow
    ChildFindingRow
    RunExplanation

Design notes
------------

All public functions accept an open sqlite3.Connection. The caller is
responsible for opening, checking compatibility, and closing the
connection. Readers never write to the database.

chain and indicators are stored as JSON arrays. Readers return them as
tuples of strings, matching the DecodedNode field types.

pickle_warning is stored as INTEGER (0/1). Readers return it as bool.

Pagination: list_runs and query_by_package accept limit and offset for
CLI display. Default limit is 50; callers may set limit=None to return
all rows (use with caution on large databases).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Row types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DbStatus:
    """Summary of the evidence database for `pydepgate db status`."""

    db_path: str
    schema_version: int | None
    pydepgate_version: str | None
    created_at: str | None
    last_modified: str | None
    total_scan_runs: int
    total_scanned_artifacts: int
    total_static_findings: int
    total_decoded_nodes: int
    total_cve_findings: int


@dataclass(frozen=True)
class ScanRunRow:
    """One row from scan_runs for list-runs display."""

    id: int
    run_id: str
    producer_id: str
    command: str
    started_at: str
    pydepgate_ver: str
    artifact_count: int
    finding_count: int
    cve_finding_count: int


@dataclass(frozen=True)
class ArtifactRow:
    """One row from scanned_artifacts for query display."""

    id: int
    scan_run_id: int
    run_id: str
    artifact_kind: str
    artifact_identity: str
    artifact_sha256: str | None
    artifact_sha512: str | None
    package_name: str | None
    package_version: str | None
    scanned_at: str
    finding_count: int
    cve_finding_count: int


@dataclass(frozen=True)
class FindingRow:
    """One row from static_findings."""

    id: int
    signal_id: str
    analyzer: str
    severity: str
    confidence: int
    scope: str
    internal_path: str
    line: int
    col: int
    description: str
    rule_id: str | None
    producer_id: str
    stored_at: str


@dataclass(frozen=True)
class CveFindingRow:
    """One row from cve_findings."""

    id: int
    cve_scan_run_id: int
    package_name: str
    package_version: str
    canonical_id: str
    severity: str | None
    cvss_v3: str | None
    cvss_v4: str | None
    summary: str | None
    match_kind: str
    producer_id: str
    stored_at: str


@dataclass(frozen=True)
class DecodedNodeRow:
    """One row from decoded_nodes."""

    id: int
    parent_node_id: int | None
    outer_signal_id: str
    outer_severity: str
    outer_location: str
    outer_length: int
    chain: tuple[str, ...]
    unwrap_status: str
    final_kind: str
    final_size: int
    indicators: tuple[str, ...]
    pickle_warning: bool
    depth: int
    stop_reason: str
    containing_file_sha256: str | None
    containing_file_sha512: str | None
    child_findings: tuple[ChildFindingRow, ...]


@dataclass(frozen=True)
class ChildFindingRow:
    """One row from decoded_child_findings."""

    id: int
    node_id: int
    signal_id: str
    severity: str
    line: int
    col: int
    description: str


@dataclass(frozen=True)
class RunExplanation:
    """Full record for a single run, for `pydepgate db explain --run-id`."""

    run_id: str
    producer_id: str
    command: str
    started_at: str
    pydepgate_ver: str
    artifact: ArtifactRow | None
    findings: tuple[FindingRow, ...]
    decoded_nodes: tuple[DecodedNodeRow, ...]
    cve_findings: tuple[CveFindingRow, ...]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _count(conn: sqlite3.Connection, table: str) -> int:
    row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    return row[0] if row else 0


def _parse_chain(raw: str) -> tuple[str, ...]:
    """Deserialize a JSON-encoded chain array."""
    try:
        return tuple(json.loads(raw))
    except (json.JSONDecodeError, TypeError):
        return ()


def _parse_indicators(raw: str) -> tuple[str, ...]:
    """Deserialize a JSON-encoded indicators array."""
    try:
        return tuple(json.loads(raw))
    except (json.JSONDecodeError, TypeError):
        return ()


def _row_to_finding(row: tuple) -> FindingRow:
    """Map a static_findings SELECT row to a FindingRow.

    Expected column order:
        id, signal_id, analyzer, severity, confidence, scope,
        internal_path, line, col, description,
        rule_id, producer_id, stored_at
    """
    return FindingRow(
        id=row[0],
        signal_id=row[1],
        analyzer=row[2],
        severity=row[3],
        confidence=row[4],
        scope=row[5],
        internal_path=row[6],
        line=row[7],
        col=row[8],
        description=row[9],
        rule_id=row[10],
        producer_id=row[11],
        stored_at=row[12],
    )


def _row_to_child_finding(row: tuple) -> ChildFindingRow:
    """Map a decoded_child_findings SELECT row to a ChildFindingRow.

    Expected column order:
        id, node_id, signal_id, severity, line, col, description
    """
    return ChildFindingRow(
        id=row[0],
        node_id=row[1],
        signal_id=row[2],
        severity=row[3],
        line=row[4],
        col=row[5],
        description=row[6],
    )


def _fetch_child_findings_for_node(
    conn: sqlite3.Connection,
    node_id: int,
) -> tuple[ChildFindingRow, ...]:
    rows = conn.execute(
        "SELECT id, node_id, signal_id, severity, line, col, description"
        " FROM decoded_child_findings"
        " WHERE node_id = ?"
        " ORDER BY line ASC, col ASC",
        (node_id,),
    ).fetchall()
    return tuple(_row_to_child_finding(r) for r in rows)


def _row_to_decoded_node(
    row: tuple,
    child_findings: tuple[ChildFindingRow, ...],
) -> DecodedNodeRow:
    """Map a decoded_nodes SELECT row to a DecodedNodeRow.

    Expected column order:
        id, parent_node_id, outer_signal_id, outer_severity,
        outer_location, outer_length, chain, unwrap_status,
        final_kind, final_size, indicators, pickle_warning,
        depth, stop_reason, containing_file_sha256,
        containing_file_sha512
    """
    return DecodedNodeRow(
        id=row[0],
        parent_node_id=row[1],
        outer_signal_id=row[2],
        outer_severity=row[3],
        outer_location=row[4],
        outer_length=row[5],
        chain=_parse_chain(row[6]),
        unwrap_status=row[7],
        final_kind=row[8],
        final_size=row[9],
        indicators=_parse_indicators(row[10]),
        pickle_warning=bool(row[11]),
        depth=row[12],
        stop_reason=row[13],
        containing_file_sha256=row[14],
        containing_file_sha512=row[15],
        child_findings=child_findings,
    )


def _fetch_decoded_nodes_for_run(
    conn: sqlite3.Connection,
    scan_run_id: int,
) -> tuple[DecodedNodeRow, ...]:
    """Fetch all decoded nodes for a scan run, with child findings attached."""
    rows = conn.execute(
        "SELECT id, parent_node_id,"
        "  outer_signal_id, outer_severity, outer_location, outer_length,"
        "  chain, unwrap_status, final_kind, final_size,"
        "  indicators, pickle_warning, depth, stop_reason,"
        "  containing_file_sha256, containing_file_sha512"
        " FROM decoded_nodes"
        " WHERE scan_run_id = ?"
        " ORDER BY depth ASC, id ASC",
        (scan_run_id,),
    ).fetchall()
    result = []
    for row in rows:
        node_id = row[0]
        child_findings = _fetch_child_findings_for_node(conn, node_id)
        result.append(_row_to_decoded_node(row, child_findings))
    return tuple(result)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_db_status(conn: sqlite3.Connection, db_path: str) -> DbStatus:
    """Return summary counts and metadata for `pydepgate db status`.

    Args:
        conn: An open pdgdb connection.
        db_path: The filesystem path to the database file, for display.

    Returns:
        A DbStatus instance. Count fields are 0 if the table is empty
        or does not exist.
    """
    from pydepgate.dbs.pdgdb.schema import (
        METADATA_KEY_SCHEMA_VERSION,
        METADATA_KEY_PYDEPGATE_VERSION,
        METADATA_KEY_CREATED_AT,
        METADATA_KEY_LAST_MODIFIED,
        read_metadata,
        read_schema_version,
    )

    schema_version = read_schema_version(conn)
    pydepgate_ver = read_metadata(conn, METADATA_KEY_PYDEPGATE_VERSION)
    created_at = read_metadata(conn, METADATA_KEY_CREATED_AT)
    last_modified = read_metadata(conn, METADATA_KEY_LAST_MODIFIED)

    try:
        total_runs = _count(conn, "scan_runs")
        total_artifacts = _count(conn, "scanned_artifacts")
        total_findings = _count(conn, "static_findings")
        total_nodes = _count(conn, "decoded_nodes")
        total_cve = _count(conn, "cve_findings")
    except sqlite3.OperationalError:
        total_runs = total_artifacts = total_findings = total_nodes = total_cve = 0

    return DbStatus(
        db_path=db_path,
        schema_version=schema_version,
        pydepgate_version=pydepgate_ver,
        created_at=created_at,
        last_modified=last_modified,
        total_scan_runs=total_runs,
        total_scanned_artifacts=total_artifacts,
        total_static_findings=total_findings,
        total_decoded_nodes=total_nodes,
        total_cve_findings=total_cve,
    )


def list_runs(
    conn: sqlite3.Connection,
    *,
    limit: int | None = 50,
    offset: int = 0,
) -> list[ScanRunRow]:
    """Return scan runs in reverse chronological order.

    Args:
        conn: An open pdgdb connection.
        limit: Maximum rows to return. None returns all rows.
        offset: Row offset for pagination.

    Returns:
        List of ScanRunRow, newest first.
    """
    actual_limit = limit if limit is not None else -1
    rows = conn.execute(
        "SELECT"
        "  sr.id, sr.run_id, sr.producer_id, sr.command,"
        "  sr.started_at, sr.pydepgate_ver,"
        "  COUNT(DISTINCT sa.id) AS artifact_count,"
        "  COUNT(DISTINCT sf.id) AS finding_count,"
        "  COUNT(DISTINCT cf.id) AS cve_finding_count"
        " FROM scan_runs sr"
        " LEFT JOIN scanned_artifacts sa ON sa.scan_run_id = sr.id"
        " LEFT JOIN static_findings sf ON sf.scan_run_id = sr.id"
        " LEFT JOIN cve_scan_runs csr ON csr.scan_run_id = sr.id"
        " LEFT JOIN cve_findings cf ON cf.cve_scan_run_id = csr.id"
        " GROUP BY sr.id"
        " ORDER BY sr.started_at DESC"
        " LIMIT ? OFFSET ?",
        (actual_limit, offset),
    ).fetchall()
    return [
        ScanRunRow(
            id=r[0],
            run_id=r[1],
            producer_id=r[2],
            command=r[3],
            started_at=r[4],
            pydepgate_ver=r[5],
            artifact_count=r[6],
            finding_count=r[7],
            cve_finding_count=r[8],
        )
        for r in rows
    ]


def query_by_package(
    conn: sqlite3.Connection,
    package_name: str,
    *,
    package_version: str | None = None,
    limit: int | None = 50,
    offset: int = 0,
) -> list[ArtifactRow]:
    """Return scanned artifact records matching a package name.

    Matches on the normalized package_name column (lowercase,
    hyphens replaced with underscores). An optional version string
    further filters results.

    Args:
        conn: An open pdgdb connection.
        package_name: Package name to search for. Normalized before
            querying so "litellm", "LiteLLM", and "lite-llm" all match
            the same rows.
        package_version: Optional version string to filter by.
        limit: Maximum rows to return.
        offset: Row offset for pagination.

    Returns:
        List of ArtifactRow, newest first.
    """
    normalized = package_name.lower().replace("-", "_")
    actual_limit = limit if limit is not None else -1

    if package_version is not None:
        rows = conn.execute(
            "SELECT"
            "  sa.id, sa.scan_run_id, sr.run_id,"
            "  sa.artifact_kind, sa.artifact_identity,"
            "  sa.artifact_sha256, sa.artifact_sha512,"
            "  sa.package_name, sa.package_version, sa.scanned_at,"
            "  COUNT(sf.id) AS finding_count,"
            "  COUNT(DISTINCT cf.id) AS cve_finding_count"
            " FROM scanned_artifacts sa"
            " JOIN scan_runs sr ON sr.id = sa.scan_run_id"
            " LEFT JOIN static_findings sf ON sf.artifact_id = sa.id"
            " LEFT JOIN cve_scan_runs csr ON csr.artifact_id = sa.id"
            " LEFT JOIN cve_findings cf ON cf.cve_scan_run_id = csr.id"
            " WHERE sa.package_name = ? AND sa.package_version = ?"
            " GROUP BY sa.id"
            " ORDER BY sa.scanned_at DESC"
            " LIMIT ? OFFSET ?",
            (normalized, package_version, actual_limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT"
            "  sa.id, sa.scan_run_id, sr.run_id,"
            "  sa.artifact_kind, sa.artifact_identity,"
            "  sa.artifact_sha256, sa.artifact_sha512,"
            "  sa.package_name, sa.package_version, sa.scanned_at,"
            "  COUNT(sf.id) AS finding_count,"
            "  COUNT(DISTINCT cf.id) AS cve_finding_count"
            " FROM scanned_artifacts sa"
            " JOIN scan_runs sr ON sr.id = sa.scan_run_id"
            " LEFT JOIN static_findings sf ON sf.artifact_id = sa.id"
            " LEFT JOIN cve_scan_runs csr ON csr.artifact_id = sa.id"
            " LEFT JOIN cve_findings cf ON cf.cve_scan_run_id = csr.id"
            " WHERE sa.package_name = ?"
            " GROUP BY sa.id"
            " ORDER BY sa.scanned_at DESC"
            " LIMIT ? OFFSET ?",
            (normalized, actual_limit, offset),
        ).fetchall()

    return [
        ArtifactRow(
            id=r[0],
            scan_run_id=r[1],
            run_id=r[2],
            artifact_kind=r[3],
            artifact_identity=r[4],
            artifact_sha256=r[5],
            artifact_sha512=r[6],
            package_name=r[7],
            package_version=r[8],
            scanned_at=r[9],
            finding_count=r[10],
            cve_finding_count=r[11],
        )
        for r in rows
    ]


def query_by_artifact_sha512(
    conn: sqlite3.Connection,
    sha512: str,
    *,
    limit: int | None = 50,
    offset: int = 0,
) -> list[ArtifactRow]:
    """Return scanned artifact records matching an artifact SHA-512.

    Args:
        conn: An open pdgdb connection.
        sha512: Lowercase hex SHA-512 string to match exactly.
        limit: Maximum rows to return.
        offset: Row offset for pagination.

    Returns:
        List of ArtifactRow, newest first.
    """
    actual_limit = limit if limit is not None else -1
    rows = conn.execute(
        "SELECT"
        "  sa.id, sa.scan_run_id, sr.run_id,"
        "  sa.artifact_kind, sa.artifact_identity,"
        "  sa.artifact_sha256, sa.artifact_sha512,"
        "  sa.package_name, sa.package_version, sa.scanned_at,"
        "  COUNT(sf.id) AS finding_count,"
        "  COUNT(DISTINCT cf.id) AS cve_finding_count"
        " FROM scanned_artifacts sa"
        " JOIN scan_runs sr ON sr.id = sa.scan_run_id"
        " LEFT JOIN static_findings sf ON sf.artifact_id = sa.id"
        " LEFT JOIN cve_scan_runs csr ON csr.artifact_id = sa.id"
        " LEFT JOIN cve_findings cf ON cf.cve_scan_run_id = csr.id"
        " WHERE sa.artifact_sha512 = ?"
        " GROUP BY sa.id"
        " ORDER BY sa.scanned_at DESC"
        " LIMIT ? OFFSET ?",
        (sha512.lower(), actual_limit, offset),
    ).fetchall()
    return [
        ArtifactRow(
            id=r[0],
            scan_run_id=r[1],
            run_id=r[2],
            artifact_kind=r[3],
            artifact_identity=r[4],
            artifact_sha256=r[5],
            artifact_sha512=r[6],
            package_name=r[7],
            package_version=r[8],
            scanned_at=r[9],
            finding_count=r[10],
            cve_finding_count=r[11],
        )
        for r in rows
    ]


def explain_run(
    conn: sqlite3.Connection,
    run_id: str,
) -> RunExplanation | None:
    """Return the full structured record for a run by its UUID.

    Fetches the scan_run, its scanned_artifact, all static findings,
    and all decoded nodes with their child findings. Returns None if
    the run_id is not found.

    Args:
        conn: An open pdgdb connection.
        run_id: The UUID4 string of the run to explain.

    Returns:
        RunExplanation, or None if not found.
    """
    run_row = conn.execute(
        "SELECT id, run_id, producer_id, command, started_at, pydepgate_ver"
        " FROM scan_runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if run_row is None:
        return None

    internal_run_id = run_row[0]

    # Artifact: one per scan run in v0.5.0.
    artifact_row = conn.execute(
        "SELECT"
        "  sa.id, sa.scan_run_id, sr.run_id,"
        "  sa.artifact_kind, sa.artifact_identity,"
        "  sa.artifact_sha256, sa.artifact_sha512,"
        "  sa.package_name, sa.package_version, sa.scanned_at,"
        "  COUNT(sf.id) AS finding_count,"
        "  COUNT(DISTINCT cf.id) AS cve_finding_count"
        " FROM scanned_artifacts sa"
        " JOIN scan_runs sr ON sr.id = sa.scan_run_id"
        " LEFT JOIN static_findings sf ON sf.artifact_id = sa.id"
        " LEFT JOIN cve_scan_runs csr ON csr.artifact_id = sa.id"
        " LEFT JOIN cve_findings cf ON cf.cve_scan_run_id = csr.id"
        " WHERE sa.scan_run_id = ?"
        " GROUP BY sa.id",
        (internal_run_id,),
    ).fetchone()

    artifact: ArtifactRow | None = None
    if artifact_row is not None:
        artifact = ArtifactRow(
            id=artifact_row[0],
            scan_run_id=artifact_row[1],
            run_id=artifact_row[2],
            artifact_kind=artifact_row[3],
            artifact_identity=artifact_row[4],
            artifact_sha256=artifact_row[5],
            artifact_sha512=artifact_row[6],
            package_name=artifact_row[7],
            package_version=artifact_row[8],
            scanned_at=artifact_row[9],
            finding_count=artifact_row[10],
            cve_finding_count=artifact_row[11],
        )

    finding_rows = conn.execute(
        "SELECT"
        "  id, signal_id, analyzer, severity, confidence, scope,"
        "  internal_path, line, col, description,"
        "  rule_id, producer_id, stored_at"
        " FROM static_findings"
        " WHERE scan_run_id = ?"
        " ORDER BY internal_path ASC, line ASC, col ASC",
        (internal_run_id,),
    ).fetchall()
    findings = tuple(_row_to_finding(r) for r in finding_rows)

    decoded_nodes = _fetch_decoded_nodes_for_run(conn, internal_run_id)

    cve_finding_rows = conn.execute(
        "SELECT"
        "  cf.id, cf.cve_scan_run_id,"
        "  cf.package_name, cf.package_version, cf.canonical_id,"
        "  cf.severity, cf.cvss_v3, cf.cvss_v4, cf.summary,"
        "  cf.match_kind, cf.producer_id, cf.stored_at"
        " FROM cve_findings cf"
        " JOIN cve_scan_runs csr ON csr.id = cf.cve_scan_run_id"
        " WHERE csr.scan_run_id = ?"
        " ORDER BY cf.canonical_id ASC",
        (internal_run_id,),
    ).fetchall()
    cve_findings = tuple(
        CveFindingRow(
            id=r[0],
            cve_scan_run_id=r[1],
            package_name=r[2],
            package_version=r[3],
            canonical_id=r[4],
            severity=r[5],
            cvss_v3=r[6],
            cvss_v4=r[7],
            summary=r[8],
            match_kind=r[9],
            producer_id=r[10],
            stored_at=r[11],
        )
        for r in cve_finding_rows
    )

    return RunExplanation(
        run_id=run_row[1],
        producer_id=run_row[2],
        command=run_row[3],
        started_at=run_row[4],
        pydepgate_ver=run_row[5],
        artifact=artifact,
        findings=findings,
        decoded_nodes=decoded_nodes,
        cve_findings=cve_findings,
    )
