"""pydepgate.dbs.pdgdb.writer

Write pydepgate scan results to the evidence database.

Public surface
--------------

    write_scan_result(conn, result, *, command, producer_id) -> int
        Persist a ScanResult to the database. Returns the scan_run rowid.
        Writes scan_run, scanned_artifact, file_identities, and
        static_findings in a single atomic transaction.

    write_decoded_tree(conn, tree, *, scan_run_id, artifact_id,
                       producer_id) -> None
        Persist a DecodedTree to the database. Writes decoded_nodes and
        decoded_child_findings in a single atomic transaction. Separate
        from write_scan_result because decode is an optional subcontractor:
        a failure here does not roll back the main scan record.

Design notes
------------

Atomicity: write_scan_result is one transaction. write_decoded_tree is
a second independent transaction. A failure writing decoded nodes does
not roll back static findings; the static findings are the primary
forensic record.

producer_id: callers supply this explicitly. CLI callers pass "cli0".
Future daemon workers pass their subsystem ID. The writer never
hardcodes a producer ID.

rule_id: Finding does not carry the applied rule ID in v0.5.0 (it
lives on EvaluationResult.rule_applied, which does not survive into
ScanResult). rule_id is stored as NULL. A future delivery will thread
rule_applied.rule_id through ScanResult when the rules engine is
refactored to expose it.

file_identity deduplication: the file_identities table has a UNIQUE
constraint on (artifact_id, internal_path). The writer uses INSERT OR
IGNORE followed by SELECT id to handle the case where two findings in
the same artifact reference the same file. This is safe with FK
references because the rowid is never replaced.

chain and indicators serialization: DecodedNode.chain and .indicators
are tuples of strings. They are stored as JSON arrays (via json.dumps)
so they are unambiguously parseable on read and safe for element values
that contain commas or other delimiters.

Timestamps: all stored_at / started_at / scanned_at values are ISO 8601
UTC strings produced by datetime.now(timezone.utc).isoformat().

Package name and version: resolved from ScanResult where possible.
For installed-env scans, artifact_identity is the package name; version
is resolved via importlib.metadata if available. For wheel and sdist
scans, name and version are parsed from the filename via
_parse_wheel_name. For loose-file scans, both are None. This covers
the common cases without blocking on a full metadata-extraction pass.
"""

from __future__ import annotations

import datetime
import importlib.metadata
import json
import re
import sqlite3
from pathlib import Path

from pydepgate.engines.base import ArtifactKind, Finding, ScanResult
from pydepgate.enrichers.decode_payloads import ChildFinding, DecodedNode, DecodedTree
from pydepgate.dbs.pdgdb import schema

# ---------------------------------------------------------------------------
# Wheel filename parser
# ---------------------------------------------------------------------------

# sdist: {name}-{version}.tar.gz / .tar.bz2 / .tar.xz / .zip
_SDIST_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"-(?P<version>[A-Za-z0-9][A-Za-z0-9.*+!_-]*)"
    r"\.(tar\.gz|tar\.bz2|tar\.xz|zip)$"
)


def _parse_wheel_name(filename: str) -> tuple[str, str] | tuple[None, None]:
    """Extract (package_name, version) from a wheel filename.

    PEP 427 structure: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl

    Split from the right: the last three segments are always platform,
    abi, python tag. If the fourth-from-right segment starts with a digit
    it is a build tag and is dropped. The remaining segments rejoin as
    name-version, split at the first '-' to separate them.

    This handles hyphenated package names (some-package-1.0.0-...) because
    we never split from the left.

    Returns (None, None) if the filename does not look like a wheel.
    Name is normalized to lowercase with hyphens replaced by underscores.
    """
    name = Path(filename).name
    if not name.endswith(".whl"):
        return None, None
    stem = name[:-4]
    parts = stem.split("-")
    # Minimum: name, version, python, abi, platform = 5 parts.
    if len(parts) < 5:
        return None, None
    # Strip the three fixed trailing tags.
    remainder = parts[:-3]
    # Drop a build tag if present. A build tag is a purely-numeric segment
    # immediately after the version. If remainder has more than 2 parts
    # and the last segment is purely numeric, it is a build tag.
    if len(remainder) > 2 and remainder[-1].isdigit():
        remainder = remainder[:-1]
    # remainder is now [name_parts..., version]. The version is the last
    # segment; everything before it is the name.
    if len(remainder) < 2:
        return None, None
    version = remainder[-1]
    pkg_name = "-".join(remainder[:-1]).lower().replace("-", "_")
    return pkg_name, version


def _parse_sdist_name(filename: str) -> tuple[str, str] | tuple[None, None]:
    """Extract (package_name, version) from a sdist filename."""
    m = _SDIST_RE.match(Path(filename).name)
    if m:
        name = m.group("name").lower().replace("-", "_")
        return name, m.group("version")
    return None, None


def _resolve_package_identity(
    result: ScanResult,
) -> tuple[str | None, str | None]:
    """Resolve (package_name, package_version) from a ScanResult.

    Resolution strategy by artifact kind:
      WHEEL       parse from filename via _parse_wheel_name
      SDIST       parse from filename via _parse_sdist_name
      INSTALLED_ENV  artifact_identity is the package name; version
                  from importlib.metadata if available
      LOOSE_FILE  None, None

    Returns (None, None) when resolution is not possible. The columns
    are nullable; callers store whatever is returned without raising.
    """
    kind = result.artifact_kind

    if kind is ArtifactKind.WHEEL:
        return _parse_wheel_name(result.artifact_identity)

    if kind is ArtifactKind.SDIST:
        return _parse_sdist_name(result.artifact_identity)

    if kind is ArtifactKind.INSTALLED_ENV:
        name = result.artifact_identity.lower().replace("-", "_")
        try:
            dist = importlib.metadata.distribution(result.artifact_identity)
            version = dist.metadata.get("Version")
            return name, version
        except importlib.metadata.PackageNotFoundError:
            return name, None

    return None, None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _touch_last_modified(conn: sqlite3.Connection) -> None:
    """Update METADATA_KEY_LAST_MODIFIED to the current UTC time.

    Called after every successful write to the evidence database so
    'db init' and 'db status' can report when the database was last
    touched. Uses write_metadata which is INSERT OR REPLACE, so the
    key is created on first write and updated on all subsequent ones.
    """
    schema.write_metadata(
        conn,
        schema.METADATA_KEY_LAST_MODIFIED,
        _now_utc(),
    )


def _insert_scan_run(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    producer_id: str,
    command: str,
    started_at: str,
    pydepgate_ver: str,
) -> int:
    """Insert a scan_runs row and return its rowid."""
    cur = conn.execute(
        "INSERT INTO scan_runs"
        " (run_id, producer_id, command, started_at, pydepgate_ver)"
        " VALUES (?, ?, ?, ?, ?)",
        (run_id, producer_id, command, started_at, pydepgate_ver),
    )
    return cur.lastrowid


def _insert_scanned_artifact(
    conn: sqlite3.Connection,
    *,
    scan_run_id: int,
    artifact_kind: str,
    artifact_identity: str,
    artifact_sha256: str | None,
    artifact_sha512: str | None,
    package_name: str | None,
    package_version: str | None,
    scanned_at: str,
) -> int:
    """Insert a scanned_artifacts row and return its rowid."""
    cur = conn.execute(
        "INSERT INTO scanned_artifacts"
        " (scan_run_id, artifact_kind, artifact_identity,"
        "  artifact_sha256, artifact_sha512,"
        "  package_name, package_version, scanned_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_run_id,
            artifact_kind,
            artifact_identity,
            artifact_sha256,
            artifact_sha512,
            package_name,
            package_version,
            scanned_at,
        ),
    )
    return cur.lastrowid


def _get_or_insert_file_identity(
    conn: sqlite3.Connection,
    *,
    artifact_id: int,
    internal_path: str,
    file_sha256: str | None,
    file_sha512: str | None,
) -> int:
    """Return the rowid for a file_identity row, inserting if absent.

    Uses INSERT OR IGNORE followed by SELECT to avoid changing the
    rowid on a row that already exists, which would break existing
    FK references from static_findings.
    """
    conn.execute(
        "INSERT OR IGNORE INTO file_identities"
        " (artifact_id, internal_path, file_sha256, file_sha512)"
        " VALUES (?, ?, ?, ?)",
        (artifact_id, internal_path, file_sha256, file_sha512),
    )
    row = conn.execute(
        "SELECT id FROM file_identities" " WHERE artifact_id = ? AND internal_path = ?",
        (artifact_id, internal_path),
    ).fetchone()
    return row[0]


def _insert_static_finding(
    conn: sqlite3.Connection,
    *,
    scan_run_id: int,
    artifact_id: int,
    file_identity_id: int | None,
    finding: Finding,
    producer_id: str,
    stored_at: str,
) -> int:
    """Insert a static_findings row and return its rowid."""
    signal = finding.signal
    cur = conn.execute(
        "INSERT INTO static_findings"
        " (scan_run_id, artifact_id, file_identity_id,"
        "  signal_id, analyzer, severity, confidence, scope,"
        "  internal_path, line, col, description,"
        "  rule_id, producer_id, stored_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_run_id,
            artifact_id,
            file_identity_id,
            signal.signal_id,
            signal.analyzer,
            finding.severity.value,
            int(signal.confidence),
            signal.scope.name,
            finding.context.internal_path.replace("\\", "/"),
            signal.location.line,
            signal.location.column,
            signal.description,
            None,  # rule_id: not available on Finding in v0.5.0
            producer_id,
            stored_at,
        ),
    )
    return cur.lastrowid


def _insert_decoded_node(
    conn: sqlite3.Connection,
    *,
    scan_run_id: int,
    artifact_id: int,
    parent_node_id: int | None,
    node: DecodedNode,
    stored_at: str,
) -> int:
    """Insert a decoded_nodes row and return its rowid."""
    cur = conn.execute(
        "INSERT INTO decoded_nodes"
        " (scan_run_id, artifact_id, parent_node_id,"
        "  outer_signal_id, outer_severity, outer_location, outer_length,"
        "  chain, unwrap_status, final_kind, final_size,"
        "  indicators, pickle_warning, depth, stop_reason,"
        "  containing_file_sha256, containing_file_sha512, stored_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_run_id,
            artifact_id,
            parent_node_id,
            node.outer_signal_id,
            node.outer_severity,
            node.outer_location,
            node.outer_length,
            json.dumps(list(node.chain)),
            node.unwrap_status,
            node.final_kind,
            node.final_size,
            json.dumps(list(node.indicators)),
            1 if node.pickle_warning else 0,
            node.depth,
            node.stop_reason,
            node.containing_file_sha256,
            node.containing_file_sha512,
            stored_at,
        ),
    )
    return cur.lastrowid


def _insert_child_findings(
    conn: sqlite3.Connection,
    node_id: int,
    child_findings: tuple[ChildFinding, ...],
) -> None:
    """Insert all decoded_child_findings rows for a node."""
    if not child_findings:
        return
    conn.executemany(
        "INSERT INTO decoded_child_findings"
        " (node_id, signal_id, severity, line, col, description)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [
            (node_id, cf.signal_id, cf.severity, cf.line, cf.column, cf.description)
            for cf in child_findings
        ],
    )


def _write_node_recursive(
    conn: sqlite3.Connection,
    node: DecodedNode,
    *,
    scan_run_id: int,
    artifact_id: int,
    parent_node_id: int | None,
    stored_at: str,
) -> None:
    """Recursively write a DecodedNode and all its descendants."""
    node_id = _insert_decoded_node(
        conn,
        scan_run_id=scan_run_id,
        artifact_id=artifact_id,
        parent_node_id=parent_node_id,
        node=node,
        stored_at=stored_at,
    )
    _insert_child_findings(conn, node_id, node.child_findings)
    for child in node.children:
        _write_node_recursive(
            conn,
            child,
            scan_run_id=scan_run_id,
            artifact_id=artifact_id,
            parent_node_id=node_id,
            stored_at=stored_at,
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def write_scan_result(
    conn: sqlite3.Connection,
    result: ScanResult,
    *,
    command: str,
    producer_id: str,
) -> tuple[int, int]:
    """Persist a ScanResult to the evidence database.

    Writes scan_run, scanned_artifact, file_identities, and
    static_findings in a single atomic transaction. Suppressed findings
    are not written.

    Args:
        conn: An open pdgdb connection. Must have schema initialized
            and schema compatibility verified by the caller.
        result: The ScanResult to persist.
        command: The CLI command that produced this result.
            Use "scan" for pydepgate scan.
        producer_id: Subsystem identifier for the writing process.
            CLI callers pass "cli0".

    Returns:
        (scan_run_id, artifact_id) as a tuple of integer rowids.
        Both are needed by the caller to pass to write_decoded_tree.

    Raises:
        sqlite3.Error: on any database failure. The transaction is
            rolled back automatically by the context manager.
    """
    import pydepgate

    now = _now_utc()
    package_name, package_version = _resolve_package_identity(result)

    with conn:
        scan_run_id = _insert_scan_run(
            conn,
            run_id=result.scan_id,
            producer_id=producer_id,
            command=command,
            started_at=now,
            pydepgate_ver=pydepgate.__version__,
        )
        artifact_id = _insert_scanned_artifact(
            conn,
            scan_run_id=scan_run_id,
            artifact_kind=result.artifact_kind.value,
            artifact_identity=result.artifact_identity,
            artifact_sha256=result.artifact_sha256,
            artifact_sha512=result.artifact_sha512,
            package_name=package_name,
            package_version=package_version,
            scanned_at=now,
        )

        for finding in result.findings:
            file_identity_id = _get_or_insert_file_identity(
                conn,
                artifact_id=artifact_id,
                internal_path=finding.context.internal_path.replace("\\", "/"),
                file_sha256=finding.context.file_sha256,
                file_sha512=finding.context.file_sha512,
            )
            _insert_static_finding(
                conn,
                scan_run_id=scan_run_id,
                artifact_id=artifact_id,
                file_identity_id=file_identity_id,
                finding=finding,
                producer_id=producer_id,
                stored_at=now,
            )
    _touch_last_modified(conn)
    return scan_run_id, artifact_id


def write_decoded_tree(
    conn: sqlite3.Connection,
    tree: DecodedTree,
    *,
    scan_run_id: int,
    artifact_id: int,
) -> None:
    """Persist a DecodedTree to the evidence database.

    Writes decoded_nodes and decoded_child_findings in a single atomic
    transaction. Separate from write_scan_result: a failure here does
    not roll back static findings.

    IOC payload bytes (decoded_source in IOCData) are never written to
    the database. Only structural metadata is stored: chain, indicators,
    hashes, stop_reason, and child findings.

    Args:
        conn: An open pdgdb connection.
        tree: The DecodedTree to persist.
        scan_run_id: The rowid of the scan_run record that owns this
            tree. Returned by write_scan_result.
        artifact_id: The rowid of the scanned_artifact record.
            Returned by write_scan_result.

    Raises:
        sqlite3.Error: on any database failure. The transaction is
            rolled back automatically.
    """
    if not tree.nodes:
        return

    stored_at = _now_utc()

    with conn:
        for node in tree.nodes:
            _write_node_recursive(
                conn,
                node,
                scan_run_id=scan_run_id,
                artifact_id=artifact_id,
                parent_node_id=None,
                stored_at=stored_at,
            )
    _touch_last_modified(conn)


def _hash_artifact_file(
    artifact_path,
) -> tuple[str | None, str | None]:
    """Return (sha256_hex, sha512_hex) for an artifact file.

    Returns (None, None) if the path is None, does not exist, or
    cannot be read. Hashing is best-effort; cvescan results remain
    writable even when the artifact file is unavailable.
    """
    import hashlib

    if artifact_path is None:
        return None, None
    try:
        data = artifact_path.read_bytes()
        return (
            hashlib.sha256(data).hexdigest(),
            hashlib.sha512(data).hexdigest(),
        )
    except OSError:
        return None, None


def write_cve_scan_result(
    conn: sqlite3.Connection,
    result,
    *,
    producer_id: str,
) -> None:
    """Persist a CveScanResult to the evidence database.

    Writes scan_run, scanned_artifact, cve_scan_run, and cve_findings
    in a single atomic transaction. Results with no package name or
    version are written with null identity fields; findings are still
    persisted if present.

    Args:
        conn: An open pdgdb connection with schema initialized.
        result: A CveScanResult from the cvescanner.
        producer_id: Subsystem identifier. CLI callers pass "cli0".

    Raises:
        sqlite3.Error: on any database failure. Transaction is rolled
            back automatically.
    """
    import pydepgate
    from pydepgate.engines.base import ArtifactKind
    from pydepgate import run_context

    now = _now_utc()

    meta = result.package_metadata
    artifact_path = getattr(meta, "artifact_path", None)
    artifact_identity = (
        str(artifact_path) if artifact_path else (result.package_name or "(unknown)")
    )
    artifact_sha256, artifact_sha512 = _hash_artifact_file(artifact_path)

    # Determine artifact kind from metadata.
    artifact_type = getattr(meta, "artifact_type", None) if meta else None
    if artifact_type == "wheel":
        artifact_kind = ArtifactKind.WHEEL.value
    elif artifact_type in ("sdist", "tar.gz"):
        artifact_kind = ArtifactKind.SDIST.value
    else:
        artifact_kind = ArtifactKind.LOOSE_FILE.value

    package_name = result.normalized_package_name or result.package_name
    package_version = result.package_version

    with conn:
        scan_run_id = _insert_scan_run(
            conn,
            run_id=run_context.get_current_run_uuid(),
            producer_id=producer_id,
            command="cvescan",
            started_at=now,
            pydepgate_ver=pydepgate.__version__,
        )
        artifact_id = _insert_scanned_artifact(
            conn,
            scan_run_id=scan_run_id,
            artifact_kind=artifact_kind,
            artifact_identity=artifact_identity,
            artifact_sha256=artifact_sha256,
            artifact_sha512=artifact_sha512,
            package_name=package_name,
            package_version=package_version,
            scanned_at=now,
        )
        cve_run_cur = conn.execute(
            "INSERT INTO cve_scan_runs"
            " (scan_run_id, artifact_id, cvedb_run_uuid, started_at)"
            " VALUES (?, ?, ?, ?)",
            (
                scan_run_id,
                artifact_id,
                None,  # cvedb_run_uuid not available at cvescan time
                now,
            ),
        )
        cve_scan_run_id = cve_run_cur.lastrowid

        if result.findings:
            conn.executemany(
                "INSERT INTO cve_findings"
                " (cve_scan_run_id, package_name, package_version,"
                "  canonical_id, severity, cvss_v3, cvss_v4, summary,"
                "  match_kind, producer_id, stored_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        cve_scan_run_id,
                        finding.package_name,
                        finding.package_version,
                        finding.canonical_id,
                        finding.severity,
                        finding.cvss_v3,
                        finding.cvss_v4,
                        finding.summary,
                        finding.match_type,
                        producer_id,
                        now,
                    )
                    for finding in result.findings
                ],
            )

    _touch_last_modified(conn)
