"""pydepgate.dbs.pdgdb.schema

SQLite schema for the pydepgate evidence database (pdgdb).

The evidence database is the persistent memory layer for pydepgate.
It stores records of scan runs, scanned artifacts, file identities,
static findings, decoded tree nodes, and CVE scan runs and findings.
It is distinct from the cvedb (the OSV vulnerability store) and lives
under pydepgate_data_dir() rather than pydepgate_cache_dir(), because
it contains user-generated state that should not be silently deleted
by cache-clearing tools.

Tables
------

  db_metadata
      Key-value store for schema version and other database-level
      metadata. Mirrors the cvedb pattern.

  schema_migrations
      Records of applied schema migrations, keyed by migration ID.
      The migration framework uses this table to determine which
      migrations have been applied and which are pending. Every
      production pdgdb will have this table; absence means the
      database predates the migration framework and should be
      rejected as incompatible.

  scan_runs
      One row per pydepgate invocation that wrote to the database.
      Covers both 'scan' and 'cvescan' command runs. The run_id
      is the UUID4 from run_context; the producer_id identifies
      the subsystem that created the record (e.g. 'cli0' for
      direct CLI invocations, 'worker0' for future daemon workers).

  scanned_artifacts
      One row per artifact processed within a scan run. A single
      scan run produces exactly one artifact row. The artifact row
      carries the artifact-level hashes and the resolved package
      name and version where available.

  file_identities
      One row per distinct file seen within a scanned artifact.
      Keyed by artifact_id and internal_path. Carries the file-level
      hashes. Multiple findings may reference the same file_identity
      row via foreign key.

  static_findings
      One row per active finding produced by the static analysis
      pass. Suppressed findings are not stored. Linked to the
      originating scan_run and scanned_artifact via foreign keys,
      and to the specific file via file_identity_id.

  decoded_nodes
      One row per DecodedNode from the decoded-payload tree. Only
      the structural metadata is stored (chain, indicators, hashes,
      stop reason); payload bytes are never written to the database.
      Nodes are linked to their parent node via parent_node_id for
      tree reconstruction.

  decoded_child_findings
      One row per ChildFinding associated with a decoded_node.
      Normalized out of decoded_nodes so that child findings are
      individually queryable by signal_id, severity, and location.

  cve_scan_runs
      One row per cvescan invocation that wrote to the database.
      Linked to the originating scan_run and scanned_artifact.

  cve_findings
      One row per CVE finding produced by the cvescan pass.
      Linked to the originating cve_scan_run.

Public surface
--------------

    connect(path) -> sqlite3.Connection
        Open a configured connection to a pdgdb database.

    initialize_schema(conn) -> None
        Apply DDL and run pending migrations. Idempotent.

    check_schema_compatibility(conn) -> None
        Verify the stored schema version matches this build.
        Raises SchemaVersionMismatch on mismatch or absence.

    apply_pending_migrations(conn) -> list[str]
        Apply any registered migrations not yet recorded in
        schema_migrations. Returns the list of applied migration
        IDs. Raises MigrationError on failure; the transaction
        is rolled back so the database remains consistent.

    read_schema_version(conn) -> int | None
    write_metadata(conn, key, value) -> None
    write_metadata_dict(conn, mapping) -> None
    read_metadata(conn, key) -> str | None
    read_all_metadata(conn) -> dict[str, str]
        Metadata table accessors.

    drop_all_tables(conn) -> None
        Destructive: drop every pdgdb table. For tests only.

    SchemaError, SchemaVersionMismatch, MigrationError
        Exception hierarchy.

Constants
---------

    PDGDB_SCHEMA_VERSION     Current schema version integer.
    APPLICATION_ID           SQLite application_id for pdgdb files.
    BUSY_TIMEOUT_MS          Connection busy timeout.
    METADATA_KEY_*           Well-known db_metadata keys.
    DDL_STATEMENTS           Full schema DDL as a tuple.
    TABLE_NAMES              Tuple of every pdgdb table name.
    MIGRATIONS               Ordered tuple of (migration_id, sql) pairs.

Database location
-----------------

    pydepgate_data_dir() / "pdgdb" / "evidence.db"

This is under the XDG data directory (not cache), because the
evidence database contains user-generated state that must not be
silently purged by cache-clearing tools. The XDG_DATA_HOME
environment variable overrides the base directory.

Schema versioning
-----------------

Schema version is stored in db_metadata under
METADATA_KEY_SCHEMA_VERSION. check_schema_compatibility raises
SchemaVersionMismatch if the stored version does not match
PDGDB_SCHEMA_VERSION. Unlike the cvedb (which can always be
rebuilt from upstream data), the pdgdb uses a migration framework:
apply_pending_migrations() upgrades an older database in place
rather than requiring a full rebuild.

The MIGRATIONS tuple is the authoritative ordered list of
migrations. Each entry is (migration_id: str, sql: str). A
migration is applied inside a transaction; on success its ID is
written to schema_migrations. A failed migration rolls back and
raises MigrationError with the migration ID and original exception.

For v0.5.0 (schema version 1) the MIGRATIONS tuple is empty
because there is no prior schema to migrate from. The framework
is present so that databases created under v0.5.0 can be upgraded
in place when v0.6.0 introduces schema changes.

Application ID
--------------

The pdgdb file carries SQLite application_id 0x70646764 ("pdgd"
in ASCII, for "pydepgate db") so external tools (file(1), sqlite3
CLI) can identify it. This is distinct from the cvedb application_id
0x70646763 ("pdgc").

Picklability
------------

sqlite3.Connection objects are not picklable. All functions take
a Connection parameter rather than storing one. This matches the
picklability discipline in CONTRIBUTING.md.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

# SQLite application_id for pdgdb files. "pdgd" in ASCII = 0x70646764.
# Distinct from the cvedb application_id (0x70646763 = "pdgc").
APPLICATION_ID = 0x70646764

BUSY_TIMEOUT_MS = 5000

# Current schema version. Bump this when the table layout changes
# incompatibly AND add a corresponding entry to MIGRATIONS.
PDGDB_SCHEMA_VERSION = 1

# Well-known db_metadata keys.
METADATA_KEY_SCHEMA_VERSION = "schema_version"
METADATA_KEY_PYDEPGATE_VERSION = "pydepgate_version"
METADATA_KEY_CREATED_AT = "created_at"
METADATA_KEY_LAST_MODIFIED = "last_modified"

# ---------------------------------------------------------------------------
# DDL statements
# ---------------------------------------------------------------------------

_DDL_CREATE_DB_METADATA = """
CREATE TABLE IF NOT EXISTS db_metadata (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
)
""".strip()

_DDL_CREATE_SCHEMA_MIGRATIONS = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_id TEXT PRIMARY KEY NOT NULL,
    applied_at   TEXT NOT NULL
)
""".strip()

_DDL_CREATE_SCAN_RUNS = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT    NOT NULL UNIQUE,
    producer_id   TEXT    NOT NULL,
    command       TEXT    NOT NULL,
    started_at    TEXT    NOT NULL,
    pydepgate_ver TEXT    NOT NULL
)
""".strip()

_DDL_CREATE_INDEX_SCAN_RUNS_RUN_ID = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_runs_run_id
ON scan_runs(run_id)
""".strip()

_DDL_CREATE_SCANNED_ARTIFACTS = """
CREATE TABLE IF NOT EXISTS scanned_artifacts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id     INTEGER NOT NULL,
    artifact_kind   TEXT    NOT NULL,
    artifact_identity TEXT  NOT NULL,
    artifact_sha256 TEXT,
    artifact_sha512 TEXT,
    package_name    TEXT,
    package_version TEXT,
    scanned_at      TEXT    NOT NULL,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
        ON DELETE CASCADE
)
""".strip()

_DDL_CREATE_INDEX_SCANNED_ARTIFACTS_RUN = """
CREATE INDEX IF NOT EXISTS idx_scanned_artifacts_run
ON scanned_artifacts(scan_run_id)
""".strip()

_DDL_CREATE_INDEX_SCANNED_ARTIFACTS_PACKAGE = """
CREATE INDEX IF NOT EXISTS idx_scanned_artifacts_package
ON scanned_artifacts(package_name, package_version)
""".strip()

_DDL_CREATE_INDEX_SCANNED_ARTIFACTS_SHA512 = """
CREATE INDEX IF NOT EXISTS idx_scanned_artifacts_sha512
ON scanned_artifacts(artifact_sha512)
""".strip()

_DDL_CREATE_FILE_IDENTITIES = """
CREATE TABLE IF NOT EXISTS file_identities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id     INTEGER NOT NULL,
    internal_path   TEXT    NOT NULL,
    file_sha256     TEXT,
    file_sha512     TEXT,
    UNIQUE (artifact_id, internal_path),
    FOREIGN KEY (artifact_id) REFERENCES scanned_artifacts(id)
        ON DELETE CASCADE
)
""".strip()

_DDL_CREATE_INDEX_FILE_IDENTITIES_ARTIFACT = """
CREATE INDEX IF NOT EXISTS idx_file_identities_artifact
ON file_identities(artifact_id)
""".strip()

_DDL_CREATE_INDEX_FILE_IDENTITIES_SHA512 = """
CREATE INDEX IF NOT EXISTS idx_file_identities_sha512
ON file_identities(file_sha512)
""".strip()

_DDL_CREATE_STATIC_FINDINGS = """
CREATE TABLE IF NOT EXISTS static_findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id      INTEGER NOT NULL,
    artifact_id      INTEGER NOT NULL,
    file_identity_id INTEGER,
    signal_id        TEXT    NOT NULL,
    analyzer         TEXT    NOT NULL,
    severity         TEXT    NOT NULL,
    confidence       INTEGER NOT NULL,
    scope            TEXT    NOT NULL,
    internal_path    TEXT    NOT NULL,
    line             INTEGER NOT NULL,
    col              INTEGER NOT NULL,
    description      TEXT    NOT NULL,
    rule_id          TEXT,
    producer_id      TEXT    NOT NULL,
    stored_at        TEXT    NOT NULL,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
        ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES scanned_artifacts(id)
        ON DELETE CASCADE,
    FOREIGN KEY (file_identity_id) REFERENCES file_identities(id)
        ON DELETE SET NULL
)
""".strip()

_DDL_CREATE_INDEX_STATIC_FINDINGS_RUN = """
CREATE INDEX IF NOT EXISTS idx_static_findings_run
ON static_findings(scan_run_id)
""".strip()

_DDL_CREATE_INDEX_STATIC_FINDINGS_ARTIFACT = """
CREATE INDEX IF NOT EXISTS idx_static_findings_artifact
ON static_findings(artifact_id)
""".strip()

_DDL_CREATE_INDEX_STATIC_FINDINGS_SIGNAL = """
CREATE INDEX IF NOT EXISTS idx_static_findings_signal
ON static_findings(signal_id)
""".strip()

_DDL_CREATE_INDEX_STATIC_FINDINGS_SEVERITY = """
CREATE INDEX IF NOT EXISTS idx_static_findings_severity
ON static_findings(severity)
""".strip()

_DDL_CREATE_DECODED_NODES = """
CREATE TABLE IF NOT EXISTS decoded_nodes (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id            INTEGER NOT NULL,
    artifact_id            INTEGER NOT NULL,
    parent_node_id         INTEGER,
    outer_signal_id        TEXT    NOT NULL,
    outer_severity         TEXT    NOT NULL,
    outer_location         TEXT    NOT NULL,
    outer_length           INTEGER NOT NULL,
    chain                  TEXT    NOT NULL,
    unwrap_status          TEXT    NOT NULL,
    final_kind             TEXT    NOT NULL,
    final_size             INTEGER NOT NULL,
    indicators             TEXT    NOT NULL,
    pickle_warning         INTEGER NOT NULL DEFAULT 0,
    depth                  INTEGER NOT NULL,
    stop_reason            TEXT    NOT NULL,
    containing_file_sha256 TEXT,
    containing_file_sha512 TEXT,
    stored_at              TEXT    NOT NULL,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
        ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES scanned_artifacts(id)
        ON DELETE CASCADE,
    FOREIGN KEY (parent_node_id) REFERENCES decoded_nodes(id)
        ON DELETE CASCADE
)
""".strip()

_DDL_CREATE_INDEX_DECODED_NODES_RUN = """
CREATE INDEX IF NOT EXISTS idx_decoded_nodes_run
ON decoded_nodes(scan_run_id)
""".strip()

_DDL_CREATE_INDEX_DECODED_NODES_ARTIFACT = """
CREATE INDEX IF NOT EXISTS idx_decoded_nodes_artifact
ON decoded_nodes(artifact_id)
""".strip()

_DDL_CREATE_INDEX_DECODED_NODES_PARENT = """
CREATE INDEX IF NOT EXISTS idx_decoded_nodes_parent
ON decoded_nodes(parent_node_id)
""".strip()

_DDL_CREATE_DECODED_CHILD_FINDINGS = """
CREATE TABLE IF NOT EXISTS decoded_child_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     INTEGER NOT NULL,
    signal_id   TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    line        INTEGER NOT NULL,
    col         INTEGER NOT NULL,
    description TEXT    NOT NULL,
    FOREIGN KEY (node_id) REFERENCES decoded_nodes(id)
        ON DELETE CASCADE
)
""".strip()

_DDL_CREATE_INDEX_DECODED_CHILD_FINDINGS_NODE = """
CREATE INDEX IF NOT EXISTS idx_decoded_child_findings_node
ON decoded_child_findings(node_id)
""".strip()

_DDL_CREATE_INDEX_DECODED_CHILD_FINDINGS_SIGNAL = """
CREATE INDEX IF NOT EXISTS idx_decoded_child_findings_signal
ON decoded_child_findings(signal_id)
""".strip()

_DDL_CREATE_CVE_SCAN_RUNS = """
CREATE TABLE IF NOT EXISTS cve_scan_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    artifact_id INTEGER NOT NULL,
    cvedb_run_uuid TEXT,
    started_at  TEXT    NOT NULL,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
        ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES scanned_artifacts(id)
        ON DELETE CASCADE
)
""".strip()

_DDL_CREATE_INDEX_CVE_SCAN_RUNS_RUN = """
CREATE INDEX IF NOT EXISTS idx_cve_scan_runs_run
ON cve_scan_runs(scan_run_id)
""".strip()

_DDL_CREATE_CVE_FINDINGS = """
CREATE TABLE IF NOT EXISTS cve_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_scan_run_id INTEGER NOT NULL,
    package_name    TEXT    NOT NULL,
    package_version TEXT    NOT NULL,
    canonical_id    TEXT    NOT NULL,
    severity        TEXT,
    cvss_v3         TEXT,
    cvss_v4         TEXT,
    summary         TEXT,
    match_kind      TEXT    NOT NULL,
    producer_id     TEXT    NOT NULL,
    stored_at       TEXT    NOT NULL,
    FOREIGN KEY (cve_scan_run_id) REFERENCES cve_scan_runs(id)
        ON DELETE CASCADE
)
""".strip()

_DDL_CREATE_INDEX_CVE_FINDINGS_SCAN_RUN = """
CREATE INDEX IF NOT EXISTS idx_cve_findings_scan_run
ON cve_findings(cve_scan_run_id)
""".strip()

_DDL_CREATE_INDEX_CVE_FINDINGS_PACKAGE = """
CREATE INDEX IF NOT EXISTS idx_cve_findings_package
ON cve_findings(package_name, package_version)
""".strip()

_DDL_CREATE_INDEX_CVE_FINDINGS_CANONICAL = """
CREATE INDEX IF NOT EXISTS idx_cve_findings_canonical
ON cve_findings(canonical_id)
""".strip()

# ---------------------------------------------------------------------------
# Public DDL and table name tuples
# ---------------------------------------------------------------------------

DDL_STATEMENTS = (
    _DDL_CREATE_DB_METADATA,
    _DDL_CREATE_SCHEMA_MIGRATIONS,
    _DDL_CREATE_SCAN_RUNS,
    _DDL_CREATE_INDEX_SCAN_RUNS_RUN_ID,
    _DDL_CREATE_SCANNED_ARTIFACTS,
    _DDL_CREATE_INDEX_SCANNED_ARTIFACTS_RUN,
    _DDL_CREATE_INDEX_SCANNED_ARTIFACTS_PACKAGE,
    _DDL_CREATE_INDEX_SCANNED_ARTIFACTS_SHA512,
    _DDL_CREATE_FILE_IDENTITIES,
    _DDL_CREATE_INDEX_FILE_IDENTITIES_ARTIFACT,
    _DDL_CREATE_INDEX_FILE_IDENTITIES_SHA512,
    _DDL_CREATE_STATIC_FINDINGS,
    _DDL_CREATE_INDEX_STATIC_FINDINGS_RUN,
    _DDL_CREATE_INDEX_STATIC_FINDINGS_ARTIFACT,
    _DDL_CREATE_INDEX_STATIC_FINDINGS_SIGNAL,
    _DDL_CREATE_INDEX_STATIC_FINDINGS_SEVERITY,
    _DDL_CREATE_DECODED_NODES,
    _DDL_CREATE_INDEX_DECODED_NODES_RUN,
    _DDL_CREATE_INDEX_DECODED_NODES_ARTIFACT,
    _DDL_CREATE_INDEX_DECODED_NODES_PARENT,
    _DDL_CREATE_DECODED_CHILD_FINDINGS,
    _DDL_CREATE_INDEX_DECODED_CHILD_FINDINGS_NODE,
    _DDL_CREATE_INDEX_DECODED_CHILD_FINDINGS_SIGNAL,
    _DDL_CREATE_CVE_SCAN_RUNS,
    _DDL_CREATE_INDEX_CVE_SCAN_RUNS_RUN,
    _DDL_CREATE_CVE_FINDINGS,
    _DDL_CREATE_INDEX_CVE_FINDINGS_SCAN_RUN,
    _DDL_CREATE_INDEX_CVE_FINDINGS_PACKAGE,
    _DDL_CREATE_INDEX_CVE_FINDINGS_CANONICAL,
)

TABLE_NAMES = (
    "db_metadata",
    "schema_migrations",
    "scan_runs",
    "scanned_artifacts",
    "file_identities",
    "static_findings",
    "decoded_nodes",
    "decoded_child_findings",
    "cve_scan_runs",
    "cve_findings",
)

# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

# Each entry is (migration_id: str, sql: str). Applied in order.
# For schema version 1 (v0.5.0) there are no prior schemas to migrate
# from, so this tuple is empty. Add entries here when future versions
# require schema changes, and bump PDGDB_SCHEMA_VERSION to match.
#
# Format for future entries:
#   ("0002_add_foo_column", "ALTER TABLE bar ADD COLUMN foo TEXT"),
#
# Each migration ID should be unique and sortable. The convention is
# a zero-padded sequential number followed by a short description.
MIGRATIONS: tuple[tuple[str, str], ...] = ()

# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------


class SchemaError(Exception):
    """Base class for pdgdb schema-related failures."""


class SchemaVersionMismatch(SchemaError):
    """The database schema version does not match this build.

    Attributes:
        actual: Version stored in the database, or None if no
            schema version metadata was found.
        expected: PDGDB_SCHEMA_VERSION at the time of raise.
    """

    def __init__(self, actual: int | None, expected: int) -> None:
        self.actual = actual
        self.expected = expected
        if actual is None:
            super().__init__(
                f"pdgdb has no schema version metadata; expected "
                f"version {expected}. The database may be from a "
                f"pre-versioning build or may be corrupted."
            )
        else:
            super().__init__(
                f"pdgdb schema version mismatch: database has "
                f"version {actual}, this build expects "
                f"version {expected}. Run "
                f"'pydepgate db migrate' to upgrade."
            )


class MigrationError(SchemaError):
    """A schema migration failed.

    Attributes:
        migration_id: The ID of the migration that failed.
        cause: The underlying exception.
    """

    def __init__(self, migration_id: str, cause: Exception) -> None:
        self.migration_id = migration_id
        self.cause = cause
        super().__init__(f"Migration '{migration_id}' failed: {cause}")


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a sqlite3 connection to a pdgdb database.

    Configures the connection with:
      * busy_timeout set to BUSY_TIMEOUT_MS
      * foreign_keys ON (required for ON DELETE CASCADE)
      * journal_mode WAL (better concurrent-reader behavior)
      * application_id set to the pdgdb identifier

    The caller is responsible for closing the connection.
    Use as a context manager for transactions:

        with conn:
            conn.execute(...)
        # committed on clean exit, rolled back on exception

    Args:
        path: Filesystem path to the database file. ":memory:"
            opens an in-memory database for tests. Accepts
            both str and Path.

    Returns:
        A configured sqlite3.Connection.
    """
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(f"PRAGMA application_id = {APPLICATION_ID}")
    return conn


# ---------------------------------------------------------------------------
# Schema initialization
# ---------------------------------------------------------------------------


def initialize_schema(conn: sqlite3.Connection) -> None:
    """Apply pdgdb DDL and run pending migrations.

    Idempotent: uses CREATE TABLE IF NOT EXISTS and CREATE INDEX
    IF NOT EXISTS throughout. After applying DDL, writes the
    current PDGDB_SCHEMA_VERSION into db_metadata if no version
    metadata exists yet. Existing version metadata is NOT
    overwritten so that a schema mismatch remains detectable.

    After DDL, calls apply_pending_migrations(conn). For a fresh
    database this is a no-op (MIGRATIONS is empty for v0.5.0).
    For an upgraded database it applies any pending migrations
    in order.

    Args:
        conn: An open pdgdb connection.
    """
    import datetime

    with conn:
        for statement in DDL_STATEMENTS:
            conn.execute(statement)

    # Write schema version only if absent. An existing value must
    # not be overwritten; callers detect mismatches via
    # check_schema_compatibility, which reads this value.
    if read_metadata(conn, METADATA_KEY_SCHEMA_VERSION) is None:
        import pydepgate

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_metadata_dict(
            conn,
            {
                METADATA_KEY_SCHEMA_VERSION: str(PDGDB_SCHEMA_VERSION),
                METADATA_KEY_PYDEPGATE_VERSION: pydepgate.__version__,
                METADATA_KEY_CREATED_AT: now,
                METADATA_KEY_LAST_MODIFIED: now,
            },
        )

    apply_pending_migrations(conn)


def check_schema_compatibility(conn: sqlite3.Connection) -> None:
    """Verify the database schema version matches this build.

    Raises SchemaVersionMismatch if the stored version is absent
    or does not match PDGDB_SCHEMA_VERSION. Callers should invoke
    this immediately after opening a pdgdb connection and before
    doing other work.

    Unlike the cvedb which hard-rejects mismatches (because it
    can always be rebuilt from upstream data), the pdgdb directs
    callers to run 'pydepgate db migrate' to upgrade in place.

    Args:
        conn: An open pdgdb connection.

    Raises:
        SchemaVersionMismatch: if the version is absent or wrong.
    """
    version = read_schema_version(conn)
    if version != PDGDB_SCHEMA_VERSION:
        raise SchemaVersionMismatch(
            actual=version,
            expected=PDGDB_SCHEMA_VERSION,
        )


def read_schema_version(conn: sqlite3.Connection) -> int | None:
    """Read the stored schema version, or None if absent.

    Returns None both when db_metadata does not exist and when it
    exists but has no schema_version entry. The caller should
    treat both cases as an incompatible database.

    Args:
        conn: An open pdgdb connection.

    Returns:
        The schema version integer, or None.
    """
    try:
        row = conn.execute(
            "SELECT value FROM db_metadata WHERE key = ?",
            (METADATA_KEY_SCHEMA_VERSION,),
        ).fetchone()
        return int(row[0]) if row else None
    except sqlite3.OperationalError:
        # db_metadata table does not exist.
        return None


# ---------------------------------------------------------------------------
# Migration framework
# ---------------------------------------------------------------------------


def apply_pending_migrations(conn: sqlite3.Connection) -> list[str]:
    """Apply any registered migrations not yet in schema_migrations.

    Iterates MIGRATIONS in order. For each entry, checks whether
    migration_id is already in schema_migrations; if not, applies
    the SQL inside a transaction, then records the migration ID
    and current timestamp.

    On failure, the transaction for the failing migration is rolled
    back (the database remains in the last successfully migrated
    state) and MigrationError is raised.

    After all migrations are applied, updates
    METADATA_KEY_SCHEMA_VERSION in db_metadata to
    PDGDB_SCHEMA_VERSION. This keeps the metadata block consistent
    with the actual schema state.

    Args:
        conn: An open pdgdb connection.

    Returns:
        List of migration IDs that were applied in this call.
        Empty list if no migrations were pending.

    Raises:
        MigrationError: if any migration SQL fails.
    """
    import datetime

    applied: list[str] = []

    for migration_id, sql in MIGRATIONS:
        row = conn.execute(
            "SELECT migration_id FROM schema_migrations WHERE migration_id = ?",
            (migration_id,),
        ).fetchone()
        if row is not None:
            continue

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with conn:
                conn.execute(sql)
                conn.execute(
                    "INSERT INTO schema_migrations (migration_id, applied_at)"
                    " VALUES (?, ?)",
                    (migration_id, now),
                )
        except Exception as exc:
            raise MigrationError(migration_id, exc) from exc

        applied.append(migration_id)

    if applied:
        write_metadata(conn, METADATA_KEY_SCHEMA_VERSION, str(PDGDB_SCHEMA_VERSION))

    return applied


def list_applied_migrations(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """Return all applied migrations as (migration_id, applied_at) tuples.

    Returns an empty list if the schema_migrations table is empty
    or does not exist.

    Args:
        conn: An open pdgdb connection.

    Returns:
        List of (migration_id, applied_at) tuples, ordered by applied_at.
    """
    try:
        rows = conn.execute(
            "SELECT migration_id, applied_at FROM schema_migrations"
            " ORDER BY applied_at ASC"
        ).fetchall()
        return [(r[0], r[1]) for r in rows]
    except sqlite3.OperationalError:
        return []


# ---------------------------------------------------------------------------
# Metadata accessors
# ---------------------------------------------------------------------------


def write_metadata(
    conn: sqlite3.Connection,
    key: str,
    value: str,
) -> None:
    """Write a single key-value pair to db_metadata.

    Uses INSERT OR REPLACE so repeated calls with the same key
    update the stored value rather than raising a uniqueness
    violation.

    Args:
        conn: An open pdgdb connection.
        key: The metadata key.
        value: The metadata value (always a string).
    """
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO db_metadata (key, value) VALUES (?, ?)",
            (key, value),
        )


def write_metadata_dict(
    conn: sqlite3.Connection,
    mapping: dict[str, str],
) -> None:
    """Write multiple key-value pairs to db_metadata atomically.

    Equivalent to calling write_metadata for each entry but
    wrapped in a single transaction so either all writes succeed
    or none do.

    Args:
        conn: An open pdgdb connection.
        mapping: Dict of key -> value pairs to write.
    """
    with conn:
        conn.executemany(
            "INSERT OR REPLACE INTO db_metadata (key, value) VALUES (?, ?)",
            list(mapping.items()),
        )


def read_metadata(
    conn: sqlite3.Connection,
    key: str,
) -> str | None:
    """Read a single metadata value by key, or None if absent.

    Args:
        conn: An open pdgdb connection.
        key: The metadata key to look up.

    Returns:
        The stored string value, or None if the key is not present.
    """
    try:
        row = conn.execute(
            "SELECT value FROM db_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        return row[0] if row else None
    except sqlite3.OperationalError:
        return None


def read_all_metadata(conn: sqlite3.Connection) -> dict[str, str]:
    """Read all key-value pairs from db_metadata.

    Returns an empty dict if db_metadata does not exist or is
    empty.

    Args:
        conn: An open pdgdb connection.

    Returns:
        Dict of all stored key -> value pairs.
    """
    try:
        rows = conn.execute(
            "SELECT key, value FROM db_metadata ORDER BY key ASC"
        ).fetchall()
        return {r[0]: r[1] for r in rows}
    except sqlite3.OperationalError:
        return {}


# ---------------------------------------------------------------------------
# Destructive helpers (tests only)
# ---------------------------------------------------------------------------


def drop_all_tables(conn: sqlite3.Connection) -> None:
    """Drop every pdgdb table.

    DESTRUCTIVE. Intended for test teardown only. Drops tables in
    an order that satisfies foreign-key constraints (children
    before parents). Indices are dropped automatically with their
    tables.

    Args:
        conn: An open pdgdb connection.
    """
    drop_order = (
        "decoded_child_findings",
        "decoded_nodes",
        "cve_findings",
        "cve_scan_runs",
        "static_findings",
        "file_identities",
        "scanned_artifacts",
        "scan_runs",
        "schema_migrations",
        "db_metadata",
    )
    with conn:
        for table in drop_order:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
