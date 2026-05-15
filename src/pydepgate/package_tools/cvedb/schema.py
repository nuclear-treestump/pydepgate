"""pydepgate.package_tools.cvedb.schema

SQLite schema for the cvedb subsystem, plus connection helpers
and schema-version verification.

Tables:

  vulnerabilities    Canonical vulnerability records, one row per
                     canonical_id (which is the highest-priority
                     identifier from the OSV record's aliases:
                     CVE > GHSA > PYSEC > the record's own id).

  aliases            Maps every known identifier (the OSV record
                     id, the CVE, the GHSA, the PYSEC, etc.) to
                     the canonical_id. Used both at import time
                     for dedup and at query time for display.

  affected_versions  The (canonical_id, package_name, version)
                     triples used by the depscan CVE lookup. One
                     row per concrete affected version.

  import_warnings    Per-record import issues for diagnostic
                     display (records without versions lists,
                     parse failures, etc.).

  db_metadata        Key-value store for schema version, OSV
                     attribution strings, import provenance.

Public surface:

    connect(path) -> sqlite3.Connection
        Open a connection with foreign_keys ON, WAL journal,
        busy_timeout, and the cvedb application_id set on the
        DB header.

    initialize_schema(conn) -> None
        Apply DDL to a database. Idempotent. Writes the schema
        version into db_metadata if absent.

    check_schema_compatibility(conn) -> None
        Verify the DB schema version matches what this build
        expects. Raises SchemaVersionMismatch on mismatch.

    read_schema_version(conn) -> int | None
        Read the stored schema version, or None if absent.

    write_metadata(conn, key, value) -> None
    write_metadata_dict(conn, mapping) -> None
    read_metadata(conn, key) -> str | None
    read_all_metadata(conn) -> dict[str, str]
        Metadata table accessors.

    drop_all_tables(conn) -> None
        Destructive: drop every cvedb table. Used by the
        importer's full re-import path and by tests.

    SchemaError, SchemaVersionMismatch
        Exception hierarchy.

Constants exposed for use by other cvedb modules:

    METADATA_KEY_*   Well-known db_metadata keys.
    APPLICATION_ID   SQLite application_id for cvedb files.
    BUSY_TIMEOUT_MS  Connection busy timeout.
    DDL_STATEMENTS   Full schema as a tuple, for introspection.
    TABLE_NAMES      Tuple of every cvedb table name.

Picklability: sqlite3.Connection objects are not picklable.
Schema functions take a Connection parameter rather than storing
one as state. This matches the picklability discipline
documented in CONTRIBUTING.md and keeps the module compatible
with any future parallel-import strategy.

Schema versioning: stored in db_metadata under
METADATA_KEY_SCHEMA_VERSION. Callers should call
check_schema_compatibility immediately after opening a cvedb
connection and before doing other work. A version mismatch
indicates the database was written by a different generation of
pydepgate and should be rebuilt rather than read in a degraded
mode.

Application ID: the cvedb file carries a SQLite application_id
of 0x70646763 ("pdgc" in ASCII) so external tools (file(1), the
sqlite3 CLI) can identify a cvedb file unambiguously.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from pydepgate.package_tools.cvedb.constants import CVE_DB_SCHEMA_VERSION

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

# SQLite application_id stored in the DB header. "pdgc" ASCII =
# 0x70646763. Set by connect() on every open; SQLite ignores the
# call if the header already carries this value.
APPLICATION_ID = 0x70646763

# Busy timeout in milliseconds. SQLite waits up to this long for
# a "database is locked" condition before giving up. The cvedb DB
# is mostly read-only after import (the importer is the only
# writer and runs with exclusive access), but the timeout
# tolerates the rare concurrent-reader-during-update case.
BUSY_TIMEOUT_MS = 5000


# Well-known db_metadata keys. The schema module owns the key
# names; the values are written by the importer or other cvedb
# modules using the appropriate sources (constants.py for OSV
# attribution, the import run for provenance).

METADATA_KEY_SCHEMA_VERSION = "schema_version"
METADATA_KEY_LAST_FULL_UPDATE = "last_full_update"
METADATA_KEY_LAST_SNAPSHOT_SHA256 = "last_snapshot_sha256"
METADATA_KEY_DATA_SOURCE_NAME = "data_source_name"
METADATA_KEY_DATA_SOURCE_URL = "data_source_url"
METADATA_KEY_DATA_LICENSE = "data_license"
METADATA_KEY_DATA_LICENSE_URL = "data_license_url"
METADATA_KEY_RECORDS_IMPORTED = "records_imported"
METADATA_KEY_RECORDS_SKIPPED_NO_VERSIONS = "records_skipped_no_versions"
METADATA_KEY_PYDEPGATE_VERSION = "pydepgate_version"


# ---------------------------------------------------------------------------
# DDL statements
# ---------------------------------------------------------------------------

# Each statement runs once per call to initialize_schema. The
# order matters for foreign-key declaration targets:
# vulnerabilities is created before tables that REFERENCE it,
# even though SQLite's deferred FK enforcement would tolerate the
# reverse order. Keeping the natural order makes the DDL readable
# as a top-to-bottom data-flow diagram.

_DDL_CREATE_DB_METADATA = """
CREATE TABLE IF NOT EXISTS db_metadata (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
)
""".strip()

_DDL_CREATE_VULNERABILITIES = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    canonical_id      TEXT PRIMARY KEY NOT NULL,
    summary           TEXT,
    details           TEXT,
    published         TEXT,
    modified          TEXT,
    cvss_v3           TEXT,
    cvss_v4           TEXT,
    severity          TEXT,
    versions_complete INTEGER NOT NULL DEFAULT 1
)
""".strip()

_DDL_CREATE_ALIASES = """
CREATE TABLE IF NOT EXISTS aliases (
    alias        TEXT PRIMARY KEY NOT NULL,
    canonical_id TEXT NOT NULL,
    alias_type   TEXT NOT NULL,
    FOREIGN KEY (canonical_id) REFERENCES vulnerabilities(canonical_id)
        ON DELETE CASCADE
)
""".strip()

_DDL_CREATE_INDEX_ALIASES_CANONICAL = """
CREATE INDEX IF NOT EXISTS idx_aliases_canonical
ON aliases(canonical_id)
""".strip()

_DDL_CREATE_INDEX_ALIASES_TYPE = """
CREATE INDEX IF NOT EXISTS idx_aliases_type
ON aliases(alias_type)
""".strip()

_DDL_CREATE_AFFECTED_VERSIONS = """
CREATE TABLE IF NOT EXISTS affected_versions (
    canonical_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version      TEXT NOT NULL,
    PRIMARY KEY (canonical_id, package_name, version),
    FOREIGN KEY (canonical_id) REFERENCES vulnerabilities(canonical_id)
        ON DELETE CASCADE
)
""".strip()

_DDL_CREATE_INDEX_AV_LOOKUP = """
CREATE INDEX IF NOT EXISTS idx_av_lookup
ON affected_versions(package_name, version)
""".strip()

_DDL_CREATE_INDEX_AV_PACKAGE = """
CREATE INDEX IF NOT EXISTS idx_av_package
ON affected_versions(package_name)
""".strip()

_DDL_CREATE_IMPORT_WARNINGS = """
CREATE TABLE IF NOT EXISTS import_warnings (
    osv_id      TEXT,
    reason      TEXT NOT NULL,
    detail      TEXT,
    imported_at TEXT NOT NULL
)
""".strip()

_DDL_CREATE_INDEX_WARNINGS_REASON = """
CREATE INDEX IF NOT EXISTS idx_warnings_reason
ON import_warnings(reason)
""".strip()


# The full schema as a tuple. Public so tests can introspect and
# so the importer's "what tables do I need to populate" inventory
# is one place rather than scattered.
DDL_STATEMENTS: tuple[str, ...] = (
    _DDL_CREATE_DB_METADATA,
    _DDL_CREATE_VULNERABILITIES,
    _DDL_CREATE_ALIASES,
    _DDL_CREATE_INDEX_ALIASES_CANONICAL,
    _DDL_CREATE_INDEX_ALIASES_TYPE,
    _DDL_CREATE_AFFECTED_VERSIONS,
    _DDL_CREATE_INDEX_AV_LOOKUP,
    _DDL_CREATE_INDEX_AV_PACKAGE,
    _DDL_CREATE_IMPORT_WARNINGS,
    _DDL_CREATE_INDEX_WARNINGS_REASON,
)


# Table names for drop_all_tables and for introspection.
TABLE_NAMES: tuple[str, ...] = (
    "vulnerabilities",
    "aliases",
    "affected_versions",
    "import_warnings",
    "db_metadata",
)


# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------


class SchemaError(Exception):
    """Base class for cvedb schema-related failures."""


class SchemaVersionMismatch(SchemaError):
    """The database's schema version does not match this build.

    Attributes:
        actual: Version stored in the database, or None if no
            schema version metadata was found.
        expected: Version this build expects, always
            CVE_DB_SCHEMA_VERSION at the time of raise.

    The two cases (absent vs mismatched) are distinct in
    operational meaning: absent suggests a pre-versioning build
    or a corrupted DB; mismatched suggests an out-of-date DB
    that needs rebuilding. The exception message reflects which
    case applies.
    """

    def __init__(self, actual: int | None, expected: int) -> None:
        self.actual = actual
        self.expected = expected
        if actual is None:
            super().__init__(
                f"cvedb has no schema version metadata; expected "
                f"version {expected}. Database may be from a "
                f"pre-versioning build or corrupted."
            )
        else:
            super().__init__(
                f"cvedb schema version mismatch: database has "
                f"version {actual}, this build expects "
                f"version {expected}."
            )


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a sqlite3 connection to a cvedb database.

    Configures the connection with:
      * busy_timeout set to BUSY_TIMEOUT_MS
      * foreign_keys ON (required for ON DELETE CASCADE)
      * journal_mode WAL (better concurrent-reader behavior;
        no-op for in-memory databases)
      * application_id set to the cvedb identifier

    The connection's default isolation level (deferred) is
    preserved so callers can use the connection as a context
    manager for transactions:

        with conn:
            conn.execute(...)
            conn.execute(...)
        # committed on clean exit, rolled back on exception

    The caller is responsible for closing the connection.

    Args:
        path: Filesystem path to the database file. ":memory:"
            opens an in-memory database (useful for tests).
            Accepts both str and Path.

    Returns:
        A configured sqlite3.Connection.
    """
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    # journal_mode WAL is sticky once set on a file DB; harmless
    # to set repeatedly. For :memory: databases SQLite returns
    # "memory" as the journal mode regardless and the pragma is
    # effectively a no-op.
    conn.execute("PRAGMA journal_mode = WAL")
    # application_id: SQLite sets the header value silently. If
    # the file already carries a different application_id (which
    # would indicate a misidentified file), the pragma overwrites
    # it. The importer can re-read to verify, but in practice the
    # check_schema_compatibility call catches that case first
    # through the schema_version metadata.
    conn.execute(f"PRAGMA application_id = {APPLICATION_ID}")
    return conn


# ---------------------------------------------------------------------------
# Schema initialization and version verification
# ---------------------------------------------------------------------------


def initialize_schema(conn: sqlite3.Connection) -> None:
    """Apply the cvedb DDL to a database.

    Idempotent: existing tables are not dropped or modified.
    Every DDL statement uses CREATE TABLE IF NOT EXISTS or
    CREATE INDEX IF NOT EXISTS. After applying DDL, writes the
    current CVE_DB_SCHEMA_VERSION into db_metadata if no version
    metadata exists yet. Existing version metadata is NOT
    overwritten, because doing so would mask a schema mismatch
    that the caller needs to detect.

    Wrap in a transaction for atomicity:

        with conn:
            initialize_schema(conn)

    Args:
        conn: An open sqlite3.Connection.
    """
    for statement in DDL_STATEMENTS:
        conn.execute(statement)
    existing = read_schema_version(conn)
    if existing is None:
        write_metadata(
            conn,
            METADATA_KEY_SCHEMA_VERSION,
            str(CVE_DB_SCHEMA_VERSION),
        )


def read_schema_version(conn: sqlite3.Connection) -> int | None:
    """Read the schema version from db_metadata.

    Returns the stored version as an int, or None if no version
    row exists. Raises SchemaError if the row exists but the
    value cannot be parsed as an integer (which would indicate
    a corrupted database or manual tampering).

    A return of None is distinct from a return of 0 or any other
    integer: it means "no schema version metadata at all," which
    is a different condition from "schema version known to be 0."
    """
    raw = read_metadata(conn, METADATA_KEY_SCHEMA_VERSION)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise SchemaError(
            f"schema version metadata is not an integer: {raw!r}"
        ) from exc


def check_schema_compatibility(conn: sqlite3.Connection) -> None:
    """Verify the DB schema version matches this build.

    Raises SchemaVersionMismatch when the version is absent or
    does not match CVE_DB_SCHEMA_VERSION. Returns None on
    success.

    Callers (the importer, the lookup module, the
    `pydepgate cvedb status` subcommand) should call this
    immediately after opening a cvedb connection and before
    doing any other work. A version mismatch indicates the
    database was written by a different generation of pydepgate
    and should be rebuilt via `pydepgate cvedb update --force`
    rather than read in a degraded mode.
    """
    actual = read_schema_version(conn)
    if actual != CVE_DB_SCHEMA_VERSION:
        raise SchemaVersionMismatch(
            actual=actual,
            expected=CVE_DB_SCHEMA_VERSION,
        )


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------


def write_metadata(
    conn: sqlite3.Connection,
    key: str,
    value: str,
) -> None:
    """Write a single db_metadata entry.

    Overwrites any existing value for the key (INSERT OR REPLACE
    semantics). Does not wrap in an internal transaction; the
    caller controls atomicity with `with conn:` if needed.
    """
    conn.execute(
        "INSERT OR REPLACE INTO db_metadata (key, value) VALUES (?, ?)",
        (key, value),
    )


def write_metadata_dict(
    conn: sqlite3.Connection,
    mapping: dict[str, str],
) -> None:
    """Write multiple db_metadata entries in one executemany call.

    Each (key, value) pair uses INSERT OR REPLACE semantics. The
    whole batch is one executemany; not wrapped in an internal
    transaction. The caller controls atomicity:

        with conn:
            write_metadata_dict(conn, {
                METADATA_KEY_LAST_FULL_UPDATE: now_iso,
                METADATA_KEY_RECORDS_IMPORTED: str(count),
                ...
            })
    """
    conn.executemany(
        "INSERT OR REPLACE INTO db_metadata (key, value) VALUES (?, ?)",
        mapping.items(),
    )


def read_metadata(
    conn: sqlite3.Connection,
    key: str,
) -> str | None:
    """Read a single db_metadata value.

    Returns the value as a string, or None if the key is not
    present in the table.
    """
    row = conn.execute(
        "SELECT value FROM db_metadata WHERE key = ?",
        (key,),
    ).fetchone()
    if row is None:
        return None
    return row[0]


def read_all_metadata(conn: sqlite3.Connection) -> dict[str, str]:
    """Read the entire db_metadata table as a dict.

    Used by the `pydepgate cvedb status` subcommand for a
    one-shot snapshot of the DB's provenance, attribution, and
    last-update timestamp.
    """
    rows = conn.execute("SELECT key, value FROM db_metadata").fetchall()
    return {key: value for key, value in rows}


# ---------------------------------------------------------------------------
# Destructive operations
# ---------------------------------------------------------------------------


def drop_all_tables(conn: sqlite3.Connection) -> None:
    """Drop every cvedb table. Destructive.

    Used by the importer's full re-import path (drop, recreate,
    repopulate) and by tests that want a fully clean slate.

    foreign_keys is temporarily disabled because dropping tables
    in the natural order still triggers cascade behavior on
    tables that have not yet been dropped, which the wipe path
    explicitly does not want. foreign_keys is restored to ON
    after the drops complete.
    """
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        for table in TABLE_NAMES:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
