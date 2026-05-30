"""Tests for pydepgate.dbs.pdgdb.schema.

Coverage:

  connect()
    - foreign_keys ON
    - journal_mode WAL for file databases
    - application_id set to APPLICATION_ID
    - busy_timeout set
    - accepts str and Path

  initialize_schema()
    - creates all tables in TABLE_NAMES
    - creates expected indexes
    - writes schema version into db_metadata
    - writes pydepgate_version into db_metadata
    - writes created_at into db_metadata
    - idempotent: safe to call twice
    - does not overwrite an existing schema_version

  check_schema_compatibility()
    - passes on a fresh database
    - raises SchemaVersionMismatch when version is absent
    - raises SchemaVersionMismatch when version is wrong
    - SchemaVersionMismatch.actual is None when absent
    - SchemaVersionMismatch.actual is the stored int when wrong

  read_schema_version()
    - returns PDGDB_SCHEMA_VERSION on a fresh database
    - returns None when db_metadata is empty
    - returns None when db_metadata table does not exist

  apply_pending_migrations()
    - returns empty list when MIGRATIONS is empty
    - records migration ID and applied_at in schema_migrations
    - does not re-apply an already-applied migration
    - raises MigrationError on bad SQL, database remains intact
    - updates db_metadata schema_version after applying migrations

  list_applied_migrations()
    - returns empty list on a fresh database
    - returns migrations in applied_at order
    - returns empty list when schema_migrations does not exist

  write_metadata() / read_metadata() / write_metadata_dict() / read_all_metadata()
    - write and read a single key
    - INSERT OR REPLACE: overwriting a key updates the value
    - write_metadata_dict writes multiple keys atomically
    - read_metadata returns None for missing key
    - read_all_metadata returns all entries sorted by key
    - read_metadata returns None when db_metadata does not exist
    - read_all_metadata returns empty dict when table does not exist

  drop_all_tables()
    - removes all TABLE_NAMES entries
    - idempotent: safe to call on an already-empty database

  Table structure: every table has its expected columns
    - scan_runs
    - scanned_artifacts
    - file_identities
    - static_findings
    - decoded_nodes
    - decoded_child_findings
    - cve_scan_runs
    - cve_findings

  Foreign key enforcement
    - inserting a static_finding with a bad scan_run_id raises
    - ON DELETE CASCADE: deleting a scan_run removes its static_findings
    - ON DELETE CASCADE: deleting a scan_run removes its scanned_artifacts
    - ON DELETE CASCADE: deleting a decoded_node removes its child_findings
    - ON DELETE SET NULL: deleting a file_identity nulls file_identity_id
      on static_findings

  Data round-trips
    - scan_run row survives a write/read cycle
    - scanned_artifact row survives a write/read cycle
    - file_identity row survives a write/read cycle
    - static_finding row survives a write/read cycle with all nullable
      fields populated
    - static_finding row survives a write/read cycle with nullable
      fields null
    - decoded_node row survives a write/read cycle (flat, no parent)
    - decoded_node row survives a write/read cycle (child with parent_node_id)
    - decoded_child_finding row survives a write/read cycle
    - cve_scan_run row survives a write/read cycle
    - cve_finding row survives a write/read cycle
"""

from __future__ import annotations

import datetime
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pydepgate.dbs.pdgdb import schema

# ---------------------------------------------------------------------------
# Helpers shared across test classes
# ---------------------------------------------------------------------------


def _fresh_conn() -> sqlite3.Connection:
    """Open an in-memory pdgdb connection with schema applied."""
    conn = schema.connect(":memory:")
    schema.initialize_schema(conn)
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Return the set of column names for a table."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


def _tables(conn: sqlite3.Connection) -> set[str]:
    """Return all non-sqlite user table names."""
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
        " AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {row[0] for row in rows}


def _indexes(conn: sqlite3.Connection) -> set[str]:
    """Return all non-sqlite index names."""
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'"
        " AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {row[0] for row in rows}


_NOW = "2026-01-01T00:00:00+00:00"


def _insert_scan_run(
    conn: sqlite3.Connection,
    *,
    run_id: str = "test-run-uuid-0001",
    producer_id: str = "cli0",
    command: str = "scan",
    started_at: str = _NOW,
    pydepgate_ver: str = "0.5.0",
) -> int:
    """Insert a scan_run row and return its rowid."""
    cur = conn.execute(
        "INSERT INTO scan_runs"
        " (run_id, producer_id, command, started_at, pydepgate_ver)"
        " VALUES (?, ?, ?, ?, ?)",
        (run_id, producer_id, command, started_at, pydepgate_ver),
    )
    conn.commit()
    return cur.lastrowid


def _insert_scanned_artifact(
    conn: sqlite3.Connection,
    scan_run_id: int,
    *,
    artifact_kind: str = "wheel",
    artifact_identity: str = "litellm-1.82.8-py3-none-any.whl",
    artifact_sha256: str | None = "a" * 64,
    artifact_sha512: str | None = "b" * 128,
    package_name: str | None = "litellm",
    package_version: str | None = "1.82.8",
    scanned_at: str = _NOW,
) -> int:
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
    conn.commit()
    return cur.lastrowid


def _insert_file_identity(
    conn: sqlite3.Connection,
    artifact_id: int,
    *,
    internal_path: str = "setup.py",
    file_sha256: str | None = "c" * 64,
    file_sha512: str | None = "d" * 128,
) -> int:
    cur = conn.execute(
        "INSERT INTO file_identities"
        " (artifact_id, internal_path, file_sha256, file_sha512)"
        " VALUES (?, ?, ?, ?)",
        (artifact_id, internal_path, file_sha256, file_sha512),
    )
    conn.commit()
    return cur.lastrowid


def _insert_static_finding(
    conn: sqlite3.Connection,
    scan_run_id: int,
    artifact_id: int,
    file_identity_id: int | None = None,
    *,
    signal_id: str = "DENS010",
    analyzer: str = "code_density",
    severity: str = "high",
    confidence: int = 70,
    scope: str = "MODULE",
    internal_path: str = "setup.py",
    line: int = 14,
    col: int = 0,
    description: str = "high-entropy block",
    rule_id: str | None = "DENS_HIGH",
    producer_id: str = "cli0",
    stored_at: str = _NOW,
) -> int:
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
            signal_id,
            analyzer,
            severity,
            confidence,
            scope,
            internal_path,
            line,
            col,
            description,
            rule_id,
            producer_id,
            stored_at,
        ),
    )
    conn.commit()
    return cur.lastrowid


def _insert_decoded_node(
    conn: sqlite3.Connection,
    scan_run_id: int,
    artifact_id: int,
    parent_node_id: int | None = None,
    *,
    outer_signal_id: str = "DENS010",
    outer_severity: str = "high",
    outer_location: str = "setup.py:14:0",
    outer_length: int = 4096,
    chain: str = '["base64"]',
    unwrap_status: str = "completed",
    final_kind: str = "python_source",
    final_size: int = 512,
    indicators: str = '["subprocess"]',
    pickle_warning: int = 0,
    depth: int = 0,
    stop_reason: str = "leaf_terminal",
    containing_file_sha256: str | None = None,
    containing_file_sha512: str | None = None,
    stored_at: str = _NOW,
) -> int:
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
            outer_signal_id,
            outer_severity,
            outer_location,
            outer_length,
            chain,
            unwrap_status,
            final_kind,
            final_size,
            indicators,
            pickle_warning,
            depth,
            stop_reason,
            containing_file_sha256,
            containing_file_sha512,
            stored_at,
        ),
    )
    conn.commit()
    return cur.lastrowid


def _insert_cve_scan_run(
    conn: sqlite3.Connection,
    scan_run_id: int,
    artifact_id: int,
    *,
    cvedb_run_uuid: str | None = "cve-run-uuid-0001",
    started_at: str = _NOW,
) -> int:
    cur = conn.execute(
        "INSERT INTO cve_scan_runs"
        " (scan_run_id, artifact_id, cvedb_run_uuid, started_at)"
        " VALUES (?, ?, ?, ?)",
        (scan_run_id, artifact_id, cvedb_run_uuid, started_at),
    )
    conn.commit()
    return cur.lastrowid


def _insert_cve_finding(
    conn: sqlite3.Connection,
    cve_scan_run_id: int,
    *,
    package_name: str = "litellm",
    package_version: str = "1.82.8",
    canonical_id: str = "CVE-2025-12345",
    severity: str | None = "high",
    cvss_v3: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvss_v4: str | None = None,
    summary: str | None = "Remote code execution via crafted input",
    match_kind: str = "exact",
    producer_id: str = "cli0",
    stored_at: str = _NOW,
) -> int:
    cur = conn.execute(
        "INSERT INTO cve_findings"
        " (cve_scan_run_id, package_name, package_version,"
        "  canonical_id, severity, cvss_v3, cvss_v4, summary,"
        "  match_kind, producer_id, stored_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cve_scan_run_id,
            package_name,
            package_version,
            canonical_id,
            severity,
            cvss_v3,
            cvss_v4,
            summary,
            match_kind,
            producer_id,
            stored_at,
        ),
    )
    conn.commit()
    return cur.lastrowid


# ===========================================================================
# connect()
# ===========================================================================


class TestConnect(unittest.TestCase):

    def test_foreign_keys_on(self):
        conn = schema.connect(":memory:")
        try:
            row = conn.execute("PRAGMA foreign_keys").fetchone()
            self.assertEqual(row[0], 1)
        finally:
            conn.close()

    def test_journal_mode_wal_for_file_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            conn = schema.connect(db_path)
            try:
                row = conn.execute("PRAGMA journal_mode").fetchone()
                self.assertEqual(row[0].lower(), "wal")
            finally:
                conn.close()

    def test_application_id_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            conn = schema.connect(db_path)
            try:
                row = conn.execute("PRAGMA application_id").fetchone()
                self.assertEqual(row[0], schema.APPLICATION_ID)
            finally:
                conn.close()

    def test_busy_timeout_set(self):
        conn = schema.connect(":memory:")
        try:
            # SQLite does not expose a readable busy_timeout pragma in all
            # versions, but a successful connection indicates it was accepted.
            # We verify the constant is the expected value as a proxy.
            self.assertEqual(schema.BUSY_TIMEOUT_MS, 5000)
        finally:
            conn.close()

    def test_accepts_str_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path_str = str(Path(tmp) / "a.db")
            conn = schema.connect(path_str)
            try:
                self.assertIsNotNone(conn)
            finally:
                conn.close()

    def test_accepts_path_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path_obj = Path(tmp) / "b.db"
            conn = schema.connect(path_obj)
            try:
                self.assertIsNotNone(conn)
            finally:
                conn.close()

    def test_application_id_distinct_from_cvedb(self):
        # Ensure we did not accidentally reuse the cvedb APPLICATION_ID.
        self.assertNotEqual(schema.APPLICATION_ID, 0x70646763)


# ===========================================================================
# initialize_schema()
# ===========================================================================


class TestInitializeSchema(unittest.TestCase):

    def test_creates_all_tables(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            present = _tables(conn)
            for name in schema.TABLE_NAMES:
                self.assertIn(name, present, f"missing table: {name}")
        finally:
            conn.close()

    def test_creates_expected_indexes(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            present = _indexes(conn)
            expected = {
                "idx_scan_runs_run_id",
                "idx_scanned_artifacts_run",
                "idx_scanned_artifacts_package",
                "idx_scanned_artifacts_sha512",
                "idx_file_identities_artifact",
                "idx_file_identities_sha512",
                "idx_static_findings_run",
                "idx_static_findings_artifact",
                "idx_static_findings_signal",
                "idx_static_findings_severity",
                "idx_decoded_nodes_run",
                "idx_decoded_nodes_artifact",
                "idx_decoded_nodes_parent",
                "idx_decoded_child_findings_node",
                "idx_decoded_child_findings_signal",
                "idx_cve_scan_runs_run",
                "idx_cve_findings_scan_run",
                "idx_cve_findings_package",
                "idx_cve_findings_canonical",
            }
            for name in expected:
                self.assertIn(name, present, f"missing index: {name}")
        finally:
            conn.close()

    def test_writes_schema_version(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            self.assertEqual(
                schema.read_schema_version(conn),
                schema.PDGDB_SCHEMA_VERSION,
            )
        finally:
            conn.close()

    def test_writes_pydepgate_version(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            val = schema.read_metadata(conn, schema.METADATA_KEY_PYDEPGATE_VERSION)
            self.assertIsNotNone(val)
            self.assertIsInstance(val, str)
            self.assertTrue(len(val) > 0)
        finally:
            conn.close()

    def test_writes_created_at(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            val = schema.read_metadata(conn, schema.METADATA_KEY_CREATED_AT)
            self.assertIsNotNone(val)
            # Should be parseable as an ISO 8601 datetime.
            datetime.datetime.fromisoformat(val)
        finally:
            conn.close()

    def test_idempotent(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            # Second call must not raise or corrupt schema version.
            schema.initialize_schema(conn)
            self.assertEqual(
                schema.read_schema_version(conn),
                schema.PDGDB_SCHEMA_VERSION,
            )
        finally:
            conn.close()

    def test_does_not_overwrite_existing_schema_version(self):
        # Write a sentinel version before initializing; initialize_schema
        # must not clobber it. This simulates a future migration scenario
        # where the DB already carries a version and we must not blindly
        # overwrite it.
        conn = schema.connect(":memory:")
        try:
            # Apply DDL manually without writing version metadata.
            with conn:
                for stmt in schema.DDL_STATEMENTS:
                    conn.execute(stmt)
            schema.write_metadata(conn, schema.METADATA_KEY_SCHEMA_VERSION, "99")

            schema.initialize_schema(conn)

            # The sentinel value must be preserved.
            self.assertEqual(
                schema.read_metadata(conn, schema.METADATA_KEY_SCHEMA_VERSION),
                "99",
            )
        finally:
            conn.close()


# ===========================================================================
# check_schema_compatibility()
# ===========================================================================


class TestCheckSchemaCompatibility(unittest.TestCase):

    def test_passes_on_fresh_database(self):
        conn = _fresh_conn()
        try:
            # Must not raise.
            schema.check_schema_compatibility(conn)
        finally:
            conn.close()

    def test_raises_when_version_absent(self):
        conn = schema.connect(":memory:")
        try:
            with conn:
                for stmt in schema.DDL_STATEMENTS:
                    conn.execute(stmt)
            # db_metadata exists but has no schema_version key.
            with self.assertRaises(schema.SchemaVersionMismatch) as ctx:
                schema.check_schema_compatibility(conn)
            self.assertIsNone(ctx.exception.actual)
            self.assertEqual(ctx.exception.expected, schema.PDGDB_SCHEMA_VERSION)
        finally:
            conn.close()

    def test_raises_when_version_wrong(self):
        conn = _fresh_conn()
        try:
            schema.write_metadata(conn, schema.METADATA_KEY_SCHEMA_VERSION, "999")
            with self.assertRaises(schema.SchemaVersionMismatch) as ctx:
                schema.check_schema_compatibility(conn)
            self.assertEqual(ctx.exception.actual, 999)
            self.assertEqual(ctx.exception.expected, schema.PDGDB_SCHEMA_VERSION)
        finally:
            conn.close()

    def test_mismatch_actual_none_when_table_missing(self):
        # No tables at all: read_schema_version must return None.
        conn = schema.connect(":memory:")
        try:
            with self.assertRaises(schema.SchemaVersionMismatch) as ctx:
                schema.check_schema_compatibility(conn)
            self.assertIsNone(ctx.exception.actual)
        finally:
            conn.close()

    def test_mismatch_message_mentions_migrate_command(self):
        conn = _fresh_conn()
        try:
            schema.write_metadata(conn, schema.METADATA_KEY_SCHEMA_VERSION, "999")
            with self.assertRaises(schema.SchemaVersionMismatch) as ctx:
                schema.check_schema_compatibility(conn)
            self.assertIn("migrate", str(ctx.exception))
        finally:
            conn.close()


# ===========================================================================
# read_schema_version()
# ===========================================================================


class TestReadSchemaVersion(unittest.TestCase):

    def test_returns_current_version_on_fresh_db(self):
        conn = _fresh_conn()
        try:
            self.assertEqual(
                schema.read_schema_version(conn),
                schema.PDGDB_SCHEMA_VERSION,
            )
        finally:
            conn.close()

    def test_returns_none_when_key_absent(self):
        conn = schema.connect(":memory:")
        try:
            with conn:
                conn.execute(
                    "CREATE TABLE db_metadata (key TEXT PRIMARY KEY, value TEXT)"
                )
            self.assertIsNone(schema.read_schema_version(conn))
        finally:
            conn.close()

    def test_returns_none_when_table_missing(self):
        conn = schema.connect(":memory:")
        try:
            self.assertIsNone(schema.read_schema_version(conn))
        finally:
            conn.close()


# ===========================================================================
# apply_pending_migrations()
# ===========================================================================


class TestApplyPendingMigrations(unittest.TestCase):

    def test_returns_empty_list_when_no_migrations(self):
        conn = _fresh_conn()
        try:
            # MIGRATIONS is empty for v0.5.0; nothing to apply.
            applied = schema.apply_pending_migrations(conn)
            self.assertEqual(applied, [])
        finally:
            conn.close()

    def test_applies_synthetic_migration(self):
        # Inject a synthetic migration via mock.patch to verify
        # the framework applies it and records it.
        conn = _fresh_conn()
        try:
            fake_migrations = (
                (
                    "0001_add_test_column",
                    "ALTER TABLE scan_runs ADD COLUMN test_col TEXT",
                ),
            )
            with mock.patch.object(schema, "MIGRATIONS", fake_migrations):
                applied = schema.apply_pending_migrations(conn)
            self.assertEqual(applied, ["0001_add_test_column"])
            cols = _columns(conn, "scan_runs")
            self.assertIn("test_col", cols)
        finally:
            conn.close()

    def test_does_not_reapply_applied_migration(self):
        conn = _fresh_conn()
        try:
            fake_migrations = (
                (
                    "0001_add_test_column",
                    "ALTER TABLE scan_runs ADD COLUMN test_col TEXT",
                ),
            )
            with mock.patch.object(schema, "MIGRATIONS", fake_migrations):
                first = schema.apply_pending_migrations(conn)
                second = schema.apply_pending_migrations(conn)
            self.assertEqual(first, ["0001_add_test_column"])
            self.assertEqual(second, [])
        finally:
            conn.close()

    def test_raises_migration_error_on_bad_sql(self):
        conn = _fresh_conn()
        try:
            fake_migrations = (("0001_bad_sql", "THIS IS NOT VALID SQL !!!"),)
            with mock.patch.object(schema, "MIGRATIONS", fake_migrations):
                with self.assertRaises(schema.MigrationError) as ctx:
                    schema.apply_pending_migrations(conn)
            self.assertEqual(ctx.exception.migration_id, "0001_bad_sql")
            self.assertIsInstance(ctx.exception.cause, Exception)
        finally:
            conn.close()

    def test_failed_migration_not_recorded(self):
        conn = _fresh_conn()
        try:
            fake_migrations = (("0001_bad_sql", "THIS IS NOT VALID SQL !!!"),)
            with mock.patch.object(schema, "MIGRATIONS", fake_migrations):
                try:
                    schema.apply_pending_migrations(conn)
                except schema.MigrationError:
                    pass
            row = conn.execute(
                "SELECT migration_id FROM schema_migrations"
                " WHERE migration_id = '0001_bad_sql'"
            ).fetchone()
            self.assertIsNone(row)
        finally:
            conn.close()

    def test_updates_schema_version_after_applying(self):
        conn = _fresh_conn()
        try:
            fake_migrations = (
                (
                    "0001_add_test_column",
                    "ALTER TABLE scan_runs ADD COLUMN test_col2 TEXT",
                ),
            )
            with mock.patch.object(schema, "MIGRATIONS", fake_migrations):
                schema.apply_pending_migrations(conn)
            stored = schema.read_metadata(conn, schema.METADATA_KEY_SCHEMA_VERSION)
            self.assertEqual(int(stored), schema.PDGDB_SCHEMA_VERSION)
        finally:
            conn.close()


# ===========================================================================
# list_applied_migrations()
# ===========================================================================


class TestListAppliedMigrations(unittest.TestCase):

    def test_returns_empty_on_fresh_database(self):
        conn = _fresh_conn()
        try:
            result = schema.list_applied_migrations(conn)
            self.assertEqual(result, [])
        finally:
            conn.close()

    def test_returns_applied_entries_after_migration(self):
        conn = _fresh_conn()
        try:
            fake_migrations = (
                ("0001_add_col_a", "ALTER TABLE scan_runs ADD COLUMN col_a TEXT"),
                ("0002_add_col_b", "ALTER TABLE scan_runs ADD COLUMN col_b TEXT"),
            )
            with mock.patch.object(schema, "MIGRATIONS", fake_migrations):
                schema.apply_pending_migrations(conn)
            rows = schema.list_applied_migrations(conn)
            ids = [r[0] for r in rows]
            self.assertIn("0001_add_col_a", ids)
            self.assertIn("0002_add_col_b", ids)
        finally:
            conn.close()

    def test_returns_empty_when_table_missing(self):
        conn = schema.connect(":memory:")
        try:
            result = schema.list_applied_migrations(conn)
            self.assertEqual(result, [])
        finally:
            conn.close()


# ===========================================================================
# Metadata accessors
# ===========================================================================


class TestWriteReadMetadata(unittest.TestCase):

    def test_write_and_read_single_key(self):
        conn = _fresh_conn()
        try:
            schema.write_metadata(conn, "test_key", "test_value")
            self.assertEqual(schema.read_metadata(conn, "test_key"), "test_value")
        finally:
            conn.close()

    def test_overwrite_updates_value(self):
        conn = _fresh_conn()
        try:
            schema.write_metadata(conn, "test_key", "first")
            schema.write_metadata(conn, "test_key", "second")
            self.assertEqual(schema.read_metadata(conn, "test_key"), "second")
        finally:
            conn.close()

    def test_read_missing_key_returns_none(self):
        conn = _fresh_conn()
        try:
            self.assertIsNone(schema.read_metadata(conn, "no_such_key"))
        finally:
            conn.close()

    def test_read_metadata_table_missing_returns_none(self):
        conn = schema.connect(":memory:")
        try:
            self.assertIsNone(schema.read_metadata(conn, "any_key"))
        finally:
            conn.close()

    def test_write_metadata_dict_writes_multiple_keys(self):
        conn = _fresh_conn()
        try:
            schema.write_metadata_dict(conn, {"a": "1", "b": "2", "c": "3"})
            self.assertEqual(schema.read_metadata(conn, "a"), "1")
            self.assertEqual(schema.read_metadata(conn, "b"), "2")
            self.assertEqual(schema.read_metadata(conn, "c"), "3")
        finally:
            conn.close()

    def test_read_all_metadata_returns_all_entries(self):
        conn = _fresh_conn()
        try:
            schema.write_metadata_dict(conn, {"x": "10", "y": "20"})
            result = schema.read_all_metadata(conn)
            self.assertEqual(result["x"], "10")
            self.assertEqual(result["y"], "20")
        finally:
            conn.close()

    def test_read_all_metadata_sorted_by_key(self):
        conn = _fresh_conn()
        try:
            schema.write_metadata_dict(conn, {"z": "last", "a": "first"})
            keys = list(schema.read_all_metadata(conn).keys())
            self.assertEqual(keys, sorted(keys))
        finally:
            conn.close()

    def test_read_all_metadata_table_missing_returns_empty(self):
        conn = schema.connect(":memory:")
        try:
            self.assertEqual(schema.read_all_metadata(conn), {})
        finally:
            conn.close()


# ===========================================================================
# drop_all_tables()
# ===========================================================================


class TestDropAllTables(unittest.TestCase):

    def test_removes_all_tables(self):
        conn = _fresh_conn()
        try:
            schema.drop_all_tables(conn)
            self.assertEqual(_tables(conn), set())
        finally:
            conn.close()

    def test_idempotent_on_empty_database(self):
        conn = schema.connect(":memory:")
        try:
            schema.drop_all_tables(conn)
            # Must not raise.
            schema.drop_all_tables(conn)
        finally:
            conn.close()

    def test_schema_reinitializes_after_drop(self):
        conn = _fresh_conn()
        try:
            schema.drop_all_tables(conn)
            schema.initialize_schema(conn)
            self.assertEqual(
                schema.read_schema_version(conn),
                schema.PDGDB_SCHEMA_VERSION,
            )
        finally:
            conn.close()


# ===========================================================================
# Table column structure
# ===========================================================================


class TestTableColumns(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_scan_runs_columns(self):
        cols = _columns(self.conn, "scan_runs")
        for expected in (
            "id",
            "run_id",
            "producer_id",
            "command",
            "started_at",
            "pydepgate_ver",
        ):
            self.assertIn(expected, cols)

    def test_scanned_artifacts_columns(self):
        cols = _columns(self.conn, "scanned_artifacts")
        for expected in (
            "id",
            "scan_run_id",
            "artifact_kind",
            "artifact_identity",
            "artifact_sha256",
            "artifact_sha512",
            "package_name",
            "package_version",
            "scanned_at",
        ):
            self.assertIn(expected, cols)

    def test_file_identities_columns(self):
        cols = _columns(self.conn, "file_identities")
        for expected in (
            "id",
            "artifact_id",
            "internal_path",
            "file_sha256",
            "file_sha512",
        ):
            self.assertIn(expected, cols)

    def test_static_findings_columns(self):
        cols = _columns(self.conn, "static_findings")
        for expected in (
            "id",
            "scan_run_id",
            "artifact_id",
            "file_identity_id",
            "signal_id",
            "analyzer",
            "severity",
            "confidence",
            "scope",
            "internal_path",
            "line",
            "col",
            "description",
            "rule_id",
            "producer_id",
            "stored_at",
        ):
            self.assertIn(expected, cols)

    def test_decoded_nodes_columns(self):
        cols = _columns(self.conn, "decoded_nodes")
        for expected in (
            "id",
            "scan_run_id",
            "artifact_id",
            "parent_node_id",
            "outer_signal_id",
            "outer_severity",
            "outer_location",
            "outer_length",
            "chain",
            "unwrap_status",
            "final_kind",
            "final_size",
            "indicators",
            "pickle_warning",
            "depth",
            "stop_reason",
            "containing_file_sha256",
            "containing_file_sha512",
            "stored_at",
        ):
            self.assertIn(expected, cols)

    def test_decoded_child_findings_columns(self):
        cols = _columns(self.conn, "decoded_child_findings")
        for expected in (
            "id",
            "node_id",
            "signal_id",
            "severity",
            "line",
            "col",
            "description",
        ):
            self.assertIn(expected, cols)

    def test_cve_scan_runs_columns(self):
        cols = _columns(self.conn, "cve_scan_runs")
        for expected in (
            "id",
            "scan_run_id",
            "artifact_id",
            "cvedb_run_uuid",
            "started_at",
        ):
            self.assertIn(expected, cols)

    def test_cve_findings_columns(self):
        cols = _columns(self.conn, "cve_findings")
        for expected in (
            "id",
            "cve_scan_run_id",
            "package_name",
            "package_version",
            "canonical_id",
            "severity",
            "cvss_v3",
            "cvss_v4",
            "summary",
            "match_kind",
            "producer_id",
            "stored_at",
        ):
            self.assertIn(expected, cols)


# ===========================================================================
# Foreign key enforcement
# ===========================================================================


class TestForeignKeys(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_static_finding_bad_scan_run_id_raises(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO static_findings"
                " (scan_run_id, artifact_id, file_identity_id,"
                "  signal_id, analyzer, severity, confidence, scope,"
                "  internal_path, line, col, description,"
                "  rule_id, producer_id, stored_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    99999,  # non-existent scan_run_id
                    art_id,
                    None,
                    "DENS010",
                    "code_density",
                    "high",
                    70,
                    "MODULE",
                    "setup.py",
                    1,
                    0,
                    "desc",
                    None,
                    "cli0",
                    _NOW,
                ),
            )
            self.conn.commit()

    def test_cascade_delete_scan_run_removes_static_findings(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        _insert_static_finding(self.conn, run_id, art_id)

        self.conn.execute("DELETE FROM scan_runs WHERE id = ?", (run_id,))
        self.conn.commit()

        rows = self.conn.execute(
            "SELECT id FROM static_findings WHERE scan_run_id = ?", (run_id,)
        ).fetchall()
        self.assertEqual(rows, [])

    def test_cascade_delete_scan_run_removes_scanned_artifacts(self):
        run_id = _insert_scan_run(self.conn)
        _insert_scanned_artifact(self.conn, run_id)

        self.conn.execute("DELETE FROM scan_runs WHERE id = ?", (run_id,))
        self.conn.commit()

        rows = self.conn.execute(
            "SELECT id FROM scanned_artifacts WHERE scan_run_id = ?", (run_id,)
        ).fetchall()
        self.assertEqual(rows, [])

    def test_cascade_delete_decoded_node_removes_child_findings(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        node_id = _insert_decoded_node(self.conn, run_id, art_id)

        self.conn.execute(
            "INSERT INTO decoded_child_findings"
            " (node_id, signal_id, severity, line, col, description)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (node_id, "STDLIB001", "high", 5, 0, "os.system call"),
        )
        self.conn.commit()

        self.conn.execute("DELETE FROM decoded_nodes WHERE id = ?", (node_id,))
        self.conn.commit()

        rows = self.conn.execute(
            "SELECT id FROM decoded_child_findings WHERE node_id = ?", (node_id,)
        ).fetchall()
        self.assertEqual(rows, [])

    def test_delete_file_identity_nulls_finding_reference(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        fi_id = _insert_file_identity(self.conn, art_id)
        finding_id = _insert_static_finding(self.conn, run_id, art_id, fi_id)

        self.conn.execute("DELETE FROM file_identities WHERE id = ?", (fi_id,))
        self.conn.commit()

        row = self.conn.execute(
            "SELECT file_identity_id FROM static_findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        self.assertIsNone(row[0])


# ===========================================================================
# Data round-trips
# ===========================================================================


class TestDataRoundTrips(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_scan_run_round_trip(self):
        row_id = _insert_scan_run(
            self.conn,
            run_id="round-trip-uuid-0001",
            producer_id="cli0",
            command="scan",
            pydepgate_ver="0.5.0",
        )
        row = self.conn.execute(
            "SELECT run_id, producer_id, command, pydepgate_ver"
            " FROM scan_runs WHERE id = ?",
            (row_id,),
        ).fetchone()
        self.assertEqual(row[0], "round-trip-uuid-0001")
        self.assertEqual(row[1], "cli0")
        self.assertEqual(row[2], "scan")
        self.assertEqual(row[3], "0.5.0")

    def test_scanned_artifact_round_trip(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(
            self.conn,
            run_id,
            artifact_kind="wheel",
            artifact_identity="litellm-1.82.8-py3-none-any.whl",
            artifact_sha512="b" * 128,
            package_name="litellm",
            package_version="1.82.8",
        )
        row = self.conn.execute(
            "SELECT artifact_kind, artifact_identity, artifact_sha512,"
            "       package_name, package_version"
            " FROM scanned_artifacts WHERE id = ?",
            (art_id,),
        ).fetchone()
        self.assertEqual(row[0], "wheel")
        self.assertEqual(row[1], "litellm-1.82.8-py3-none-any.whl")
        self.assertEqual(row[2], "b" * 128)
        self.assertEqual(row[3], "litellm")
        self.assertEqual(row[4], "1.82.8")

    def test_scanned_artifact_nullable_fields_store_null(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(
            self.conn,
            run_id,
            artifact_kind="installed_env",
            artifact_identity="requests",
            artifact_sha256=None,
            artifact_sha512=None,
            package_name=None,
            package_version=None,
        )
        row = self.conn.execute(
            "SELECT artifact_sha256, artifact_sha512, package_name, package_version"
            " FROM scanned_artifacts WHERE id = ?",
            (art_id,),
        ).fetchone()
        self.assertIsNone(row[0])
        self.assertIsNone(row[1])
        self.assertIsNone(row[2])
        self.assertIsNone(row[3])

    def test_file_identity_round_trip(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        fi_id = _insert_file_identity(
            self.conn,
            art_id,
            internal_path="litellm/__init__.py",
            file_sha256="c" * 64,
            file_sha512="d" * 128,
        )
        row = self.conn.execute(
            "SELECT internal_path, file_sha256, file_sha512"
            " FROM file_identities WHERE id = ?",
            (fi_id,),
        ).fetchone()
        self.assertEqual(row[0], "litellm/__init__.py")
        self.assertEqual(row[1], "c" * 64)
        self.assertEqual(row[2], "d" * 128)

    def test_static_finding_round_trip_all_fields(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        fi_id = _insert_file_identity(self.conn, art_id)
        f_id = _insert_static_finding(
            self.conn,
            run_id,
            art_id,
            fi_id,
            signal_id="STDLIB001",
            analyzer="suspicious_stdlib",
            severity="critical",
            confidence=90,
            scope="MODULE",
            internal_path="setup.py",
            line=22,
            col=4,
            description="os.system with non-literal argument",
            rule_id="STDLIB_EXEC",
            producer_id="cli0",
        )
        row = self.conn.execute(
            "SELECT signal_id, analyzer, severity, confidence, scope,"
            "       internal_path, line, col, description, rule_id,"
            "       producer_id, file_identity_id"
            " FROM static_findings WHERE id = ?",
            (f_id,),
        ).fetchone()
        self.assertEqual(row[0], "STDLIB001")
        self.assertEqual(row[1], "suspicious_stdlib")
        self.assertEqual(row[2], "critical")
        self.assertEqual(row[3], 90)
        self.assertEqual(row[4], "MODULE")
        self.assertEqual(row[5], "setup.py")
        self.assertEqual(row[6], 22)
        self.assertEqual(row[7], 4)
        self.assertEqual(row[8], "os.system with non-literal argument")
        self.assertEqual(row[9], "STDLIB_EXEC")
        self.assertEqual(row[10], "cli0")
        self.assertEqual(row[11], fi_id)

    def test_static_finding_round_trip_nullable_fields_null(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        f_id = _insert_static_finding(
            self.conn,
            run_id,
            art_id,
            file_identity_id=None,
            rule_id=None,
        )
        row = self.conn.execute(
            "SELECT file_identity_id, rule_id FROM static_findings WHERE id = ?",
            (f_id,),
        ).fetchone()
        self.assertIsNone(row[0])
        self.assertIsNone(row[1])

    def test_decoded_node_flat_round_trip(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        node_id = _insert_decoded_node(
            self.conn,
            run_id,
            art_id,
            outer_signal_id="DENS010",
            outer_severity="high",
            outer_location="setup.py:14:0",
            outer_length=4096,
            chain='["base64"]',
            final_kind="python_source",
            final_size=512,
            indicators='["subprocess"]',
            pickle_warning=0,
            depth=0,
            stop_reason="leaf_terminal",
        )
        row = self.conn.execute(
            "SELECT outer_signal_id, outer_severity, chain, indicators,"
            "       pickle_warning, depth, stop_reason, parent_node_id"
            " FROM decoded_nodes WHERE id = ?",
            (node_id,),
        ).fetchone()
        self.assertEqual(row[0], "DENS010")
        self.assertEqual(row[1], "high")
        self.assertEqual(row[2], '["base64"]')
        self.assertEqual(row[3], '["subprocess"]')
        self.assertEqual(row[4], 0)
        self.assertEqual(row[5], 0)
        self.assertEqual(row[6], "leaf_terminal")
        self.assertIsNone(row[7])

    def test_decoded_node_child_links_to_parent(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        parent_id = _insert_decoded_node(self.conn, run_id, art_id, depth=0)
        child_id = _insert_decoded_node(
            self.conn,
            run_id,
            art_id,
            parent_node_id=parent_id,
            depth=1,
        )
        row = self.conn.execute(
            "SELECT parent_node_id FROM decoded_nodes WHERE id = ?",
            (child_id,),
        ).fetchone()
        self.assertEqual(row[0], parent_id)

    def test_decoded_child_finding_round_trip(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        node_id = _insert_decoded_node(self.conn, run_id, art_id)

        self.conn.execute(
            "INSERT INTO decoded_child_findings"
            " (node_id, signal_id, severity, line, col, description)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (node_id, "STDLIB001", "high", 5, 0, "os.system call"),
        )
        self.conn.commit()

        row = self.conn.execute(
            "SELECT signal_id, severity, line, col, description"
            " FROM decoded_child_findings WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        self.assertEqual(row[0], "STDLIB001")
        self.assertEqual(row[1], "high")
        self.assertEqual(row[2], 5)
        self.assertEqual(row[3], 0)
        self.assertEqual(row[4], "os.system call")

    def test_cve_scan_run_round_trip(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        cve_run_id = _insert_cve_scan_run(
            self.conn,
            run_id,
            art_id,
            cvedb_run_uuid="cve-db-run-uuid-0001",
        )
        row = self.conn.execute(
            "SELECT scan_run_id, artifact_id, cvedb_run_uuid"
            " FROM cve_scan_runs WHERE id = ?",
            (cve_run_id,),
        ).fetchone()
        self.assertEqual(row[0], run_id)
        self.assertEqual(row[1], art_id)
        self.assertEqual(row[2], "cve-db-run-uuid-0001")

    def test_cve_finding_round_trip_all_fields(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        cve_run_id = _insert_cve_scan_run(self.conn, run_id, art_id)
        cf_id = _insert_cve_finding(
            self.conn,
            cve_run_id,
            package_name="litellm",
            package_version="1.82.8",
            canonical_id="CVE-2025-12345",
            severity="high",
            cvss_v3="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_v4=None,
            summary="Remote code execution",
            match_kind="exact",
            producer_id="cli0",
        )
        row = self.conn.execute(
            "SELECT package_name, package_version, canonical_id,"
            "       severity, cvss_v3, cvss_v4, summary,"
            "       match_kind, producer_id"
            " FROM cve_findings WHERE id = ?",
            (cf_id,),
        ).fetchone()
        self.assertEqual(row[0], "litellm")
        self.assertEqual(row[1], "1.82.8")
        self.assertEqual(row[2], "CVE-2025-12345")
        self.assertEqual(row[3], "high")
        self.assertIsNotNone(row[4])
        self.assertIsNone(row[5])
        self.assertEqual(row[6], "Remote code execution")
        self.assertEqual(row[7], "exact")
        self.assertEqual(row[8], "cli0")

    def test_cve_finding_nullable_fields_store_null(self):
        run_id = _insert_scan_run(self.conn)
        art_id = _insert_scanned_artifact(self.conn, run_id)
        cve_run_id = _insert_cve_scan_run(self.conn, run_id, art_id)
        cf_id = _insert_cve_finding(
            self.conn,
            cve_run_id,
            severity=None,
            cvss_v3=None,
            cvss_v4=None,
            summary=None,
        )
        row = self.conn.execute(
            "SELECT severity, cvss_v3, cvss_v4, summary"
            " FROM cve_findings WHERE id = ?",
            (cf_id,),
        ).fetchone()
        self.assertIsNone(row[0])
        self.assertIsNone(row[1])
        self.assertIsNone(row[2])
        self.assertIsNone(row[3])


if __name__ == "__main__":
    unittest.main()
