"""Tests for pydepgate.package_tools.cvedb.schema.

Coverage:

  * connect() sets foreign_keys, busy_timeout, application_id,
    journal_mode (WAL on file, "memory" on in-memory).
  * initialize_schema creates every expected table and index,
    writes the schema version, and is idempotent.
  * check_schema_compatibility passes after initialize, raises
    SchemaVersionMismatch when version is absent or mismatched.
  * read_schema_version returns None when absent, raises on
    unparseable values.
  * Metadata round-trips, batch writes, and read-all behave as
    documented.
  * Foreign keys enforce alias and affected_version references
    to vulnerabilities, with ON DELETE CASCADE working.
  * PRIMARY KEY uniqueness rejects duplicate aliases and
    duplicate (canonical, package, version) triples.
  * The actual lookup-query shape the depscan pass will use
    returns the expected rows.
  * drop_all_tables wipes everything, is idempotent, and allows
    reinitialization to a fresh state.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from pydepgate.package_tools.cvedb import schema
from pydepgate.package_tools.cvedb.constants import CVE_DB_SCHEMA_VERSION

# ---------------------------------------------------------------------------
# connect()
# ---------------------------------------------------------------------------


class TestConnect(unittest.TestCase):
    def test_in_memory_works(self):
        conn = schema.connect(":memory:")
        try:
            row = conn.execute("SELECT 1").fetchone()
            self.assertEqual(row[0], 1)
        finally:
            conn.close()

    def test_foreign_keys_enabled(self):
        conn = schema.connect(":memory:")
        try:
            row = conn.execute("PRAGMA foreign_keys").fetchone()
            self.assertEqual(row[0], 1)
        finally:
            conn.close()

    def test_busy_timeout_set(self):
        conn = schema.connect(":memory:")
        try:
            row = conn.execute("PRAGMA busy_timeout").fetchone()
            self.assertEqual(row[0], schema.BUSY_TIMEOUT_MS)
        finally:
            conn.close()

    def test_application_id_set_on_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            conn = schema.connect(db_path)
            try:
                row = conn.execute("PRAGMA application_id").fetchone()
                self.assertEqual(row[0], schema.APPLICATION_ID)
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

    def test_accepts_string_or_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            for path in (str(Path(tmp) / "a.db"), Path(tmp) / "b.db"):
                conn = schema.connect(path)
                try:
                    self.assertIsNotNone(conn)
                finally:
                    conn.close()


# ---------------------------------------------------------------------------
# initialize_schema()
# ---------------------------------------------------------------------------


class TestInitializeSchema(unittest.TestCase):
    def _all_tables(self, conn):
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return {row[0] for row in rows}

    def _all_indexes(self, conn):
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return {row[0] for row in rows}

    def test_creates_all_tables(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            tables = self._all_tables(conn)
            for expected in schema.TABLE_NAMES:
                self.assertIn(expected, tables)
        finally:
            conn.close()

    def test_creates_expected_indexes(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            indexes = self._all_indexes(conn)
            for expected in (
                "idx_aliases_canonical",
                "idx_aliases_type",
                "idx_av_lookup",
                "idx_av_package",
                "idx_warnings_reason",
            ):
                self.assertIn(expected, indexes)
        finally:
            conn.close()

    def test_writes_schema_version(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            self.assertEqual(
                schema.read_schema_version(conn),
                CVE_DB_SCHEMA_VERSION,
            )
        finally:
            conn.close()

    def test_idempotent(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            # Second call must not raise or alter state.
            schema.initialize_schema(conn)
            tables = self._all_tables(conn)
            for expected in schema.TABLE_NAMES:
                self.assertIn(expected, tables)
        finally:
            conn.close()

    def test_existing_version_metadata_not_overwritten(self):
        # If an existing DB carries a different schema version,
        # initialize_schema must NOT silently rewrite it. Doing
        # so would mask the version mismatch the caller is
        # supposed to detect.
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_SCHEMA_VERSION,
                "99",
            )
            schema.initialize_schema(conn)
            self.assertEqual(schema.read_schema_version(conn), 99)
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Schema version verification
# ---------------------------------------------------------------------------


class TestSchemaVersion(unittest.TestCase):
    def test_check_passes_after_initialize(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            schema.check_schema_compatibility(conn)
        finally:
            conn.close()

    def test_check_raises_when_version_absent(self):
        conn = schema.connect(":memory:")
        try:
            # Create db_metadata but no version row.
            conn.execute(
                "CREATE TABLE db_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            with self.assertRaises(schema.SchemaVersionMismatch) as ctx:
                schema.check_schema_compatibility(conn)
            self.assertIsNone(ctx.exception.actual)
            self.assertEqual(ctx.exception.expected, CVE_DB_SCHEMA_VERSION)
        finally:
            conn.close()

    def test_check_raises_when_version_mismatch(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_SCHEMA_VERSION,
                "99",
            )
            with self.assertRaises(schema.SchemaVersionMismatch) as ctx:
                schema.check_schema_compatibility(conn)
            self.assertEqual(ctx.exception.actual, 99)
            self.assertEqual(ctx.exception.expected, CVE_DB_SCHEMA_VERSION)
        finally:
            conn.close()

    def test_read_schema_version_returns_none_when_absent(self):
        conn = schema.connect(":memory:")
        try:
            conn.execute(
                "CREATE TABLE db_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self.assertIsNone(schema.read_schema_version(conn))
        finally:
            conn.close()

    def test_read_schema_version_raises_on_unparseable(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_SCHEMA_VERSION,
                "not_a_number",
            )
            with self.assertRaises(schema.SchemaError):
                schema.read_schema_version(conn)
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------


class TestMetadata(unittest.TestCase):
    def setUp(self):
        self.conn = schema.connect(":memory:")
        schema.initialize_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_write_read_round_trip(self):
        schema.write_metadata(self.conn, "test_key", "test_value")
        self.assertEqual(
            schema.read_metadata(self.conn, "test_key"),
            "test_value",
        )

    def test_read_returns_none_for_missing_key(self):
        self.assertIsNone(schema.read_metadata(self.conn, "missing"))

    def test_write_overwrites_existing(self):
        schema.write_metadata(self.conn, "test_key", "first")
        schema.write_metadata(self.conn, "test_key", "second")
        self.assertEqual(
            schema.read_metadata(self.conn, "test_key"),
            "second",
        )

    def test_write_metadata_dict(self):
        schema.write_metadata_dict(self.conn, {"a": "1", "b": "2", "c": "3"})
        self.assertEqual(schema.read_metadata(self.conn, "a"), "1")
        self.assertEqual(schema.read_metadata(self.conn, "b"), "2")
        self.assertEqual(schema.read_metadata(self.conn, "c"), "3")

    def test_read_all_metadata(self):
        schema.write_metadata_dict(self.conn, {"a": "1", "b": "2"})
        result = schema.read_all_metadata(self.conn)
        # schema_version row is also present from initialize_schema.
        self.assertIn("a", result)
        self.assertIn("b", result)
        self.assertEqual(result["a"], "1")
        self.assertEqual(result["b"], "2")


# ---------------------------------------------------------------------------
# Foreign-key enforcement
# ---------------------------------------------------------------------------


class TestForeignKeys(unittest.TestCase):
    def setUp(self):
        self.conn = schema.connect(":memory:")
        schema.initialize_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def _insert_vuln(self, canonical_id):
        self.conn.execute(
            "INSERT INTO vulnerabilities (canonical_id) VALUES (?)",
            (canonical_id,),
        )

    def _insert_alias(self, alias, canonical_id, alias_type="CVE"):
        self.conn.execute(
            "INSERT INTO aliases (alias, canonical_id, alias_type) " "VALUES (?, ?, ?)",
            (alias, canonical_id, alias_type),
        )

    def _insert_version(self, canonical_id, package, version):
        self.conn.execute(
            "INSERT INTO affected_versions "
            "(canonical_id, package_name, version) VALUES (?, ?, ?)",
            (canonical_id, package, version),
        )

    def test_alias_with_unknown_canonical_id_raises(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_alias("CVE-9999-9999", "CVE-NONEXISTENT")

    def test_affected_version_with_unknown_canonical_id_raises(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_version("CVE-NONEXISTENT", "pkg", "1.0")

    def test_delete_vuln_cascades_to_aliases(self):
        self._insert_vuln("CVE-1234-5678")
        self._insert_alias("PYSEC-2025-1", "CVE-1234-5678", "PYSEC")
        self.conn.execute(
            "DELETE FROM vulnerabilities WHERE canonical_id = ?",
            ("CVE-1234-5678",),
        )
        row = self.conn.execute(
            "SELECT COUNT(*) FROM aliases WHERE alias = ?",
            ("PYSEC-2025-1",),
        ).fetchone()
        self.assertEqual(row[0], 0)

    def test_delete_vuln_cascades_to_affected_versions(self):
        self._insert_vuln("CVE-1234-5678")
        self._insert_version("CVE-1234-5678", "somepkg", "1.0")
        self._insert_version("CVE-1234-5678", "somepkg", "1.1")
        self.conn.execute(
            "DELETE FROM vulnerabilities WHERE canonical_id = ?",
            ("CVE-1234-5678",),
        )
        row = self.conn.execute(
            "SELECT COUNT(*) FROM affected_versions WHERE canonical_id = ?",
            ("CVE-1234-5678",),
        ).fetchone()
        self.assertEqual(row[0], 0)


# ---------------------------------------------------------------------------
# Primary-key uniqueness
# ---------------------------------------------------------------------------


class TestDataIntegrity(unittest.TestCase):
    def setUp(self):
        self.conn = schema.connect(":memory:")
        schema.initialize_schema(self.conn)
        self.conn.execute(
            "INSERT INTO vulnerabilities (canonical_id) VALUES (?)",
            ("CVE-2025-1",),
        )

    def tearDown(self):
        self.conn.close()

    def test_duplicate_alias_string_rejected(self):
        # Two records claiming the same alias for the same
        # canonical: still rejected. The importer must use
        # INSERT OR IGNORE if it expects dedup-driven retries.
        self.conn.execute(
            "INSERT INTO aliases (alias, canonical_id, alias_type) " "VALUES (?, ?, ?)",
            ("GHSA-xxxx", "CVE-2025-1", "GHSA"),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO aliases (alias, canonical_id, alias_type) "
                "VALUES (?, ?, ?)",
                ("GHSA-xxxx", "CVE-2025-1", "GHSA"),
            )

    def test_duplicate_affected_version_triple_rejected(self):
        self.conn.execute(
            "INSERT INTO affected_versions "
            "(canonical_id, package_name, version) VALUES (?, ?, ?)",
            ("CVE-2025-1", "pkg", "1.0"),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO affected_versions "
                "(canonical_id, package_name, version) VALUES (?, ?, ?)",
                ("CVE-2025-1", "pkg", "1.0"),
            )

    def test_different_packages_same_version_allowed(self):
        # One CVE can affect multiple packages at the same
        # version (e.g. a CVE in a shared dependency).
        self.conn.execute(
            "INSERT INTO affected_versions "
            "(canonical_id, package_name, version) VALUES (?, ?, ?)",
            ("CVE-2025-1", "pkg-a", "1.0"),
        )
        self.conn.execute(
            "INSERT INTO affected_versions "
            "(canonical_id, package_name, version) VALUES (?, ?, ?)",
            ("CVE-2025-1", "pkg-b", "1.0"),
        )
        row = self.conn.execute(
            "SELECT COUNT(*) FROM affected_versions WHERE canonical_id = ?",
            ("CVE-2025-1",),
        ).fetchone()
        self.assertEqual(row[0], 2)


# ---------------------------------------------------------------------------
# Lookup-query shape (smoke test for the depscan pass)
# ---------------------------------------------------------------------------


class TestLookupQuery(unittest.TestCase):
    """Exercise the actual query the depscan CVE pass will use."""

    def setUp(self):
        self.conn = schema.connect(":memory:")
        schema.initialize_schema(self.conn)
        for cid, summary in [
            ("CVE-2025-47273", "setuptools path traversal"),
            ("CVE-2014-9706", "dulwich code exec"),
        ]:
            self.conn.execute(
                "INSERT INTO vulnerabilities (canonical_id, summary) " "VALUES (?, ?)",
                (cid, summary),
            )
        for cid, pkg, ver in [
            ("CVE-2025-47273", "setuptools", "75.0.0"),
            ("CVE-2025-47273", "setuptools", "78.0.0"),
            ("CVE-2014-9706", "dulwich", "0.9.7"),
            ("CVE-2014-9706", "dulwich", "0.9.8"),
        ]:
            self.conn.execute(
                "INSERT INTO affected_versions "
                "(canonical_id, package_name, version) VALUES (?, ?, ?)",
                (cid, pkg, ver),
            )

    def tearDown(self):
        self.conn.close()

    def test_lookup_hits(self):
        rows = self.conn.execute(
            "SELECT v.canonical_id, v.summary "
            "FROM affected_versions av "
            "JOIN vulnerabilities v ON av.canonical_id = v.canonical_id "
            "WHERE av.package_name = ? AND av.version = ?",
            ("setuptools", "75.0.0"),
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "CVE-2025-47273")

    def test_lookup_miss_on_safe_version(self):
        rows = self.conn.execute(
            "SELECT v.canonical_id "
            "FROM affected_versions av "
            "JOIN vulnerabilities v ON av.canonical_id = v.canonical_id "
            "WHERE av.package_name = ? AND av.version = ?",
            ("setuptools", "79.0.0"),
        ).fetchall()
        self.assertEqual(len(rows), 0)


# ---------------------------------------------------------------------------
# drop_all_tables
# ---------------------------------------------------------------------------


class TestDropAllTables(unittest.TestCase):
    def test_drops_all_tables(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            schema.drop_all_tables(conn)
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            self.assertEqual(rows, [])
        finally:
            conn.close()

    def test_idempotent(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            schema.drop_all_tables(conn)
            # Second call: must not raise.
            schema.drop_all_tables(conn)
        finally:
            conn.close()

    def test_can_reinitialize_after_drop(self):
        conn = schema.connect(":memory:")
        try:
            schema.initialize_schema(conn)
            schema.write_metadata(conn, "test", "old_value")
            schema.drop_all_tables(conn)
            schema.initialize_schema(conn)
            # Old metadata is gone (dropped with the table).
            self.assertIsNone(schema.read_metadata(conn, "test"))
            # Fresh schema version is written.
            self.assertEqual(
                schema.read_schema_version(conn),
                CVE_DB_SCHEMA_VERSION,
            )
        finally:
            conn.close()


"""
Test classes added for the v2 schema bump. Append to the existing
tests/package_tools/cvedb/test_schema.py. The imports at the top
of the existing test file already cover everything needed here.
"""


class TestSchemaVersionV2(unittest.TestCase):
    def test_constant_is_2(self):
        self.assertEqual(schema.CVE_DB_SCHEMA_VERSION, 2)

    def test_fresh_db_records_v2(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            conn = schema.connect(db_path)
            try:
                schema.initialize_schema(conn)
                conn.commit()
                version = schema.read_schema_version(conn)
                self.assertEqual(version, 2)
            finally:
                conn.close()


class TestRunUuidMetadataKey(unittest.TestCase):
    def test_constant_defined(self):
        self.assertEqual(
            schema.METADATA_KEY_LAST_IMPORT_RUN_UUID,
            "last_import_run_uuid",
        )

    def test_run_uuid_writes_and_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            conn = schema.connect(db_path)
            try:
                schema.initialize_schema(conn)
                run_uid = "550e8400-e29b-41d4-a716-446655440000"
                schema.write_metadata(
                    conn,
                    schema.METADATA_KEY_LAST_IMPORT_RUN_UUID,
                    run_uid,
                )
                conn.commit()

                got = schema.read_metadata(
                    conn,
                    schema.METADATA_KEY_LAST_IMPORT_RUN_UUID,
                )
                self.assertEqual(got, run_uid)
            finally:
                conn.close()


class TestAffectedRangesTable(unittest.TestCase):
    def _open(self, tmp: str):
        db_path = Path(tmp) / "test.db"
        conn = schema.connect(db_path)
        schema.initialize_schema(conn)
        return conn

    def test_table_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._open(tmp)
            try:
                rows = conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='affected_ranges'"
                ).fetchall()
                self.assertEqual(len(rows), 1)
            finally:
                conn.close()

    def test_table_has_expected_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._open(tmp)
            try:
                cols = conn.execute("PRAGMA table_info(affected_ranges)").fetchall()
                col_names = {c[1] for c in cols}
                self.assertIn("canonical_id", col_names)
                self.assertIn("package_name", col_names)
                self.assertIn("range_type", col_names)
                self.assertIn("introduced", col_names)
                self.assertIn("fixed", col_names)
                self.assertIn("last_affected", col_names)
            finally:
                conn.close()

    def test_optional_columns_default_to_empty_string(self):
        """fixed and last_affected default to '' per Option A."""
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._open(tmp)
            try:
                # Insert with only required columns; defaults fill the rest
                conn.execute(
                    "INSERT INTO vulnerabilities (canonical_id) " "VALUES (?)",
                    ("CVE-2025-1",),
                )
                conn.execute(
                    "INSERT INTO affected_ranges "
                    "(canonical_id, package_name, range_type, introduced) "
                    "VALUES (?, ?, ?, ?)",
                    ("CVE-2025-1", "somepkg", "ECOSYSTEM", "1.0"),
                )
                row = conn.execute(
                    "SELECT fixed, last_affected FROM affected_ranges "
                    "WHERE canonical_id = ?",
                    ("CVE-2025-1",),
                ).fetchone()
                self.assertEqual(row[0], "")
                self.assertEqual(row[1], "")
            finally:
                conn.close()

    def test_primary_key_dedups_identical_ranges(self):
        """Composite PK across all columns; INSERT OR IGNORE swallows dups."""
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._open(tmp)
            try:
                conn.execute(
                    "INSERT INTO vulnerabilities (canonical_id) VALUES (?)",
                    ("CVE-2025-1",),
                )
                row = ("CVE-2025-1", "somepkg", "ECOSYSTEM", "1.0", "2.0", "")
                conn.execute(
                    "INSERT OR IGNORE INTO affected_ranges "
                    "(canonical_id, package_name, range_type, "
                    "introduced, fixed, last_affected) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    row,
                )
                conn.execute(
                    "INSERT OR IGNORE INTO affected_ranges "
                    "(canonical_id, package_name, range_type, "
                    "introduced, fixed, last_affected) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    row,
                )
                count = conn.execute(
                    "SELECT COUNT(*) FROM affected_ranges " "WHERE canonical_id = ?",
                    ("CVE-2025-1",),
                ).fetchone()[0]
                self.assertEqual(count, 1)
            finally:
                conn.close()

    def test_primary_key_allows_distinct_ranges(self):
        """Different (introduced, fixed, last_affected) are distinct rows."""
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._open(tmp)
            try:
                conn.execute(
                    "INSERT INTO vulnerabilities (canonical_id) VALUES (?)",
                    ("CVE-2025-1",),
                )
                # Three different ranges for the same CVE/package
                ranges = [
                    ("CVE-2025-1", "somepkg", "ECOSYSTEM", "1.0", "1.5", ""),
                    ("CVE-2025-1", "somepkg", "ECOSYSTEM", "2.0", "2.3", ""),
                    ("CVE-2025-1", "somepkg", "ECOSYSTEM", "3.0", "", ""),
                ]
                for r in ranges:
                    conn.execute(
                        "INSERT INTO affected_ranges "
                        "(canonical_id, package_name, range_type, "
                        "introduced, fixed, last_affected) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        r,
                    )
                count = conn.execute(
                    "SELECT COUNT(*) FROM affected_ranges " "WHERE canonical_id = ?",
                    ("CVE-2025-1",),
                ).fetchone()[0]
                self.assertEqual(count, 3)
            finally:
                conn.close()

    def test_cascade_delete_on_vulnerability(self):
        """Deleting a vulnerability cascades to affected_ranges."""
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._open(tmp)
            try:
                conn.execute(
                    "INSERT INTO vulnerabilities (canonical_id) VALUES (?)",
                    ("CVE-2025-1",),
                )
                conn.execute(
                    "INSERT INTO affected_ranges "
                    "(canonical_id, package_name, range_type, "
                    "introduced, fixed, last_affected) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    ("CVE-2025-1", "somepkg", "ECOSYSTEM", "1.0", "2.0", ""),
                )
                conn.execute(
                    "DELETE FROM vulnerabilities WHERE canonical_id = ?",
                    ("CVE-2025-1",),
                )
                count = conn.execute("SELECT COUNT(*) FROM affected_ranges").fetchone()[
                    0
                ]
                self.assertEqual(count, 0)
            finally:
                conn.close()

    def test_package_index_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._open(tmp)
            try:
                rows = conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='index' AND name='idx_ranges_package'"
                ).fetchall()
                self.assertEqual(len(rows), 1)
            finally:
                conn.close()


class TestTableNamesIncludesRanges(unittest.TestCase):
    def test_affected_ranges_in_table_names(self):
        self.assertIn("affected_ranges", schema.TABLE_NAMES)

    def test_drop_all_tables_includes_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            conn = schema.connect(db_path)
            try:
                schema.initialize_schema(conn)
                # Verify table exists before drop
                exists = conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='affected_ranges'"
                ).fetchall()
                self.assertEqual(len(exists), 1)
                schema.drop_all_tables(conn)
                # Verify table gone after drop
                exists = conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='affected_ranges'"
                ).fetchall()
                self.assertEqual(len(exists), 0)
            finally:
                conn.close()


class TestSchemaCompatibilityWithV1Db(unittest.TestCase):
    def test_v1_db_is_rejected(self):
        """A DB with v1 schema version triggers SchemaVersionMismatch."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            conn = schema.connect(db_path)
            try:
                schema.initialize_schema(conn)
                # Manually downgrade the recorded version to 1
                schema.write_metadata(
                    conn,
                    schema.METADATA_KEY_SCHEMA_VERSION,
                    "1",
                )
                conn.commit()
                with self.assertRaises(schema.SchemaVersionMismatch) as ctx:
                    schema.check_schema_compatibility(conn)
                self.assertEqual(ctx.exception.actual, 1)
                self.assertEqual(ctx.exception.expected, 2)
            finally:
                conn.close()

    def test_v2_db_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            conn = schema.connect(db_path)
            try:
                schema.initialize_schema(conn)
                conn.commit()
                # Should not raise
                schema.check_schema_compatibility(conn)
            finally:
                conn.close()

    def test_no_version_metadata_is_rejected(self):
        """A DB with no version metadata at all is still rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            conn = schema.connect(db_path)
            try:
                # Create the tables but skip the version write
                for stmt in schema.DDL_STATEMENTS:
                    conn.execute(stmt)
                conn.commit()
                with self.assertRaises(schema.SchemaVersionMismatch) as ctx:
                    schema.check_schema_compatibility(conn)
                self.assertIsNone(ctx.exception.actual)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
