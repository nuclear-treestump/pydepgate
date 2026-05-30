"""Tests for pydepgate.package_tools.cvedb.lookup.

Coverage:

  * Exact affected_versions matches return vulnerability fields.
  * ALL-sentinel affected_versions rows match any queried version.
  * Package names are normalized defensively during lookup.
  * Aliases are returned in deterministic order.
  * Duplicate exact and ALL rows collapse to one match, preferring
    the exact-version row.
  * ECOSYSTEM affected_ranges rows are evaluated with the private
    PEP 440 helper.
  * Unsupported or unparseable affected_ranges rows are surfaced as
    unevaluated range hints, not definite matches.
  * Empty name or version inputs return warnings without touching DB
    schema state.
  * File-backed lookup opens and closes the database.
  * Missing database paths raise CveDatabaseNotFound.
  * Schema mismatches propagate as schema.SchemaVersionMismatch.
  * Result records are pickle-safe.
"""

from __future__ import annotations

import pickle
import sqlite3
import tempfile
import unittest
from pathlib import Path

from pydepgate.dbs import cvedb
from pydepgate.dbs.cvedb import constants
from pydepgate.dbs.cvedb import importer
from pydepgate.dbs.cvedb import lookup
from pydepgate.dbs.cvedb import schema

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_conn() -> sqlite3.Connection:
    conn = schema.connect(":memory:")
    schema.initialize_schema(conn)
    return conn


def _insert_vulnerability(
    conn: sqlite3.Connection,
    canonical_id: str,
    *,
    summary: str | None = None,
    details: str | None = None,
    severity: str | None = None,
    cvss_v3: str | None = None,
    cvss_v4: str | None = None,
    versions_complete: int = 1,
) -> None:
    conn.execute(
        "INSERT INTO vulnerabilities "
        "(canonical_id, summary, details, published, modified, "
        "cvss_v3, cvss_v4, severity, versions_complete) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            canonical_id,
            summary,
            details,
            "2025-01-02T00:00:00Z",
            "2025-01-03T00:00:00Z",
            cvss_v3,
            cvss_v4,
            severity,
            versions_complete,
        ),
    )
    conn.execute(
        "INSERT INTO aliases (alias, canonical_id, alias_type) " "VALUES (?, ?, ?)",
        (
            canonical_id,
            canonical_id,
            "CVE" if canonical_id.startswith("CVE-") else "OTHER",
        ),
    )


def _insert_alias(
    conn: sqlite3.Connection,
    canonical_id: str,
    alias: str,
    alias_type: str,
) -> None:
    conn.execute(
        "INSERT INTO aliases (alias, canonical_id, alias_type) " "VALUES (?, ?, ?)",
        (alias, canonical_id, alias_type),
    )


def _insert_version(
    conn: sqlite3.Connection,
    canonical_id: str,
    package_name: str,
    version: str,
) -> None:
    conn.execute(
        "INSERT INTO affected_versions "
        "(canonical_id, package_name, version) VALUES (?, ?, ?)",
        (canonical_id, package_name, version),
    )


def _insert_range(
    conn: sqlite3.Connection,
    canonical_id: str,
    package_name: str,
    *,
    introduced: str = "0",
    fixed: str = "2.0.0",
    last_affected: str = "",
    range_type: str = "ECOSYSTEM",
) -> None:
    conn.execute(
        "INSERT INTO affected_ranges "
        "(canonical_id, package_name, range_type, introduced, fixed, "
        "last_affected) VALUES (?, ?, ?, ?, ?, ?)",
        (canonical_id, package_name, range_type, introduced, fixed, last_affected),
    )


# ---------------------------------------------------------------------------
# normalize_package_name()
# ---------------------------------------------------------------------------


class NormalizePackageNameTests(unittest.TestCase):
    def test_normalizes_pep503_style(self):
        self.assertEqual(
            lookup.normalize_package_name("Foo_Bar.baz---Qux"),
            "foo-bar-baz-qux",
        )


# ---------------------------------------------------------------------------
# lookup_package()
# ---------------------------------------------------------------------------


class LookupPackageTests(unittest.TestCase):
    def test_exact_version_hit_returns_vulnerability_fields(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(
                conn,
                "CVE-2025-0001",
                summary="bad package",
                details="details here",
                severity="HIGH",
                cvss_v3="CVSS:3.1/test",
            )
            _insert_version(conn, "CVE-2025-0001", "example-pkg", "1.2.3")

            result = lookup.lookup_package(conn, "example-pkg", "1.2.3")

            self.assertEqual(result.package_name, "example-pkg")
            self.assertEqual(result.normalized_package_name, "example-pkg")
            self.assertEqual(result.package_version, "1.2.3")
            self.assertEqual(result.warnings, ())
            self.assertEqual(len(result.matches), 1)
            match = result.matches[0]
            self.assertEqual(match.canonical_id, "CVE-2025-0001")
            self.assertEqual(match.match_type, lookup.MATCH_TYPE_EXACT_VERSION)
            self.assertEqual(match.database_package_name, "example-pkg")
            self.assertEqual(match.database_version, "1.2.3")
            self.assertEqual(match.summary, "bad package")
            self.assertEqual(match.details, "details here")
            self.assertEqual(match.severity, "HIGH")
            self.assertEqual(match.cvss_v3, "CVSS:3.1/test")
            self.assertTrue(match.versions_complete)
        finally:
            conn.close()

    def test_exact_version_miss_returns_empty_result(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0002")
            _insert_version(conn, "CVE-2025-0002", "example-pkg", "1.2.3")

            result = lookup.lookup_package(conn, "example-pkg", "9.9.9")

            self.assertFalse(result.has_matches)
            self.assertEqual(result.matches, ())
            self.assertEqual(result.warnings, ())
        finally:
            conn.close()

    def test_all_versions_sentinel_matches_any_version(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0003", severity="CRITICAL")
            _insert_version(
                conn,
                "CVE-2025-0003",
                "evil-pkg",
                importer.ALL_VERSIONS_SENTINEL,
            )

            result = lookup.lookup_package(conn, "evil-pkg", "999.0")

            self.assertEqual(len(result.matches), 1)
            match = result.matches[0]
            self.assertEqual(match.match_type, lookup.MATCH_TYPE_ALL_VERSIONS)
            self.assertEqual(match.database_version, importer.ALL_VERSIONS_SENTINEL)
            self.assertEqual(match.severity, "CRITICAL")
        finally:
            conn.close()

    def test_aliases_are_returned_sorted(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0004")
            _insert_alias(conn, "CVE-2025-0004", "GHSA-zzzz-yyyy-xxxx", "GHSA")
            _insert_alias(conn, "CVE-2025-0004", "PYSEC-2025-4", "PYSEC")
            _insert_version(conn, "CVE-2025-0004", "example-pkg", "1.0")

            result = lookup.lookup_package(conn, "example-pkg", "1.0")

            self.assertEqual(
                result.matches[0].aliases,
                ("CVE-2025-0004", "GHSA-zzzz-yyyy-xxxx", "PYSEC-2025-4"),
            )
        finally:
            conn.close()

    def test_normalized_name_lookup_matches_database_variants(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0005")
            _insert_version(conn, "CVE-2025-0005", "Example_Pkg", "1.0")

            result = lookup.lookup_package(conn, "example-pkg", "1.0")

            self.assertEqual(len(result.matches), 1)
            self.assertEqual(result.matches[0].database_package_name, "Example_Pkg")
            self.assertEqual(result.normalized_package_name, "example-pkg")
        finally:
            conn.close()

    def test_exact_row_preferred_over_all_row_for_same_canonical(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0006")
            _insert_version(
                conn,
                "CVE-2025-0006",
                "example-pkg",
                importer.ALL_VERSIONS_SENTINEL,
            )
            _insert_version(conn, "CVE-2025-0006", "example-pkg", "1.0")

            result = lookup.lookup_package(conn, "example-pkg", "1.0")

            self.assertEqual(len(result.matches), 1)
            self.assertEqual(
                result.matches[0].match_type,
                lookup.MATCH_TYPE_EXACT_VERSION,
            )
            self.assertEqual(result.matches[0].database_version, "1.0")
        finally:
            conn.close()

    def test_fixed_range_row_matches_when_version_is_inside_range(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0007")
            _insert_range(
                conn,
                "CVE-2025-0007",
                "setuptools",
                introduced="0",
                fixed="78.1.1",
            )

            result = lookup.lookup_package(conn, "setuptools", "70.0.0")

            self.assertFalse(result.has_unevaluated_ranges)
            self.assertEqual(result.warnings, ())
            self.assertEqual(len(result.matches), 1)
            match = result.matches[0]
            self.assertEqual(match.canonical_id, "CVE-2025-0007")
            self.assertEqual(match.match_type, lookup.MATCH_TYPE_RANGE_FIXED)
            self.assertEqual(match.database_package_name, "setuptools")
            self.assertEqual(match.database_version, "")
            self.assertEqual(match.range_type, "ECOSYSTEM")
            self.assertEqual(match.introduced, "0")
            self.assertEqual(match.fixed, "78.1.1")
            self.assertEqual(match.last_affected, "")
        finally:
            conn.close()

    def test_fixed_range_row_does_not_match_when_version_is_after_fix(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0010")
            _insert_range(
                conn,
                "CVE-2025-0010",
                "setuptools",
                introduced="0",
                fixed="78.1.1",
            )

            result = lookup.lookup_package(conn, "setuptools", "78.1.1")

            self.assertEqual(result.matches, ())
            self.assertEqual(result.unevaluated_ranges, ())
            self.assertEqual(result.warnings, ())
        finally:
            conn.close()

    def test_last_affected_range_row_matches_inclusive_upper_bound(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0011")
            _insert_range(
                conn,
                "CVE-2025-0011",
                "example-pkg",
                introduced="1.0",
                fixed="",
                last_affected="1.5",
            )

            result = lookup.lookup_package(conn, "example-pkg", "1.5")

            self.assertEqual(len(result.matches), 1)
            self.assertEqual(
                result.matches[0].match_type,
                lookup.MATCH_TYPE_RANGE_LAST_AFFECTED,
            )
            self.assertEqual(result.matches[0].last_affected, "1.5")
        finally:
            conn.close()

    def test_open_range_row_matches_from_introduced_onward(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0012")
            _insert_range(
                conn,
                "CVE-2025-0012",
                "example-pkg",
                introduced="2.0",
                fixed="",
                last_affected="",
            )

            result = lookup.lookup_package(conn, "example-pkg", "2.1")

            self.assertEqual(len(result.matches), 1)
            self.assertEqual(result.matches[0].match_type, lookup.MATCH_TYPE_RANGE_OPEN)
            self.assertEqual(result.matches[0].introduced, "2.0")
        finally:
            conn.close()

    def test_unparseable_range_row_is_reported_but_not_matched(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0013")
            _insert_range(
                conn,
                "CVE-2025-0013",
                "setuptools",
                introduced="not-a-version",
                fixed="78.1.1",
            )

            result = lookup.lookup_package(conn, "setuptools", "70.0.0")

            self.assertEqual(result.matches, ())
            self.assertTrue(result.has_unevaluated_ranges)
            self.assertIn(
                lookup.WARNING_RANGE_ROWS_UNEVALUATED,
                result.warnings,
            )
            self.assertEqual(len(result.unevaluated_ranges), 1)
            range_hint = result.unevaluated_ranges[0]
            self.assertEqual(range_hint.canonical_id, "CVE-2025-0013")
            self.assertEqual(range_hint.package_name, "setuptools")
            self.assertEqual(range_hint.introduced, "not-a-version")
            self.assertEqual(range_hint.fixed, "78.1.1")
            self.assertEqual(
                range_hint.reason,
                lookup.UNEVALUATED_REASON_UNPARSEABLE_VERSION_RANGE,
            )
        finally:
            conn.close()

    def test_git_range_row_is_reported_but_not_compared(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0018")
            _insert_range(
                conn,
                "CVE-2025-0018",
                "luigi",
                introduced="0",
                fixed="b5d1b965ead7d9f777a3216369b5baf23ec08999",
                range_type="GIT",
            )

            result = lookup.lookup_package(conn, "luigi", "3.6.0")

            self.assertEqual(result.matches, ())
            self.assertTrue(result.has_unevaluated_ranges)
            self.assertIn(
                lookup.WARNING_RANGE_ROWS_UNEVALUATED,
                result.warnings,
            )
            self.assertEqual(len(result.unevaluated_ranges), 1)
            range_hint = result.unevaluated_ranges[0]
            self.assertEqual(range_hint.canonical_id, "CVE-2025-0018")
            self.assertEqual(range_hint.package_name, "luigi")
            self.assertEqual(range_hint.range_type, "GIT")
            self.assertEqual(range_hint.introduced, "0")
            self.assertEqual(
                range_hint.fixed,
                "b5d1b965ead7d9f777a3216369b5baf23ec08999",
            )
            self.assertEqual(
                range_hint.reason,
                lookup.UNEVALUATED_REASON_UNSUPPORTED_RANGE_TYPE,
            )
        finally:
            conn.close()

    def test_exact_row_preferred_over_range_row_for_same_canonical(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0014")
            _insert_range(
                conn,
                "CVE-2025-0014",
                "example-pkg",
                introduced="0",
                fixed="2.0",
            )
            _insert_version(conn, "CVE-2025-0014", "example-pkg", "1.0")

            result = lookup.lookup_package(conn, "example-pkg", "1.0")

            self.assertEqual(len(result.matches), 1)
            self.assertEqual(
                result.matches[0].match_type,
                lookup.MATCH_TYPE_EXACT_VERSION,
            )
            self.assertEqual(result.matches[0].database_version, "1.0")
        finally:
            conn.close()

    def test_range_row_preferred_over_all_row_for_same_canonical(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0015")
            _insert_version(
                conn,
                "CVE-2025-0015",
                "example-pkg",
                importer.ALL_VERSIONS_SENTINEL,
            )
            _insert_range(
                conn,
                "CVE-2025-0015",
                "example-pkg",
                introduced="0",
                fixed="2.0",
            )

            result = lookup.lookup_package(conn, "example-pkg", "1.0")

            self.assertEqual(len(result.matches), 1)
            self.assertEqual(
                result.matches[0].match_type, lookup.MATCH_TYPE_RANGE_FIXED
            )
            self.assertEqual(result.matches[0].fixed, "2.0")
        finally:
            conn.close()

    def test_empty_package_name_returns_warning_without_schema(self):
        conn = sqlite3.connect(":memory:")
        try:
            result = lookup.lookup_package(conn, "  ", "1.0")
            self.assertEqual(result.matches, ())
            self.assertIn(lookup.WARNING_EMPTY_PACKAGE_NAME, result.warnings)
        finally:
            conn.close()

    def test_empty_version_returns_warning_without_schema(self):
        conn = sqlite3.connect(":memory:")
        try:
            result = lookup.lookup_package(conn, "example-pkg", "  ")
            self.assertEqual(result.matches, ())
            self.assertIn(lookup.WARNING_EMPTY_PACKAGE_VERSION, result.warnings)
        finally:
            conn.close()

    def test_schema_version_mismatch_propagates(self):
        conn = _make_conn()
        try:
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_SCHEMA_VERSION,
                "999",
            )
            with self.assertRaises(schema.SchemaVersionMismatch):
                lookup.lookup_package(conn, "example-pkg", "1.0")
        finally:
            conn.close()

    def test_attribution_uses_db_metadata_when_present(self):
        conn = _make_conn()
        try:
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_DATA_SOURCE_NAME,
                "Test Source",
            )
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_DATA_SOURCE_URL,
                "https://example.invalid",
            )
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_DATA_LICENSE,
                "TEST-LICENSE",
            )
            result = lookup.lookup_package(conn, "example-pkg", "1.0")
            self.assertEqual(
                result.attribution,
                "Vulnerability data: Test Source "
                "(https://example.invalid), TEST-LICENSE.",
            )
        finally:
            conn.close()

    def test_attribution_falls_back_to_constant(self):
        conn = _make_conn()
        try:
            result = lookup.lookup_package(conn, "example-pkg", "1.0")
            self.assertEqual(result.attribution, constants.OSV_DATA_ATTRIBUTION_LINE)
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# lookup_package_in_db()
# ---------------------------------------------------------------------------


class LookupPackageInDbTests(unittest.TestCase):
    def test_missing_db_path_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.db"
            with self.assertRaises(lookup.CveDatabaseNotFound) as ctx:
                lookup.lookup_package_in_db(missing, "example-pkg", "1.0")
            self.assertEqual(ctx.exception.path, missing)

    def test_file_backed_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "cvedb.sqlite"
            conn = schema.connect(db_path)
            try:
                schema.initialize_schema(conn)
                _insert_vulnerability(conn, "CVE-2025-0008")
                _insert_version(conn, "CVE-2025-0008", "example-pkg", "1.0")
                conn.commit()
            finally:
                conn.close()

            result = lookup.lookup_package_in_db(db_path, "example-pkg", "1.0")

            self.assertEqual(len(result.matches), 1)
            self.assertEqual(result.matches[0].canonical_id, "CVE-2025-0008")


# ---------------------------------------------------------------------------
# Pickle safety
# ---------------------------------------------------------------------------


class PickleSafetyTests(unittest.TestCase):
    def test_lookup_result_round_trip(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0009")
            _insert_version(conn, "CVE-2025-0009", "example-pkg", "1.0")
            _insert_range(conn, "CVE-2025-0009", "example-pkg")

            result = lookup.lookup_package(conn, "example-pkg", "1.0")
            restored = pickle.loads(pickle.dumps(result))

            self.assertEqual(restored, result)
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Public cvedb shim
# ---------------------------------------------------------------------------


class PublicCvedbShimTests(unittest.TestCase):
    def test_lookup_package_shim_delegates_to_lookup_module(self):
        conn = _make_conn()
        try:
            _insert_vulnerability(conn, "CVE-2025-0016")
            _insert_version(conn, "CVE-2025-0016", "example-pkg", "1.0")

            result = cvedb.lookup_package(conn, "example-pkg", "1.0")

            self.assertEqual(len(result.matches), 1)
            self.assertEqual(result.matches[0].canonical_id, "CVE-2025-0016")
        finally:
            conn.close()

    def test_lookup_package_in_db_shim_delegates_to_lookup_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "cvedb.sqlite"
            conn = schema.connect(db_path)
            try:
                schema.initialize_schema(conn)
                _insert_vulnerability(conn, "CVE-2025-0017")
                _insert_version(conn, "CVE-2025-0017", "example-pkg", "1.0")
                conn.commit()
            finally:
                conn.close()

            result = cvedb.lookup_package_in_db(db_path, "example-pkg", "1.0")

            self.assertEqual(len(result.matches), 1)
            self.assertEqual(result.matches[0].canonical_id, "CVE-2025-0017")


if __name__ == "__main__":
    unittest.main()
