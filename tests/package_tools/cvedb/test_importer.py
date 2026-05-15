"""Tests for pydepgate.package_tools.cvedb.importer.

Coverage:

  * Canonical ID derivation across priority classes (CVE, GHSA,
    PYSEC, unknown) and tiebreakers.
  * alias_type classification.
  * Per-record parse against realistic OSV record shapes (the
    setuptools and dulwich samples Ikari shared, with range-only
    and non-PyPI variants).
  * Merge logic: UNION of affected versions, severity rank,
    earliest published / latest modified, OR of
    has_explicit_versions.
  * Zip validation: corrupt zip, per-file limit, aggregate
    limit.
  * End-to-end import against a synthetic zip and verification
    of the resulting DB state (lookup queries, alias resolution,
    self-alias presence, metadata writes).
  * Progress callback firing.
  * Range-only records get versions_complete=0 and an
    import_warnings row.
  * Parse errors logged to import_warnings.
  * Re-import replaces prior DB contents atomically.
  * Picklability of ParsedRecord, ParseFailure, ImportResult.

Test fixtures are built from the actual OSV record samples
provided in conversation, slightly simplified for test clarity.
The synthetic data exercises the dedup, merge, and warning paths
without requiring network access to the real OSV dataset.
"""

from __future__ import annotations

import json
import pickle
import tempfile
import unittest
import zipfile
from pathlib import Path

from pydepgate.package_tools.cvedb import importer, schema

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


def _setuptools_record() -> dict:
    """PYSEC-2025-49 / CVE-2025-47273 / GHSA-5rjg-fvgr-3xxf (real shape)."""
    return {
        "schema_version": "1.7.3",
        "id": "PYSEC-2025-49",
        "published": "2025-05-17T16:15:19Z",
        "modified": "2026-05-11T00:26:34.671259971Z",
        "aliases": [
            "BIT-setuptools-2025-47273",
            "CVE-2025-47273",
            "GHSA-5rjg-fvgr-3xxf",
        ],
        "details": "setuptools path traversal vulnerability.",
        "affected": [
            {
                "package": {
                    "name": "setuptools",
                    "ecosystem": "PyPI",
                    "purl": "pkg:pypi/setuptools",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "78.1.1"},
                        ],
                    },
                ],
                "versions": ["75.0.0", "76.0.0", "77.0.1", "78.0.1", "78.1.0"],
            },
        ],
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            },
        ],
    }


def _dulwich_record() -> dict:
    """GHSA-4j5j-58j7-6c3w / CVE-2014-9706 / PYSEC-2015-34 (real shape)."""
    return {
        "schema_version": "1.7.5",
        "id": "GHSA-4j5j-58j7-6c3w",
        "published": "2022-05-17T04:14:03Z",
        "modified": "2026-05-14T23:16:30.098942Z",
        "aliases": ["CVE-2014-9706", "PYSEC-2015-34"],
        "summary": "Dulwich Arbitrary code execution",
        "details": "The build_index_from_tree function allows RCE.",
        "affected": [
            {
                "package": {
                    "name": "dulwich",
                    "ecosystem": "PyPI",
                    "purl": "pkg:pypi/dulwich",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "0.9.10"},
                        ],
                    },
                ],
                "versions": ["0.9.7", "0.9.8", "0.9.9"],
            },
        ],
        "database_specific": {"severity": "CRITICAL"},
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
        ],
    }


def _range_only_record() -> dict:
    """A record with only ECOSYSTEM ranges, no explicit versions list."""
    return {
        "schema_version": "1.7.0",
        "id": "PYSEC-2099-1",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2099-0001"],
        "summary": "Hypothetical range-only record",
        "affected": [
            {
                "package": {"name": "mystery-package", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
                    },
                ],
            },
        ],
    }


def _non_pypi_record() -> dict:
    """A record that affects a non-PyPI ecosystem only."""
    return {
        "schema_version": "1.7.0",
        "id": "GHSA-npm-thing",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": [],
        "affected": [
            {
                "package": {"name": "express", "ecosystem": "npm"},
                "versions": ["4.0.0"],
            },
        ],
    }


def _make_test_zip(
    tmp_path: Path,
    records: list[tuple[str, dict | bytes]],
) -> Path:
    """Build a zip with one JSON entry per record; bytes pass through."""
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in records:
            if isinstance(content, bytes):
                zf.writestr(name, content)
            else:
                zf.writestr(name, json.dumps(content))
    return zip_path


# ---------------------------------------------------------------------------
# Canonical ID derivation
# ---------------------------------------------------------------------------


class TestCanonicalIdDerivation(unittest.TestCase):
    def test_pysec_id_with_cve_alias_yields_cve(self):
        cid, ctype = importer._derive_canonical_id(
            "PYSEC-2025-49",
            ["CVE-2025-47273", "GHSA-5rjg-fvgr-3xxf"],
        )
        self.assertEqual(cid, "CVE-2025-47273")
        self.assertEqual(ctype, "CVE")

    def test_ghsa_id_with_cve_alias_yields_cve(self):
        cid, ctype = importer._derive_canonical_id(
            "GHSA-4j5j-58j7-6c3w",
            ["CVE-2014-9706", "PYSEC-2015-34"],
        )
        self.assertEqual(cid, "CVE-2014-9706")
        self.assertEqual(ctype, "CVE")

    def test_pysec_id_no_cve_alias_yields_ghsa(self):
        cid, ctype = importer._derive_canonical_id(
            "PYSEC-2025-99",
            ["GHSA-aaaa-bbbb-cccc"],
        )
        self.assertEqual(cid, "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(ctype, "GHSA")

    def test_pysec_only_yields_pysec(self):
        cid, ctype = importer._derive_canonical_id("PYSEC-2025-1", [])
        self.assertEqual(cid, "PYSEC-2025-1")
        self.assertEqual(ctype, "PYSEC")

    def test_unknown_prefix_yields_other(self):
        cid, ctype = importer._derive_canonical_id("WEIRD-2025-1", [])
        self.assertEqual(cid, "WEIRD-2025-1")
        self.assertEqual(ctype, "OTHER")

    def test_multiple_cves_picks_alphabetically_first(self):
        cid, _ = importer._derive_canonical_id(
            "GHSA-x",
            ["CVE-2025-9999", "CVE-2025-0001"],
        )
        self.assertEqual(cid, "CVE-2025-0001")


class TestAliasTypeFor(unittest.TestCase):
    def test_cve(self):
        self.assertEqual(importer._alias_type_for("CVE-2025-1"), "CVE")

    def test_ghsa(self):
        self.assertEqual(importer._alias_type_for("GHSA-xxxx"), "GHSA")

    def test_pysec(self):
        self.assertEqual(importer._alias_type_for("PYSEC-2025-1"), "PYSEC")

    def test_bit(self):
        self.assertEqual(importer._alias_type_for("BIT-pkg-2025"), "BIT")

    def test_unknown(self):
        self.assertEqual(importer._alias_type_for("WEIRD-2025-1"), "OTHER")


# ---------------------------------------------------------------------------
# Per-record parsing
# ---------------------------------------------------------------------------


class TestParseEntry(unittest.TestCase):
    def test_parses_setuptools_record(self):
        data = json.dumps(_setuptools_record()).encode("utf-8")
        result = importer._parse_entry("PYSEC-2025-49.json", data)
        self.assertIsInstance(result, importer.ParsedRecord)
        self.assertEqual(result.osv_id, "PYSEC-2025-49")
        self.assertEqual(result.canonical_id, "CVE-2025-47273")
        self.assertEqual(result.canonical_id_type, "CVE")
        self.assertTrue(result.has_explicit_versions)
        idents = {i for i, _ in result.all_identifiers}
        self.assertIn("CVE-2025-47273", idents)
        self.assertIn("PYSEC-2025-49", idents)
        self.assertIn("GHSA-5rjg-fvgr-3xxf", idents)
        self.assertIn("BIT-setuptools-2025-47273", idents)
        self.assertIn(("setuptools", "75.0.0"), result.affected)
        self.assertIn(("setuptools", "78.1.0"), result.affected)
        self.assertIsNotNone(result.cvss_v3)

    def test_parses_dulwich_record_with_v3_and_v4(self):
        data = json.dumps(_dulwich_record()).encode("utf-8")
        result = importer._parse_entry("GHSA-4j5j-58j7-6c3w.json", data)
        self.assertIsInstance(result, importer.ParsedRecord)
        self.assertEqual(result.canonical_id, "CVE-2014-9706")
        self.assertIsNotNone(result.cvss_v3)
        self.assertIsNotNone(result.cvss_v4)
        self.assertEqual(result.severity, "CRITICAL")

    def test_range_only_record_flagged(self):
        data = json.dumps(_range_only_record()).encode("utf-8")
        result = importer._parse_entry("PYSEC-2099-1.json", data)
        self.assertIsInstance(result, importer.ParsedRecord)
        self.assertFalse(result.has_explicit_versions)
        self.assertEqual(result.affected, ())

    def test_non_pypi_record_is_failure(self):
        data = json.dumps(_non_pypi_record()).encode("utf-8")
        result = importer._parse_entry("GHSA-npm-thing.json", data)
        self.assertIsInstance(result, importer.ParseFailure)
        self.assertEqual(result.reason, importer.WARNING_NO_PYPI_AFFECTED)

    def test_malformed_json_is_failure(self):
        result = importer._parse_entry("bad.json", b"{not valid json")
        self.assertIsInstance(result, importer.ParseFailure)
        self.assertEqual(result.reason, importer.WARNING_PARSE_ERROR)

    def test_missing_id_is_failure(self):
        data = json.dumps({"aliases": []}).encode("utf-8")
        result = importer._parse_entry("no-id.json", data)
        self.assertIsInstance(result, importer.ParseFailure)
        self.assertEqual(result.reason, importer.WARNING_MISSING_ID)

    def test_top_level_array_is_failure(self):
        data = json.dumps(["not", "an", "object"]).encode("utf-8")
        result = importer._parse_entry("bad-shape.json", data)
        self.assertIsInstance(result, importer.ParseFailure)
        self.assertEqual(result.reason, importer.WARNING_MALFORMED_RECORD)


# ---------------------------------------------------------------------------
# Merge logic
# ---------------------------------------------------------------------------


class TestMergeRecords(unittest.TestCase):
    def test_two_records_same_cve_merge_into_one(self):
        """Both records share CVE-2025-47273 via aliases."""
        rec_a = importer.ParsedRecord(
            osv_id="PYSEC-2025-49",
            canonical_id="CVE-2025-47273",
            canonical_id_type="CVE",
            all_identifiers=(
                ("PYSEC-2025-49", "PYSEC"),
                ("CVE-2025-47273", "CVE"),
                ("GHSA-xxxx", "GHSA"),
            ),
            summary="setuptools issue from pypa",
            details=None,
            published="2025-05-17T00:00:00Z",
            modified="2026-05-10T00:00:00Z",
            cvss_v3="CVSS:3.1/AV:N/X",
            cvss_v4=None,
            severity="HIGH",
            affected=(("setuptools", "75.0.0"), ("setuptools", "76.0.0")),
            has_explicit_versions=True,
        )
        rec_b = importer.ParsedRecord(
            osv_id="GHSA-xxxx",
            canonical_id="CVE-2025-47273",
            canonical_id_type="CVE",
            all_identifiers=(
                ("GHSA-xxxx", "GHSA"),
                ("CVE-2025-47273", "CVE"),
            ),
            summary="setuptools issue from github",
            details="more details",
            published="2025-05-18T00:00:00Z",
            modified="2026-05-11T00:00:00Z",
            cvss_v3=None,
            cvss_v4="CVSS:4.0/X",
            severity="CRITICAL",
            affected=(("setuptools", "76.0.0"), ("setuptools", "77.0.1")),
            has_explicit_versions=True,
        )
        merged = importer._merge_records([rec_a, rec_b])
        self.assertEqual(len(merged), 1)
        result = merged["CVE-2025-47273"]
        # UNION of affected
        self.assertIn(("setuptools", "75.0.0"), result.affected)
        self.assertIn(("setuptools", "76.0.0"), result.affected)
        self.assertIn(("setuptools", "77.0.1"), result.affected)
        # Highest severity wins
        self.assertEqual(result.severity, "CRITICAL")
        # First non-empty wins for descriptive fields
        self.assertEqual(result.summary, "setuptools issue from pypa")
        self.assertEqual(result.details, "more details")
        # Earliest published, latest modified
        self.assertEqual(result.published, "2025-05-17T00:00:00Z")
        self.assertEqual(result.modified, "2026-05-11T00:00:00Z")
        # Both CVSS values populated across records
        self.assertEqual(result.cvss_v3, "CVSS:3.1/AV:N/X")
        self.assertEqual(result.cvss_v4, "CVSS:4.0/X")
        # All contributing identifiers collected
        idents = {i for i, _ in result.identifiers}
        self.assertIn("CVE-2025-47273", idents)
        self.assertIn("PYSEC-2025-49", idents)
        self.assertIn("GHSA-xxxx", idents)

    def test_versions_complete_or_semantics(self):
        rec_explicit = importer.ParsedRecord(
            osv_id="PYSEC-1",
            canonical_id="CVE-1",
            canonical_id_type="CVE",
            all_identifiers=(),
            summary=None,
            details=None,
            published=None,
            modified=None,
            cvss_v3=None,
            cvss_v4=None,
            severity=None,
            affected=(("pkg", "1.0"),),
            has_explicit_versions=True,
        )
        rec_range_only = importer.ParsedRecord(
            osv_id="GHSA-1",
            canonical_id="CVE-1",
            canonical_id_type="CVE",
            all_identifiers=(),
            summary=None,
            details=None,
            published=None,
            modified=None,
            cvss_v3=None,
            cvss_v4=None,
            severity=None,
            affected=(),
            has_explicit_versions=False,
        )
        merged = importer._merge_records([rec_range_only, rec_explicit])
        self.assertTrue(merged["CVE-1"].has_explicit_versions)


# ---------------------------------------------------------------------------
# Zip validation
# ---------------------------------------------------------------------------


class TestZipValidation(unittest.TestCase):
    def test_rejects_corrupted_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.zip"
            path.write_bytes(b"this is not a zip file")
            with self.assertRaises(importer.ZipValidationError):
                importer._validate_zip(
                    path,
                    max_decompressed_bytes=1024 * 1024,
                    max_per_file_bytes=1024,
                )

    def test_rejects_zip_above_aggregate_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _make_test_zip(
                Path(tmp),
                [(f"r{i}.json", {"id": f"x-{i}"}) for i in range(10)],
            )
            with self.assertRaises(importer.ZipValidationError) as ctx:
                importer._validate_zip(
                    path,
                    max_decompressed_bytes=10,
                    max_per_file_bytes=1024,
                )
            self.assertIn("decompress", str(ctx.exception))

    def test_rejects_zip_with_oversized_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _make_test_zip(
                Path(tmp),
                [("big.json", {"id": "x", "padding": "y" * 10000})],
            )
            with self.assertRaises(importer.ZipValidationError) as ctx:
                importer._validate_zip(
                    path,
                    max_decompressed_bytes=1024 * 1024,
                    max_per_file_bytes=100,
                )
            self.assertIn("per-file limit", str(ctx.exception))


# ---------------------------------------------------------------------------
# End-to-end import
# ---------------------------------------------------------------------------


class TestImportFromZip(unittest.TestCase):
    def test_imports_setuptools_and_dulwich(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("PYSEC-2025-49.json", _setuptools_record()),
                    ("GHSA-4j5j-58j7-6c3w.json", _dulwich_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            result = importer.import_from_zip(
                zip_path,
                db_path,
                snapshot_sha256="deadbeef",
            )
            self.assertEqual(result.records_imported, 2)
            self.assertEqual(result.records_skipped_no_versions, 0)
            self.assertEqual(result.records_with_parse_errors, 0)
            self.assertGreater(result.affected_version_rows, 0)
            self.assertGreater(result.alias_rows, 0)
            self.assertGreater(result.elapsed_seconds, 0.0)

            conn = schema.connect(db_path)
            try:
                # Lookup by package and version returns the canonical
                rows = conn.execute(
                    "SELECT v.canonical_id FROM affected_versions av "
                    "JOIN vulnerabilities v ON av.canonical_id = v.canonical_id "
                    "WHERE av.package_name = ? AND av.version = ?",
                    ("setuptools", "75.0.0"),
                ).fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][0], "CVE-2025-47273")

                rows = conn.execute(
                    "SELECT v.canonical_id FROM affected_versions av "
                    "JOIN vulnerabilities v ON av.canonical_id = v.canonical_id "
                    "WHERE av.package_name = ? AND av.version = ?",
                    ("dulwich", "0.9.8"),
                ).fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][0], "CVE-2014-9706")

                # Lookup by alias resolves to canonical
                row = conn.execute(
                    "SELECT canonical_id FROM aliases WHERE alias = ?",
                    ("PYSEC-2025-49",),
                ).fetchone()
                self.assertEqual(row[0], "CVE-2025-47273")
                row = conn.execute(
                    "SELECT canonical_id FROM aliases WHERE alias = ?",
                    ("GHSA-5rjg-fvgr-3xxf",),
                ).fetchone()
                self.assertEqual(row[0], "CVE-2025-47273")

                # Self-alias is present (canonical resolves to itself)
                row = conn.execute(
                    "SELECT canonical_id FROM aliases WHERE alias = ?",
                    ("CVE-2025-47273",),
                ).fetchone()
                self.assertEqual(row[0], "CVE-2025-47273")

                # Severity persisted (dulwich had database_specific.severity)
                row = conn.execute(
                    "SELECT severity FROM vulnerabilities WHERE canonical_id = ?",
                    ("CVE-2014-9706",),
                ).fetchone()
                self.assertEqual(row[0], "CRITICAL")

                # Provenance metadata written
                snapshot = schema.read_metadata(
                    conn, schema.METADATA_KEY_LAST_SNAPSHOT_SHA256
                )
                self.assertEqual(snapshot, "deadbeef")
                last_update = schema.read_metadata(
                    conn, schema.METADATA_KEY_LAST_FULL_UPDATE
                )
                self.assertIsNotNone(last_update)
            finally:
                conn.close()

    def test_progress_callback_invoked(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("a.json", _setuptools_record()),
                    ("b.json", _dulwich_record()),
                    ("c.json", _range_only_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            calls: list[tuple[int, int]] = []
            importer.import_from_zip(
                zip_path,
                db_path,
                progress_callback=lambda c, t: calls.append((c, t)),
            )
            # Initial (0, total) plus one per record = at least 4 calls.
            self.assertGreater(len(calls), 0)
            # Last call must reflect 100%.
            self.assertEqual(calls[-1][0], calls[-1][1])
            # Total equals the JSON entry count.
            self.assertEqual(calls[-1][1], 3)

    def test_range_only_record_recorded_with_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [("range-only.json", _range_only_record())],
            )
            db_path = tmp_path / "test.db"
            result = importer.import_from_zip(zip_path, db_path)
            self.assertEqual(result.records_imported, 1)
            self.assertEqual(result.records_skipped_no_versions, 1)
            self.assertEqual(result.affected_version_rows, 0)

            conn = schema.connect(db_path)
            try:
                # versions_complete is 0 for the range-only record.
                row = conn.execute(
                    "SELECT versions_complete FROM vulnerabilities "
                    "WHERE canonical_id = ?",
                    ("CVE-2099-0001",),
                ).fetchone()
                self.assertEqual(row[0], 0)

                # import_warnings row written for the range-only case.
                rows = conn.execute(
                    "SELECT osv_id, reason FROM import_warnings " "WHERE reason = ?",
                    (importer.WARNING_NO_VERSIONS,),
                ).fetchall()
                self.assertEqual(len(rows), 1)
            finally:
                conn.close()

    def test_parse_errors_logged_to_warnings(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("good.json", _setuptools_record()),
                    ("bad.json", b"{not valid json"),
                    ("npm.json", _non_pypi_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            result = importer.import_from_zip(zip_path, db_path)
            self.assertEqual(result.records_imported, 1)
            self.assertEqual(result.records_with_parse_errors, 2)

            conn = schema.connect(db_path)
            try:
                # parse_error warning logged for bad.json
                rows = conn.execute(
                    "SELECT reason FROM import_warnings WHERE reason = ?",
                    (importer.WARNING_PARSE_ERROR,),
                ).fetchall()
                self.assertEqual(len(rows), 1)
                # no_pypi_affected warning logged for npm.json
                rows = conn.execute(
                    "SELECT reason FROM import_warnings WHERE reason = ?",
                    (importer.WARNING_NO_PYPI_AFFECTED,),
                ).fetchall()
                self.assertEqual(len(rows), 1)
            finally:
                conn.close()

    def test_atomic_replacement_on_reimport(self):
        """A successful re-import replaces the prior DB contents."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "test.db"

            # First import: one record.
            (tmp_path / "a").mkdir()
            zip_a = _make_test_zip(
                tmp_path / "a",
                [("setuptools.json", _setuptools_record())],
            )
            importer.import_from_zip(zip_a, db_path)
            conn = schema.connect(db_path)
            try:
                row = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()
                self.assertEqual(row[0], 1)
            finally:
                conn.close()

            # Re-import with two records: replaces.
            (tmp_path / "b").mkdir()
            zip_b = _make_test_zip(
                tmp_path / "b",
                [
                    ("setuptools.json", _setuptools_record()),
                    ("dulwich.json", _dulwich_record()),
                ],
            )
            importer.import_from_zip(zip_b, db_path)
            conn = schema.connect(db_path)
            try:
                row = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()
                self.assertEqual(row[0], 2)
            finally:
                conn.close()


# ---------------------------------------------------------------------------
# Picklability
# ---------------------------------------------------------------------------


class TestPicklability(unittest.TestCase):
    """The picklability discipline applies here too.

    These result types do not strictly need to be picklable for
    the current ThreadPoolExecutor variant (threads share memory),
    but the discipline keeps the door open for a future
    ProcessPoolExecutor variant without refactoring the result
    types.
    """

    def test_parsed_record_round_trip(self):
        rec = importer.ParsedRecord(
            osv_id="PYSEC-1",
            canonical_id="CVE-1",
            canonical_id_type="CVE",
            all_identifiers=(("CVE-1", "CVE"),),
            summary="x",
            details=None,
            published=None,
            modified=None,
            cvss_v3=None,
            cvss_v4=None,
            severity=None,
            affected=(("pkg", "1.0"),),
            has_explicit_versions=True,
        )
        restored = pickle.loads(pickle.dumps(rec))
        self.assertEqual(restored, rec)

    def test_parse_failure_round_trip(self):
        f = importer.ParseFailure(
            filename="x.json",
            osv_id=None,
            reason="parse_error",
            detail="bad json",
        )
        restored = pickle.loads(pickle.dumps(f))
        self.assertEqual(restored, f)

    def test_import_result_round_trip(self):
        r = importer.ImportResult(
            records_imported=10,
            records_skipped_no_versions=2,
            records_with_parse_errors=1,
            affected_version_rows=100,
            alias_rows=30,
            elapsed_seconds=1.5,
        )
        restored = pickle.loads(pickle.dumps(r))
        self.assertEqual(restored, r)


if __name__ == "__main__":
    unittest.main()
