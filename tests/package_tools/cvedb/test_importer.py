"""Tests for cvedb importer (v2)."""

from __future__ import annotations

import json
import pickle
import tempfile
import unittest
import zipfile
from pathlib import Path

from pydepgate.package_tools.cvedb import importer, schema
from pydepgate import run_context

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _setuptools_record() -> dict:
    return {
        "schema_version": "1.7.3",
        "id": "PYSEC-2025-49",
        "published": "2025-05-17T16:15:19Z",
        "modified": "2026-05-11T00:26:34Z",
        "aliases": [
            "BIT-setuptools-2025-47273",
            "CVE-2025-47273",
            "GHSA-5rjg-fvgr-3xxf",
        ],
        "details": "setuptools path traversal.",
        "affected": [
            {
                "package": {"name": "setuptools", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "78.1.1"}],
                    }
                ],
                "versions": ["75.0.0", "76.0.0", "77.0.1", "78.0.1", "78.1.0"],
            }
        ],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/X"}],
    }


def _dulwich_record() -> dict:
    return {
        "schema_version": "1.7.5",
        "id": "GHSA-4j5j-58j7-6c3w",
        "published": "2022-05-17T04:14:03Z",
        "modified": "2026-05-14T23:16:30Z",
        "aliases": ["CVE-2014-9706", "PYSEC-2015-34"],
        "summary": "Dulwich Arbitrary code execution",
        "details": "The build_index_from_tree function allows RCE.",
        "affected": [
            {
                "package": {"name": "dulwich", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "0.9.10"}],
                    }
                ],
                "versions": ["0.9.7", "0.9.8", "0.9.9"],
            }
        ],
        "database_specific": {"severity": "CRITICAL"},
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/X"},
            {"type": "CVSS_V4", "score": "CVSS:4.0/X"},
        ],
    }


def _range_only_record() -> dict:
    return {
        "schema_version": "1.7.0",
        "id": "PYSEC-2099-1",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2099-0001"],
        "summary": "Range-only record",
        "affected": [
            {
                "package": {"name": "mystery-package", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
                    }
                ],
            }
        ],
    }


def _all_versions_malicious() -> dict:
    return {
        "schema_version": "1.7.0",
        "id": "MAL-2025-1234",
        "modified": "2025-01-01T00:00:00Z",
        "aliases": [],
        "summary": "Malicious package",
        "affected": [
            {
                "package": {"name": "evil-pkg", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}],
                    }
                ],
            }
        ],
        "database_specific": {"severity": "CRITICAL"},
    }


def _multi_range_record() -> dict:
    return {
        "schema_version": "1.7.0",
        "id": "PYSEC-2024-5",
        "modified": "2024-06-01T00:00:00Z",
        "aliases": ["CVE-2024-5555"],
        "summary": "Regression vuln",
        "affected": [
            {
                "package": {"name": "regressing-pkg", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0"},
                            {"fixed": "1.5"},
                            {"introduced": "2.0"},
                            {"fixed": "2.3"},
                        ],
                    }
                ],
            }
        ],
    }


def _last_affected_record() -> dict:
    return {
        "schema_version": "1.7.0",
        "id": "PYSEC-2024-6",
        "modified": "2024-06-01T00:00:00Z",
        "aliases": ["CVE-2024-6666"],
        "summary": "last_affected semantics",
        "affected": [
            {
                "package": {"name": "lastpkg", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0"},
                            {"last_affected": "1.5"},
                        ],
                    }
                ],
            }
        ],
    }


def _make_test_zip(tmp_path: Path, records: list) -> Path:
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in records:
            if isinstance(content, bytes):
                zf.writestr(name, content)
            else:
                zf.writestr(name, json.dumps(content))
    return zip_path


# ---------------------------------------------------------------------------
# Range parsing state machine
# ---------------------------------------------------------------------------


class TestRangeParser(unittest.TestCase):
    def test_simple_pair(self):
        result, has_all = importer._parse_ranges_for_package(
            [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}]
        )
        self.assertEqual(result, [("ECOSYSTEM", "1.0", "2.0", "")])
        self.assertFalse(has_all)

    def test_introduced_only_open_ended(self):
        result, has_all = importer._parse_ranges_for_package(
            [{"type": "ECOSYSTEM", "events": [{"introduced": "1.5"}]}]
        )
        self.assertEqual(result, [("ECOSYSTEM", "1.5", "", "")])
        self.assertFalse(has_all)

    def test_zero_no_closer_is_all(self):
        result, has_all = importer._parse_ranges_for_package(
            [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
        )
        self.assertEqual(result, [("ECOSYSTEM", "0", "", "")])
        self.assertTrue(has_all)

    def test_zero_with_fixed_not_all(self):
        result, has_all = importer._parse_ranges_for_package(
            [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]
        )
        self.assertEqual(result, [("ECOSYSTEM", "0", "1.0", "")])
        self.assertFalse(has_all)

    def test_last_affected(self):
        result, has_all = importer._parse_ranges_for_package(
            [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0"}, {"last_affected": "1.5"}],
                }
            ]
        )
        self.assertEqual(result, [("ECOSYSTEM", "1.0", "", "1.5")])
        self.assertFalse(has_all)

    def test_multiple_pairs(self):
        result, has_all = importer._parse_ranges_for_package(
            [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0"},
                        {"fixed": "1.5"},
                        {"introduced": "2.0"},
                        {"fixed": "2.3"},
                    ],
                }
            ]
        )
        self.assertEqual(len(result), 2)
        self.assertIn(("ECOSYSTEM", "1.0", "1.5", ""), result)
        self.assertIn(("ECOSYSTEM", "2.0", "2.3", ""), result)

    def test_dangling_after_pair(self):
        result, has_all = importer._parse_ranges_for_package(
            [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0"},
                        {"fixed": "1.5"},
                        {"introduced": "2.0"},
                    ],
                }
            ]
        )
        self.assertEqual(len(result), 2)
        self.assertIn(("ECOSYSTEM", "1.0", "1.5", ""), result)
        self.assertIn(("ECOSYSTEM", "2.0", "", ""), result)

    def test_consecutive_introduced(self):
        result, has_all = importer._parse_ranges_for_package(
            [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0"},
                        {"introduced": "2.0"},
                    ],
                }
            ]
        )
        self.assertEqual(len(result), 2)
        self.assertIn(("ECOSYSTEM", "1.0", "", ""), result)
        self.assertIn(("ECOSYSTEM", "2.0", "", ""), result)

    def test_fixed_without_introduced(self):
        result, has_all = importer._parse_ranges_for_package(
            [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0"}]}]
        )
        self.assertEqual(result, [])

    def test_multiple_range_entries(self):
        result, has_all = importer._parse_ranges_for_package(
            [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
                },
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "3.0"}, {"fixed": "4.0"}],
                },
            ]
        )
        self.assertEqual(len(result), 2)

    def test_malformed_events_skipped(self):
        result, has_all = importer._parse_ranges_for_package(
            [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        "not a dict",
                        {"introduced": 0},
                        {"introduced": ""},
                        {"introduced": "1.0"},
                        {"fixed": "2.0"},
                    ],
                }
            ]
        )
        self.assertEqual(result, [("ECOSYSTEM", "1.0", "2.0", "")])


# ---------------------------------------------------------------------------
# Per-record parser with ranges
# ---------------------------------------------------------------------------


class TestParseEntryV2(unittest.TestCase):
    def test_setuptools_both_versions_and_ranges(self):
        data = json.dumps(_setuptools_record()).encode("utf-8")
        result = importer._parse_entry("PYSEC-2025-49.json", data)
        self.assertIsInstance(result, importer.ParsedRecord)
        self.assertEqual(len(result.affected), 5)
        self.assertEqual(len(result.ranges), 1)
        self.assertEqual(
            result.ranges[0], ("setuptools", "ECOSYSTEM", "0", "78.1.1", "")
        )
        self.assertEqual(result.all_versions_packages, ())

    def test_range_only_record(self):
        data = json.dumps(_range_only_record()).encode("utf-8")
        result = importer._parse_entry("PYSEC-2099-1.json", data)
        self.assertIsInstance(result, importer.ParsedRecord)
        self.assertEqual(result.affected, ())
        self.assertFalse(result.has_explicit_versions)
        self.assertEqual(len(result.ranges), 1)
        self.assertEqual(result.all_versions_packages, ())

    def test_malicious_all_detected(self):
        data = json.dumps(_all_versions_malicious()).encode("utf-8")
        result = importer._parse_entry("MAL-2025-1234.json", data)
        self.assertIsInstance(result, importer.ParsedRecord)
        self.assertEqual(result.all_versions_packages, ("evil-pkg",))
        self.assertEqual(len(result.ranges), 1)

    def test_multi_range(self):
        data = json.dumps(_multi_range_record()).encode("utf-8")
        result = importer._parse_entry("PYSEC-2024-5.json", data)
        self.assertIsInstance(result, importer.ParsedRecord)
        self.assertEqual(len(result.ranges), 2)

    def test_last_affected(self):
        data = json.dumps(_last_affected_record()).encode("utf-8")
        result = importer._parse_entry("PYSEC-2024-6.json", data)
        self.assertIsInstance(result, importer.ParsedRecord)
        self.assertEqual(len(result.ranges), 1)
        self.assertEqual(result.ranges[0], ("lastpkg", "ECOSYSTEM", "1.0", "", "1.5"))


# ---------------------------------------------------------------------------
# Merge logic with ranges
# ---------------------------------------------------------------------------


class TestMergeRanges(unittest.TestCase):
    def test_union_ranges(self):
        rec_a = importer.ParsedRecord(
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
            affected=(),
            has_explicit_versions=False,
            ranges=(("pkg", "ECOSYSTEM", "1.0", "1.5", ""),),
            all_versions_packages=(),
        )
        rec_b = importer.ParsedRecord(
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
            ranges=(("pkg", "ECOSYSTEM", "2.0", "2.3", ""),),
            all_versions_packages=(),
        )
        merged = importer._merge_records([rec_a, rec_b])
        self.assertEqual(len(merged["CVE-1"].ranges), 2)

    def test_all_packages_union(self):
        rec_a = importer.ParsedRecord(
            osv_id="A",
            canonical_id="CVE-X",
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
            ranges=(),
            all_versions_packages=("foo",),
        )
        rec_b = importer.ParsedRecord(
            osv_id="B",
            canonical_id="CVE-X",
            canonical_id_type="CVE",
            all_identifiers=(),
            summary=None,
            details=None,
            published=None,
            modified=None,
            cvss_v3=None,
            cvss_v4=None,
            severity=None,
            affected=(("foo", "1.0"),),
            has_explicit_versions=True,
            ranges=(),
            all_versions_packages=(),
        )
        merged = importer._merge_records([rec_a, rec_b])
        self.assertIn("foo", merged["CVE-X"].all_versions_packages)
        self.assertIn(("foo", "1.0"), merged["CVE-X"].affected)


# ---------------------------------------------------------------------------
# End-to-end import: ranges and ALL appear in the DB
# ---------------------------------------------------------------------------


class TestImportWithRanges(unittest.TestCase):
    def test_setuptools_writes_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("PYSEC-2025-49.json", _setuptools_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            result = importer.import_from_zip(
                zip_path,
                db_path,
                snapshot_sha256="deadbeef",
                run_uuid="test-run-uuid",
            )
            self.assertEqual(result.records_imported, 1)
            self.assertEqual(result.affected_version_rows, 5)
            self.assertEqual(result.affected_range_rows, 1)

            conn = schema.connect(db_path)
            try:
                rows = conn.execute(
                    "SELECT introduced, fixed, last_affected "
                    "FROM affected_ranges WHERE package_name = ?",
                    ("setuptools",),
                ).fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0], ("0", "78.1.1", ""))
            finally:
                conn.close()

    def test_all_versions_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("MAL-2025-1234.json", _all_versions_malicious()),
                ],
            )
            db_path = tmp_path / "test.db"
            result = importer.import_from_zip(
                zip_path,
                db_path,
                run_uuid="test-run-uuid",
            )
            self.assertEqual(result.records_imported, 1)

            conn = schema.connect(db_path)
            try:
                rows = conn.execute(
                    "SELECT version FROM affected_versions " "WHERE package_name = ?",
                    ("evil-pkg",),
                ).fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][0], importer.ALL_VERSIONS_SENTINEL)
            finally:
                conn.close()

    def test_range_only_no_warning(self):
        """v2: range-only records contribute data, not warnings."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("range-only.json", _range_only_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            result = importer.import_from_zip(
                zip_path,
                db_path,
                run_uuid="test-run-uuid",
            )
            self.assertEqual(result.records_imported, 1)
            self.assertEqual(result.records_with_no_usable_data, 0)
            self.assertEqual(result.affected_version_rows, 0)
            self.assertEqual(result.affected_range_rows, 1)

            conn = schema.connect(db_path)
            try:
                rows = conn.execute("SELECT COUNT(*) FROM import_warnings").fetchone()
                self.assertEqual(rows[0], 0)
            finally:
                conn.close()

    def test_run_uuid_in_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("PYSEC-2025-49.json", _setuptools_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            importer.import_from_zip(
                zip_path,
                db_path,
                run_uuid="explicit-uuid-1234",
            )

            conn = schema.connect(db_path)
            try:
                stored = schema.read_metadata(
                    conn,
                    schema.METADATA_KEY_LAST_IMPORT_RUN_UUID,
                )
                self.assertEqual(stored, "explicit-uuid-1234")
            finally:
                conn.close()

    def test_default_uses_run_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("PYSEC-2025-49.json", _setuptools_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            expected = run_context.reset_for_new_run()
            importer.import_from_zip(zip_path, db_path)

            conn = schema.connect(db_path)
            try:
                stored = schema.read_metadata(
                    conn,
                    schema.METADATA_KEY_LAST_IMPORT_RUN_UUID,
                )
                self.assertEqual(stored, expected)
            finally:
                conn.close()

    def test_schema_v2_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("PYSEC-2025-49.json", _setuptools_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            importer.import_from_zip(zip_path, db_path, run_uuid="x")

            conn = schema.connect(db_path)
            try:
                version = schema.read_schema_version(conn)
                self.assertEqual(version, 2)
            finally:
                conn.close()


# ---------------------------------------------------------------------------
# Three-callback progress API
# ---------------------------------------------------------------------------


class TestThreePhaseProgress(unittest.TestCase):
    def test_all_three_phases_fire(self):
        read_calls = []
        parse_calls = []
        write_calls = []
        read_done = [0]
        parse_done = [0]
        write_done = [0]

        progress = importer.ProgressCallbacks(
            read_update=lambda c, t: read_calls.append((c, t)),
            read_finish=lambda: read_done.__setitem__(0, read_done[0] + 1),
            parse_update=lambda c, t: parse_calls.append((c, t)),
            parse_finish=lambda: parse_done.__setitem__(0, parse_done[0] + 1),
            write_update=lambda c, t: write_calls.append((c, t)),
            write_finish=lambda: write_done.__setitem__(0, write_done[0] + 1),
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("a.json", _setuptools_record()),
                    ("b.json", _dulwich_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            importer.import_from_zip(
                zip_path,
                db_path,
                run_uuid="x",
                progress=progress,
            )

        self.assertGreater(len(read_calls), 0)
        self.assertGreater(len(parse_calls), 0)
        self.assertGreater(len(write_calls), 0)

        self.assertEqual(read_done[0], 1)
        self.assertEqual(parse_done[0], 1)
        self.assertEqual(write_done[0], 1)

        self.assertEqual(read_calls[-1][0], read_calls[-1][1])
        self.assertEqual(parse_calls[-1][0], parse_calls[-1][1])
        self.assertEqual(write_calls[-1][0], write_calls[-1][1])
        self.assertGreater(write_calls[-1][1], 0)

    def test_no_progress_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("a.json", _setuptools_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            result = importer.import_from_zip(
                zip_path,
                db_path,
                run_uuid="x",
            )
            self.assertEqual(result.records_imported, 1)

    def test_buggy_callback_does_not_abort(self):
        def angry(c, t):
            raise RuntimeError("bad bar")

        progress = importer.ProgressCallbacks(
            read_update=angry,
            parse_update=angry,
            write_update=angry,
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(
                tmp_path,
                [
                    ("a.json", _setuptools_record()),
                ],
            )
            db_path = tmp_path / "test.db"
            result = importer.import_from_zip(
                zip_path,
                db_path,
                run_uuid="x",
                progress=progress,
            )
            self.assertEqual(result.records_imported, 1)


# ---------------------------------------------------------------------------
# Batched writes
# ---------------------------------------------------------------------------


class TestBatchedWrites(unittest.TestCase):
    def test_many_records(self):
        records = []
        for i in range(2500):
            records.append(
                (
                    f"r{i}.json",
                    {
                        "id": f"PYSEC-2025-{i}",
                        "modified": "2025-01-01T00:00:00Z",
                        "aliases": [],
                        "affected": [
                            {
                                "package": {"name": f"pkg-{i}", "ecosystem": "PyPI"},
                                "versions": [f"1.{i}"],
                            }
                        ],
                    },
                )
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = _make_test_zip(tmp_path, records)
            db_path = tmp_path / "test.db"

            write_seen = []
            progress = importer.ProgressCallbacks(
                write_update=lambda c, t: write_seen.append((c, t)),
            )

            result = importer.import_from_zip(
                zip_path,
                db_path,
                run_uuid="x",
                progress=progress,
            )
            self.assertEqual(result.records_imported, 2500)
            self.assertGreater(len(write_seen), 3)
            for i in range(1, len(write_seen)):
                self.assertGreaterEqual(write_seen[i][0], write_seen[i - 1][0])


# ---------------------------------------------------------------------------
# Picklability of new ImportResult shape
# ---------------------------------------------------------------------------


class TestPicklability(unittest.TestCase):
    def test_import_result_round_trip(self):
        r = importer.ImportResult(
            records_imported=10,
            records_with_parse_errors=2,
            records_with_no_usable_data=1,
            affected_version_rows=100,
            affected_range_rows=20,
            alias_rows=30,
            elapsed_seconds=1.5,
        )
        restored = pickle.loads(pickle.dumps(r))
        self.assertEqual(restored, r)

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
            ranges=(("pkg", "ECOSYSTEM", "0", "2.0", ""),),
            all_versions_packages=(),
            has_explicit_versions=True,
        )
        restored = pickle.loads(pickle.dumps(rec))
        self.assertEqual(restored, rec)


if __name__ == "__main__":
    unittest.main()
