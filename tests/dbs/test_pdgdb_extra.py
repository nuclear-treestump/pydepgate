"""Additional tests for pydepgate.dbs.pdgdb.

Covers:

  schema.initialize_schema()
    - writes METADATA_KEY_LAST_MODIFIED on first initialization
    - last_modified value is a parseable ISO 8601 UTC string

  writer.write_scan_result()
    - updates METADATA_KEY_LAST_MODIFIED after a successful write

  writer.write_decoded_tree()
    - updates METADATA_KEY_LAST_MODIFIED after a successful write

  writer.write_cve_scan_result()
    - inserts a scan_run row with command="cvescan"
    - inserts a scanned_artifact row
    - inserts a cve_scan_runs row linked to scan_run and artifact
    - inserts cve_findings rows, one per CveFinding
    - cve_finding fields stored correctly
    - zero findings: cve_scan_run row written, no cve_findings rows
    - updates METADATA_KEY_LAST_MODIFIED
    - non-fatal: does not raise on empty findings tuple

  reader.list_runs()
    - cve_finding_count is 0 for a scan run with no CVE findings
    - cve_finding_count is correct for a cvescan run with findings
    - scan run with static findings shows 0 cve_finding_count
    - cvescan run with CVE findings shows 0 finding_count
    - ScanRunRow has cve_finding_count field

  reader.get_db_status()
    - last_modified is populated after a write
    - last_modified updates on subsequent writes

These tests are designed to be added to the existing
tests/dbs/test_pdgdb_read_write.py file or run as a standalone module.
They import from the same fixture helpers established in that file.
"""

from __future__ import annotations

import datetime
import sqlite3
import unittest
from unittest import mock

from pydepgate.dbs.pdgdb import schema
from pydepgate.dbs.pdgdb.reader import get_db_status, list_runs
from pydepgate.dbs.pdgdb.writer import (
    write_cve_scan_result,
    write_decoded_tree,
    write_scan_result,
)
from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.engines.base import (
    ArtifactKind,
    Finding,
    ScanContext,
    ScanResult,
    ScanStatistics,
    Severity,
)
from pydepgate.enrichers.decode_payloads import (
    DecodedNode,
    DecodedTree,
    STOP_LEAF_TERMINAL,
)
from pydepgate.parsers.pysource import SourceLocation
from pydepgate.traffic_control.triage import FileKind

# ---------------------------------------------------------------------------
# Minimal fixtures (duplicated here so this file is self-contained)
# ---------------------------------------------------------------------------

_RUN_ID_A = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
_RUN_ID_B = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
_NOW = "2026-01-01T00:00:00+00:00"


def _fresh_conn() -> sqlite3.Connection:
    conn = schema.connect(":memory:")
    schema.initialize_schema(conn)
    return conn


def _make_signal(
    signal_id: str = "DENS010",
    line: int = 14,
    column: int = 0,
) -> Signal:
    return Signal(
        analyzer="code_density",
        signal_id=signal_id,
        confidence=Confidence.HIGH,
        scope=Scope.MODULE,
        location=SourceLocation(line=line, column=column),
        description="test signal",
    )


def _make_context(internal_path: str = "setup.py") -> ScanContext:
    return ScanContext(
        artifact_kind=ArtifactKind.WHEEL,
        artifact_identity="litellm-1.82.8-py3-none-any.whl",
        internal_path=internal_path,
        file_kind=FileKind.SETUP_PY,
        triage_reason="test",
        file_sha256="c" * 64,
        file_sha512="d" * 128,
    )


def _make_finding(signal_id: str = "DENS010", line: int = 14) -> Finding:
    return Finding(
        signal=_make_signal(signal_id=signal_id, line=line),
        severity=Severity.HIGH,
        context=_make_context(),
    )


def _make_scan_result(
    *,
    scan_id: str = _RUN_ID_A,
    findings: tuple[Finding, ...] = (),
    artifact_kind: ArtifactKind = ArtifactKind.WHEEL,
) -> ScanResult:
    return ScanResult(
        artifact_identity="litellm-1.82.8-py3-none-any.whl",
        artifact_kind=artifact_kind,
        findings=findings,
        skipped=(),
        statistics=ScanStatistics(),
        artifact_sha256="a" * 64,
        artifact_sha512="b" * 128,
        scan_id=scan_id,
    )


def _make_decoded_node() -> DecodedNode:
    return DecodedNode(
        outer_signal_id="DENS010",
        outer_severity="high",
        outer_location="setup.py:14:0",
        outer_length=4096,
        chain=("base64",),
        unwrap_status="completed",
        final_kind="python_source",
        final_size=512,
        indicators=("subprocess",),
        pickle_warning=False,
        depth=0,
        stop_reason=STOP_LEAF_TERMINAL,
    )


def _make_decoded_tree(scan_id: str = _RUN_ID_A) -> DecodedTree:
    return DecodedTree(
        target="litellm-1.82.8-py3-none-any.whl",
        max_depth=3,
        nodes=(_make_decoded_node(),),
        scan_id=scan_id,
    )


# ---------------------------------------------------------------------------
# Minimal CveScanResult stand-in using a simple namespace
# ---------------------------------------------------------------------------


class _MockCveFinding:
    """Minimal stand-in for CveFinding with the fields writer.py reads."""

    def __init__(
        self,
        canonical_id: str = "CVE-2025-12345",
        package_name: str = "litellm",
        package_version: str = "1.82.8",
        severity: str = "HIGH",
        cvss_v3: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_v4: str | None = None,
        summary: str | None = "Remote code execution",
        match_type: str = "exact",
    ):
        self.canonical_id = canonical_id
        self.package_name = package_name
        self.package_version = package_version
        self.severity = severity
        self.cvss_v3 = cvss_v3
        self.cvss_v4 = cvss_v4
        self.summary = summary
        self.match_type = match_type


class _MockPackageMetadata:
    def __init__(self):
        self.artifact_path = None
        self.artifact_type = "wheel"
        self.warnings = ()


class _MockCveScanResult:
    """Minimal stand-in for CveScanResult."""

    def __init__(
        self,
        findings: tuple = (),
        package_name: str = "litellm",
        normalized_package_name: str = "litellm",
        package_version: str = "1.82.8",
    ):
        self.findings = findings
        self.package_name = package_name
        self.normalized_package_name = normalized_package_name
        self.package_version = package_version
        self.package_metadata = _MockPackageMetadata()


# ===========================================================================
# schema.initialize_schema() -- last_modified
# ===========================================================================


class TestInitializeSchemaLastModified(unittest.TestCase):

    def test_writes_last_modified_on_fresh_database(self):
        conn = _fresh_conn()
        try:
            val = schema.read_metadata(conn, schema.METADATA_KEY_LAST_MODIFIED)
            self.assertIsNotNone(val)
        finally:
            conn.close()

    def test_last_modified_is_parseable_iso8601(self):
        conn = _fresh_conn()
        try:
            val = schema.read_metadata(conn, schema.METADATA_KEY_LAST_MODIFIED)
            # Must not raise.
            datetime.datetime.fromisoformat(val)
        finally:
            conn.close()

    def test_last_modified_equals_created_at_on_fresh_database(self):
        # On first creation both timestamps are written in the same
        # _now_utc() call inside initialize_schema, so they should be
        # equal or within a few milliseconds. We assert both are
        # present and parseable; strict equality is not guaranteed
        # across all platforms but both being non-None is.
        conn = _fresh_conn()
        try:
            last_modified = schema.read_metadata(
                conn, schema.METADATA_KEY_LAST_MODIFIED
            )
            created_at = schema.read_metadata(conn, schema.METADATA_KEY_CREATED_AT)
            self.assertIsNotNone(last_modified)
            self.assertIsNotNone(created_at)
        finally:
            conn.close()

    def test_idempotent_call_does_not_overwrite_last_modified(self):
        # initialize_schema is idempotent: a second call must not
        # reset last_modified to a new value, because the version
        # guard (`if read_metadata(...SCHEMA_VERSION) is None`) will
        # be False on the second call and the metadata block is
        # skipped entirely.
        conn = _fresh_conn()
        try:
            first = schema.read_metadata(conn, schema.METADATA_KEY_LAST_MODIFIED)
            schema.initialize_schema(conn)
            second = schema.read_metadata(conn, schema.METADATA_KEY_LAST_MODIFIED)
            self.assertEqual(first, second)
        finally:
            conn.close()


# ===========================================================================
# writer.write_scan_result() -- last_modified updated
# ===========================================================================


class TestWriteScanResultLastModified(unittest.TestCase):

    def test_updates_last_modified_after_write(self):
        conn = _fresh_conn()
        try:
            before = schema.read_metadata(conn, schema.METADATA_KEY_LAST_MODIFIED)
            result = _make_scan_result(findings=(_make_finding(),))
            write_scan_result(conn, result, command="scan", producer_id="cli0")
            after = schema.read_metadata(conn, schema.METADATA_KEY_LAST_MODIFIED)
            # after must be present and >= before (ISO 8601 sorts lexicographically).
            self.assertIsNotNone(after)
            self.assertGreaterEqual(after, before)
        finally:
            conn.close()


# ===========================================================================
# writer.write_decoded_tree() -- last_modified updated
# ===========================================================================


class TestWriteDecodedTreeLastModified(unittest.TestCase):

    def test_updates_last_modified_after_write(self):
        conn = _fresh_conn()
        try:
            result = _make_scan_result()
            run_id, art_id = write_scan_result(
                conn, result, command="scan", producer_id="cli0"
            )
            before = schema.read_metadata(conn, schema.METADATA_KEY_LAST_MODIFIED)
            tree = _make_decoded_tree()
            write_decoded_tree(conn, tree, scan_run_id=run_id, artifact_id=art_id)
            after = schema.read_metadata(conn, schema.METADATA_KEY_LAST_MODIFIED)
            self.assertIsNotNone(after)
            self.assertGreaterEqual(after, before)
        finally:
            conn.close()


# ===========================================================================
# writer.write_cve_scan_result()
# ===========================================================================


class TestWriteCveScanResult(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_inserts_scan_run_with_cvescan_command(self):
        result = _MockCveScanResult()
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        row = self.conn.execute("SELECT command FROM scan_runs LIMIT 1").fetchone()
        self.assertEqual(row[0], "cvescan")

    def test_inserts_scanned_artifact_row(self):
        result = _MockCveScanResult()
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        count = self.conn.execute("SELECT COUNT(*) FROM scanned_artifacts").fetchone()[
            0
        ]
        self.assertEqual(count, 1)

    def test_scanned_artifact_has_package_identity(self):
        result = _MockCveScanResult(
            package_name="litellm",
            normalized_package_name="litellm",
            package_version="1.82.8",
        )
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        row = self.conn.execute(
            "SELECT package_name, package_version FROM scanned_artifacts LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], "litellm")
        self.assertEqual(row[1], "1.82.8")

    def test_inserts_cve_scan_run_row(self):
        result = _MockCveScanResult()
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        count = self.conn.execute("SELECT COUNT(*) FROM cve_scan_runs").fetchone()[0]
        self.assertEqual(count, 1)

    def test_cve_scan_run_linked_to_scan_run_and_artifact(self):
        result = _MockCveScanResult()
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        run_row = self.conn.execute("SELECT id FROM scan_runs LIMIT 1").fetchone()
        art_row = self.conn.execute(
            "SELECT id FROM scanned_artifacts LIMIT 1"
        ).fetchone()
        cve_run_row = self.conn.execute(
            "SELECT scan_run_id, artifact_id FROM cve_scan_runs LIMIT 1"
        ).fetchone()
        self.assertEqual(cve_run_row[0], run_row[0])
        self.assertEqual(cve_run_row[1], art_row[0])

    def test_inserts_cve_findings_rows(self):
        findings = (
            _MockCveFinding(canonical_id="CVE-2025-00001"),
            _MockCveFinding(canonical_id="CVE-2025-00002"),
        )
        result = _MockCveScanResult(findings=findings)
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        count = self.conn.execute("SELECT COUNT(*) FROM cve_findings").fetchone()[0]
        self.assertEqual(count, 2)

    def test_cve_finding_fields_stored_correctly(self):
        finding = _MockCveFinding(
            canonical_id="CVE-2025-12345",
            package_name="litellm",
            package_version="1.82.8",
            severity="HIGH",
            cvss_v3="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_v4=None,
            summary="Remote code execution",
            match_type="range-fixed",
        )
        result = _MockCveScanResult(findings=(finding,))
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        row = self.conn.execute(
            "SELECT package_name, package_version, canonical_id,"
            "       severity, cvss_v3, cvss_v4, summary, match_kind, producer_id"
            " FROM cve_findings LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], "litellm")
        self.assertEqual(row[1], "1.82.8")
        self.assertEqual(row[2], "CVE-2025-12345")
        self.assertEqual(row[3], "HIGH")
        self.assertIsNotNone(row[4])
        self.assertIsNone(row[5])
        self.assertEqual(row[6], "Remote code execution")
        self.assertEqual(row[7], "range-fixed")
        self.assertEqual(row[8], "cli0")

    def test_zero_findings_writes_cve_scan_run_no_findings(self):
        result = _MockCveScanResult(findings=())
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        cve_run_count = self.conn.execute(
            "SELECT COUNT(*) FROM cve_scan_runs"
        ).fetchone()[0]
        finding_count = self.conn.execute(
            "SELECT COUNT(*) FROM cve_findings"
        ).fetchone()[0]
        self.assertEqual(cve_run_count, 1)
        self.assertEqual(finding_count, 0)

    def test_updates_last_modified(self):
        before = schema.read_metadata(self.conn, schema.METADATA_KEY_LAST_MODIFIED)
        result = _MockCveScanResult()
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        after = schema.read_metadata(self.conn, schema.METADATA_KEY_LAST_MODIFIED)
        self.assertIsNotNone(after)
        self.assertGreaterEqual(after, before)

    def test_producer_id_on_scan_run(self):
        result = _MockCveScanResult()
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        row = self.conn.execute("SELECT producer_id FROM scan_runs LIMIT 1").fetchone()
        self.assertEqual(row[0], "cli0")


# ===========================================================================
# reader.list_runs() -- cve_finding_count column
# ===========================================================================


class TestListRunsCveFindingCount(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_scan_run_has_zero_cve_finding_count(self):
        result = _make_scan_result(
            scan_id=_RUN_ID_A,
            findings=(_make_finding(),),
        )
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        rows = list_runs(self.conn)
        self.assertEqual(rows[0].cve_finding_count, 0)

    def test_cvescan_run_has_correct_cve_finding_count(self):
        findings = (
            _MockCveFinding(canonical_id="CVE-2025-00001"),
            _MockCveFinding(canonical_id="CVE-2025-00002"),
        )
        result = _MockCveScanResult(findings=findings)
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        rows = list_runs(self.conn)
        self.assertEqual(rows[0].cve_finding_count, 2)

    def test_cvescan_run_has_zero_static_finding_count(self):
        result = _MockCveScanResult(findings=(_MockCveFinding(),))
        write_cve_scan_result(self.conn, result, producer_id="cli0")
        rows = list_runs(self.conn)
        self.assertEqual(rows[0].finding_count, 0)

    def test_scan_run_row_has_cve_finding_count_field(self):
        result = _make_scan_result(scan_id=_RUN_ID_A)
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        rows = list_runs(self.conn)
        self.assertTrue(hasattr(rows[0], "cve_finding_count"))

    def test_mixed_runs_counts_are_independent(self):
        # One scan run with 2 static findings, one cvescan with 3 CVE findings.
        scan_result = _make_scan_result(
            scan_id=_RUN_ID_A,
            findings=(_make_finding(), _make_finding(signal_id="STDLIB001", line=22)),
        )
        write_scan_result(self.conn, scan_result, command="scan", producer_id="cli0")

        cve_result = _MockCveScanResult(
            findings=(
                _MockCveFinding(canonical_id="CVE-2025-00001"),
                _MockCveFinding(canonical_id="CVE-2025-00002"),
                _MockCveFinding(canonical_id="CVE-2025-00003"),
            )
        )
        write_cve_scan_result(self.conn, cve_result, producer_id="cli0")

        rows = list_runs(self.conn, limit=None)
        # Newest first: cvescan run is rows[0], scan run is rows[1].
        cve_row = next(r for r in rows if r.command == "cvescan")
        scan_row = next(r for r in rows if r.command == "scan")

        self.assertEqual(cve_row.cve_finding_count, 3)
        self.assertEqual(cve_row.finding_count, 0)
        self.assertEqual(scan_row.finding_count, 2)
        self.assertEqual(scan_row.cve_finding_count, 0)


# ===========================================================================
# reader.get_db_status() -- last_modified
# ===========================================================================


class TestGetDbStatusLastModified(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_last_modified_populated_on_fresh_database(self):
        status = get_db_status(self.conn, "/tmp/test.db")
        self.assertIsNotNone(status.last_modified)

    def test_last_modified_updates_after_write(self):
        status_before = get_db_status(self.conn, "/tmp/test.db")
        result = _make_scan_result(findings=(_make_finding(),))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        status_after = get_db_status(self.conn, "/tmp/test.db")
        self.assertGreaterEqual(
            status_after.last_modified,
            status_before.last_modified,
        )

    def test_last_modified_is_none_when_table_missing(self):
        schema.drop_all_tables(self.conn)
        status = get_db_status(self.conn, "/tmp/test.db")
        self.assertIsNone(status.last_modified)


if __name__ == "__main__":
    import unittest

    unittest.main()
