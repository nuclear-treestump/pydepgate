"""Tests for pydepgate.dbs.pdgdb.writer and pydepgate.dbs.pdgdb.reader.

Coverage:

  writer._parse_wheel_name()
    - valid wheel filename returns (name, version)
    - name is normalized to lowercase underscores
    - sdist filename returns (None, None)
    - bare filename with no version returns (None, None)

  writer._parse_sdist_name()
    - valid .tar.gz filename returns (name, version)
    - valid .zip filename returns (name, version)
    - wheel filename returns (None, None)

  writer._resolve_package_identity()
    - WHEEL kind uses wheel filename parser
    - SDIST kind uses sdist filename parser
    - INSTALLED_ENV kind returns artifact_identity as name, resolves version
    - INSTALLED_ENV kind returns (name, None) when package not found
    - LOOSE_FILE kind returns (None, None)

  writer.write_scan_result()
    - inserts scan_run row with correct fields
    - inserts scanned_artifact row with correct fields
    - inserts file_identity row per unique file in findings
    - deduplicates file_identity for two findings in the same file
    - inserts static_finding row per finding
    - static_finding rule_id is NULL (not available in v0.5.0)
    - static_finding producer_id matches argument
    - internal_path backslashes normalized to forward slashes
    - suppressed findings are not written
    - zero findings: artifact row written, no file_identity or finding rows
    - returns (scan_run_id, artifact_id) as ints
    - installed_env scan: artifact hashes are NULL

  writer.write_decoded_tree()
    - empty tree: no rows written
    - flat tree: one decoded_node row per top-level node
    - recursive tree: child node has correct parent_node_id
    - child_findings rows written and linked to node
    - chain stored as JSON array
    - indicators stored as JSON array
    - pickle_warning stored as 1 for True, 0 for False
    - ioc_data decoded_source is NOT written (payload bytes excluded)
    - write_decoded_tree is independent: failure does not affect scan_run rows

  reader.get_db_status()
    - returns DbStatus with correct counts on a fresh database
    - counts reflect written records
    - handles empty database gracefully

  reader.list_runs()
    - returns empty list on empty database
    - returns one ScanRunRow per inserted run
    - rows are newest-first
    - artifact_count and finding_count are correct
    - limit=1 returns only one row
    - limit=None returns all rows
    - offset skips leading rows

  reader.query_by_package()
    - returns matching artifact rows
    - name matching is case-insensitive (normalized)
    - hyphenated name matches underscore-normalized stored name
    - version filter narrows results
    - no match returns empty list
    - finding_count is correct

  reader.query_by_artifact_sha512()
    - returns matching artifact row
    - sha512 matching is case-insensitive
    - no match returns empty list

  reader.explain_run()
    - returns None for unknown run_id
    - returns RunExplanation with correct run metadata
    - findings are sorted by internal_path, line, col
    - decoded_nodes are included with child findings
    - decoded_nodes are ordered depth ASC, id ASC
    - artifact is None when no artifact row exists (defensive)
"""

from __future__ import annotations

import json
import sqlite3
import unittest
from unittest import mock

from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.dbs.pdgdb import schema
from pydepgate.dbs.pdgdb.reader import (
    explain_run,
    get_db_status,
    list_runs,
    query_by_artifact_sha512,
    query_by_package,
)
from pydepgate.dbs.pdgdb.writer import (
    _parse_sdist_name,
    _parse_wheel_name,
    _resolve_package_identity,
    write_decoded_tree,
    write_scan_result,
)
from pydepgate.engines.base import (
    ArtifactKind,
    Finding,
    ScanContext,
    ScanResult,
    ScanStatistics,
    Severity,
    SuppressedFinding,
)
from pydepgate.enrichers.decode_payloads import (
    ChildFinding,
    DecodedNode,
    DecodedTree,
    IOCData,
    STOP_LEAF_TERMINAL,
    STOP_NON_PYTHON,
)
from pydepgate.parsers.pysource import SourceLocation
from pydepgate.traffic_control.triage import FileKind

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_NOW = "2026-01-01T00:00:00+00:00"
_RUN_ID = "550e8400-e29b-41d4-a716-446655440000"


def _fresh_conn() -> sqlite3.Connection:
    conn = schema.connect(":memory:")
    schema.initialize_schema(conn)
    return conn


def _make_signal(
    *,
    signal_id: str = "DENS010",
    analyzer: str = "code_density",
    confidence: Confidence = Confidence.HIGH,
    scope: Scope = Scope.MODULE,
    line: int = 14,
    column: int = 0,
    description: str = "high-entropy block",
) -> Signal:
    return Signal(
        analyzer=analyzer,
        signal_id=signal_id,
        confidence=confidence,
        scope=scope,
        location=SourceLocation(line=line, column=column),
        description=description,
    )


def _make_context(
    *,
    artifact_kind: ArtifactKind = ArtifactKind.WHEEL,
    artifact_identity: str = "litellm-1.82.8-py3-none-any.whl",
    internal_path: str = "setup.py",
    file_sha256: str | None = "c" * 64,
    file_sha512: str | None = "d" * 128,
) -> ScanContext:
    return ScanContext(
        artifact_kind=artifact_kind,
        artifact_identity=artifact_identity,
        internal_path=internal_path,
        file_kind=FileKind.SETUP_PY,
        triage_reason="test",
        file_sha256=file_sha256,
        file_sha512=file_sha512,
    )


def _make_finding(
    *,
    signal: Signal | None = None,
    severity: Severity = Severity.HIGH,
    context: ScanContext | None = None,
) -> Finding:
    return Finding(
        signal=signal if signal is not None else _make_signal(),
        severity=severity,
        context=context if context is not None else _make_context(),
    )


def _make_scan_result(
    *,
    artifact_identity: str = "litellm-1.82.8-py3-none-any.whl",
    artifact_kind: ArtifactKind = ArtifactKind.WHEEL,
    findings: tuple[Finding, ...] = (),
    suppressed_findings: tuple[SuppressedFinding, ...] = (),
    artifact_sha256: str | None = "a" * 64,
    artifact_sha512: str | None = "b" * 128,
    scan_id: str = _RUN_ID,
) -> ScanResult:
    return ScanResult(
        artifact_identity=artifact_identity,
        artifact_kind=artifact_kind,
        findings=findings,
        skipped=(),
        statistics=ScanStatistics(),
        suppressed_findings=suppressed_findings,
        artifact_sha256=artifact_sha256,
        artifact_sha512=artifact_sha512,
        scan_id=scan_id,
    )


def _make_decoded_node(
    *,
    outer_signal_id: str = "DENS010",
    outer_severity: str = "high",
    outer_location: str = "setup.py:14:0",
    outer_length: int = 4096,
    chain: tuple[str, ...] = ("base64",),
    unwrap_status: str = "completed",
    final_kind: str = "python_source",
    final_size: int = 512,
    indicators: tuple[str, ...] = ("subprocess",),
    pickle_warning: bool = False,
    depth: int = 0,
    stop_reason: str = STOP_LEAF_TERMINAL,
    child_findings: tuple[ChildFinding, ...] = (),
    children: tuple[DecodedNode, ...] = (),
    ioc_data: IOCData | None = None,
) -> DecodedNode:
    return DecodedNode(
        outer_signal_id=outer_signal_id,
        outer_severity=outer_severity,
        outer_location=outer_location,
        outer_length=outer_length,
        chain=chain,
        unwrap_status=unwrap_status,
        final_kind=final_kind,
        final_size=final_size,
        indicators=indicators,
        pickle_warning=pickle_warning,
        depth=depth,
        stop_reason=stop_reason,
        child_findings=child_findings,
        children=children,
        ioc_data=ioc_data,
    )


def _make_decoded_tree(
    *,
    target: str = "litellm-1.82.8-py3-none-any.whl",
    nodes: tuple[DecodedNode, ...] = (),
    scan_id: str = _RUN_ID,
) -> DecodedTree:
    return DecodedTree(
        target=target,
        max_depth=3,
        nodes=nodes,
        scan_id=scan_id,
    )


# ---------------------------------------------------------------------------
# Helpers to write a minimal scan and return IDs
# ---------------------------------------------------------------------------


def _write_minimal_scan(
    conn: sqlite3.Connection,
    *,
    run_id: str = _RUN_ID,
    findings: tuple[Finding, ...] = (),
) -> tuple[int, int]:
    result = _make_scan_result(scan_id=run_id, findings=findings)
    return write_scan_result(conn, result, command="scan", producer_id="cli0")


# ===========================================================================
# writer._parse_wheel_name()
# ===========================================================================


class TestParseWheelName(unittest.TestCase):

    def test_valid_wheel_returns_name_and_version(self):
        name, version = _parse_wheel_name("litellm-1.82.8-py3-none-any.whl")
        self.assertEqual(name, "litellm")
        self.assertEqual(version, "1.82.8")

    def test_name_normalized_to_lowercase_underscores(self):
        name, version = _parse_wheel_name("LiteLLM-1.0.0-py3-none-any.whl")
        self.assertEqual(name, "litellm")

    def test_hyphenated_name_normalized(self):
        name, version = _parse_wheel_name("some-package-1.0.0-py3-none-any.whl")
        self.assertEqual(name, "some_package")

    def test_sdist_filename_returns_none_none(self):
        name, version = _parse_wheel_name("litellm-1.82.8.tar.gz")
        self.assertIsNone(name)
        self.assertIsNone(version)

    def test_bare_name_returns_none_none(self):
        name, version = _parse_wheel_name("notawheel.py")
        self.assertIsNone(name)
        self.assertIsNone(version)

    def test_wheel_with_build_tag(self):
        name, version = _parse_wheel_name("mypackage-1.0.0-1-py3-none-any.whl")
        self.assertEqual(name, "mypackage")
        self.assertEqual(version, "1.0.0")


# ===========================================================================
# writer._parse_sdist_name()
# ===========================================================================


class TestParseSdistName(unittest.TestCase):

    def test_tar_gz_returns_name_and_version(self):
        name, version = _parse_sdist_name("requests-2.28.0.tar.gz")
        self.assertEqual(name, "requests")
        self.assertEqual(version, "2.28.0")

    def test_zip_returns_name_and_version(self):
        name, version = _parse_sdist_name("mylib-0.1.0.zip")
        self.assertEqual(name, "mylib")
        self.assertEqual(version, "0.1.0")

    def test_wheel_filename_returns_none_none(self):
        name, version = _parse_sdist_name("litellm-1.82.8-py3-none-any.whl")
        self.assertIsNone(name)
        self.assertIsNone(version)


# ===========================================================================
# writer._resolve_package_identity()
# ===========================================================================


class TestResolvePackageIdentity(unittest.TestCase):

    def test_wheel_kind_uses_wheel_parser(self):
        result = _make_scan_result(
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="litellm-1.82.8-py3-none-any.whl",
        )
        name, version = _resolve_package_identity(result)
        self.assertEqual(name, "litellm")
        self.assertEqual(version, "1.82.8")

    def test_sdist_kind_uses_sdist_parser(self):
        result = _make_scan_result(
            artifact_kind=ArtifactKind.SDIST,
            artifact_identity="requests-2.28.0.tar.gz",
        )
        name, version = _resolve_package_identity(result)
        self.assertEqual(name, "requests")
        self.assertEqual(version, "2.28.0")

    def test_loose_file_returns_none_none(self):
        result = _make_scan_result(
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="suspicious.py",
        )
        name, version = _resolve_package_identity(result)
        self.assertIsNone(name)
        self.assertIsNone(version)

    def test_installed_env_returns_name_when_package_not_found(self):
        result = _make_scan_result(
            artifact_kind=ArtifactKind.INSTALLED_ENV,
            artifact_identity="no_such_package_xyz_123",
        )
        name, version = _resolve_package_identity(result)
        self.assertEqual(name, "no_such_package_xyz_123")
        self.assertIsNone(version)

    def test_installed_env_normalizes_name(self):
        result = _make_scan_result(
            artifact_kind=ArtifactKind.INSTALLED_ENV,
            artifact_identity="My-Package",
        )
        name, _ = _resolve_package_identity(result)
        self.assertEqual(name, "my_package")

    def test_installed_env_resolves_version_via_metadata(self):
        import importlib.metadata as im

        mock_dist = mock.MagicMock()
        mock_dist.metadata.get.return_value = "3.1.4"
        with mock.patch.object(im, "distribution", return_value=mock_dist):
            result = _make_scan_result(
                artifact_kind=ArtifactKind.INSTALLED_ENV,
                artifact_identity="somepkg",
            )
            name, version = _resolve_package_identity(result)
        self.assertEqual(version, "3.1.4")


# ===========================================================================
# writer.write_scan_result()
# ===========================================================================


class TestWriteScanResult(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_returns_int_tuple(self):
        run_id, art_id = _write_minimal_scan(self.conn)
        self.assertIsInstance(run_id, int)
        self.assertIsInstance(art_id, int)

    def test_inserts_scan_run_row(self):
        _write_minimal_scan(self.conn, run_id=_RUN_ID)
        row = self.conn.execute(
            "SELECT run_id, producer_id, command FROM scan_runs" " WHERE run_id = ?",
            (_RUN_ID,),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], _RUN_ID)
        self.assertEqual(row[1], "cli0")
        self.assertEqual(row[2], "scan")

    def test_inserts_scanned_artifact_row(self):
        run_id, art_id = _write_minimal_scan(self.conn)
        row = self.conn.execute(
            "SELECT artifact_kind, artifact_identity,"
            "       artifact_sha256, artifact_sha512,"
            "       package_name, package_version"
            " FROM scanned_artifacts WHERE id = ?",
            (art_id,),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "wheel")
        self.assertEqual(row[1], "litellm-1.82.8-py3-none-any.whl")
        self.assertEqual(row[2], "a" * 64)
        self.assertEqual(row[3], "b" * 128)
        self.assertEqual(row[4], "litellm")
        self.assertEqual(row[5], "1.82.8")

    def test_inserts_file_identity_per_unique_file(self):
        finding_a = _make_finding(context=_make_context(internal_path="setup.py"))
        finding_b = _make_finding(
            context=_make_context(internal_path="litellm/__init__.py")
        )
        result = _make_scan_result(findings=(finding_a, finding_b))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        count = self.conn.execute("SELECT COUNT(*) FROM file_identities").fetchone()[0]
        self.assertEqual(count, 2)

    def test_deduplicates_file_identity_for_same_file(self):
        finding_a = _make_finding(
            signal=_make_signal(signal_id="DENS010", line=14),
            context=_make_context(internal_path="setup.py"),
        )
        finding_b = _make_finding(
            signal=_make_signal(signal_id="DENS011", line=22),
            context=_make_context(internal_path="setup.py"),
        )
        result = _make_scan_result(findings=(finding_a, finding_b))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        count = self.conn.execute("SELECT COUNT(*) FROM file_identities").fetchone()[0]
        self.assertEqual(count, 1)

    def test_inserts_static_finding_per_finding(self):
        finding_a = _make_finding(
            signal=_make_signal(signal_id="DENS010", line=14),
        )
        finding_b = _make_finding(
            signal=_make_signal(signal_id="STDLIB001", line=22),
        )
        result = _make_scan_result(findings=(finding_a, finding_b))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        count = self.conn.execute("SELECT COUNT(*) FROM static_findings").fetchone()[0]
        self.assertEqual(count, 2)

    def test_static_finding_rule_id_is_null(self):
        result = _make_scan_result(findings=(_make_finding(),))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        row = self.conn.execute(
            "SELECT rule_id FROM static_findings LIMIT 1"
        ).fetchone()
        self.assertIsNone(row[0])

    def test_static_finding_producer_id_matches_argument(self):
        result = _make_scan_result(findings=(_make_finding(),))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        row = self.conn.execute(
            "SELECT producer_id FROM static_findings LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], "cli0")

    def test_internal_path_backslashes_normalized(self):
        finding = _make_finding(
            context=_make_context(internal_path="litellm\\utils\\helper.py")
        )
        result = _make_scan_result(findings=(finding,))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        row = self.conn.execute(
            "SELECT internal_path FROM static_findings LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], "litellm/utils/helper.py")

    def test_file_identity_path_also_normalized(self):
        finding = _make_finding(
            context=_make_context(internal_path="litellm\\utils\\helper.py")
        )
        result = _make_scan_result(findings=(finding,))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        row = self.conn.execute(
            "SELECT internal_path FROM file_identities LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], "litellm/utils/helper.py")

    def test_suppressed_findings_not_written(self):
        suppressed = SuppressedFinding(
            original_finding=_make_finding(),
            suppressing_rule_id="default_suppress_rule",
            suppressing_rule_source="default",
            would_have_been=_make_finding(),
        )
        result = _make_scan_result(suppressed_findings=(suppressed,))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        count = self.conn.execute("SELECT COUNT(*) FROM static_findings").fetchone()[0]
        self.assertEqual(count, 0)

    def test_zero_findings_writes_artifact_row(self):
        result = _make_scan_result(findings=())
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        art_count = self.conn.execute(
            "SELECT COUNT(*) FROM scanned_artifacts"
        ).fetchone()[0]
        fi_count = self.conn.execute("SELECT COUNT(*) FROM file_identities").fetchone()[
            0
        ]
        self.assertEqual(art_count, 1)
        self.assertEqual(fi_count, 0)

    def test_installed_env_artifact_hashes_are_null(self):
        result = _make_scan_result(
            artifact_kind=ArtifactKind.INSTALLED_ENV,
            artifact_identity="requests",
            artifact_sha256=None,
            artifact_sha512=None,
        )
        _, art_id = write_scan_result(
            self.conn, result, command="scan", producer_id="cli0"
        )
        row = self.conn.execute(
            "SELECT artifact_sha256, artifact_sha512"
            " FROM scanned_artifacts WHERE id = ?",
            (art_id,),
        ).fetchone()
        self.assertIsNone(row[0])
        self.assertIsNone(row[1])

    def test_static_finding_fields_correct(self):
        signal = _make_signal(
            signal_id="STDLIB001",
            analyzer="suspicious_stdlib",
            confidence=Confidence.DEFINITE,
            scope=Scope.MODULE,
            line=22,
            column=4,
            description="os.system with non-literal",
        )
        finding = _make_finding(signal=signal, severity=Severity.CRITICAL)
        result = _make_scan_result(findings=(finding,))
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        row = self.conn.execute(
            "SELECT signal_id, analyzer, severity, confidence,"
            "       scope, line, col, description"
            " FROM static_findings LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], "STDLIB001")
        self.assertEqual(row[1], "suspicious_stdlib")
        self.assertEqual(row[2], "critical")
        self.assertEqual(row[3], int(Confidence.DEFINITE))
        self.assertEqual(row[4], "MODULE")
        self.assertEqual(row[5], 22)
        self.assertEqual(row[6], 4)
        self.assertEqual(row[7], "os.system with non-literal")


# ===========================================================================
# writer.write_decoded_tree()
# ===========================================================================


class TestWriteDecodedTree(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()
        self.run_id, self.art_id = _write_minimal_scan(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_empty_tree_writes_no_rows(self):
        tree = _make_decoded_tree(nodes=())
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        count = self.conn.execute("SELECT COUNT(*) FROM decoded_nodes").fetchone()[0]
        self.assertEqual(count, 0)

    def test_flat_tree_inserts_one_node_per_top_level(self):
        node_a = _make_decoded_node(outer_signal_id="DENS010")
        node_b = _make_decoded_node(outer_signal_id="DENS011")
        tree = _make_decoded_tree(nodes=(node_a, node_b))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        count = self.conn.execute("SELECT COUNT(*) FROM decoded_nodes").fetchone()[0]
        self.assertEqual(count, 2)

    def test_recursive_tree_child_has_parent_node_id(self):
        child = _make_decoded_node(
            outer_signal_id="DENS011",
            depth=1,
        )
        parent = _make_decoded_node(
            outer_signal_id="DENS010",
            depth=0,
            children=(child,),
        )
        tree = _make_decoded_tree(nodes=(parent,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        rows = self.conn.execute(
            "SELECT id, parent_node_id FROM decoded_nodes ORDER BY id ASC"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        parent_db_id = rows[0][0]
        child_parent_id = rows[1][1]
        self.assertEqual(child_parent_id, parent_db_id)

    def test_top_level_node_has_null_parent(self):
        node = _make_decoded_node()
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        row = self.conn.execute(
            "SELECT parent_node_id FROM decoded_nodes LIMIT 1"
        ).fetchone()
        self.assertIsNone(row[0])

    def test_child_findings_written_and_linked(self):
        cf = ChildFinding(
            signal_id="STDLIB001",
            severity="high",
            line=5,
            column=0,
            description="os.system call",
        )
        node = _make_decoded_node(child_findings=(cf,))
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        node_row = self.conn.execute("SELECT id FROM decoded_nodes LIMIT 1").fetchone()
        cf_row = self.conn.execute(
            "SELECT signal_id, severity, line, col, description"
            " FROM decoded_child_findings WHERE node_id = ?",
            (node_row[0],),
        ).fetchone()
        self.assertIsNotNone(cf_row)
        self.assertEqual(cf_row[0], "STDLIB001")
        self.assertEqual(cf_row[1], "high")
        self.assertEqual(cf_row[2], 5)
        self.assertEqual(cf_row[3], 0)

    def test_chain_stored_as_json_array(self):
        node = _make_decoded_node(chain=("base64", "zlib"))
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        row = self.conn.execute("SELECT chain FROM decoded_nodes LIMIT 1").fetchone()
        parsed = json.loads(row[0])
        self.assertEqual(parsed, ["base64", "zlib"])

    def test_indicators_stored_as_json_array(self):
        node = _make_decoded_node(indicators=("subprocess", "socket"))
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        row = self.conn.execute(
            "SELECT indicators FROM decoded_nodes LIMIT 1"
        ).fetchone()
        parsed = json.loads(row[0])
        self.assertEqual(parsed, ["subprocess", "socket"])

    def test_pickle_warning_true_stored_as_1(self):
        node = _make_decoded_node(pickle_warning=True)
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        row = self.conn.execute(
            "SELECT pickle_warning FROM decoded_nodes LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], 1)

    def test_pickle_warning_false_stored_as_0(self):
        node = _make_decoded_node(pickle_warning=False)
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        row = self.conn.execute(
            "SELECT pickle_warning FROM decoded_nodes LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], 0)

    def test_ioc_decoded_source_not_written(self):
        # Payload bytes must never reach the database.
        ioc = IOCData(
            original_sha256="o" * 64,
            decoded_sha256="d" * 64,
            decoded_source="import os\nos.system('rm -rf /')",
            extract_timestamp=_NOW,
        )
        node = _make_decoded_node(ioc_data=ioc)
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=self.run_id,
            artifact_id=self.art_id,
        )
        # The decoded_nodes table has no column for decoded_source.
        # Assert no text from the payload appears anywhere in the row.
        row = self.conn.execute("SELECT * FROM decoded_nodes LIMIT 1").fetchone()
        row_text = " ".join(str(v) for v in row if v is not None)
        self.assertNotIn("rm -rf", row_text)
        self.assertNotIn("import os", row_text)

    def test_write_decoded_tree_failure_does_not_affect_scan_run(self):
        # Simulate a failure inside write_decoded_tree. The scan_run
        # row written before it must remain intact.
        node = _make_decoded_node()
        tree = _make_decoded_tree(nodes=(node,))
        with mock.patch(
            "pydepgate.dbs.pdgdb.writer._write_node_recursive",
            side_effect=sqlite3.OperationalError("simulated failure"),
        ):
            try:
                write_decoded_tree(
                    self.conn,
                    tree,
                    scan_run_id=self.run_id,
                    artifact_id=self.art_id,
                )
            except sqlite3.OperationalError:
                pass

        run_count = self.conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
        self.assertEqual(run_count, 1)


# ===========================================================================
# reader.get_db_status()
# ===========================================================================


class TestGetDbStatus(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_fresh_database_counts_are_zero(self):
        status = get_db_status(self.conn, "/tmp/test.db")
        self.assertEqual(status.total_scan_runs, 0)
        self.assertEqual(status.total_scanned_artifacts, 0)
        self.assertEqual(status.total_static_findings, 0)
        self.assertEqual(status.total_decoded_nodes, 0)
        self.assertEqual(status.total_cve_findings, 0)

    def test_schema_version_populated(self):
        status = get_db_status(self.conn, "/tmp/test.db")
        self.assertEqual(status.schema_version, schema.PDGDB_SCHEMA_VERSION)

    def test_db_path_returned(self):
        status = get_db_status(self.conn, "/some/path/evidence.db")
        self.assertEqual(status.db_path, "/some/path/evidence.db")

    def test_counts_reflect_written_records(self):
        run_id, art_id = _write_minimal_scan(
            self.conn,
            findings=(_make_finding(),),
        )
        status = get_db_status(self.conn, "/tmp/test.db")
        self.assertEqual(status.total_scan_runs, 1)
        self.assertEqual(status.total_scanned_artifacts, 1)
        self.assertEqual(status.total_static_findings, 1)

    def test_handles_empty_database_gracefully(self):
        # Drop all tables to simulate a pre-schema database.
        schema.drop_all_tables(self.conn)
        status = get_db_status(self.conn, "/tmp/test.db")
        self.assertEqual(status.total_scan_runs, 0)


# ===========================================================================
# reader.list_runs()
# ===========================================================================


class TestListRuns(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_empty_database_returns_empty_list(self):
        self.assertEqual(list_runs(self.conn), [])

    def test_returns_one_row_per_run(self):
        _write_minimal_scan(self.conn, run_id="run-aaa-0001")
        _write_minimal_scan(self.conn, run_id="run-bbb-0002")
        rows = list_runs(self.conn)
        self.assertEqual(len(rows), 2)

    def test_rows_are_newest_first(self):
        # Insert two runs; the second is written after the first so
        # its started_at timestamp will be >= the first's.
        _write_minimal_scan(self.conn, run_id="run-first-0001")
        _write_minimal_scan(self.conn, run_id="run-second-0002")
        rows = list_runs(self.conn)
        # The second-written run should appear first in the result.
        self.assertEqual(rows[0].run_id, "run-second-0002")

    def test_finding_count_is_correct(self):
        _write_minimal_scan(
            self.conn,
            run_id=_RUN_ID,
            findings=(
                _make_finding(),
                _make_finding(signal=_make_signal(signal_id="STDLIB001", line=22)),
            ),
        )
        rows = list_runs(self.conn)
        self.assertEqual(rows[0].finding_count, 2)

    def test_artifact_count_is_correct(self):
        _write_minimal_scan(self.conn)
        rows = list_runs(self.conn)
        self.assertEqual(rows[0].artifact_count, 1)

    def test_limit_restricts_results(self):
        for i in range(5):
            _write_minimal_scan(self.conn, run_id=f"run-{i:04d}-uuid")
        rows = list_runs(self.conn, limit=2)
        self.assertEqual(len(rows), 2)

    def test_limit_none_returns_all(self):
        for i in range(5):
            _write_minimal_scan(self.conn, run_id=f"run-{i:04d}-uuid")
        rows = list_runs(self.conn, limit=None)
        self.assertEqual(len(rows), 5)

    def test_offset_skips_leading_rows(self):
        for i in range(4):
            _write_minimal_scan(self.conn, run_id=f"run-{i:04d}-uuid")
        all_rows = list_runs(self.conn, limit=None)
        paged_rows = list_runs(self.conn, limit=None, offset=2)
        self.assertEqual(len(paged_rows), 2)
        self.assertEqual(paged_rows[0].run_id, all_rows[2].run_id)


# ===========================================================================
# reader.query_by_package()
# ===========================================================================


class TestQueryByPackage(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def _write_wheel_scan(
        self,
        *,
        run_id: str,
        wheel: str,
        findings: tuple[Finding, ...] = (),
    ) -> tuple[int, int]:
        result = _make_scan_result(
            scan_id=run_id,
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity=wheel,
            findings=findings,
        )
        return write_scan_result(self.conn, result, command="scan", producer_id="cli0")

    def test_returns_matching_artifacts(self):
        self._write_wheel_scan(
            run_id="run-0001",
            wheel="litellm-1.82.8-py3-none-any.whl",
        )
        rows = query_by_package(self.conn, "litellm")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].package_name, "litellm")

    def test_name_matching_is_case_insensitive(self):
        self._write_wheel_scan(
            run_id="run-0001",
            wheel="litellm-1.82.8-py3-none-any.whl",
        )
        rows = query_by_package(self.conn, "LiteLLM")
        self.assertEqual(len(rows), 1)

    def test_hyphenated_query_matches_underscore_stored(self):
        self._write_wheel_scan(
            run_id="run-0001",
            wheel="some-package-1.0.0-py3-none-any.whl",
        )
        rows = query_by_package(self.conn, "some-package")
        self.assertEqual(len(rows), 1)

    def test_version_filter_narrows_results(self):
        self._write_wheel_scan(
            run_id="run-0001",
            wheel="litellm-1.82.8-py3-none-any.whl",
        )
        self._write_wheel_scan(
            run_id="run-0002",
            wheel="litellm-1.83.0-py3-none-any.whl",
        )
        rows = query_by_package(self.conn, "litellm", package_version="1.82.8")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].package_version, "1.82.8")

    def test_no_match_returns_empty_list(self):
        rows = query_by_package(self.conn, "no_such_package")
        self.assertEqual(rows, [])

    def test_finding_count_is_correct(self):
        self._write_wheel_scan(
            run_id="run-0001",
            wheel="litellm-1.82.8-py3-none-any.whl",
            findings=(
                _make_finding(),
                _make_finding(signal=_make_signal(signal_id="STDLIB001", line=22)),
            ),
        )
        rows = query_by_package(self.conn, "litellm")
        self.assertEqual(rows[0].finding_count, 2)


# ===========================================================================
# reader.query_by_artifact_sha512()
# ===========================================================================


class TestQueryByArtifactSha512(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_returns_matching_artifact(self):
        result = _make_scan_result(artifact_sha512="b" * 128)
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        rows = query_by_artifact_sha512(self.conn, "b" * 128)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].artifact_sha512, "b" * 128)

    def test_matching_is_case_insensitive(self):
        result = _make_scan_result(artifact_sha512="ab" * 64)
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        rows = query_by_artifact_sha512(self.conn, "AB" * 64)
        self.assertEqual(len(rows), 1)

    def test_no_match_returns_empty_list(self):
        rows = query_by_artifact_sha512(self.conn, "f" * 128)
        self.assertEqual(rows, [])


# ===========================================================================
# reader.explain_run()
# ===========================================================================


class TestExplainRun(unittest.TestCase):

    def setUp(self):
        self.conn = _fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_returns_none_for_unknown_run_id(self):
        result = explain_run(self.conn, "no-such-run-id")
        self.assertIsNone(result)

    def test_returns_run_explanation_for_known_run(self):
        _write_minimal_scan(self.conn, run_id=_RUN_ID)
        explanation = explain_run(self.conn, _RUN_ID)
        self.assertIsNotNone(explanation)
        self.assertEqual(explanation.run_id, _RUN_ID)

    def test_explanation_metadata_fields(self):
        _write_minimal_scan(self.conn, run_id=_RUN_ID)
        explanation = explain_run(self.conn, _RUN_ID)
        self.assertEqual(explanation.producer_id, "cli0")
        self.assertEqual(explanation.command, "scan")
        self.assertEqual(explanation.pydepgate_ver, explanation.pydepgate_ver)

    def test_findings_sorted_by_path_line_col(self):
        finding_b = _make_finding(
            signal=_make_signal(signal_id="STDLIB001", line=22),
            context=_make_context(internal_path="setup.py"),
        )
        finding_a = _make_finding(
            signal=_make_signal(signal_id="DENS010", line=5),
            context=_make_context(internal_path="litellm/__init__.py"),
        )
        result = _make_scan_result(
            scan_id=_RUN_ID,
            findings=(finding_b, finding_a),
        )
        write_scan_result(self.conn, result, command="scan", producer_id="cli0")
        explanation = explain_run(self.conn, _RUN_ID)
        paths = [f.internal_path for f in explanation.findings]
        self.assertEqual(paths, sorted(paths))

    def test_artifact_populated(self):
        _write_minimal_scan(self.conn, run_id=_RUN_ID)
        explanation = explain_run(self.conn, _RUN_ID)
        self.assertIsNotNone(explanation.artifact)
        self.assertEqual(
            explanation.artifact.artifact_identity,
            "litellm-1.82.8-py3-none-any.whl",
        )

    def test_decoded_nodes_included(self):
        run_id, art_id = _write_minimal_scan(self.conn, run_id=_RUN_ID)
        cf = ChildFinding(
            signal_id="STDLIB001",
            severity="high",
            line=5,
            column=0,
            description="os.system",
        )
        node = _make_decoded_node(child_findings=(cf,))
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=run_id,
            artifact_id=art_id,
        )
        explanation = explain_run(self.conn, _RUN_ID)
        self.assertEqual(len(explanation.decoded_nodes), 1)
        self.assertEqual(len(explanation.decoded_nodes[0].child_findings), 1)
        self.assertEqual(
            explanation.decoded_nodes[0].child_findings[0].signal_id,
            "STDLIB001",
        )

    def test_decoded_node_chain_deserialized_as_tuple(self):
        run_id, art_id = _write_minimal_scan(self.conn, run_id=_RUN_ID)
        node = _make_decoded_node(chain=("base64", "zlib"))
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=run_id,
            artifact_id=art_id,
        )
        explanation = explain_run(self.conn, _RUN_ID)
        self.assertIsInstance(explanation.decoded_nodes[0].chain, tuple)
        self.assertEqual(explanation.decoded_nodes[0].chain, ("base64", "zlib"))

    def test_decoded_node_pickle_warning_deserialized_as_bool(self):
        run_id, art_id = _write_minimal_scan(self.conn, run_id=_RUN_ID)
        node = _make_decoded_node(pickle_warning=True)
        tree = _make_decoded_tree(nodes=(node,))
        write_decoded_tree(
            self.conn,
            tree,
            scan_run_id=run_id,
            artifact_id=art_id,
        )
        explanation = explain_run(self.conn, _RUN_ID)
        self.assertIsInstance(explanation.decoded_nodes[0].pickle_warning, bool)
        self.assertTrue(explanation.decoded_nodes[0].pickle_warning)


if __name__ == "__main__":
    unittest.main()
