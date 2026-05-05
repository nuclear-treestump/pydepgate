"""Phase 3 tests: renderer wiring + schema bump for hash fields."""

import io
import json
import pickle
import unittest

from pydepgate.engines.base import (
    ArtifactKind,
    Finding,
    ScanContext,
    ScanResult,
    ScanStatistics,
    Severity,
)
from pydepgate.enrichers.decode_payloads import (
    ChildFinding,
    DecodedNode,
    DecodedTree,
    IOCData,
    STOP_LEAF_TERMINAL,
    filter_tree_by_severity
)
from pydepgate.reporters.decoded_tree import text as render_text
from pydepgate.reporters.decoded_tree import iocs as render_iocs
from pydepgate.reporters.decoded_tree import json as render_decode_json
from pydepgate.reporters.decoded_tree import sources as render_sources
from pydepgate.reporters.scan_result.json import render as report_render_json


# ---------------------------------------------------------------------------
# ScanContext: file hashes round-trip
# ---------------------------------------------------------------------------

class ScanContextHashFieldsTests(unittest.TestCase):

    def test_defaults_to_none(self):
        from pydepgate.traffic_control.triage import FileKind
        ctx = ScanContext(
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="x.whl",
            internal_path="x.py",
            file_kind=FileKind.LIBRARY_PY,
            triage_reason="test",
        )
        self.assertIsNone(ctx.file_sha256)
        self.assertIsNone(ctx.file_sha512)

    def test_pickles_round_trip(self):
        from pydepgate.traffic_control.triage import FileKind
        ctx = ScanContext(
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="x.whl",
            internal_path="x.py",
            file_kind=FileKind.LIBRARY_PY,
            triage_reason="test",
            file_sha256="a" * 64,
            file_sha512="b" * 128,
        )
        restored = pickle.loads(pickle.dumps(ctx))
        self.assertEqual(restored.file_sha256, "a" * 64)
        self.assertEqual(restored.file_sha512, "b" * 128)


# ---------------------------------------------------------------------------
# DecodedNode: containing_file_sha256/sha512 round-trip
# ---------------------------------------------------------------------------

class DecodedNodeContainingFileHashTests(unittest.TestCase):

    def test_defaults_to_none(self):
        node = DecodedNode(
            outer_signal_id="DENS010",
            outer_severity="high",
            outer_location="x.py:1:0",
            outer_length=100,
            chain=("base64",),
            unwrap_status="completed",
            final_kind="python_source",
            final_size=50,
            indicators=(),
            pickle_warning=False,
            depth=0,
            stop_reason=STOP_LEAF_TERMINAL,
        )
        self.assertIsNone(node.containing_file_sha256)
        self.assertIsNone(node.containing_file_sha512)

    def test_pickles_round_trip(self):
        node = DecodedNode(
            outer_signal_id="DENS010",
            outer_severity="high",
            outer_location="x.py:1:0",
            outer_length=100,
            chain=("base64",),
            unwrap_status="completed",
            final_kind="python_source",
            final_size=50,
            indicators=(),
            pickle_warning=False,
            depth=0,
            stop_reason=STOP_LEAF_TERMINAL,
            containing_file_sha256="c" * 64,
            containing_file_sha512="d" * 128,
        )
        restored = pickle.loads(pickle.dumps(node))
        self.assertEqual(restored.containing_file_sha256, "c" * 64)
        self.assertEqual(restored.containing_file_sha512, "d" * 128)


# ---------------------------------------------------------------------------
# filter_tree_by_severity preserves containing-file hashes
# ---------------------------------------------------------------------------

class FilterPreservesContainingFileHashesTests(unittest.TestCase):

    def test_filter_preserves_containing_file_hashes(self):
        node = DecodedNode(
            outer_signal_id="DENS010",
            outer_severity="critical",  # passes any threshold
            outer_location="x.py:1:0",
            outer_length=100,
            chain=("base64",),
            unwrap_status="completed",
            final_kind="python_source",
            final_size=50,
            indicators=(),
            pickle_warning=False,
            depth=0,
            stop_reason=STOP_LEAF_TERMINAL,
            containing_file_sha256="c" * 64,
            containing_file_sha512="d" * 128,
        )
        tree = DecodedTree(
            target="x.whl",
            max_depth=3,
            nodes=(node,),
            artifact_sha256="a" * 64,
        )
        filtered = filter_tree_by_severity(tree, "high")
        self.assertEqual(len(filtered.nodes), 1)
        self.assertEqual(filtered.nodes[0].containing_file_sha256, "c" * 64)
        self.assertEqual(filtered.nodes[0].containing_file_sha512, "d" * 128)


# ---------------------------------------------------------------------------
# render_iocs emits artifact header
# ---------------------------------------------------------------------------

def _make_node_with_ioc(
    *,
    severity: str = "high",
    decoded_source: str | None = None,
    containing_file_sha256: str | None = None,
) -> DecodedNode:
    ioc = IOCData(
        original_sha256="o" * 64,
        original_sha512="O" * 128,
        decoded_sha256="d" * 64,
        decoded_sha512="D" * 128,
        decoded_source=decoded_source,
        extract_timestamp="2026-04-29T12:00:00+00:00",
    )
    return DecodedNode(
        outer_signal_id="DENS010",
        outer_severity=severity,
        outer_location="foo.py:10:5",
        outer_length=100,
        chain=("base64",),
        unwrap_status="completed",
        final_kind="python_source",
        final_size=50,
        indicators=(),
        pickle_warning=False,
        depth=0,
        stop_reason=STOP_LEAF_TERMINAL,
        triggered_by=("DENS010",),
        ioc_data=ioc,
        containing_file_sha256=containing_file_sha256,
    )


class RenderIocsArtifactHeaderTests(unittest.TestCase):

    def test_artifact_header_emitted_when_hashes_populated(self):
        tree = DecodedTree(
            target="litellm.whl",
            max_depth=3,
            nodes=(_make_node_with_ioc(),),
            artifact_sha256="a" * 64,
            artifact_sha512="A" * 128,
        )
        out = render_iocs(tree)

        self.assertIn(f"# artifact: litellm.whl", out)
        self.assertIn(f"artifact_sha256 {'a' * 64}", out)
        self.assertIn(f"artifact_sha512 {'A' * 128}", out)

    def test_artifact_header_omitted_when_no_artifact_hashes(self):
        # Installed-package scan: no artifact hashes.
        tree = DecodedTree(
            target="some-installed-pkg",
            max_depth=3,
            nodes=(_make_node_with_ioc(),),
        )
        out = render_iocs(tree)
        self.assertNotIn("artifact_sha256", out)
        self.assertNotIn("artifact_sha512", out)

    def test_artifact_header_emitted_on_empty_tree_when_hashes_present(self):
        # Stub archive case: NOFINDINGS but artifact hashes still
        # there. The header anchors what was scanned even when
        # nothing was found.
        tree = DecodedTree(
            target="clean.whl",
            max_depth=3,
            nodes=(),
            artifact_sha256="a" * 64,
            artifact_sha512="A" * 128,
        )
        out = render_iocs(tree)
        self.assertIn(f"artifact_sha256 {'a' * 64}", out)
        self.assertIn("nothing to record", out)


# ---------------------------------------------------------------------------
# render_iocs emits containing_file when meaningfully different
# ---------------------------------------------------------------------------

class RenderIocsContainingFileTests(unittest.TestCase):

    def test_containing_file_emitted_when_differs_from_artifact(self):
        tree = DecodedTree(
            target="litellm.whl",
            max_depth=3,
            nodes=(_make_node_with_ioc(
                containing_file_sha256="b" * 64,  # different from artifact
            ),),
            artifact_sha256="a" * 64,
        )
        out = render_iocs(tree)
        self.assertIn(f"file_sha256 {'b' * 64}", out)

    def test_containing_file_omitted_when_equals_artifact(self):
        # Loose-file --single scan: same hash for both, no need to
        # double-print.
        same_hash = "a" * 64
        tree = DecodedTree(
            target="loose.py",
            max_depth=3,
            nodes=(_make_node_with_ioc(
                containing_file_sha256=same_hash,
            ),),
            artifact_sha256=same_hash,
        )
        out = render_iocs(tree)
        # The artifact_sha256 line is present (once).
        artifact_count = out.count(f"artifact_sha256 {same_hash}")
        self.assertEqual(artifact_count, 1)
        # The redundant file_sha256 line is suppressed.
        self.assertNotIn(f"file_sha256 {same_hash}", out)

    def test_containing_file_omitted_when_node_lacks_hash(self):
        # Inner-recursive nodes have no containing-file hash; the
        # renderer should not emit the line for them.
        tree = DecodedTree(
            target="x.whl",
            max_depth=3,
            nodes=(_make_node_with_ioc(
                containing_file_sha256=None,  # inner node
            ),),
            artifact_sha256="a" * 64,
        )
        out = render_iocs(tree)
        self.assertNotIn("file_sha256 ", out.replace("artifact_sha256", ""))


# ---------------------------------------------------------------------------
# render_sources artifact header
# ---------------------------------------------------------------------------

class RenderSourcesArtifactHeaderTests(unittest.TestCase):

    def test_artifact_header_in_sources_output(self):
        node = _make_node_with_ioc(
            decoded_source="import os\n",
        )
        tree = DecodedTree(
            target="litellm.whl",
            max_depth=3,
            nodes=(node,),
            artifact_sha256="a" * 64,
            artifact_sha512="A" * 128,
        )
        out = render_sources(tree)
        self.assertIn("# artifact: litellm.whl", out)
        self.assertIn(f"# artifact SHA256: {'a' * 64}", out)


# ---------------------------------------------------------------------------
# render_json schema_version
# ---------------------------------------------------------------------------

class DecodeJsonSchemaTests(unittest.TestCase):

    def test_schema_version_emitted(self):
        tree = DecodedTree(target="x", max_depth=3, nodes=())
        out = render_decode_json(tree)
        data = json.loads(out)
        self.assertEqual(data["schema_version"], 1)

    def test_artifact_hashes_in_json(self):
        tree = DecodedTree(
            target="x.whl",
            max_depth=3,
            nodes=(),
            artifact_sha256="a" * 64,
            artifact_sha512="A" * 128,
        )
        data = json.loads(render_decode_json(tree))
        self.assertEqual(data["artifact_sha256"], "a" * 64)
        self.assertEqual(data["artifact_sha512"], "A" * 128)

    def test_containing_file_hashes_in_node_json(self):
        node = _make_node_with_ioc(
            containing_file_sha256="b" * 64,
        )
        tree = DecodedTree(
            target="x.whl",
            max_depth=3,
            nodes=(node,),
        )
        data = json.loads(render_decode_json(tree))
        self.assertEqual(
            data["nodes"][0]["containing_file_sha256"], "b" * 64,
        )


# ---------------------------------------------------------------------------
# Reporter (main scan output) schema bump and per-finding hashes
# ---------------------------------------------------------------------------

class ReporterSchemaBumpTests(unittest.TestCase):

    def test_schema_version_is_3(self):
        result = ScanResult(
            artifact_identity="x.whl",
            artifact_kind=ArtifactKind.WHEEL,
            findings=(),
            skipped=(),
            statistics=ScanStatistics(),
        )
        stream = io.StringIO()
        report_render_json(result, stream)
        data = json.loads(stream.getvalue())
        self.assertEqual(data["schema_version"], 3)

    def test_artifact_hashes_in_main_json(self):
        result = ScanResult(
            artifact_identity="x.whl",
            artifact_kind=ArtifactKind.WHEEL,
            findings=(),
            skipped=(),
            statistics=ScanStatistics(),
            artifact_sha256="a" * 64,
            artifact_sha512="A" * 128,
        )
        stream = io.StringIO()
        report_render_json(result, stream)
        data = json.loads(stream.getvalue())
        self.assertEqual(data["artifact"]["sha256"], "a" * 64)
        self.assertEqual(data["artifact"]["sha512"], "A" * 128)

    def test_artifact_hashes_null_for_installed_scan(self):
        # Installed package: artifact has no single-file hash.
        result = ScanResult(
            artifact_identity="some-pkg",
            artifact_kind=ArtifactKind.INSTALLED_ENV,
            findings=(),
            skipped=(),
            statistics=ScanStatistics(),
        )
        stream = io.StringIO()
        report_render_json(result, stream)
        data = json.loads(stream.getvalue())
        self.assertIsNone(data["artifact"]["sha256"])
        self.assertIsNone(data["artifact"]["sha512"])


if __name__ == "__main__":
    unittest.main()