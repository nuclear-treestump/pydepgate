"""Phase 1 tests: data model carries the new hash fields."""

import pickle
import unittest

from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    FileScanOutput,
    ScanResult,
    ScanStatistics,
)
from pydepgate.enrichers.decode_payloads import (
    DecodedTree,
    filter_tree_by_severity,
)


class FileScanInputHashFieldsTests(unittest.TestCase):

    def test_defaults_to_none(self):
        inp = FileScanInput(
            content=b"x",
            internal_path="x.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="x.py",
        )
        self.assertIsNone(inp.file_sha256)
        self.assertIsNone(inp.file_sha512)

    def test_accepts_hex_strings(self):
        inp = FileScanInput(
            content=b"x",
            internal_path="x.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="x.py",
            file_sha256="a" * 64,
            file_sha512="b" * 128,
        )
        self.assertEqual(inp.file_sha256, "a" * 64)
        self.assertEqual(inp.file_sha512, "b" * 128)

    def test_pickles_round_trip(self):
        # The picklability contract: every input must survive a
        # round-trip without losing information.
        inp = FileScanInput(
            content=b"x",
            internal_path="x.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="x.py",
            file_sha256="a" * 64,
            file_sha512="b" * 128,
        )
        restored = pickle.loads(pickle.dumps(inp))
        self.assertEqual(restored.file_sha256, "a" * 64)
        self.assertEqual(restored.file_sha512, "b" * 128)


class FileScanOutputHashFieldsTests(unittest.TestCase):

    def test_defaults_to_none(self):
        out = FileScanOutput(
            findings=(),
            suppressed_findings=(),
            skipped=(),
            diagnostics=(),
            internal_path="x.py",
            statistics=ScanStatistics()
        )
        self.assertIsNone(out.file_sha256)
        self.assertIsNone(out.file_sha512)

    def test_pickles_round_trip(self):
        out = FileScanOutput(
            findings=(),
            suppressed_findings=(),
            skipped=(),
            diagnostics=(),
            file_sha256="a" * 64,
            file_sha512="b" * 128,
            internal_path="x.py",
            statistics=ScanStatistics()
        )
        restored = pickle.loads(pickle.dumps(out))
        self.assertEqual(restored.file_sha256, "a" * 64)
        self.assertEqual(restored.file_sha512, "b" * 128)


class ScanResultHashFieldsTests(unittest.TestCase):

    def test_defaults_to_none(self):
        result = ScanResult(
            findings=(),
            suppressed_findings=(),
            skipped=(),
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="x.whl",
            diagnostics=(),
            statistics=ScanStatistics(
                files_total=0,
                files_scanned=0,
                files_skipped=0,
                duration_seconds=0,
            ),
        )
        self.assertIsNone(result.artifact_sha256)
        self.assertIsNone(result.artifact_sha512)

    def test_pickles_round_trip(self):
        result = ScanResult(
            findings=(),
            suppressed_findings=(),
            skipped=(),
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="x.whl",
            diagnostics=(),
            statistics=ScanStatistics(
                files_total=0,
                files_scanned=0,
                files_skipped=0,
                duration_seconds=0,
            ),
            artifact_sha256="a" * 64,
            artifact_sha512="b" * 128,
        )
        restored = pickle.loads(pickle.dumps(result))
        self.assertEqual(restored.artifact_sha256, "a" * 64)
        self.assertEqual(restored.artifact_sha512, "b" * 128)


class DecodedTreeHashFieldsTests(unittest.TestCase):

    def test_defaults_to_none(self):
        tree = DecodedTree(target="x", max_depth=3, nodes=())
        self.assertIsNone(tree.artifact_sha256)
        self.assertIsNone(tree.artifact_sha512)

    def test_pickles_round_trip(self):
        tree = DecodedTree(
            target="x",
            max_depth=3,
            nodes=(),
            artifact_sha256="a" * 64,
            artifact_sha512="b" * 128,
        )
        restored = pickle.loads(pickle.dumps(tree))
        self.assertEqual(restored.artifact_sha256, "a" * 64)
        self.assertEqual(restored.artifact_sha512, "b" * 128)

    def test_filter_preserves_artifact_hashes(self):
        # Critical: filter_tree_by_severity rebuilds the tree, and
        # the rebuild must preserve the artifact-level metadata.
        # Without this, filtering drops the hashes.
        tree = DecodedTree(
            target="x",
            max_depth=3,
            nodes=(),
            artifact_sha256="a" * 64,
            artifact_sha512="b" * 128,
        )
        filtered = filter_tree_by_severity(tree, "high")
        self.assertEqual(filtered.artifact_sha256, "a" * 64)
        self.assertEqual(filtered.artifact_sha512, "b" * 128)


if __name__ == "__main__":
    unittest.main()