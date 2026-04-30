"""Phase 2 tests: hashes propagate from enumerator through to result."""

import hashlib
import unittest

from pydepgate.engines.base import ArtifactKind
from pydepgate.engines._hashes import hash_pair


class HashPairTests(unittest.TestCase):

    def test_known_input(self):
        # SHA256 of empty string is well-known.
        sha256, sha512 = hash_pair(b"")
        self.assertEqual(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_returns_lowercase_hex(self):
        sha256, sha512 = hash_pair(b"hello")
        self.assertEqual(sha256, sha256.lower())
        self.assertEqual(sha512, sha512.lower())

    def test_lengths_correct(self):
        sha256, sha512 = hash_pair(b"any input")
        self.assertEqual(len(sha256), 64)  # 32 bytes hex
        self.assertEqual(len(sha512), 128)  # 64 bytes hex

    def test_deterministic(self):
        a = hash_pair(b"some content")
        b = hash_pair(b"some content")
        self.assertEqual(a, b)

    def test_different_inputs_different_hashes(self):
        a = hash_pair(b"a")
        b = hash_pair(b"b")
        self.assertNotEqual(a[0], b[0])
        self.assertNotEqual(a[1], b[1])


# Integration tests. Construct a real engine, run scan_bytes, verify
# the resulting ScanResult carries hashes that match what
# hash_pair would have produced.

from pydepgate.engines.static import StaticEngine
from pydepgate.engines.base import ScanResult


class ScanBytesPropagatesHashesTests(unittest.TestCase):

    def setUp(self):
        # An engine with no analyzers and no rules. We're testing
        # the hashing infrastructure, not detection logic.
        self.engine = StaticEngine(analyzers=[], rules=[])

    def test_scan_bytes_populates_artifact_hashes(self):
        content = b"# clean python file\nprint('hello')\n"
        result = self.engine.scan_bytes(
            content=content,
            internal_path="x.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        expected_sha256, expected_sha512 = hash_pair(content)
        self.assertEqual(result.artifact_sha256, expected_sha256)
        self.assertEqual(result.artifact_sha512, expected_sha512)

    def test_scan_bytes_artifact_and_file_hashes_match_for_loose(self):
        # For single-file scans, artifact_sha256 == file_sha256.
        # We can't directly access file_sha256 from the ScanResult
        # (it's per-file), but we can confirm artifact_sha256 is
        # what hash_pair produces.
        content = b"x = 1\n"
        result = self.engine.scan_bytes(
            content=content,
            internal_path="x.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        sha256, sha512 = hash_pair(content)
        self.assertEqual(result.artifact_sha256, sha256)
        self.assertEqual(result.artifact_sha512, sha512)


# scan_loose_file_as test: needs a temp file. If your test suite
# already has fixtures for this, copy the pattern; otherwise:

import os
import tempfile
from pathlib import Path
from pydepgate.traffic_control.triage import FileKind


class ScanLooseFileAsPropagatesHashesTests(unittest.TestCase):

    def setUp(self):
        self.engine = StaticEngine(analyzers=[], rules=[])

    def test_loose_file_hashes_match_disk_content(self):
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".py", delete=False,
        ) as f:
            content = b"def hello(): return 'world'\n"
            f.write(content)
            path = Path(f.name)

        try:
            result = self.engine.scan_loose_file_as(path, FileKind.LIBRARY_PY)
            sha256, sha512 = hash_pair(content)
            self.assertEqual(result.artifact_sha256, sha256)
            self.assertEqual(result.artifact_sha512, sha512)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()