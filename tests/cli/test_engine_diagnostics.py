"""
Tests for StaticEngine.initial_diagnostics threading.

The engine accepts initial_diagnostics at construction. Every
ScanResult it produces (success or failure path) must include
those diagnostics, prepended ahead of per-scan diagnostics.

Covers all six ScanResult construction sites:
  - scan_file OSError path
  - scan_loose_file_as OSError path
  - scan_installed package-not-found path
  - _scan_artifact_with_enumerator enumerate-failure path
  - _aggregate_outputs success path
  - _wrap_single_output_as_result (exercised via scan_bytes)
"""

import unittest
from pathlib import Path

from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import ArtifactKind
from pydepgate.engines.static import StaticEngine
from pydepgate.traffic_control.triage import FileKind

_CLI_DIAGS = (
    "warning: synthetic CLI warning for test",
    "note: a second synthetic CLI diagnostic",
)


def _make_engine_with_diags(diags=_CLI_DIAGS):
    return StaticEngine(
        analyzers=[EncodingAbuseAnalyzer()],
        rules=[],
        initial_diagnostics=diags,
    )


def _assert_starts_with(test, result, expected):
    """The first N entries of result.diagnostics must match expected."""
    test.assertGreaterEqual(
        len(result.diagnostics),
        len(expected),
        msg=(
            f"expected at least {len(expected)} diagnostics, got "
            f"{len(result.diagnostics)}: {result.diagnostics}"
        ),
    )
    for i, want in enumerate(expected):
        test.assertEqual(result.diagnostics[i], want)


# =============================================================================


class ScanFileErrorPathTests(unittest.TestCase):
    """OSError path in scan_file prepends initial_diagnostics."""

    def test_missing_file_includes_initial_diagnostics(self):
        engine = _make_engine_with_diags()
        result = engine.scan_file(Path("/does/not/exist/file.py"))
        _assert_starts_with(self, result, _CLI_DIAGS)
        # And the actual failure diagnostic follows.
        self.assertTrue(any("failed to read" in d for d in result.diagnostics))


class ScanLooseFileAsErrorPathTests(unittest.TestCase):
    """OSError path in scan_loose_file_as prepends initial_diagnostics."""

    def test_missing_file_includes_initial_diagnostics(self):
        engine = _make_engine_with_diags()
        result = engine.scan_loose_file_as(
            Path("/does/not/exist/file.py"),
            FileKind.SETUP_PY,
        )
        _assert_starts_with(self, result, _CLI_DIAGS)
        self.assertTrue(any("failed to read" in d for d in result.diagnostics))


class ScanInstalledErrorPathTests(unittest.TestCase):
    """package-not-found path in scan_installed prepends diagnostics."""

    def test_missing_package_includes_initial_diagnostics(self):
        engine = _make_engine_with_diags()
        result = engine.scan_installed(
            "definitely-not-a-real-package-name-pydepgate-test-12345",
        )
        _assert_starts_with(self, result, _CLI_DIAGS)
        self.assertTrue(any("not installed" in d for d in result.diagnostics))


class EnumerateFailurePathTests(unittest.TestCase):
    """enumerate-failure path in _scan_artifact_with_enumerator prepends."""

    def test_enumerate_exception_includes_initial_diagnostics(self):
        engine = _make_engine_with_diags()

        def bad_enumerator():
            raise RuntimeError("synthetic enumerate failure")

        result = engine._scan_artifact_with_enumerator(
            identity="test",
            artifact_kind=ArtifactKind.WHEEL,
            enumerate_fn=bad_enumerator,
            extract_entry=lambda item: None,
            extract_skipped=lambda item: None,
        )
        _assert_starts_with(self, result, _CLI_DIAGS)
        self.assertTrue(any("failed to enumerate" in d for d in result.diagnostics))


class AggregateSuccessPathTests(unittest.TestCase):
    """_aggregate_outputs success path prepends initial_diagnostics."""

    def test_success_path_includes_initial_diagnostics(self):
        engine = _make_engine_with_diags()
        corpus = [
            ("pkg/__init__.py", b"x = 1\n"),
            ("pkg/other.py", b"y = 2\n"),
        ]
        result = engine._scan_artifact_with_enumerator(
            identity="test",
            artifact_kind=ArtifactKind.WHEEL,
            enumerate_fn=lambda: iter(corpus),
            extract_entry=lambda item: item,
            extract_skipped=lambda item: None,
        )
        _assert_starts_with(self, result, _CLI_DIAGS)


class WrapSingleOutputPathTests(unittest.TestCase):
    """_wrap_single_output_as_result (via scan_bytes) prepends."""

    def test_scan_bytes_includes_initial_diagnostics(self):
        engine = _make_engine_with_diags()
        result = engine.scan_bytes(
            content=b"x = 1\n",
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        _assert_starts_with(self, result, _CLI_DIAGS)


class DefaultBehaviorPreservationTests(unittest.TestCase):
    """Empty initial_diagnostics preserves existing behavior exactly."""

    def test_default_empty_no_extra_diagnostics(self):
        # An engine constructed without initial_diagnostics behaves
        # exactly as it did before this change.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
        )
        result = engine.scan_bytes(
            content=b"x = 1\n",
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        # The result should not contain our synthetic CLI diagnostics.
        for diag in result.diagnostics:
            self.assertNotIn("synthetic", diag)


if __name__ == "__main__":
    unittest.main()
