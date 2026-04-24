"""Tests for the static analysis engine."""

import pathlib
import tempfile
import unittest

from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import ArtifactKind, Severity
from pydepgate.engines.static import StaticEngine


class StaticEngineScopeTests(unittest.TestCase):
    """Files that triage rejects should not produce findings."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_unknown_file_type_is_skipped(self):
        result = self.engine.scan_bytes(
            content=b"arbitrary content",
            internal_path="README.md",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.statistics.files_scanned, 0)
        self.assertEqual(result.statistics.files_skipped, 1)
        self.assertEqual(len(result.skipped), 1)

    def test_skip_reason_is_populated(self):
        result = self.engine.scan_bytes(
            content=b"x = 1",
            internal_path="mypackage/utils.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(len(result.skipped), 1)
        self.assertIn("not a known startup vector", result.skipped[0].reason)

    def test_file_in_tests_directory_is_skipped(self):
        result = self.engine.scan_bytes(
            content=b"import os\nexec(compile('', '', 'exec'))\n",
            internal_path="tests/test_foo.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.statistics.files_scanned, 0)


class StaticEngineSetupPyTests(unittest.TestCase):
    """setup.py is analyzed as Python source."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_clean_setup_py_produces_no_findings(self):
        source = (
            b"from setuptools import setup\n"
            b"setup(name='foo', version='1.0')\n"
        )
        result = self.engine.scan_bytes(
            content=source,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.statistics.files_scanned, 1)

    def test_setup_py_with_exec_base64_produces_finding(self):
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        result = self.engine.scan_bytes(
            content=source,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.signal.analyzer, "encoding_abuse")
        self.assertEqual(finding.context.internal_path, "setup.py")

    def test_severity_derived_from_confidence(self):
        # A long base64 literal should produce DEFINITE confidence,
        # which maps to HIGH severity under the v0.1 bridge.
        long_payload = "A" * 80
        source = (
            f"import base64\n"
            f"exec(base64.b64decode('{long_payload}'))\n"
        ).encode("utf-8")
        result = self.engine.scan_bytes(
            content=source,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)


class StaticEngineInitPyTests(unittest.TestCase):
    """Top-level __init__.py is analyzed; deep ones are skipped in v0.1."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_top_level_init_is_analyzed(self):
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        result = self.engine.scan_bytes(
            content=source,
            internal_path="mypackage/__init__.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(len(result.findings), 1)

    def test_deep_init_is_skipped(self):
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        result = self.engine.scan_bytes(
            content=source,
            internal_path="mypackage/sub/__init__.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.statistics.files_skipped, 1)


class StaticEnginePthTests(unittest.TestCase):
    """Option A: .pth exec lines are reparsed as Python and analyzed."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_clean_pth_produces_no_findings(self):
        content = b"/some/legitimate/path\n"
        result = self.engine.scan_bytes(
            content=content,
            internal_path="foo.pth",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.statistics.files_scanned, 1)

    def test_pth_exec_line_with_encoding_abuse_is_detected(self):
        # Direct analog to LiteLLM 1.82.8: a .pth file whose exec line
        # decodes and runs encoded content. Payload here is inert.
        content = (
            b"import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        result = self.engine.scan_bytes(
            content=content,
            internal_path="malicious.pth",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.signal.analyzer, "encoding_abuse")

    def test_pth_exec_line_location_remapped_correctly(self):
        # Exec line is on line 3 of the .pth file. The signal should
        # report line 3, not line 1.
        content = (
            b"# a comment\n"
            b"/some/path\n"
            b"import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        result = self.engine.scan_bytes(
            content=content,
            internal_path="malicious.pth",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].signal.location.line, 3)

    def test_pth_path_only_lines_produce_no_findings(self):
        content = (
            b"/some/path\n"
            b"/another/path\n"
        )
        result = self.engine.scan_bytes(
            content=content,
            internal_path="normal.pth",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(result.findings, ())


class StaticEngineFileTests(unittest.TestCase):
    """scan_file reads bytes from disk and delegates."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_scan_file_on_existing_pth(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "sample.pth"
            path.write_bytes(
                b"import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"
            )
            result = self.engine.scan_file(path)
            self.assertEqual(len(result.findings), 1)

    def test_scan_file_on_nonexistent_path(self):
        path = pathlib.Path("/nonexistent/does/not/exist.pth")
        result = self.engine.scan_file(path)
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.diagnostics), 1)
        self.assertIn("failed to read", result.diagnostics[0])


class StaticEngineStatisticsTests(unittest.TestCase):
    """ScanStatistics should reflect what actually happened."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_files_scanned_counted(self):
        result = self.engine.scan_bytes(
            content=b"x = 1\n",
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(result.statistics.files_scanned, 1)
        self.assertEqual(result.statistics.files_skipped, 0)

    def test_signals_emitted_counted(self):
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        result = self.engine.scan_bytes(
            content=source,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(result.statistics.signals_emitted, 1)

    def test_duration_is_recorded(self):
        result = self.engine.scan_bytes(
            content=b"x = 1\n",
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertGreaterEqual(result.statistics.duration_seconds, 0.0)


class StaticEngineAnalyzerErrorTests(unittest.TestCase):
    """A buggy analyzer must not crash the scan."""

    def test_analyzer_exception_recorded_in_diagnostics(self):
        class CrashingAnalyzer:
            name = "crasher"
            def analyze_python(self, parsed):
                raise RuntimeError("boom")

        engine = StaticEngine(analyzers=[CrashingAnalyzer()])
        result = engine.scan_bytes(
            content=b"x = 1\n",
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        # Scan completes despite the exception.
        self.assertEqual(result.statistics.files_scanned, 1)
        self.assertTrue(any(
            "crasher raised" in d for d in result.diagnostics
        ))


if __name__ == "__main__":
    unittest.main()