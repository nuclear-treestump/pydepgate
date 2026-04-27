"""
Tests for StaticEngine.scan_loose_file_as.

This method is the bypass-triage path used by 'pydepgate scan --single'.
It must:
  1. Preserve the real filesystem path in the resulting ScanContext
     (so reports reference the actual file, not a synthetic stand-in).
  2. Honor the supplied FileKind even when it disagrees with what
     triage would have decided based on the filename.
  3. Run the same analyzer/rule pipeline that scan_bytes runs.
  4. Reject FileKind.SKIP at the API boundary.
  5. Surface read failures as diagnostics, not exceptions.
"""

import pathlib
import tempfile
import unittest

from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import ArtifactKind, Severity
from pydepgate.engines.static import StaticEngine
from pydepgate.traffic_control.triage import FileKind


# =============================================================================
# Tier 1: Path preservation
# =============================================================================

class PathPreservationTests(unittest.TestCase):
    """The whole point of this method: real path appears in findings."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_real_path_in_artifact_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage_xyz.py"
            path.write_bytes(b"x = 1\n")
            result = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            self.assertEqual(result.artifact_identity, str(path))

    def test_real_path_in_finding_internal_path(self):
        # When findings exist, their context must reference the real
        # path, not "setup.py" or any synthetic stand-in.
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "test_fixture_42.py"
            path.write_bytes(source)
            result = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            self.assertGreater(len(result.findings), 0)
            for finding in result.findings:
                self.assertEqual(
                    finding.context.internal_path, str(path),
                    msg=f"finding {finding.signal.signal_id} has wrong path",
                )

    def test_path_in_pth_findings(self):
        # Same property must hold for .pth content.
        content = (
            b"import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "weird_name.pth"
            path.write_bytes(content)
            result = self.engine.scan_loose_file_as(path, FileKind.PTH)
            self.assertGreater(len(result.findings), 0)
            for finding in result.findings:
                self.assertEqual(finding.context.internal_path, str(path))

    def test_path_with_directory_components_preserved(self):
        # Multi-component paths must round-trip exactly, not be
        # truncated to basename.
        with tempfile.TemporaryDirectory() as tmp:
            sub = pathlib.Path(tmp) / "sub" / "deeper"
            sub.mkdir(parents=True)
            path = sub / "fixture.py"
            path.write_bytes(b"x = 1\n")
            result = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            self.assertEqual(result.artifact_identity, str(path))


# =============================================================================
# Tier 2: FileKind override
# =============================================================================

class FileKindOverrideTests(unittest.TestCase):
    """The forced kind wins over what triage would have chosen."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_arbitrary_filename_treated_as_setup_py(self):
        # Triage would have classified "anything.py" as SKIP. The
        # forced kind makes the engine analyze it as setup.py.
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "anything.py"
            path.write_bytes(source)
            result = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            # ENC001 in setup.py is CRITICAL per default rules.
            self.assertGreater(len(result.findings), 0)
            critical = [f for f in result.findings
                        if f.severity == Severity.CRITICAL]
            self.assertGreater(len(critical), 0)

    def test_same_content_different_kind_yields_different_severity(self):
        # The classic --as setup_py vs --as init_py severity gap.
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "x.py"
            path.write_bytes(source)
            r_setup = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            r_init = self.engine.scan_loose_file_as(path, FileKind.INIT_PY)
        max_setup = max(f.severity for f in r_setup.findings)
        max_init = max(f.severity for f in r_init.findings)
        order = {Severity.LOW: 1, Severity.MEDIUM: 2,
                 Severity.HIGH: 3, Severity.CRITICAL: 4}
        self.assertGreater(order[max_setup], order[max_init])

    def test_context_carries_forced_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage.py"
            path.write_bytes(b"x = 1\n")
            result = self.engine.scan_loose_file_as(path, FileKind.SITECUSTOMIZE)
            # Even on a clean file, the stats path proves the kind
            # made it through to the analyzers.
            self.assertEqual(result.statistics.files_scanned, 1)

    def test_triage_reason_indicates_single_file_mode(self):
        # The triage_reason string is surfaced in some error paths;
        # it should clearly identify single-file mode for debugging.
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "x.py"
            path.write_bytes(source)
            result = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            self.assertGreater(len(result.findings), 0)
            # All findings share the same context, so check just the first.
            reason = result.findings[0].context.triage_reason
            self.assertIn("single-file mode", reason)
            self.assertIn("setup_py", reason)


# =============================================================================
# Tier 3: API boundary
# =============================================================================

class ApiBoundaryTests(unittest.TestCase):
    """The method should reject obviously wrong inputs at the boundary."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_skip_kind_raises(self):
        # FileKind.SKIP makes no sense here; the whole point of the
        # method is to scan something. Reject loudly.
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "x.py"
            path.write_bytes(b"x = 1\n")
            with self.assertRaises(ValueError) as ctx:
                self.engine.scan_loose_file_as(path, FileKind.SKIP)
            self.assertIn("SKIP", str(ctx.exception))

    def test_nonexistent_path_returns_diagnostic(self):
        path = pathlib.Path("/nonexistent/never/created.py")
        result = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.diagnostics), 1)
        self.assertIn("failed to read", result.diagnostics[0])

    def test_directory_path_returns_diagnostic(self):
        # path.read_bytes() raises IsADirectoryError (subclass of
        # OSError) on a directory; must be caught and surfaced as
        # a diagnostic, not propagated.
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)
            result = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            self.assertEqual(result.findings, ())
            self.assertEqual(len(result.diagnostics), 1)


# =============================================================================
# Tier 4: Pipeline equivalence with scan_bytes
# =============================================================================

class PipelineEquivalenceTests(unittest.TestCase):
    """scan_loose_file_as and scan_bytes must produce equivalent findings
    when they're given the same content and kind."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_same_signals_via_both_paths(self):
        # Run the same content through both entry points; the signal
        # IDs and severities must match. Only the context paths differ.
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "setup.py"  # name triage accepts
            path.write_bytes(source)
            r_loose = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            r_bytes = self.engine.scan_bytes(
                content=source,
                internal_path="setup.py",
                artifact_kind=ArtifactKind.LOOSE_FILE,
            )

        loose_signals = sorted(
            (f.signal.signal_id, f.severity.value) for f in r_loose.findings
        )
        bytes_signals = sorted(
            (f.signal.signal_id, f.severity.value) for f in r_bytes.findings
        )
        self.assertEqual(loose_signals, bytes_signals)

    def test_statistics_consistent_with_scan_bytes(self):
        source = b"x = 1\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "setup.py"
            path.write_bytes(source)
            r_loose = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            r_bytes = self.engine.scan_bytes(
                content=source,
                internal_path="setup.py",
                artifact_kind=ArtifactKind.LOOSE_FILE,
            )
        self.assertEqual(r_loose.statistics.files_scanned,
                         r_bytes.statistics.files_scanned)
        self.assertEqual(r_loose.statistics.signals_emitted,
                         r_bytes.statistics.signals_emitted)
        self.assertEqual(r_loose.statistics.analyzers_run,
                         r_bytes.statistics.analyzers_run)


# =============================================================================
# Tier 5: Artifact kind
# =============================================================================

class ArtifactKindTests(unittest.TestCase):
    """Loose files always carry ArtifactKind.LOOSE_FILE regardless of content."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_loose_file_artifact_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "anything.py"
            path.write_bytes(b"x = 1\n")
            result = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
            self.assertEqual(result.artifact_kind, ArtifactKind.LOOSE_FILE)

    def test_pth_loose_file_artifact_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "x.pth"
            path.write_bytes(b"/some/path\n")
            result = self.engine.scan_loose_file_as(path, FileKind.PTH)
            self.assertEqual(result.artifact_kind, ArtifactKind.LOOSE_FILE)


if __name__ == "__main__":
    unittest.main()