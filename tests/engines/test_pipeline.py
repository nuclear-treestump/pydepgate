"""
Pipeline-shape tests for the post-refactor StaticEngine.

These tests verify the invariants that make future parallelism a
one-line change:

  Invariant 1: _scan_one_file is a pure function in call shape.
    Calling it twice with the same input produces the same findings.
    self is not mutated by the call.

  Invariant 2: scan_bytes and scan_loose_file_as both go through
    _scan_one_file and produce equivalent findings for equivalent
    input. The wrapper is just shape conversion.

  Invariant 3: per_file_statistics is populated for multi-file
    scans (wheel, sdist, installed) and empty for single-file
    scans (scan_bytes, scan_loose_file_as).

  Invariant 4: The aggregator (_aggregate_outputs) sums per-file
    stats correctly, including the pre-enumeration skip case.

  Invariant 5: forced_file_kind on FileScanInput skips triage.
    triage's decision is used when forced_file_kind is None.

If any of these break, parallelism either won't work at all or will
produce different results than serial execution. Lock them down here.
"""

import tempfile
import unittest
from pathlib import Path

from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    FileScanOutput,
    FileStatsEntry,
    ScanStatistics,
    SkippedFile,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.traffic_control.triage import FileKind


_MALICIOUS_SETUP_PY = b"""
import base64
exec(base64.b64decode('cHJpbnQoMSk='))
"""


# =============================================================================
# Invariant 1: _scan_one_file is pure
# =============================================================================

class PureFunctionShapeTests(unittest.TestCase):
    """The per-file pipeline does not mutate engine state."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[
            EncodingAbuseAnalyzer(),
            CodeDensityAnalyzer(),
        ])

    def _input(self, content=b"x = 1\n", path="setup.py", forced=None):
        return FileScanInput(
            content=content,
            internal_path=path,
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity=path,
            forced_file_kind=forced,
        )

    def test_repeated_calls_produce_same_findings(self):
        inp = self._input(_MALICIOUS_SETUP_PY)
        out1 = self.engine._scan_one_file(inp)
        out2 = self.engine._scan_one_file(inp)
        # Findings must be identical (count, IDs, severities).
        self.assertEqual(
            [f.signal.signal_id for f in out1.findings],
            [f.signal.signal_id for f in out2.findings],
        )
        self.assertEqual(
            [f.severity for f in out1.findings],
            [f.severity for f in out2.findings],
        )

    def test_call_does_not_mutate_engine_analyzers_tuple(self):
        analyzers_before = self.engine.analyzers
        rules_before = list(self.engine.rules)
        self.engine._scan_one_file(self._input(_MALICIOUS_SETUP_PY))
        self.assertIs(self.engine.analyzers, analyzers_before)
        self.assertEqual(self.engine.rules, rules_before)

    def test_output_is_a_filescanoutput(self):
        out = self.engine._scan_one_file(self._input())
        self.assertIsInstance(out, FileScanOutput)

    def test_output_internal_path_echoes_input(self):
        inp = self._input(path="custom/path/file.py")
        out = self.engine._scan_one_file(inp)
        self.assertEqual(out.internal_path, "custom/path/file.py")


# =============================================================================
# Invariant 2: scan_bytes and scan_loose_file_as are equivalent wrappers
# =============================================================================

class WrapperEquivalenceTests(unittest.TestCase):
    """The two single-file public methods produce the same findings
    for the same content + file kind."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_scan_bytes_and_scan_loose_file_as_agree(self):
        # scan_bytes via filename triage on "setup.py" should produce
        # the same findings as scan_loose_file_as with FileKind.SETUP_PY.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "setup.py"
            path.write_bytes(_MALICIOUS_SETUP_PY)

            r_bytes = self.engine.scan_bytes(
                content=_MALICIOUS_SETUP_PY,
                internal_path="setup.py",
                artifact_kind=ArtifactKind.LOOSE_FILE,
            )
            r_loose = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)

        # Same findings (signal IDs and severities), same count.
        bytes_pairs = sorted(
            (f.signal.signal_id, f.severity.value) for f in r_bytes.findings
        )
        loose_pairs = sorted(
            (f.signal.signal_id, f.severity.value) for f in r_loose.findings
        )
        self.assertEqual(bytes_pairs, loose_pairs)

    def test_both_paths_use_scan_one_file(self):
        # The actual bytes both paths produce should match what
        # _scan_one_file returns directly. This is the smoking gun
        # that the wrappers really are wrappers.
        inp_no_force = FileScanInput(
            content=_MALICIOUS_SETUP_PY,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="setup.py",
        )
        inp_forced = FileScanInput(
            content=_MALICIOUS_SETUP_PY,
            internal_path="/tmp/x.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="/tmp/x.py",
            forced_file_kind=FileKind.SETUP_PY,
        )

        out_no_force = self.engine._scan_one_file(inp_no_force)
        out_forced = self.engine._scan_one_file(inp_forced)

        # Same finding IDs and severities; only the contexts'
        # internal_paths differ (one is "setup.py", other is /tmp/x.py).
        self.assertEqual(
            [f.signal.signal_id for f in out_no_force.findings],
            [f.signal.signal_id for f in out_forced.findings],
        )
        self.assertEqual(
            [f.severity for f in out_no_force.findings],
            [f.severity for f in out_forced.findings],
        )


# =============================================================================
# Invariant 3: per_file_statistics population
# =============================================================================

class PerFileStatisticsPopulationTests(unittest.TestCase):
    """per_file_statistics is empty for single-file scans, populated
    for multi-file (artifact) scans."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_scan_bytes_has_no_per_file_stats(self):
        result = self.engine.scan_bytes(
            content=b"x = 1\n",
            internal_path="setup.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
        )
        self.assertEqual(result.per_file_statistics, ())

    def test_scan_loose_file_as_has_no_per_file_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "setup.py"
            path.write_bytes(b"x = 1\n")
            result = self.engine.scan_loose_file_as(path, FileKind.SETUP_PY)
        self.assertEqual(result.per_file_statistics, ())

    def test_aggregate_outputs_populates_per_file_stats(self):
        # Drive the aggregator directly with synthetic outputs to
        # verify it writes the per_file_statistics field. This avoids
        # needing a real wheel or sdist for this property.
        outputs = [
            FileScanOutput(
                internal_path="pkg/foo.py",
                findings=(),
                skipped=(),
                diagnostics=(),
                suppressed_findings=(),
                statistics=ScanStatistics(
                    files_total=1,
                    files_scanned=1,
                    signals_emitted=3,
                    duration_seconds=0.001,
                ),
            ),
            FileScanOutput(
                internal_path="pkg/bar.py",
                findings=(),
                skipped=(),
                diagnostics=(),
                suppressed_findings=(),
                statistics=ScanStatistics(
                    files_total=1,
                    files_scanned=1,
                    signals_emitted=0,
                    duration_seconds=0.002,
                ),
            ),
        ]
        result = self.engine._aggregate_outputs(
            identity="some.whl",
            artifact_kind=ArtifactKind.WHEEL,
            outputs=outputs,
            pre_skipped=(),
            started_at=0.0,
        )
        self.assertEqual(len(result.per_file_statistics), 2)
        paths = [s.internal_path for s in result.per_file_statistics]
        self.assertIn("pkg/foo.py", paths)
        self.assertIn("pkg/bar.py", paths)


# =============================================================================
# Invariant 4: aggregation correctness
# =============================================================================

class AggregationCorrectnessTests(unittest.TestCase):
    """The aggregator sums stats correctly, including pre-enumeration skips."""

    def setUp(self):
        self.engine = StaticEngine(analyzers=[])

    def _output(self, path, scanned=True, signals=0):
        if scanned:
            stats = ScanStatistics(
                files_total=1, files_scanned=1,
                signals_emitted=signals, duration_seconds=0.001,
            )
        else:
            stats = ScanStatistics(
                files_total=1, files_skipped=1, duration_seconds=0.0,
            )
        skipped = (
            (SkippedFile(internal_path=path, reason="triage skip"),)
            if not scanned else ()
        )
        return FileScanOutput(
            internal_path=path,
            findings=(),
            skipped=skipped,
            diagnostics=(),
            suppressed_findings=(),
            statistics=stats,
        )

    def test_files_total_includes_pre_skips_and_outputs(self):
        result = self.engine._aggregate_outputs(
            identity="some.whl",
            artifact_kind=ArtifactKind.WHEEL,
            outputs=[
                self._output("a.py"),
                self._output("b.py"),
            ],
            pre_skipped=(
                SkippedFile(internal_path="binary.so", reason="not python"),
            ),
            started_at=0.0,
        )
        # 2 scanned outputs + 1 pre-skipped = 3 total.
        self.assertEqual(result.statistics.files_total, 3)

    def test_files_scanned_only_counts_scanned_outputs(self):
        result = self.engine._aggregate_outputs(
            identity="some.whl",
            artifact_kind=ArtifactKind.WHEEL,
            outputs=[
                self._output("a.py", scanned=True),
                self._output("b.py", scanned=False),
                self._output("c.py", scanned=True),
            ],
            pre_skipped=(),
            started_at=0.0,
        )
        self.assertEqual(result.statistics.files_scanned, 2)

    def test_files_skipped_includes_pre_skips_and_triage_skips(self):
        result = self.engine._aggregate_outputs(
            identity="some.whl",
            artifact_kind=ArtifactKind.WHEEL,
            outputs=[
                self._output("a.py", scanned=False),  # triage skip
                self._output("b.py", scanned=True),
            ],
            pre_skipped=(
                SkippedFile(internal_path="binary.so", reason="not python"),
            ),
            started_at=0.0,
        )
        # 1 pre-skip + 1 triage skip = 2.
        self.assertEqual(result.statistics.files_skipped, 2)

    def test_signals_emitted_sums_over_outputs(self):
        result = self.engine._aggregate_outputs(
            identity="some.whl",
            artifact_kind=ArtifactKind.WHEEL,
            outputs=[
                self._output("a.py", signals=5),
                self._output("b.py", signals=3),
                self._output("c.py", signals=0),
            ],
            pre_skipped=(),
            started_at=0.0,
        )
        self.assertEqual(result.statistics.signals_emitted, 8)

    def test_skipped_field_includes_both_pre_and_triage_skips(self):
        result = self.engine._aggregate_outputs(
            identity="some.whl",
            artifact_kind=ArtifactKind.WHEEL,
            outputs=[
                self._output("triage_skip.py", scanned=False),
            ],
            pre_skipped=(
                SkippedFile(internal_path="pre_skip.so", reason="binary"),
            ),
            started_at=0.0,
        )
        skipped_paths = {s.internal_path for s in result.skipped}
        self.assertEqual(skipped_paths, {"pre_skip.so", "triage_skip.py"})


# =============================================================================
# Invariant 5: forced_file_kind bypasses triage
# =============================================================================

class ForcedFileKindTests(unittest.TestCase):

    def setUp(self):
        self.engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])

    def test_forced_kind_treats_arbitrary_filename_as_setup_py(self):
        # "garbage_xyz.py" would normally be triaged out (not a known
        # startup vector). With forced_file_kind=SETUP_PY, the engine
        # analyzes it anyway.
        inp = FileScanInput(
            content=_MALICIOUS_SETUP_PY,
            internal_path="garbage_xyz.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="garbage_xyz.py",
            forced_file_kind=FileKind.SETUP_PY,
        )
        out = self.engine._scan_one_file(inp)
        # Findings should be present.
        self.assertGreater(len(out.findings), 0)
        # And no SkippedFile should have been emitted.
        self.assertEqual(len(out.skipped), 0)

    def test_no_forced_kind_lets_triage_skip(self):
        # Same content, no forced kind, name that triage skips.
        inp = FileScanInput(
            content=_MALICIOUS_SETUP_PY,
            internal_path="random_module.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="random_module.py",
            forced_file_kind=None,
        )
        out = self.engine._scan_one_file(inp)
        # Triage should have skipped it.
        self.assertEqual(len(out.findings), 0)
        self.assertEqual(len(out.skipped), 1)
        self.assertEqual(out.statistics.files_skipped, 1)
        self.assertEqual(out.statistics.files_scanned, 0)

    def test_forced_skip_is_handled_defensively(self):
        # Public APIs reject FileKind.SKIP, but if a caller manages
        # to pass it through FileScanInput directly, _scan_one_file
        # should produce a SKIP output rather than crashing.
        inp = FileScanInput(
            content=b"x = 1\n",
            internal_path="anything.py",
            artifact_kind=ArtifactKind.LOOSE_FILE,
            artifact_identity="anything.py",
            forced_file_kind=FileKind.SKIP,
        )
        out = self.engine._scan_one_file(inp)
        self.assertEqual(len(out.findings), 0)
        self.assertEqual(out.statistics.files_skipped, 1)


if __name__ == "__main__":
    unittest.main()