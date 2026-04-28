"""
Engine-level tests for deep_mode and LIBRARY_PY analyzer scoping.

These tests verify the engine's behavior in deep mode without going
through the CLI:

  Invariant 1: An engine with deep_mode=True passes deep_mode through
    to triage when scanning bytes (or arbitrary inputs through
    _scan_one_file). An engine with deep_mode=False does not.

  Invariant 2: For LIBRARY_PY files, only analyzers with
    `safe_for_library_scan = True` run. The non-density analyzers
    are filtered out.

  Invariant 3: For non-LIBRARY_PY files, all analyzers run regardless
    of their safe_for_library_scan flag. The flag does not affect
    setup.py / __init__.py / etc.

  Invariant 4: A library .py file fed to a deep_mode engine
    produces density-only findings; the same file fed to a
    default-mode engine produces no findings (it's skipped).

  Invariant 5: The engine remains picklable in deep mode. (The
    refactor's parallelism contract still holds.)
"""

import pickle
import unittest

from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.analyzers.dynamic_execution import DynamicExecutionAnalyzer
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.analyzers.string_ops import StringOpsAnalyzer
from pydepgate.analyzers.suspicious_stdlib import SuspiciousStdlibAnalyzer
from pydepgate.engines.base import (
    ArtifactKind,
    FileScanInput,
    Severity,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.traffic_control.triage import FileKind


# A multi-shape source that fires across multiple analyzers:
#
#   - The long base64 literal fires DENS010 (high entropy, AMBIGUOUS
#     confidence) and DENS011 (base64 alphabet over the length
#     threshold). Both come from code_density.
#   - The exec(base64.b64decode(_payload)) call fires ENC001
#     (encoding_abuse) and DYN002 (dynamic_execution: exec with a
#     non-literal argument at module scope).
#
# CRITICAL: the base64 string must be a SINGLE literal of meaningful
# length, NOT something like 'short' * 10 -- AST analyzers see
# operands separately; multiplication is runtime semantics, not
# static. A 12-char literal multiplied by an integer at runtime is
# still a 12-char literal in the AST, which sits below density's
# entropy-length thresholds.
_MIXED_SOURCE = (
    b"# Multi-shape fixture: encoded string + exec(decode(...)).\n"
    b"import base64\n"
    b"_payload = 'QWxsIHRoZSB3b3JsZHMgYSBzdGFnZSBhbmQgYWxsIHRoZSBtZW4g"
    b"YW5kIHdvbWVuIGFyZSBtZXJlbHkgcGxheWVycyB0aGV5IGhhdmUgdGhlaXIgZXhp"
    b"dHMgYW5kIHRoZWlyIGVudHJhbmNlcw=='\n"
    b"exec(base64.b64decode(_payload))\n"
)


def _all_analyzers():
    return [
        EncodingAbuseAnalyzer(),
        DynamicExecutionAnalyzer(),
        StringOpsAnalyzer(),
        SuspiciousStdlibAnalyzer(),
        CodeDensityAnalyzer(),
    ]


# =============================================================================
# Invariant 1: deep_mode is threaded through to triage
# =============================================================================

class DeepModeThreadedToTriageTests(unittest.TestCase):

    def test_deep_engine_classifies_random_py_as_library(self):
        # A path triage would normally skip ("foo/util.py") should
        # produce a finding (or at least not be classified as SKIP)
        # when the engine is in deep mode.
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=True,
        )
        result = engine.scan_bytes(
            content=_MIXED_SOURCE,
            internal_path="mymod/util.py",
            artifact_kind=ArtifactKind.WHEEL,
        )
        # In deep mode, this file is scanned (LIBRARY_PY kind).
        # Density analyzer runs and fires DENS010/DENS011 on the
        # long base64 literal. Findings should exist.
        self.assertGreater(len(result.findings), 0)
        # And NO SkippedFile entries: the file was treated as
        # LIBRARY_PY, not skipped.
        self.assertEqual(len(result.skipped), 0)

    def test_default_engine_skips_random_py(self):
        # Same call, but engine is in default mode. Triage should
        # skip the file and the result should record a SkippedFile.
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=False,
        )
        result = engine.scan_bytes(
            content=_MIXED_SOURCE,
            internal_path="mymod/util.py",
            artifact_kind=ArtifactKind.WHEEL,
        )
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.skipped), 1)

    def test_default_engine_default_value_is_false(self):
        # Regression: the default value of deep_mode should be False
        # so existing callers continue to behave the way they did.
        engine = StaticEngine(analyzers=[])
        self.assertFalse(engine.deep_mode)


# =============================================================================
# Invariant 2: LIBRARY_PY filters analyzers via safe_for_library_scan
# =============================================================================

class LibraryPyAnalyzerFilteringTests(unittest.TestCase):

    def test_library_py_runs_only_density_analyzer(self):
        # Force LIBRARY_PY via the FileScanInput so we can test the
        # engine's analyzer selection without going through triage.
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=True,
        )
        inp = FileScanInput(
            content=_MIXED_SOURCE,
            internal_path="mymod/util.py",
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="test.whl",
            forced_file_kind=FileKind.LIBRARY_PY,
        )
        output = engine._scan_one_file(inp)
        # Every finding's analyzer should be 'code_density'. If
        # anything else slips through, the safe_for_library_scan
        # filter is broken.
        for finding in output.findings:
            self.assertEqual(
                finding.signal.analyzer, "code_density",
                msg=(
                    f"finding {finding.signal.signal_id} from "
                    f"{finding.signal.analyzer} should not have run "
                    f"in LIBRARY_PY context"
                ),
            )

    def test_library_py_does_not_fire_enc001_or_dyn002(self):
        # ENC001 is the canonical encoding_abuse signal; DYN002 is
        # dynamic_execution's headline. In a setup.py context this
        # content fires both; in LIBRARY_PY it must not.
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=True,
        )
        inp = FileScanInput(
            content=_MIXED_SOURCE,
            internal_path="mymod/util.py",
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="test.whl",
            forced_file_kind=FileKind.LIBRARY_PY,
        )
        output = engine._scan_one_file(inp)
        signal_ids = [f.signal.signal_id for f in output.findings]
        self.assertNotIn("ENC001", signal_ids)
        self.assertNotIn("DYN002", signal_ids)

    def test_library_py_still_fires_density_signals(self):
        # Sanity: density signals DO fire. If they don't, the filter
        # is over-aggressive and dropped the wrong analyzer.
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=True,
        )
        inp = FileScanInput(
            content=_MIXED_SOURCE,
            internal_path="mymod/util.py",
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="test.whl",
            forced_file_kind=FileKind.LIBRARY_PY,
        )
        output = engine._scan_one_file(inp)
        signal_ids = [f.signal.signal_id for f in output.findings]
        density_ids = [s for s in signal_ids if s.startswith("DENS")]
        self.assertGreater(
            len(density_ids), 0,
            msg=f"expected density signals; got signal_ids={signal_ids}",
        )


# =============================================================================
# Invariant 3: Non-LIBRARY_PY kinds run all analyzers
# =============================================================================

class NonLibraryPyKindsUnaffectedTests(unittest.TestCase):
    """Setup.py and friends still run the full analyzer set."""

    def test_setup_py_runs_all_analyzers(self):
        # Same content as the LIBRARY_PY test but forced as SETUP_PY.
        # We expect to see findings from MULTIPLE analyzers, not just
        # code_density.
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=True,
        )
        inp = FileScanInput(
            content=_MIXED_SOURCE,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.SDIST,
            artifact_identity="test.tar.gz",
            forced_file_kind=FileKind.SETUP_PY,
        )
        output = engine._scan_one_file(inp)
        analyzers_seen = {f.signal.analyzer for f in output.findings}
        # Should see code_density AND at least one non-density analyzer.
        self.assertIn(
            "code_density", analyzers_seen,
            msg=f"expected density findings; got analyzers_seen={analyzers_seen}",
        )
        non_density = analyzers_seen - {"code_density"}
        self.assertGreater(
            len(non_density), 0,
            msg=f"expected non-density findings; got {analyzers_seen}",
        )

    def test_init_py_runs_all_analyzers(self):
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=True,
        )
        inp = FileScanInput(
            content=_MIXED_SOURCE,
            internal_path="mymod/__init__.py",
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="test.whl",
            forced_file_kind=FileKind.INIT_PY,
        )
        output = engine._scan_one_file(inp)
        analyzers_seen = {f.signal.analyzer for f in output.findings}
        non_density = analyzers_seen - {"code_density"}
        self.assertGreater(len(non_density), 0)


# =============================================================================
# Invariant 4: Deep vs default end-to-end equivalence on library files
# =============================================================================

class DeepVsDefaultEndToEndTests(unittest.TestCase):
    """The user-facing observable behavior: --deep finds things in
    library files that a default scan would have skipped."""

    def test_library_file_in_deep_engine_produces_findings(self):
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=True,
        )
        result = engine.scan_bytes(
            content=_MIXED_SOURCE,
            internal_path="mymod/util.py",
            artifact_kind=ArtifactKind.WHEEL,
        )
        self.assertGreater(
            len(result.findings), 0,
            msg=(
                f"expected density findings on library file in deep mode; "
                f"got 0. skipped={result.skipped} "
                f"diagnostics={result.diagnostics}"
            ),
        )

    def test_library_file_in_default_engine_produces_no_findings(self):
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=False,
        )
        result = engine.scan_bytes(
            content=_MIXED_SOURCE,
            internal_path="mymod/util.py",
            artifact_kind=ArtifactKind.WHEEL,
        )
        self.assertEqual(len(result.findings), 0)
        # And the file should appear in the skipped list.
        self.assertEqual(len(result.skipped), 1)

    def test_setup_py_works_identically_in_both_modes(self):
        # setup.py is a startup vector regardless of mode. A scan of
        # the same content as setup.py should produce the same
        # findings whether deep_mode is True or False.
        deep = StaticEngine(
            analyzers=_all_analyzers(), deep_mode=True,
        )
        default = StaticEngine(
            analyzers=_all_analyzers(), deep_mode=False,
        )
        r_deep = deep.scan_bytes(
            content=_MIXED_SOURCE,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.SDIST,
        )
        r_default = default.scan_bytes(
            content=_MIXED_SOURCE,
            internal_path="setup.py",
            artifact_kind=ArtifactKind.SDIST,
        )
        # Same set of (signal_id, severity) findings in both modes.
        deep_pairs = sorted(
            (f.signal.signal_id, f.severity.value) for f in r_deep.findings
        )
        default_pairs = sorted(
            (f.signal.signal_id, f.severity.value) for f in r_default.findings
        )
        self.assertEqual(deep_pairs, default_pairs)


# =============================================================================
# Invariant 5: Deep-mode engine remains picklable
# =============================================================================

class DeepModePicklabilityTests(unittest.TestCase):
    """The structural-refactor parallelism contract holds in deep mode."""

    def test_deep_engine_pickles(self):
        engine = StaticEngine(
            analyzers=_all_analyzers(),
            deep_mode=True,
        )
        round_tripped = pickle.loads(pickle.dumps(engine))
        self.assertTrue(round_tripped.deep_mode)
        self.assertEqual(len(round_tripped.analyzers), 5)

    def test_deep_engine_method_pickles(self):
        # For ProcessPoolExecutor.map(self._scan_one_file, ...) to work.
        engine = StaticEngine(
            analyzers=[CodeDensityAnalyzer()],
            deep_mode=True,
        )
        method = engine._scan_one_file
        unpickled = pickle.loads(pickle.dumps(method))
        # Smoke test: the unpickled method works.
        inp = FileScanInput(
            content=b"x = 1\n",
            internal_path="mymod/util.py",
            artifact_kind=ArtifactKind.WHEEL,
            artifact_identity="test.whl",
        )
        original_output = method(inp)
        unpickled_output = unpickled(inp)
        # Findings should match (timing varies).
        self.assertEqual(
            original_output.findings, unpickled_output.findings,
        )


# =============================================================================
# Tier 6: _select_analyzers_for_kind helper directly
# =============================================================================

class SelectAnalyzersForKindTests(unittest.TestCase):
    """Unit-level tests for the analyzer-selection helper."""

    def test_setup_py_returns_all_analyzers(self):
        engine = StaticEngine(analyzers=_all_analyzers())
        selected = engine._select_analyzers_for_kind(FileKind.SETUP_PY)
        self.assertEqual(len(selected), 5)

    def test_library_py_returns_only_density(self):
        engine = StaticEngine(analyzers=_all_analyzers())
        selected = engine._select_analyzers_for_kind(FileKind.LIBRARY_PY)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].name, "code_density")

    def test_pth_returns_all_analyzers(self):
        # PTH is a startup vector; full analyzer set applies.
        engine = StaticEngine(analyzers=_all_analyzers())
        selected = engine._select_analyzers_for_kind(FileKind.PTH)
        self.assertEqual(len(selected), 5)

    def test_engine_with_no_density_returns_empty_for_library_py(self):
        # If the engine is configured without the density analyzer,
        # LIBRARY_PY scans run zero analyzers (and produce nothing).
        # Not an error; the file simply yields no findings.
        engine = StaticEngine(
            analyzers=[
                EncodingAbuseAnalyzer(),
                DynamicExecutionAnalyzer(),
            ],
        )
        selected = engine._select_analyzers_for_kind(FileKind.LIBRARY_PY)
        self.assertEqual(len(selected), 0)


if __name__ == "__main__":
    unittest.main()