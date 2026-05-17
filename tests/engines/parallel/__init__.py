"""Parallel testing for engines."""

"""
Parallel-execution tests for the static engine.

Locks the v0.4.5 contracts:
  - workers >= 2 with file count at or above threshold runs parallel
  - workers >= 2 with file count below threshold falls back to serial
    with one fallback diagnostic in ScanResult.diagnostics
  - workers=None and workers=1 both run serial without any fallback
    diagnostic (intentional-serial is not a fallback)
  - serial and parallel produce equivalent ScanResults modulo timing
  - parallel_threshold=0 forces parallel above 1 worker regardless of
    file count (this is what --force-parallel will translate to in
    Delivery 3)
"""

import unittest

from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import ArtifactKind
from pydepgate.engines.static import StaticEngine

# Fixture that fires the encoding_abuse analyzer.
_FIXTURE_HIT = b"""
import base64
exec(base64.b64decode('cHJpbnQoMSk='))
"""

# Fixture that does not fire anything.
_FIXTURE_CLEAN = b"x = 1\n"


def _make_corpus(count: int) -> list[tuple[str, bytes]]:
    """Build a synthetic corpus mixing in-scope and skipped files.

    Pattern by index modulo 3:
      0: pkg_<i>/__init__.py with a hit          (INIT_PY, fires)
      1: pkg_<i>/__init__.py with clean content  (INIT_PY, silent)
      2: docs/file_<i>.txt                       (SKIP via docs/)
    """
    items = []
    for i in range(count):
        if i % 3 == 0:
            items.append((f"pkg_{i}/__init__.py", _FIXTURE_HIT))
        elif i % 3 == 1:
            items.append((f"pkg_{i}/__init__.py", _FIXTURE_CLEAN))
        else:
            items.append((f"docs/file_{i}.txt", b"text"))
    return items


def _run_through_enumerator(engine, corpus):
    """Drive _scan_artifact_with_enumerator with a synthetic corpus.

    The corpus is a list of (internal_path, content) tuples. The
    `extract_entry` callback is identity since our items already match
    that shape. `extract_skipped` returns None because pre-Phase-1
    skips are not part of the test surface here.
    """
    return engine._scan_artifact_with_enumerator(
        identity="synthetic",
        artifact_kind=ArtifactKind.WHEEL,
        enumerate_fn=lambda: iter(corpus),
        extract_entry=lambda item: item,
        extract_skipped=lambda item: None,
    )


def _assert_results_equivalent(test_case, a, b):
    """Assert two ScanResults are equivalent modulo timing.

    Findings, skipped files, and structural counts must match exactly.
    `duration_seconds` is expected to differ between serial and parallel
    runs and is not compared.
    """
    test_case.assertEqual(a.findings, b.findings, "findings differ")
    test_case.assertEqual(a.skipped, b.skipped, "skipped files differ")
    test_case.assertEqual(
        a.statistics.files_total,
        b.statistics.files_total,
        "files_total differs",
    )
    test_case.assertEqual(
        a.statistics.files_scanned,
        b.statistics.files_scanned,
        "files_scanned differs",
    )
    test_case.assertEqual(
        a.statistics.files_skipped,
        b.statistics.files_skipped,
        "files_skipped differs",
    )
    test_case.assertEqual(
        a.statistics.signals_emitted,
        b.statistics.signals_emitted,
        "signals_emitted differs",
    )
    # Per-file stats: paths and counts must match exactly; durations
    # may differ between runs.
    a_perfile = [
        (p.internal_path, p.signals_emitted, p.findings_count)
        for p in a.per_file_statistics
    ]
    b_perfile = [
        (p.internal_path, p.signals_emitted, p.findings_count)
        for p in b.per_file_statistics
    ]
    test_case.assertEqual(a_perfile, b_perfile, "per-file stats differ")


def _count_fallback_diagnostics(result) -> int:
    """How many fallback diagnostics ended up in this ScanResult."""
    return sum(1 for d in result.diagnostics if "running serial" in d)


# =============================================================================


class ParallelGatingTests(unittest.TestCase):
    """Tests for the parallel-vs-serial decision tree."""

    def test_workers_none_is_serial(self):
        # workers=None must run serial and emit no fallback diagnostic.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
            workers=None,
            parallel_threshold=10,
        )
        corpus = _make_corpus(30)
        result = _run_through_enumerator(engine, corpus)
        self.assertEqual(_count_fallback_diagnostics(result), 0)
        # Sanity: scan produced findings (workers=None still scans).
        self.assertGreater(len(result.findings), 0)

    def test_workers_one_is_serial(self):
        # workers=1 must run serial and emit no fallback diagnostic.
        # A pool of one is overhead without benefit, so we treat it
        # the same as workers=None.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
            workers=1,
            parallel_threshold=10,
        )
        corpus = _make_corpus(30)
        result = _run_through_enumerator(engine, corpus)
        self.assertEqual(_count_fallback_diagnostics(result), 0)
        self.assertGreater(len(result.findings), 0)

    def test_above_threshold_runs_parallel(self):
        # workers=2, threshold=10, corpus=30: parallel engages, no
        # fallback diagnostic.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
            workers=2,
            parallel_threshold=10,
        )
        corpus = _make_corpus(30)
        result = _run_through_enumerator(engine, corpus)
        self.assertEqual(_count_fallback_diagnostics(result), 0)
        self.assertGreater(len(result.findings), 0)

    def test_below_threshold_falls_back_with_diagnostic(self):
        # workers=4, threshold=1000, corpus=30: fallback path runs,
        # diagnostic appears exactly once.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
            workers=4,
            parallel_threshold=1000,
        )
        corpus = _make_corpus(30)
        result = _run_through_enumerator(engine, corpus)
        self.assertEqual(
            _count_fallback_diagnostics(result),
            1,
            msg=(
                f"expected exactly one fallback diagnostic, got "
                f"{result.diagnostics}"
            ),
        )
        self.assertGreater(len(result.findings), 0)

    def test_force_parallel_via_threshold_zero(self):
        # parallel_threshold=0 forces parallel when workers >= 2,
        # regardless of how few files there are. This is what
        # --force-parallel will translate to in Delivery 3.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
            workers=2,
            parallel_threshold=0,
        )
        corpus = _make_corpus(5)
        result = _run_through_enumerator(engine, corpus)
        self.assertEqual(_count_fallback_diagnostics(result), 0)

    def test_empty_corpus_no_fallback_diagnostic(self):
        # Empty inputs should not produce a fallback diagnostic even
        # when workers is set. There is no scan to downgrade.
        engine = StaticEngine(
            analyzers=[EncodingAbuseAnalyzer()],
            rules=[],
            workers=4,
            parallel_threshold=1000,
        )
        result = _run_through_enumerator(engine, [])
        self.assertEqual(_count_fallback_diagnostics(result), 0)


class ParallelSerialEquivalenceTests(unittest.TestCase):
    """Same inputs through serial and parallel engines must agree."""

    def test_findings_match_modulo_timing(self):
        analyzers = [EncodingAbuseAnalyzer()]
        serial_engine = StaticEngine(
            analyzers=analyzers,
            rules=[],
            workers=None,
        )
        parallel_engine = StaticEngine(
            analyzers=analyzers,
            rules=[],
            workers=4,
            parallel_threshold=10,
        )
        corpus = _make_corpus(30)
        serial = _run_through_enumerator(serial_engine, corpus)
        parallel = _run_through_enumerator(parallel_engine, corpus)
        _assert_results_equivalent(self, serial, parallel)

    def test_findings_match_with_force_parallel(self):
        # Equivalence holds even for tiny corpora when threshold=0.
        analyzers = [EncodingAbuseAnalyzer()]
        serial_engine = StaticEngine(
            analyzers=analyzers,
            rules=[],
            workers=None,
        )
        parallel_engine = StaticEngine(
            analyzers=analyzers,
            rules=[],
            workers=2,
            parallel_threshold=0,
        )
        corpus = _make_corpus(6)
        serial = _run_through_enumerator(serial_engine, corpus)
        parallel = _run_through_enumerator(parallel_engine, corpus)
        _assert_results_equivalent(self, serial, parallel)


if __name__ == "__main__":
    unittest.main()
