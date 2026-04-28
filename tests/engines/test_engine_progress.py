"""
Integration tests for engine progress callbacks.

These tests pin down the engine's progress-callback contract:
  - Called once per file in Phase 2.
  - Called with `total = len(inputs)` (i.e. files that survived
    pre-Phase-2 triage; not pre-skipped files).
  - Not called when callback is None.
  - Not called when there are no in-scope files.
  - A buggy callback must not abort the scan.

The tests drive `_scan_artifact_with_enumerator` directly with a
synthetic enumerator. This is the underscore-prefixed seam that
`scan_wheel`/`scan_sdist`/`scan_installed` all funnel through;
exercising it directly avoids needing real wheel/sdist fixtures.
"""

from __future__ import annotations

import unittest

from pydepgate.engines.base import ArtifactKind
from pydepgate.engines.static import StaticEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine() -> StaticEngine:
    """Engine with no analyzers and no rules.

    Phase 2 still runs (the callback fires once per input regardless
    of analyzer activity), but each file scan is essentially a no-op
    so tests are fast and don't depend on parser correctness.
    """
    return StaticEngine(analyzers=[], rules=[], deep_mode=True)


def _drive_scan(engine: StaticEngine, files, progress_callback=None):
    """Run _scan_artifact_with_enumerator with a list of synthetic files.

    `files` is a list of (internal_path, content_bytes) tuples that
    the engine should treat as in-scope inputs. Returns the ScanResult.
    """
    items = [(internal_path, content) for internal_path, content in files]
    return engine._scan_artifact_with_enumerator(
        identity="synthetic.whl",
        artifact_kind=ArtifactKind.WHEEL,
        enumerate_fn=lambda: items,
        # Each item is a (path, content) tuple; extract returns it.
        extract_entry=lambda item: item,
        # Nothing pre-skipped in these tests.
        extract_skipped=lambda item: None,
        progress_callback=progress_callback,
    )


def _make_synthetic_files(n: int):
    """Generate n synthetic Python files with distinct internal paths."""
    return [
        (f"pkg/file{i:03d}.py", b"# placeholder\n")
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEngineProgressCallback(unittest.TestCase):
    """The engine invokes the callback once per file with correct counts."""

    def test_callback_invoked_once_per_file(self):
        engine = _make_engine()
        calls: list[tuple[int, int]] = []
        files = _make_synthetic_files(5)
        _drive_scan(
            engine, files,
            progress_callback=lambda c, t: calls.append((c, t)),
        )
        self.assertEqual(len(calls), 5)

    def test_callback_completed_counts_increment(self):
        engine = _make_engine()
        calls: list[tuple[int, int]] = []
        files = _make_synthetic_files(5)
        _drive_scan(
            engine, files,
            progress_callback=lambda c, t: calls.append((c, t)),
        )
        # Completed values should be 1, 2, 3, 4, 5 (in order).
        completed_values = [c for c, _t in calls]
        self.assertEqual(completed_values, [1, 2, 3, 4, 5])

    def test_callback_total_is_input_count(self):
        engine = _make_engine()
        calls: list[tuple[int, int]] = []
        files = _make_synthetic_files(7)
        _drive_scan(
            engine, files,
            progress_callback=lambda c, t: calls.append((c, t)),
        )
        # Every call gets the same total: the count of in-scope inputs.
        totals = {t for _c, t in calls}
        self.assertEqual(totals, {7})

    def test_callback_final_call_has_completed_equal_total(self):
        engine = _make_engine()
        calls: list[tuple[int, int]] = []
        files = _make_synthetic_files(10)
        _drive_scan(
            engine, files,
            progress_callback=lambda c, t: calls.append((c, t)),
        )
        # The last call must reach 100% so the bar can render
        # its final state.
        self.assertEqual(calls[-1], (10, 10))

    def test_no_callback_does_not_crash(self):
        engine = _make_engine()
        files = _make_synthetic_files(5)
        # Just exercise the path with progress_callback=None.
        result = _drive_scan(engine, files, progress_callback=None)
        self.assertEqual(len(result.findings), 0)

    def test_zero_files_no_callback_invocations(self):
        engine = _make_engine()
        calls: list[tuple[int, int]] = []
        _drive_scan(
            engine, [],
            progress_callback=lambda c, t: calls.append((c, t)),
        )
        # No inputs means no Phase 2 iterations, so no callback fires.
        self.assertEqual(calls, [])


class TestEngineProgressRobustness(unittest.TestCase):
    """A buggy callback must not abort a scan."""

    def test_callback_that_raises_does_not_abort_scan(self):
        engine = _make_engine()
        files = _make_synthetic_files(3)

        def angry_callback(completed: int, total: int) -> None:
            raise RuntimeError("I am a buggy progress bar")

        # The scan should complete normally despite the callback
        # raising on every invocation. The progress UX is broken
        # for this run, but correctness is preserved.
        result = _drive_scan(engine, files, progress_callback=angry_callback)
        # All three files were processed (no findings since
        # analyzers list is empty).
        self.assertEqual(result.statistics.files_scanned, 3)

    def test_callback_with_wrong_signature_does_not_abort_scan(self):
        # Defensive: even a callable that raises TypeError on call
        # shouldn't take down the scan.
        engine = _make_engine()
        files = _make_synthetic_files(2)

        def wrong_sig() -> None:  # takes no args
            pass

        result = _drive_scan(
            engine, files,
            progress_callback=wrong_sig,  # type: ignore[arg-type]
        )
        self.assertEqual(result.statistics.files_scanned, 2)


if __name__ == "__main__":
    unittest.main()