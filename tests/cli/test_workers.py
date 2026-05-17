"""
Tests for the --workers and --force-parallel CLI flags and the
_resolve_workers_config function in pydepgate.cli.main.

Covers the full conflict matrix from the Delivery 3 design:
  Case 1: --workers serial + --force-parallel
  Case 2a: --workers 1 + --force-parallel
  Case 2b: --workers 0 / negative (argparse rejects)
  Case 3:  thrashing (>2x), severe thrashing (>4x)
  Case 4:  --workers banana (argparse rejects)
  Case 4 extended: --workers > 8x available CPUs (refuse)
  Case 5: --force-parallel alone
  Case 6: --workers auto on single-CPU
  Case 7: --workers == 2x exactly (no warning at the boundary)
"""

import argparse
import io
import unittest
from unittest.mock import patch

from pydepgate.cli.main import (
    DEFAULT_PARALLEL_THRESHOLD,
    THRASH_REFUSE_MULTIPLIER,
    THRASH_SEVERE_MULTIPLIER,
    THRASH_WARN_MULTIPLIER,
    WorkersSpec,
    _available_cpus,
    _parse_workers,
    _resolve_workers_config,
)

# =============================================================================
# _parse_workers
# =============================================================================


class ParseWorkersTests(unittest.TestCase):

    def test_serial(self):
        spec = _parse_workers("serial")
        self.assertIsNone(spec.value)
        self.assertFalse(spec.was_auto)

    def test_auto_returns_at_least_one(self):
        spec = _parse_workers("auto")
        self.assertIsNotNone(spec.value)
        self.assertGreaterEqual(spec.value, 1)
        self.assertTrue(spec.was_auto)

    def test_positive_int(self):
        spec = _parse_workers("4")
        self.assertEqual(spec.value, 4)
        self.assertFalse(spec.was_auto)

    def test_one_is_valid(self):
        spec = _parse_workers("1")
        self.assertEqual(spec.value, 1)

    def test_zero_raises(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_workers("0")

    def test_negative_raises(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_workers("-3")

    def test_banana_raises(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_workers("banana")

    def test_float_raises(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_workers("1.5")

    def test_empty_raises(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_workers("")


# =============================================================================
# _available_cpus
# =============================================================================


class AvailableCpusTests(unittest.TestCase):

    def test_returns_at_least_one(self):
        # Sanity: never returns 0 or negative.
        self.assertGreaterEqual(_available_cpus(), 1)


# =============================================================================
# _resolve_workers_config: helper for building fake args
# =============================================================================


def _make_args(workers=None, force_parallel=False):
    """Build a fake argparse namespace for resolver tests."""
    ns = argparse.Namespace()
    ns.workers = workers
    ns.force_parallel = force_parallel
    return ns


# =============================================================================
# _resolve_workers_config: no-op and serial cases
# =============================================================================


class ResolveWorkersSerialCasesTests(unittest.TestCase):

    def test_no_workers_no_force_is_silent(self):
        args = _make_args(workers=None, force_parallel=False)
        stderr = io.StringIO()
        workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertIsNone(workers)
        self.assertEqual(threshold, DEFAULT_PARALLEL_THRESHOLD)
        self.assertEqual(diags, [])
        self.assertEqual(stderr.getvalue(), "")

    def test_workers_serial_no_warning(self):
        spec = WorkersSpec(value=None, was_auto=False)
        args = _make_args(workers=spec, force_parallel=False)
        stderr = io.StringIO()
        workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertIsNone(workers)
        self.assertEqual(diags, [])
        self.assertEqual(stderr.getvalue(), "")

    def test_workers_one_no_warning(self):
        spec = WorkersSpec(value=1, was_auto=False)
        args = _make_args(workers=spec, force_parallel=False)
        stderr = io.StringIO()
        workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertEqual(workers, 1)
        self.assertEqual(diags, [])
        self.assertEqual(stderr.getvalue(), "")


# =============================================================================
# _resolve_workers_config: force-parallel conflict cases (1, 2a, 5)
# =============================================================================


class ResolveForceParallelConflictTests(unittest.TestCase):

    def test_case_5_force_parallel_alone_warns(self):
        # --force-parallel without --workers: warn, threshold stays
        # at default, no parallel.
        args = _make_args(workers=None, force_parallel=True)
        stderr = io.StringIO()
        workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertIsNone(workers)
        self.assertEqual(threshold, DEFAULT_PARALLEL_THRESHOLD)
        self.assertEqual(len(diags), 1)
        self.assertIn("no effect", stderr.getvalue())
        self.assertIn("serial", stderr.getvalue())

    def test_case_1_serial_plus_force_parallel_warns(self):
        spec = WorkersSpec(value=None, was_auto=False)
        args = _make_args(workers=spec, force_parallel=True)
        stderr = io.StringIO()
        workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertIsNone(workers)
        self.assertEqual(threshold, DEFAULT_PARALLEL_THRESHOLD)
        self.assertEqual(len(diags), 1)
        self.assertIn("no effect", stderr.getvalue())

    def test_case_2a_workers_one_plus_force_parallel_warns(self):
        spec = WorkersSpec(value=1, was_auto=False)
        args = _make_args(workers=spec, force_parallel=True)
        stderr = io.StringIO()
        workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertEqual(workers, 1)
        self.assertEqual(threshold, DEFAULT_PARALLEL_THRESHOLD)
        self.assertEqual(len(diags), 1)
        self.assertIn("no effect", stderr.getvalue())
        self.assertIn("must be >= 2", stderr.getvalue())

    def test_force_parallel_with_workers_two_applies(self):
        # --workers 2 --force-parallel: threshold drops to 0, no warning.
        spec = WorkersSpec(value=2, was_auto=False)
        args = _make_args(workers=spec, force_parallel=True)
        stderr = io.StringIO()
        # Mock _available_cpus to ensure 2 workers is not over the
        # thrashing threshold on whatever machine runs the tests.
        with patch("pydepgate.cli.main._available_cpus", return_value=4):
            workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertEqual(workers, 2)
        self.assertEqual(threshold, 0)
        self.assertEqual(diags, [])


# =============================================================================
# _resolve_workers_config: auto resolution (Case 6)
# =============================================================================


class ResolveAutoTests(unittest.TestCase):

    def test_auto_single_cpu_emits_note(self):
        # Auto resolved to 1: emit informational note.
        spec = WorkersSpec(value=1, was_auto=True)
        args = _make_args(workers=spec, force_parallel=False)
        stderr = io.StringIO()
        workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertEqual(workers, 1)
        self.assertEqual(len(diags), 1)
        self.assertIn("auto resolved to 1", stderr.getvalue())

    def test_auto_multi_cpu_no_note(self):
        # Auto on a multi-CPU machine produces no note.
        spec = WorkersSpec(value=4, was_auto=True)
        args = _make_args(workers=spec, force_parallel=False)
        stderr = io.StringIO()
        with patch("pydepgate.cli.main._available_cpus", return_value=4):
            workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertEqual(workers, 4)
        self.assertEqual(diags, [])
        self.assertEqual(stderr.getvalue(), "")


# =============================================================================
# _resolve_workers_config: thrashing tiers (Cases 3, 7, and 4-extended)
# =============================================================================


class ResolveThrashingTests(unittest.TestCase):
    """Use a mocked CPU count of 4 to make the math obvious."""

    def _mock_cpus(self, count):
        return patch("pydepgate.cli.main._available_cpus", return_value=count)

    def test_at_2x_no_warning_boundary_inclusive_for_user(self):
        # workers == 2 * cpus exactly: no thrashing warning.
        spec = WorkersSpec(value=8, was_auto=False)  # 2 * 4
        args = _make_args(workers=spec, force_parallel=False)
        stderr = io.StringIO()
        with self._mock_cpus(4):
            workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertEqual(workers, 8)
        self.assertEqual(diags, [])
        self.assertEqual(stderr.getvalue(), "")

    def test_above_2x_warns(self):
        # workers > 2 * cpus: warn (Case 3).
        spec = WorkersSpec(value=9, was_auto=False)  # 2 * 4 + 1
        args = _make_args(workers=spec, force_parallel=False)
        stderr = io.StringIO()
        with self._mock_cpus(4):
            workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertEqual(workers, 9)
        self.assertEqual(len(diags), 1)
        self.assertIn("expect CPU contention", stderr.getvalue())

    def test_above_4x_severe_warns(self):
        # workers > 4 * cpus: severe warning.
        spec = WorkersSpec(value=17, was_auto=False)  # 4 * 4 + 1
        args = _make_args(workers=spec, force_parallel=False)
        stderr = io.StringIO()
        with self._mock_cpus(4):
            workers, threshold, diags = _resolve_workers_config(args, stderr)
        self.assertEqual(workers, 17)
        self.assertEqual(len(diags), 1)
        self.assertIn("severe CPU thrashing", stderr.getvalue())

    def test_above_8x_refuses(self):
        # workers > 8 * cpus: sys.exit(TOOL_ERROR).
        spec = WorkersSpec(value=33, was_auto=False)  # 8 * 4 + 1
        args = _make_args(workers=spec, force_parallel=False)
        stderr = io.StringIO()
        with self._mock_cpus(4), self.assertRaises(SystemExit) as ctx:
            _resolve_workers_config(args, stderr)
        # exit_codes.TOOL_ERROR is what the CLI uses for user errors.
        from pydepgate.cli import exit_codes

        self.assertEqual(ctx.exception.code, exit_codes.TOOL_ERROR)
        self.assertIn("refusing to run", stderr.getvalue())

    def test_severe_takes_precedence_over_warn(self):
        # workers > 4x should emit ONLY the severe warning, not both.
        spec = WorkersSpec(value=20, was_auto=False)
        args = _make_args(workers=spec, force_parallel=False)
        stderr = io.StringIO()
        with self._mock_cpus(4):
            workers, threshold, diags = _resolve_workers_config(args, stderr)
        # Exactly one diagnostic line, and it's the severe one.
        self.assertEqual(len(diags), 1)
        self.assertIn("severe", stderr.getvalue())
        # No double-warning.
        self.assertEqual(stderr.getvalue().count("warning:"), 1)


if __name__ == "__main__":
    unittest.main()
