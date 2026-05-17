"""Tests for env-var-derived defaults of --workers and --force-parallel.

PYDEPGATE_WORKERS and PYDEPGATE_FORCE_PARALLEL provide defaults at
parser construction time, with the same precedence as every other
global flag in pydepgate: explicit CLI flag wins, env var second,
hard-coded default last. Bogus env values fall back silently to
"as if unset" rather than crashing argparse before parse can
surface a useful error.

Test coverage:

  _workers_default_from_env unit tests:
    - unset env returns None
    - empty string returns None
    - whitespace-only returns None
    - 'serial' returns the correct spec
    - 'auto' returns a spec with was_auto=True
    - integer string returns the correct spec
    - integer with surrounding whitespace is stripped
    - invalid strings return None silently
    - zero returns None silently (validation in _parse_workers)
    - negative integers return None silently

  Integration through build_parser:
    - env -> args.workers when no CLI flag
    - env -> args.force_parallel when no CLI flag
    - CLI flag overrides env at top-level position
    - CLI flag overrides env at subcommand position
    - PYDEPGATE_FORCE_PARALLEL truthy variants all read True
    - PYDEPGATE_FORCE_PARALLEL falsy variants all read False
"""

import os
import unittest
from unittest.mock import patch

from pydepgate.cli.main import (
    WorkersSpec,
    _workers_default_from_env,
    build_parser,
)


def _parse_with_env(argv, env):
    """Helper: parse argv with os.environ patched to env.

    Uses clear=True so the test does not inherit any pydepgate
    env vars from the host environment (which would otherwise
    contaminate the per-test invariants).
    """
    with patch.dict(os.environ, env, clear=True):
        parser = build_parser()
        return parser.parse_args(argv)


# ==========================================================================
# _workers_default_from_env unit tests
# ==========================================================================


class WorkersDefaultFromEnvTests(unittest.TestCase):
    """PYDEPGATE_WORKERS resolution at parser build time."""

    def test_env_unset_returns_none(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(_workers_default_from_env())

    def test_env_empty_string_returns_none(self):
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": ""}, clear=True):
            self.assertIsNone(_workers_default_from_env())

    def test_env_whitespace_only_returns_none(self):
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": "   "}, clear=True):
            self.assertIsNone(_workers_default_from_env())

    def test_env_serial(self):
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": "serial"}, clear=True):
            spec = _workers_default_from_env()
            self.assertIsNotNone(spec)
            self.assertIsNone(spec.value)
            self.assertFalse(spec.was_auto)

    def test_env_auto(self):
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": "auto"}, clear=True):
            spec = _workers_default_from_env()
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.value)
            self.assertGreaterEqual(spec.value, 1)
            self.assertTrue(spec.was_auto)

    def test_env_integer(self):
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": "4"}, clear=True):
            spec = _workers_default_from_env()
            self.assertEqual(spec, WorkersSpec(value=4, was_auto=False))

    def test_env_integer_with_surrounding_whitespace(self):
        # The helper strips whitespace before parsing, so leading
        # or trailing spaces in the env value should not break it.
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": "  8  "}, clear=True):
            spec = _workers_default_from_env()
            self.assertEqual(spec, WorkersSpec(value=8, was_auto=False))

    def test_env_invalid_string_silently_ignored(self):
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": "bogus"}, clear=True):
            self.assertIsNone(_workers_default_from_env())

    def test_env_zero_silently_ignored(self):
        # _parse_workers raises ArgumentTypeError for n < 1.
        # The helper swallows that and returns None.
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": "0"}, clear=True):
            self.assertIsNone(_workers_default_from_env())

    def test_env_negative_silently_ignored(self):
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": "-3"}, clear=True):
            self.assertIsNone(_workers_default_from_env())

    def test_env_float_silently_ignored(self):
        # Floats fail int() conversion in _parse_workers; the
        # ArgumentTypeError is swallowed and we get None.
        with patch.dict(os.environ, {"PYDEPGATE_WORKERS": "2.5"}, clear=True):
            self.assertIsNone(_workers_default_from_env())


# ==========================================================================
# Integration through build_parser
# ==========================================================================


class WorkersEnvParserIntegrationTests(unittest.TestCase):
    """End-to-end: PYDEPGATE_WORKERS flows from env to args.workers."""

    def test_env_serial_becomes_args_workers(self):
        args = _parse_with_env([], {"PYDEPGATE_WORKERS": "serial"})
        self.assertIsNotNone(args.workers)
        self.assertIsNone(args.workers.value)
        self.assertFalse(args.workers.was_auto)

    def test_env_integer_becomes_args_workers(self):
        args = _parse_with_env([], {"PYDEPGATE_WORKERS": "2"})
        self.assertEqual(args.workers, WorkersSpec(value=2, was_auto=False))

    def test_env_auto_becomes_args_workers(self):
        args = _parse_with_env([], {"PYDEPGATE_WORKERS": "auto"})
        self.assertIsNotNone(args.workers)
        self.assertTrue(args.workers.was_auto)
        self.assertGreaterEqual(args.workers.value, 1)

    def test_env_unset_args_workers_is_none(self):
        args = _parse_with_env([], {})
        self.assertIsNone(args.workers)

    def test_env_bogus_args_workers_is_none(self):
        args = _parse_with_env([], {"PYDEPGATE_WORKERS": "bogus"})
        self.assertIsNone(args.workers)

    def test_cli_flag_overrides_env_at_top_level(self):
        args = _parse_with_env(
            ["--workers", "8"],
            {"PYDEPGATE_WORKERS": "2"},
        )
        self.assertEqual(args.workers, WorkersSpec(value=8, was_auto=False))

    def test_cli_flag_overrides_env_at_subcommand_position(self):
        # --workers placed after a subcommand name should still
        # override the env-derived default.
        args = _parse_with_env(
            ["version", "--workers", "8"],
            {"PYDEPGATE_WORKERS": "2"},
        )
        self.assertEqual(args.workers, WorkersSpec(value=8, was_auto=False))


# ==========================================================================
# --force-parallel env var
# ==========================================================================


class ForceParallelEnvDefaultTests(unittest.TestCase):
    """PYDEPGATE_FORCE_PARALLEL env var integration."""

    def test_env_unset_false(self):
        args = _parse_with_env([], {})
        self.assertFalse(args.force_parallel)

    def test_env_truthy_values_all_read_true(self):
        for val in ("1", "true", "yes", "on", "TRUE", "Yes", "ON"):
            with self.subTest(val=val):
                args = _parse_with_env(
                    [],
                    {"PYDEPGATE_FORCE_PARALLEL": val},
                )
                self.assertTrue(
                    args.force_parallel,
                    msg=(
                        f"PYDEPGATE_FORCE_PARALLEL={val!r} " f"should resolve to True"
                    ),
                )

    def test_env_falsy_values_all_read_false(self):
        for val in ("", "0", "false", "no", "off", "bogus", "2"):
            with self.subTest(val=val):
                args = _parse_with_env(
                    [],
                    {"PYDEPGATE_FORCE_PARALLEL": val},
                )
                self.assertFalse(
                    args.force_parallel,
                    msg=(
                        f"PYDEPGATE_FORCE_PARALLEL={val!r} " f"should resolve to False"
                    ),
                )

    def test_cli_flag_overrides_env_at_top_level(self):
        # CLI --force-parallel sets True regardless of env value.
        args = _parse_with_env(
            ["--force-parallel"],
            {"PYDEPGATE_FORCE_PARALLEL": "0"},
        )
        self.assertTrue(args.force_parallel)

    def test_cli_flag_overrides_env_at_subcommand_position(self):
        args = _parse_with_env(
            ["version", "--force-parallel"],
            {"PYDEPGATE_FORCE_PARALLEL": "0"},
        )
        self.assertTrue(args.force_parallel)


if __name__ == "__main__":
    unittest.main()
