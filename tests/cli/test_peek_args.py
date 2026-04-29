"""
Tests for `pydepgate.cli.peek_args`.

Covers:
  - Argument parsing with default values.
  - Environment variable defaulting.
  - CLI-overrides-env precedence.
  - Validation: soft warnings for tuning flags without --peek,
    hard errors for out-of-range values.
  - Enricher construction: returns None when peek is off, returns
    a configured PayloadPeek when on.
  - peek_chain_enabled correctness across flag combinations.
"""

import argparse
import io
import os
import unittest
from unittest import mock

from pydepgate.cli.peek_args import (
    ENV_PEEK,
    ENV_PEEK_BUDGET,
    ENV_PEEK_CHAIN,
    ENV_PEEK_DEPTH,
    ENV_PEEK_MIN_LENGTH,
    PEEK_DEPTH_CEILING,
    add_peek_arguments,
    build_peek_enricher,
    peek_chain_enabled,
    validate_peek_args,
)
from pydepgate.enrichers.payload_peek import (
    DEFAULT_MAX_BUDGET,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MIN_LENGTH,
    MIN_BUDGET_FLOOR,
    MIN_LENGTH_FLOOR,
    PayloadPeek,
)


# All peek-related env vars, used to clear environment between tests
# so an inherited PYDEPGATE_PEEK_* doesn't leak in from the test
# runner's environment.
_PEEK_ENV_VARS = (
    ENV_PEEK,
    ENV_PEEK_DEPTH,
    ENV_PEEK_BUDGET,
    ENV_PEEK_CHAIN,
    ENV_PEEK_MIN_LENGTH,
)


def _build_parser(env_overrides: dict | None = None) -> argparse.ArgumentParser:
    """Build a parser with peek args, optionally with env overrides."""
    parser = argparse.ArgumentParser()
    if env_overrides is None:
        env_overrides = {}
    # Clear all peek env vars first so test isolation is clean.
    clean_env = {
        k: v for k, v in os.environ.items()
        if k not in _PEEK_ENV_VARS
    }
    clean_env.update(env_overrides)
    with mock.patch.dict(os.environ, clean_env, clear=True):
        add_peek_arguments(parser, stderr=io.StringIO())
    return parser


# ===========================================================================
# Default parsing
# ===========================================================================

class DefaultArgumentParsingTests(unittest.TestCase):

    def test_no_args_yields_disabled_peek(self):
        parser = _build_parser()
        args = parser.parse_args([])
        self.assertFalse(args.peek)
        self.assertFalse(args.peek_chain)
        self.assertEqual(args.peek_depth, DEFAULT_MAX_DEPTH)
        self.assertEqual(args.peek_budget, DEFAULT_MAX_BUDGET)
        self.assertEqual(args.peek_min_length, DEFAULT_MIN_LENGTH)

    def test_peek_flag_enables(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek"])
        self.assertTrue(args.peek)

    def test_peek_chain_flag(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek", "--peek-chain"])
        self.assertTrue(args.peek_chain)

    def test_explicit_depth_override(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek", "--peek-depth", "5"])
        self.assertEqual(args.peek_depth, 5)

    def test_explicit_budget_override(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek", "--peek-budget", "65536"])
        self.assertEqual(args.peek_budget, 65536)

    def test_explicit_min_length_override(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek", "--peek-min-length", "256"])
        self.assertEqual(args.peek_min_length, 256)


# ===========================================================================
# Environment-variable defaults
# ===========================================================================

class EnvironmentVariableDefaultsTests(unittest.TestCase):

    def test_env_peek_truthy_enables_default(self):
        for truthy in ["1", "true", "yes", "on", "TRUE", "Yes"]:
            with self.subTest(value=truthy):
                parser = _build_parser({ENV_PEEK: truthy})
                args = parser.parse_args([])
                self.assertTrue(args.peek)

    def test_env_peek_falsy_keeps_disabled(self):
        for falsy in ["0", "false", "no", "off", "", "garbage"]:
            with self.subTest(value=falsy):
                parser = _build_parser({ENV_PEEK: falsy})
                args = parser.parse_args([])
                self.assertFalse(args.peek)

    def test_env_peek_depth_used_as_default(self):
        parser = _build_parser({ENV_PEEK_DEPTH: "5"})
        args = parser.parse_args([])
        self.assertEqual(args.peek_depth, 5)

    def test_env_peek_budget_used_as_default(self):
        parser = _build_parser({ENV_PEEK_BUDGET: "65536"})
        args = parser.parse_args([])
        self.assertEqual(args.peek_budget, 65536)

    def test_env_peek_min_length_used_as_default(self):
        parser = _build_parser({ENV_PEEK_MIN_LENGTH: "256"})
        args = parser.parse_args([])
        self.assertEqual(args.peek_min_length, 256)

    def test_env_peek_chain_truthy(self):
        parser = _build_parser({ENV_PEEK_CHAIN: "1"})
        args = parser.parse_args([])
        self.assertTrue(args.peek_chain)

    def test_malformed_int_env_uses_default_with_warning(self):
        stderr = io.StringIO()
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in _PEEK_ENV_VARS
        }
        clean_env[ENV_PEEK_DEPTH] = "not-a-number"
        with mock.patch.dict(os.environ, clean_env, clear=True):
            parser = argparse.ArgumentParser()
            add_peek_arguments(parser, stderr=stderr)
        args = parser.parse_args([])
        self.assertEqual(args.peek_depth, DEFAULT_MAX_DEPTH)
        self.assertIn("not-a-number", stderr.getvalue())

    def test_malformed_min_length_env_uses_default_with_warning(self):
        # Same robustness check for the new env var: a typo'd
        # PYDEPGATE_PEEK_MIN_LENGTH should warn but not abort.
        stderr = io.StringIO()
        clean_env = {
            k: v for k, v in os.environ.items()
            if k not in _PEEK_ENV_VARS
        }
        clean_env[ENV_PEEK_MIN_LENGTH] = "thirty-two"
        with mock.patch.dict(os.environ, clean_env, clear=True):
            parser = argparse.ArgumentParser()
            add_peek_arguments(parser, stderr=stderr)
        args = parser.parse_args([])
        self.assertEqual(args.peek_min_length, DEFAULT_MIN_LENGTH)
        self.assertIn("thirty-two", stderr.getvalue())


# ===========================================================================
# CLI overrides environment
# ===========================================================================

class CliOverridesEnvTests(unittest.TestCase):

    def test_cli_depth_overrides_env(self):
        parser = _build_parser({ENV_PEEK_DEPTH: "5"})
        args = parser.parse_args(["--peek-depth", "7"])
        self.assertEqual(args.peek_depth, 7)

    def test_cli_peek_overrides_env_disabled(self):
        parser = _build_parser({ENV_PEEK: "0"})
        args = parser.parse_args(["--peek"])
        self.assertTrue(args.peek)

    def test_cli_min_length_overrides_env(self):
        parser = _build_parser({ENV_PEEK_MIN_LENGTH: "256"})
        args = parser.parse_args(["--peek-min-length", "128"])
        self.assertEqual(args.peek_min_length, 128)


# ===========================================================================
# Validation: soft warnings
# ===========================================================================

class SoftWarningTests(unittest.TestCase):

    def test_no_warning_when_only_defaults(self):
        parser = _build_parser()
        args = parser.parse_args([])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)
        self.assertEqual(stderr.getvalue(), "")

    def test_warning_when_depth_set_without_peek(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek-depth", "5"])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)
        self.assertIn("--peek-depth", stderr.getvalue())
        self.assertIn("--peek", stderr.getvalue())

    def test_warning_when_budget_set_without_peek(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek-budget", "8192"])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)
        self.assertIn("--peek-budget", stderr.getvalue())

    def test_warning_when_min_length_set_without_peek(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek-min-length", "256"])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)
        self.assertIn("--peek-min-length", stderr.getvalue())

    def test_warning_when_chain_set_without_peek(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek-chain"])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)
        self.assertIn("--peek-chain", stderr.getvalue())

    def test_warning_lists_multiple_ignored_flags(self):
        parser = _build_parser()
        args = parser.parse_args([
            "--peek-depth", "5",
            "--peek-chain",
            "--peek-budget", "8192",
            "--peek-min-length", "256",
        ])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)
        msg = stderr.getvalue()
        self.assertIn("--peek-depth", msg)
        self.assertIn("--peek-budget", msg)
        self.assertIn("--peek-chain", msg)
        self.assertIn("--peek-min-length", msg)

    def test_no_warning_when_peek_enabled_and_tuning_set(self):
        parser = _build_parser()
        args = parser.parse_args([
            "--peek", "--peek-depth", "5", "--peek-min-length", "256",
        ])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)
        self.assertEqual(stderr.getvalue(), "")


# ===========================================================================
# Validation: hard errors
# ===========================================================================

class HardErrorTests(unittest.TestCase):

    def test_depth_zero_raises_when_peek_enabled(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek", "--peek-depth", "0"])
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            validate_peek_args(args, stderr=stderr)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("at least 1", stderr.getvalue())

    def test_depth_above_ceiling_raises(self):
        parser = _build_parser()
        args = parser.parse_args([
            "--peek", "--peek-depth", str(PEEK_DEPTH_CEILING + 1),
        ])
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            validate_peek_args(args, stderr=stderr)
        self.assertIn(str(PEEK_DEPTH_CEILING), stderr.getvalue())

    def test_budget_below_floor_raises(self):
        parser = _build_parser()
        args = parser.parse_args([
            "--peek", "--peek-budget", str(MIN_BUDGET_FLOOR - 1),
        ])
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            validate_peek_args(args, stderr=stderr)
        self.assertIn(str(MIN_BUDGET_FLOOR), stderr.getvalue())

    def test_min_length_below_floor_raises(self):
        parser = _build_parser()
        args = parser.parse_args([
            "--peek", "--peek-min-length", str(MIN_LENGTH_FLOOR - 1),
        ])
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            validate_peek_args(args, stderr=stderr)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn(str(MIN_LENGTH_FLOOR), stderr.getvalue())

    def test_min_length_at_floor_allowed(self):
        # Exactly at the floor should be accepted; the check is
        # strictly less-than.
        parser = _build_parser()
        args = parser.parse_args([
            "--peek", "--peek-min-length", str(MIN_LENGTH_FLOOR),
        ])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)  # should not raise
        self.assertEqual(stderr.getvalue(), "")

    def test_out_of_range_does_not_raise_when_peek_disabled(self):
        # When --peek is off, out-of-range values are ignored
        # entirely (no enricher will be built). They should
        # produce a soft warning, not a hard error.
        parser = _build_parser()
        args = parser.parse_args(["--peek-depth", "999"])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)  # should not raise
        self.assertIn("--peek-depth", stderr.getvalue())

    def test_min_length_below_floor_does_not_raise_when_peek_disabled(self):
        # Same: an out-of-range min_length without --peek is a soft
        # warning, not a hard error.
        parser = _build_parser()
        args = parser.parse_args(["--peek-min-length", "1"])
        stderr = io.StringIO()
        validate_peek_args(args, stderr=stderr)  # should not raise
        self.assertIn("--peek-min-length", stderr.getvalue())


# ===========================================================================
# Enricher construction
# ===========================================================================

class BuildPeekEnricherTests(unittest.TestCase):

    def test_returns_none_when_peek_disabled(self):
        parser = _build_parser()
        args = parser.parse_args([])
        self.assertIsNone(build_peek_enricher(args))

    def test_returns_configured_enricher_when_enabled(self):
        parser = _build_parser()
        args = parser.parse_args([
            "--peek", "--peek-depth", "2", "--peek-budget", "32768",
        ])
        enricher = build_peek_enricher(args)
        self.assertIsInstance(enricher, PayloadPeek)
        self.assertEqual(enricher.max_depth, 2)
        self.assertEqual(enricher.max_budget, 32768)

    def test_returns_default_enricher_when_no_tuning(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek"])
        enricher = build_peek_enricher(args)
        self.assertIsInstance(enricher, PayloadPeek)
        self.assertEqual(enricher.max_depth, DEFAULT_MAX_DEPTH)
        self.assertEqual(enricher.max_budget, DEFAULT_MAX_BUDGET)
        self.assertEqual(enricher.min_length, DEFAULT_MIN_LENGTH)

    def test_min_length_threaded_through_to_enricher(self):
        # The new flag has to actually configure the enricher, not
        # just sit in the namespace unused. This test catches
        # plumbing regressions.
        parser = _build_parser()
        args = parser.parse_args([
            "--peek", "--peek-min-length", "256",
        ])
        enricher = build_peek_enricher(args)
        self.assertIsInstance(enricher, PayloadPeek)
        self.assertEqual(enricher.min_length, 256)


# ===========================================================================
# peek_chain_enabled
# ===========================================================================

class PeekChainEnabledTests(unittest.TestCase):

    def test_false_when_peek_off(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek-chain"])
        self.assertFalse(peek_chain_enabled(args))

    def test_false_when_chain_off(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek"])
        self.assertFalse(peek_chain_enabled(args))

    def test_true_when_both_on(self):
        parser = _build_parser()
        args = parser.parse_args(["--peek", "--peek-chain"])
        self.assertTrue(peek_chain_enabled(args))


if __name__ == "__main__":
    unittest.main()