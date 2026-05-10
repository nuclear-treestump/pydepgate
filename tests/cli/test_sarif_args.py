"""Tests for pydepgate.cli.sarif_args.

Covers --sarif-srcroot parsing, the sarif_srcroot() query
helper, and validate_sarif_args() soft-warning behavior.
Mirrors the structure of test_decode_args.py.
"""

from __future__ import annotations

import argparse
import io
import os
import unittest
from unittest.mock import patch

from pydepgate.cli.command_handlers.sarif_args import (
    ENV_SARIF_SRCROOT,
    add_sarif_arguments,
    sarif_srcroot,
    validate_sarif_args,
)

# ===========================================================================
# Test helpers
# ===========================================================================


def _build_parser():
    """Build a parser with sarif args attached.

    Includes --format because validate_sarif_args reads it. Does
    NOT mark this as a subparser; that case is exercised
    separately in SubparserDefaultTests.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", default=None)
    add_sarif_arguments(parser, is_subparser=False)
    return parser


# ===========================================================================
# Argparse parsing
# ===========================================================================


class ParsingTests(unittest.TestCase):
    """Argparse parsing of --sarif-srcroot."""

    def test_default_is_none(self):
        # No flag, no env var: argparse default is None.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV_SARIF_SRCROOT, None)
            parser = _build_parser()
            args = parser.parse_args([])
        self.assertIsNone(args.sarif_srcroot)

    def test_explicit_value_with_equals(self):
        parser = _build_parser()
        args = parser.parse_args(["--sarif-srcroot=/path/to/repo"])
        self.assertEqual(args.sarif_srcroot, "/path/to/repo")

    def test_explicit_value_with_space(self):
        # `--sarif-srcroot /path/to/repo` (space-separated) is the
        # standard argparse syntax and should also work.
        parser = _build_parser()
        args = parser.parse_args(["--sarif-srcroot", "/path/to/repo"])
        self.assertEqual(args.sarif_srcroot, "/path/to/repo")

    def test_empty_string_value_parses(self):
        # argparse accepts empty string. The sarif_srcroot helper
        # converts empty to None at query time; argparse itself
        # does not.
        parser = _build_parser()
        args = parser.parse_args(["--sarif-srcroot="])
        self.assertEqual(args.sarif_srcroot, "")

    def test_env_var_provides_default(self):
        # When the env var is set and no CLI flag is given, the
        # env value becomes the default.
        with patch.dict(
            os.environ,
            {ENV_SARIF_SRCROOT: "/from/env"},
            clear=False,
        ):
            parser = _build_parser()
            args = parser.parse_args([])
        self.assertEqual(args.sarif_srcroot, "/from/env")

    def test_cli_overrides_env_var(self):
        # When both are set, the CLI flag wins.
        with patch.dict(
            os.environ,
            {ENV_SARIF_SRCROOT: "/from/env"},
            clear=False,
        ):
            parser = _build_parser()
            args = parser.parse_args(["--sarif-srcroot=/from/cli"])
        self.assertEqual(args.sarif_srcroot, "/from/cli")

    def test_empty_env_var_treated_as_unset(self):
        # _env_str treats empty strings as unset, returning the
        # default (None).
        with patch.dict(
            os.environ,
            {ENV_SARIF_SRCROOT: ""},
            clear=False,
        ):
            parser = _build_parser()
            args = parser.parse_args([])
        self.assertIsNone(args.sarif_srcroot)


# ===========================================================================
# Subparser default behavior
# ===========================================================================


class SubparserDefaultTests(unittest.TestCase):
    """argparse.SUPPRESS on subparsers prevents clobbering."""

    def test_subparser_default_is_suppress(self):
        # When called with is_subparser=True, the default should
        # be argparse.SUPPRESS so values from the top-level parser
        # survive subcommand dispatch. We test that by checking
        # that the attribute is not set when no flag is given.
        parser = argparse.ArgumentParser()
        parser.add_argument("--format", default=None)
        subparsers = parser.add_subparsers()
        sub = subparsers.add_parser("scan")
        add_sarif_arguments(sub, is_subparser=True)

        args = parser.parse_args(["scan"])
        # SUPPRESS means the attribute is not added at all when
        # the flag is absent.
        self.assertFalse(hasattr(args, "sarif_srcroot"))

    def test_top_level_value_survives_subparser(self):
        # The whole point of SUPPRESS: a value set at the top
        # level should not be overwritten by argparse when the
        # subcommand is dispatched.
        parser = argparse.ArgumentParser()
        parser.add_argument("--format", default=None)
        add_sarif_arguments(parser, is_subparser=False)
        subparsers = parser.add_subparsers()
        sub = subparsers.add_parser("scan")
        add_sarif_arguments(sub, is_subparser=True)

        args = parser.parse_args(["--sarif-srcroot=/from/top", "scan"])
        self.assertEqual(args.sarif_srcroot, "/from/top")


# ===========================================================================
# sarif_srcroot helper
# ===========================================================================


class HelperTests(unittest.TestCase):
    """sarif_srcroot() query helper behavior."""

    def test_returns_none_when_attr_missing(self):
        # When SUPPRESS was the default and the flag was not
        # given, the namespace has no sarif_srcroot attribute.
        ns = argparse.Namespace()
        self.assertIsNone(sarif_srcroot(ns))

    def test_returns_none_when_value_is_none(self):
        ns = argparse.Namespace(sarif_srcroot=None)
        self.assertIsNone(sarif_srcroot(ns))

    def test_returns_none_when_value_is_empty_string(self):
        # Empty string treated as unset, consistent with how
        # decode_archive_password handles the empty-string case.
        ns = argparse.Namespace(sarif_srcroot="")
        self.assertIsNone(sarif_srcroot(ns))

    def test_returns_value_when_set(self):
        ns = argparse.Namespace(sarif_srcroot="/path/to/repo")
        self.assertEqual(sarif_srcroot(ns), "/path/to/repo")


# ===========================================================================
# validate_sarif_args
# ===========================================================================


class ValidationTests(unittest.TestCase):
    """validate_sarif_args() soft-warning behavior."""

    def test_no_warning_when_unset(self):
        ns = argparse.Namespace(format=None, sarif_srcroot=None)
        stderr = io.StringIO()
        validate_sarif_args(ns, stderr=stderr)
        self.assertEqual(stderr.getvalue(), "")

    def test_no_warning_when_unset_and_format_is_sarif(self):
        ns = argparse.Namespace(format="sarif", sarif_srcroot=None)
        stderr = io.StringIO()
        validate_sarif_args(ns, stderr=stderr)
        self.assertEqual(stderr.getvalue(), "")

    def test_no_warning_when_set_and_format_is_sarif(self):
        # Happy path: srcroot is meaningful with --format sarif.
        ns = argparse.Namespace(format="sarif", sarif_srcroot="/path/to/repo")
        stderr = io.StringIO()
        validate_sarif_args(ns, stderr=stderr)
        self.assertEqual(stderr.getvalue(), "")

    def test_warning_when_set_and_format_is_json(self):
        ns = argparse.Namespace(format="json", sarif_srcroot="/path/to/repo")
        stderr = io.StringIO()
        validate_sarif_args(ns, stderr=stderr)
        output = stderr.getvalue()
        self.assertIn("--sarif-srcroot", output)
        self.assertIn("not 'sarif'", output)

    def test_warning_when_set_and_format_is_human(self):
        ns = argparse.Namespace(format="human", sarif_srcroot="/path/to/repo")
        stderr = io.StringIO()
        validate_sarif_args(ns, stderr=stderr)
        self.assertIn("warning", stderr.getvalue().lower())

    def test_warning_when_set_and_format_is_none(self):
        # format may be None at validate time (CI defaults run
        # later). The warning fires because format is not yet
        # 'sarif'. This is intentional: a user setting srcroot
        # without --format=sarif sees the warning regardless of
        # how the format was meant to be defaulted.
        ns = argparse.Namespace(format=None, sarif_srcroot="/path/to/repo")
        stderr = io.StringIO()
        validate_sarif_args(ns, stderr=stderr)
        self.assertIn("--sarif-srcroot", stderr.getvalue())

    def test_warning_says_value_will_be_ignored(self):
        # The user needs to understand the consequence of the
        # mismatched flag combination.
        ns = argparse.Namespace(format="json", sarif_srcroot="/path/to/repo")
        stderr = io.StringIO()
        validate_sarif_args(ns, stderr=stderr)
        self.assertIn("ignored", stderr.getvalue().lower())

    def test_empty_string_does_not_trigger_warning(self):
        # Empty string is treated as unset by sarif_srcroot(),
        # so no warning fires. This matches the contract that
        # empty == unset.
        ns = argparse.Namespace(format="json", sarif_srcroot="")
        stderr = io.StringIO()
        validate_sarif_args(ns, stderr=stderr)
        self.assertEqual(stderr.getvalue(), "")

    def test_uses_sys_stderr_by_default(self):
        # When the stderr kwarg is not provided, sys.stderr is
        # used. We patch sys.stderr to verify.
        ns = argparse.Namespace(format="json", sarif_srcroot="/path/to/repo")
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            validate_sarif_args(ns)
        self.assertIn("--sarif-srcroot", stderr_capture.getvalue())

    def test_no_hard_errors_raised(self):
        # All validation paths are advisory; none should raise.
        # This test exercises the most-likely-to-error case
        # (everything set, mismatched format) and confirms no
        # SystemExit.
        ns = argparse.Namespace(format="json", sarif_srcroot="/path/to/repo")
        stderr = io.StringIO()
        # If the function raises, the test fails immediately.
        validate_sarif_args(ns, stderr=stderr)


if __name__ == "__main__":
    unittest.main()
