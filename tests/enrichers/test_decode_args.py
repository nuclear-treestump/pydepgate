"""
Tests for the tristate --decode-iocs flag and supporting helpers.

These can be merged into an existing tests/cli/test_decode_args.py
or run stand-alone. They exercise the new behavior added when the
boolean --decode-iocs was replaced with a tristate.

Coverage:
    - Tristate parsing (off, hashes, full, bare).
    - Bare form is recorded as deprecated via _decode_iocs_was_bare.
    - Helpers: decode_iocs_mode, decode_extract_iocs,
      decode_archive_password, decode_archive_compression.
    - Validation: hashes/full requires --peek (hard error).
    - Validation: bare form fires deprecation notice (soft warning).
    - Validation: archive flags warn when iocs != full.
    - Env var ENV_DECODE_IOCS handled correctly.
    - Invalid env var falls back to default with warning.
"""

from __future__ import annotations

import argparse
import io
import os
import unittest
from unittest.mock import patch

from pydepgate.cli.decode_args import (
    DECODE_IOCS_FULL,
    DECODE_IOCS_HASHES,
    DECODE_IOCS_OFF,
    DEFAULT_ARCHIVE_PASSWORD,
    DEFAULT_DECODE_IOCS,
    ENV_DECODE_ARCHIVE_PASSWORD,
    ENV_DECODE_IOCS,
    add_decode_arguments,
    decode_archive_compression,
    decode_archive_password,
    decode_extract_iocs,
    decode_iocs_mode,
    validate_decode_args,
)


def _build_parser(stderr=None):
    """Build a parser with the decode args attached. Adds --peek too
    because validation references it. add_decode_arguments installs
    --decode-payload-depth itself; the test helper does not duplicate it.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--peek", action="store_true")
    add_decode_arguments(parser, is_subparser=False, stderr=stderr or io.StringIO())
    return parser


class TristateParsingTests(unittest.TestCase):

    def test_default_is_off(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV_DECODE_IOCS, None)
            parser = _build_parser()
            args = parser.parse_args([])
        self.assertEqual(args.decode_iocs, DECODE_IOCS_OFF)
        self.assertFalse(getattr(args, "_decode_iocs_was_bare", False))

    def test_explicit_off(self):
        parser = _build_parser()
        args = parser.parse_args(["--decode-iocs=off"])
        self.assertEqual(args.decode_iocs, DECODE_IOCS_OFF)
        self.assertFalse(args._decode_iocs_was_bare)

    def test_explicit_hashes(self):
        parser = _build_parser()
        args = parser.parse_args(["--decode-iocs=hashes"])
        self.assertEqual(args.decode_iocs, DECODE_IOCS_HASHES)
        self.assertFalse(args._decode_iocs_was_bare)

    def test_explicit_full(self):
        parser = _build_parser()
        args = parser.parse_args(["--decode-iocs=full"])
        self.assertEqual(args.decode_iocs, DECODE_IOCS_FULL)
        self.assertFalse(args._decode_iocs_was_bare)

    def test_bare_form_maps_to_hashes_and_records_deprecation(self):
        parser = _build_parser()
        args = parser.parse_args(["--decode-iocs"])
        self.assertEqual(args.decode_iocs, DECODE_IOCS_HASHES)
        self.assertTrue(args._decode_iocs_was_bare)

    def test_invalid_value_exits(self):
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--decode-iocs=banana"])

    def test_space_separated_value_works(self):
        # `--decode-iocs hashes` (space) should also parse.
        parser = _build_parser()
        args = parser.parse_args(["--decode-iocs", "hashes"])
        self.assertEqual(args.decode_iocs, DECODE_IOCS_HASHES)


class HelperFunctionTests(unittest.TestCase):

    def test_decode_iocs_mode_returns_off_by_default(self):
        ns = argparse.Namespace()
        self.assertEqual(decode_iocs_mode(ns), DECODE_IOCS_OFF)

    def test_decode_iocs_mode_returns_set_value(self):
        ns = argparse.Namespace(decode_iocs="hashes")
        self.assertEqual(decode_iocs_mode(ns), "hashes")

    def test_decode_iocs_mode_falls_back_on_invalid(self):
        # Defensive against downstream mutation.
        ns = argparse.Namespace(decode_iocs="garbage")
        self.assertEqual(decode_iocs_mode(ns), DECODE_IOCS_OFF)

    def test_decode_extract_iocs_off_returns_false(self):
        ns = argparse.Namespace(decode_iocs="off")
        self.assertFalse(decode_extract_iocs(ns))

    def test_decode_extract_iocs_hashes_returns_true(self):
        ns = argparse.Namespace(decode_iocs="hashes")
        self.assertTrue(decode_extract_iocs(ns))

    def test_decode_extract_iocs_full_returns_true(self):
        ns = argparse.Namespace(decode_iocs="full")
        self.assertTrue(decode_extract_iocs(ns))

    def test_decode_archive_password_default(self):
        ns = argparse.Namespace()
        self.assertEqual(
            decode_archive_password(ns), DEFAULT_ARCHIVE_PASSWORD,
        )

    def test_decode_archive_password_custom(self):
        ns = argparse.Namespace(decode_archive_password="custom-pw")
        self.assertEqual(decode_archive_password(ns), "custom-pw")

    def test_decode_archive_password_empty_string_treated_as_default(self):
        ns = argparse.Namespace(decode_archive_password="")
        self.assertEqual(
            decode_archive_password(ns), DEFAULT_ARCHIVE_PASSWORD,
        )

    def test_decode_archive_password_none_treated_as_default(self):
        ns = argparse.Namespace(decode_archive_password=None)
        self.assertEqual(
            decode_archive_password(ns), DEFAULT_ARCHIVE_PASSWORD,
        )

    def test_decode_archive_compression_default_deflate(self):
        ns = argparse.Namespace()
        self.assertEqual(decode_archive_compression(ns), "deflate")

    def test_decode_archive_compression_stored_when_flag_set(self):
        ns = argparse.Namespace(decode_archive_stored=True)
        self.assertEqual(decode_archive_compression(ns), "stored")


class ValidationTests(unittest.TestCase):

    def test_hashes_without_peek_hard_errors(self):
        # Hashes mode without --peek is a hard error (IOC extraction
        # depends on peek output).
        ns = argparse.Namespace(
            peek=False,
            decode_payload_depth=-1,
            decode_location=None,
            decode_format="text",
            decode_iocs="hashes",
            decode_archive_password=DEFAULT_ARCHIVE_PASSWORD,
            decode_archive_stored=False,
            _decode_iocs_was_bare=False,
        )
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as cm:
            validate_decode_args(ns, stderr=stderr)
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("--decode-iocs=hashes requires --peek", stderr.getvalue())

    def test_full_without_peek_hard_errors(self):
        ns = argparse.Namespace(
            peek=False,
            decode_payload_depth=-1,
            decode_location=None,
            decode_format="text",
            decode_iocs="full",
            decode_archive_password=DEFAULT_ARCHIVE_PASSWORD,
            decode_archive_stored=False,
            _decode_iocs_was_bare=False,
        )
        stderr = io.StringIO()
        with self.assertRaises(SystemExit):
            validate_decode_args(ns, stderr=stderr)
        self.assertIn("--decode-iocs=full requires --peek", stderr.getvalue())

    def test_off_without_peek_passes(self):
        # Off + no peek + no depth: nothing happens, no errors.
        ns = argparse.Namespace(
            peek=False,
            decode_payload_depth=-1,
            decode_location=None,
            decode_format="text",
            decode_iocs="off",
            decode_archive_password=DEFAULT_ARCHIVE_PASSWORD,
            decode_archive_stored=False,
            _decode_iocs_was_bare=False,
        )
        stderr = io.StringIO()
        validate_decode_args(ns, stderr=stderr)
        # No SystemExit. Note depth was not enabled either, so no
        # warnings fire about unused flags.

    def test_bare_form_emits_deprecation_warning(self):
        # The bare form should emit a deprecation notice on stderr,
        # but is not a hard error by itself (it's still functional).
        ns = argparse.Namespace(
            peek=True,
            decode_payload_depth=3,
            decode_location=None,
            decode_format="text",
            decode_iocs="hashes",
            decode_archive_password=DEFAULT_ARCHIVE_PASSWORD,
            decode_archive_stored=False,
            _decode_iocs_was_bare=True,
        )
        stderr = io.StringIO()
        validate_decode_args(ns, stderr=stderr)
        self.assertIn("deprecated", stderr.getvalue().lower())
        self.assertIn("--decode-iocs=hashes", stderr.getvalue())

    def test_archive_password_warning_when_iocs_not_full(self):
        # --decode-archive-password is meaningless unless full mode.
        ns = argparse.Namespace(
            peek=True,
            decode_payload_depth=3,
            decode_location=None,
            decode_format="text",
            decode_iocs="hashes",
            decode_archive_password="custom-pw",  # set
            decode_archive_stored=False,
            _decode_iocs_was_bare=False,
        )
        stderr = io.StringIO()
        validate_decode_args(ns, stderr=stderr)
        self.assertIn("--decode-archive-password", stderr.getvalue())
        self.assertIn("no effect", stderr.getvalue())

    def test_archive_stored_warning_when_iocs_not_full(self):
        ns = argparse.Namespace(
            peek=True,
            decode_payload_depth=3,
            decode_location=None,
            decode_format="text",
            decode_iocs="off",
            decode_archive_password=DEFAULT_ARCHIVE_PASSWORD,
            decode_archive_stored=True,
            _decode_iocs_was_bare=False,
        )
        stderr = io.StringIO()
        validate_decode_args(ns, stderr=stderr)
        # Archive flags warning fires (because off mode).
        # Plus the disabled-path warning fires too because depth is enabled
        # but iocs is off, AND we have archive flags set.
        # Either way, stderr should mention --decode-archive-stored.
        self.assertIn("--decode-archive-stored", stderr.getvalue())

    def test_full_mode_archive_flags_no_warning(self):
        # In full mode, archive flags are valid; no warning.
        ns = argparse.Namespace(
            peek=True,
            decode_payload_depth=3,
            decode_location=None,
            decode_format="text",
            decode_iocs="full",
            decode_archive_password="custom-pw",
            decode_archive_stored=True,
            _decode_iocs_was_bare=False,
        )
        stderr = io.StringIO()
        validate_decode_args(ns, stderr=stderr)
        self.assertEqual(stderr.getvalue(), "")

    def test_iocs_set_without_depth_warns(self):
        # Depth disabled but iocs set: warn that the flag has no effect.
        # Only valid combination here is iocs=off (since hashes/full
        # without peek is a hard error and we're testing depth-disabled
        # but peek is irrelevant to that path).
        # Actually, we need iocs != off AND peek enabled (so the
        # iocs-without-peek hard error doesn't fire) AND depth disabled.
        ns = argparse.Namespace(
            peek=True,  # peek on so iocs!=off doesn't hard-error
            decode_payload_depth=-1,  # depth disabled
            decode_location=None,
            decode_format="text",
            decode_iocs="hashes",
            decode_archive_password=DEFAULT_ARCHIVE_PASSWORD,
            decode_archive_stored=False,
            _decode_iocs_was_bare=False,
        )
        stderr = io.StringIO()
        validate_decode_args(ns, stderr=stderr)
        self.assertIn("--decode-iocs=hashes", stderr.getvalue())
        self.assertIn("no effect", stderr.getvalue())


class EnvVarHandlingTests(unittest.TestCase):

    def test_env_var_sets_default(self):
        with patch.dict(os.environ, {ENV_DECODE_IOCS: "full"}, clear=False):
            parser = _build_parser()
            args = parser.parse_args([])
        # Default applies because no CLI flag was given.
        self.assertEqual(args.decode_iocs, "full")

    def test_invalid_env_var_falls_back_to_default(self):
        stderr = io.StringIO()
        with patch.dict(os.environ, {ENV_DECODE_IOCS: "garbage"}, clear=False):
            parser = _build_parser(stderr=stderr)
            args = parser.parse_args([])
        self.assertEqual(args.decode_iocs, DEFAULT_DECODE_IOCS)
        self.assertIn("not a valid mode", stderr.getvalue())

    def test_cli_overrides_env(self):
        with patch.dict(os.environ, {ENV_DECODE_IOCS: "full"}, clear=False):
            parser = _build_parser()
            args = parser.parse_args(["--decode-iocs=off"])
        self.assertEqual(args.decode_iocs, "off")

    def test_archive_password_env_var(self):
        with patch.dict(
            os.environ,
            {ENV_DECODE_ARCHIVE_PASSWORD: "env-password"},
            clear=False,
        ):
            parser = _build_parser()
            args = parser.parse_args([])
        self.assertEqual(args.decode_archive_password, "env-password")


if __name__ == "__main__":
    unittest.main()