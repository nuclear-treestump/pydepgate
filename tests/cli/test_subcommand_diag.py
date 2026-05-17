"""
Tests for CLI-diagnostic threading in the scan subcommand.

Covers _empty_result_with_diag's initial_diagnostics handling and
_dispatch_single's pre-engine error paths. The engine-side threading
is covered separately in test_engine_initial_diagnostics.py.
"""

import unittest
from pathlib import Path

from pydepgate.cli.subcommands.scan import (
    _dispatch_single,
    _empty_result_with_diag,
)

_CLI_DIAGS = ("warning: synthetic CLI warning",)


class EmptyResultWithDiagTests(unittest.TestCase):

    def test_no_initial_diags_default_unchanged(self):
        # Default behavior preserved: empty initial_diagnostics
        # produces a single-element diagnostics tuple.
        result = _empty_result_with_diag(
            Path("/tmp/nonexistent.py"),
            "file not found",
        )
        self.assertEqual(result.diagnostics, ("file not found",))

    def test_initial_diags_prepended(self):
        result = _empty_result_with_diag(
            Path("/tmp/nonexistent.py"),
            "file not found",
            initial_diagnostics=_CLI_DIAGS,
        )
        self.assertEqual(
            result.diagnostics,
            _CLI_DIAGS + ("file not found",),
        )


class DispatchSingleErrorPathTests(unittest.TestCase):
    """The pre-engine error paths in _dispatch_single thread diagnostics."""

    def test_missing_path_includes_initial_diagnostics(self):
        # _dispatch_single never reaches the engine when the file
        # is missing, so threading happens via _empty_result_with_diag.
        result = _dispatch_single(
            engine=None,  # never called when file missing
            path_str="/definitely/does/not/exist/file.py",
            as_kind=None,
            initial_diagnostics=_CLI_DIAGS,
        )
        self.assertEqual(result.diagnostics[0], _CLI_DIAGS[0])
        self.assertIn("file not found", result.diagnostics[-1])

    def test_missing_path_default_no_diagnostics(self):
        # Without initial_diagnostics, behavior is unchanged.
        result = _dispatch_single(
            engine=None,
            path_str="/definitely/does/not/exist/file.py",
            as_kind=None,
        )
        self.assertEqual(len(result.diagnostics), 1)
        self.assertIn("file not found", result.diagnostics[0])


if __name__ == "__main__":
    unittest.main()
