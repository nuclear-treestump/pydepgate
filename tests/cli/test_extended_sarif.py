"""Tests for SARIF CLI integration.

Three test classes:

  SarifScanModeTests
      Unit tests for _sarif_scan_mode, the helper that builds
      the automationDetails.id scan-mode segment from
      ScanResult.artifact_kind plus the --deep flag.

  ComputeDecodedTreeTests
      Unit tests for _compute_decoded_tree, the helper that
      runs decode_payloads and applies the --min-severity
      filter. Mocks decode_payloads and filter_tree_by_severity
      to isolate the helper's branching behavior.

  SarifIntegrationTests
      End-to-end tests using subprocess (_run_cli). Verifies
      that --sarif-srcroot, --decode-payload-depth, and the
      env-var equivalents propagate correctly into the emitted
      SARIF document. Uses 'pip' as the target because it is
      always installed and produces a clean scan.

The integration tests duplicate _run_cli locally rather than
importing from tests.cli.test_dispatch to keep this file
self-contained. Ikari may merge them into the existing
SarifFormatTests class in test_dispatch.py.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from pydepgate.cli.subcommands.scan import (
    _compute_decoded_tree,
    _sarif_scan_mode,
)
from pydepgate.engines.base import ArtifactKind

# ===========================================================================
# Test helpers (shared across classes)
# ===========================================================================


def _run_cli(args, env=None, timeout=15):
    """Run pydepgate CLI in a subprocess.

    Mirrors the helper in tests/cli/test_dispatch.py. Strips
    any pydepgate-related env vars so tests are deterministic;
    explicit env kwarg merges in afterwards.
    """
    base_env = os.environ.copy()
    for k in list(base_env.keys()):
        if k.startswith("PYDEPGATE_") or k == "NO_COLOR":
            del base_env[k]
    if env:
        base_env.update(env)
    result = subprocess.run(
        [sys.executable, "-m", "pydepgate"] + list(args),
        capture_output=True,
        text=True,
        env=base_env,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _make_args(
    *,
    decode_payload_depth: int = 3,
    peek_min_length: int = 32,
    peek_depth: int = 4,
    peek_budget: int = 4_000_000,
    decode_iocs: str = "off",
    min_severity: str | None = None,
    deep: bool = False,
) -> argparse.Namespace:
    """Build a Namespace sufficient for _compute_decoded_tree.

    decode_payloads is mocked in these tests so the values are
    forwarded but not consumed; min_severity and deep are
    consumed by the helper logic.
    """
    return argparse.Namespace(
        decode_payload_depth=decode_payload_depth,
        peek_min_length=peek_min_length,
        peek_depth=peek_depth,
        peek_budget=peek_budget,
        decode_iocs=decode_iocs,
        min_severity=min_severity,
        deep=deep,
    )


def _fake_result(
    *,
    identity: str = "test.whl",
    artifact_kind: ArtifactKind = ArtifactKind.WHEEL,
) -> SimpleNamespace:
    """Minimal ScanResult-like object for the helpers under test."""
    return SimpleNamespace(
        artifact_identity=identity,
        artifact_kind=artifact_kind,
        findings=[],
    )


# ===========================================================================
# _sarif_scan_mode
# ===========================================================================


class SarifScanModeTests(unittest.TestCase):
    """_sarif_scan_mode combines artifact_kind with --deep."""

    def test_returns_none_when_deep_false(self):
        # Without --deep, return None so the SARIF assembler
        # defaults to artifact_kind.value alone.
        result = _fake_result(artifact_kind=ArtifactKind.WHEEL)
        args = _make_args(deep=False)
        self.assertIsNone(_sarif_scan_mode(result, args))

    def test_returns_wheel_deep_for_deep_wheel(self):
        result = _fake_result(artifact_kind=ArtifactKind.WHEEL)
        args = _make_args(deep=True)
        self.assertEqual(_sarif_scan_mode(result, args), "wheel_deep")

    def test_returns_sdist_deep_for_deep_sdist(self):
        result = _fake_result(artifact_kind=ArtifactKind.SDIST)
        args = _make_args(deep=True)
        self.assertEqual(_sarif_scan_mode(result, args), "sdist_deep")

    def test_returns_installed_env_deep_for_deep_installed(self):
        # Per Q2/Q6 reasoning: enum values verbatim, suffixed
        # with _deep. So 'installed_env_deep', not 'installed_deep'.
        result = _fake_result(artifact_kind=ArtifactKind.INSTALLED_ENV)
        args = _make_args(deep=True)
        self.assertEqual(_sarif_scan_mode(result, args), "installed_env_deep")

    def test_handles_missing_deep_attr_gracefully(self):
        # A namespace without args.deep returns None (treated as
        # not-deep). This protects against subcommands that do
        # not register --deep.
        result = _fake_result(artifact_kind=ArtifactKind.WHEEL)
        args = argparse.Namespace()
        self.assertIsNone(_sarif_scan_mode(result, args))


# ===========================================================================
# _compute_decoded_tree
# ===========================================================================


class ComputeDecodedTreeTests(unittest.TestCase):
    """_compute_decoded_tree wraps decode_payloads and filter."""

    def test_returns_tree_on_success(self):
        sentinel_tree = SimpleNamespace(nodes=())
        with patch(
            "pydepgate.cli.subcommands.scan.decode_payloads",
            return_value=sentinel_tree,
        ):
            args = _make_args(min_severity=None)
            result = _compute_decoded_tree(_fake_result(), engine=Mock(), args=args)
        self.assertIs(result, sentinel_tree)

    def test_returns_none_on_decode_exception(self):
        # Failures are non-fatal: stderr warning, return None.
        with patch(
            "pydepgate.cli.subcommands.scan.decode_payloads",
            side_effect=RuntimeError("decode broke"),
        ):
            args = _make_args()
            stderr_capture = io.StringIO()
            with patch("sys.stderr", stderr_capture):
                result = _compute_decoded_tree(_fake_result(), engine=Mock(), args=args)
        self.assertIsNone(result)

    def test_writes_warning_on_decode_exception(self):
        with patch(
            "pydepgate.cli.subcommands.scan.decode_payloads",
            side_effect=RuntimeError("decode broke"),
        ):
            args = _make_args()
            stderr_capture = io.StringIO()
            with patch("sys.stderr", stderr_capture):
                _compute_decoded_tree(_fake_result(), engine=Mock(), args=args)
        output = stderr_capture.getvalue()
        self.assertIn("warning", output.lower())
        self.assertIn("decoded-payload pass failed", output)

    def test_warning_includes_exception_type_and_message(self):
        # Helps the user diagnose why decode failed.
        with patch(
            "pydepgate.cli.subcommands.scan.decode_payloads",
            side_effect=ValueError("specific reason"),
        ):
            args = _make_args()
            stderr_capture = io.StringIO()
            with patch("sys.stderr", stderr_capture):
                _compute_decoded_tree(_fake_result(), engine=Mock(), args=args)
        output = stderr_capture.getvalue()
        self.assertIn("ValueError", output)
        self.assertIn("specific reason", output)

    def test_applies_min_severity_filter_when_set(self):
        raw_tree = SimpleNamespace(nodes=("raw",))
        filtered_tree = SimpleNamespace(nodes=("filtered",))
        with patch(
            "pydepgate.cli.subcommands.scan.decode_payloads",
            return_value=raw_tree,
        ):
            with patch(
                "pydepgate.cli.subcommands.scan.filter_tree_by_severity",
                return_value=filtered_tree,
            ) as mock_filter:
                args = _make_args(min_severity="high")
                result = _compute_decoded_tree(_fake_result(), engine=Mock(), args=args)
        # Filter was called with the raw tree and the threshold.
        mock_filter.assert_called_once_with(raw_tree, "high")
        # The returned tree is the filter's output, not the raw.
        self.assertIs(result, filtered_tree)

    def test_does_not_apply_filter_when_min_severity_unset(self):
        # When min_severity is None (the default), the filter
        # should not be called.
        raw_tree = SimpleNamespace(nodes=("raw",))
        with patch(
            "pydepgate.cli.subcommands.scan.decode_payloads",
            return_value=raw_tree,
        ):
            with patch(
                "pydepgate.cli.subcommands.scan.filter_tree_by_severity"
            ) as mock_filter:
                args = _make_args(min_severity=None)
                result = _compute_decoded_tree(_fake_result(), engine=Mock(), args=args)
        mock_filter.assert_not_called()
        self.assertIs(result, raw_tree)

    def test_decode_payloads_receives_correct_kwargs(self):
        # The forward call should pass through the depth, peek
        # config, and extract_iocs from the args.
        with patch(
            "pydepgate.cli.subcommands.scan.decode_payloads",
            return_value=SimpleNamespace(nodes=()),
        ) as mock_decode:
            args = _make_args(
                decode_payload_depth=5,
                peek_min_length=64,
                peek_depth=6,
                peek_budget=1_000_000,
                decode_iocs="hashes",
            )
            _compute_decoded_tree(_fake_result(), engine=Mock(), args=args)
        # decode_payloads should have been called with the values
        # from args. extract_iocs is True because mode is hashes.
        kwargs = mock_decode.call_args.kwargs
        self.assertEqual(kwargs["max_depth"], 5)
        self.assertEqual(kwargs["peek_min_length"], 64)
        self.assertEqual(kwargs["peek_max_depth"], 6)
        self.assertEqual(kwargs["peek_max_budget"], 1_000_000)
        self.assertTrue(kwargs["extract_iocs"])

    def test_extract_iocs_false_when_mode_is_off(self):
        with patch(
            "pydepgate.cli.subcommands.scan.decode_payloads",
            return_value=SimpleNamespace(nodes=()),
        ) as mock_decode:
            args = _make_args(decode_iocs="off")
            _compute_decoded_tree(_fake_result(), engine=Mock(), args=args)
        self.assertFalse(mock_decode.call_args.kwargs["extract_iocs"])


# ===========================================================================
# SARIF integration via subprocess
# ===========================================================================


class SarifIntegrationTests(unittest.TestCase):
    """End-to-end tests of the new flag plumbing."""

    def test_sarif_with_srcroot_propagates_to_uri_base_ids(self):
        # --sarif-srcroot should appear in the SARIF document at
        # originalUriBaseIds.PROJECTROOT.uri.
        rc, out, err = _run_cli(
            [
                "scan",
                "pip",
                "--format",
                "sarif",
                "--sarif-srcroot=/test/repo",
            ]
        )
        self.assertEqual(rc, 0, msg=f"stderr: {err}")
        payload = json.loads(out)
        self.assertEqual(
            payload["runs"][0]["originalUriBaseIds"]["PROJECTROOT"]["uri"],
            "/test/repo",
        )

    def test_sarif_srcroot_via_env_var(self):
        # PYDEPGATE_SARIF_SRCROOT should also work.
        rc, out, err = _run_cli(
            ["scan", "pip", "--format", "sarif"],
            env={"PYDEPGATE_SARIF_SRCROOT": "/from/env"},
        )
        self.assertEqual(rc, 0, msg=f"stderr: {err}")
        payload = json.loads(out)
        self.assertEqual(
            payload["runs"][0]["originalUriBaseIds"]["PROJECTROOT"]["uri"],
            "/from/env",
        )

    def test_sarif_srcroot_cli_overrides_env_var(self):
        rc, out, err = _run_cli(
            [
                "scan",
                "pip",
                "--format",
                "sarif",
                "--sarif-srcroot=/from/cli",
            ],
            env={"PYDEPGATE_SARIF_SRCROOT": "/from/env"},
        )
        self.assertEqual(rc, 0, msg=f"stderr: {err}")
        payload = json.loads(out)
        self.assertEqual(
            payload["runs"][0]["originalUriBaseIds"]["PROJECTROOT"]["uri"],
            "/from/cli",
        )

    def test_srcroot_warning_when_format_is_json(self):
        # Soft warning: scan completes, exit 0, stderr contains
        # the warning text.
        rc, out, err = _run_cli(
            [
                "scan",
                "pip",
                "--format",
                "json",
                "--sarif-srcroot=/test/repo",
            ]
        )
        self.assertEqual(rc, 0, msg=f"stderr: {err}")
        self.assertIn("--sarif-srcroot", err)
        self.assertIn("not 'sarif'", err)

    def test_srcroot_no_warning_when_format_is_sarif(self):
        # The flag is meaningful here, so no warning.
        rc, out, err = _run_cli(
            [
                "scan",
                "pip",
                "--format",
                "sarif",
                "--sarif-srcroot=/test/repo",
            ]
        )
        self.assertEqual(rc, 0, msg=f"stderr: {err}")
        self.assertNotIn("--sarif-srcroot", err)

    def test_sarif_clean_scan_uri_is_empty_placeholder(self):
        # Without --sarif-srcroot, the PROJECTROOT entry carries
        # the empty placeholder URI.
        rc, out, err = _run_cli(
            [
                "scan",
                "pip",
                "--format",
                "sarif",
            ]
        )
        self.assertEqual(rc, 0, msg=f"stderr: {err}")
        payload = json.loads(out)
        self.assertEqual(
            payload["runs"][0]["originalUriBaseIds"]["PROJECTROOT"]["uri"],
            "",
        )

    def test_sarif_clean_scan_automation_details(self):
        # pip is an installed package, so artifact_kind is
        # INSTALLED_ENV. Without --deep, scan_mode is just the
        # enum value.
        rc, out, err = _run_cli(
            [
                "scan",
                "pip",
                "--format",
                "sarif",
            ]
        )
        self.assertEqual(rc, 0, msg=f"stderr: {err}")
        payload = json.loads(out)
        self.assertEqual(
            payload["runs"][0]["automationDetails"]["id"],
            "pydepgate/installed_env/",
        )

    def test_sarif_with_decode_payload_runs_cleanly(self):
        # pip has no payload-bearing findings, so decode_tree
        # will be empty. We verify the combination does not
        # crash and produces valid SARIF.
        rc, out, err = _run_cli(
            [
                "scan",
                "pip",
                "--format",
                "sarif",
                "--peek",
                "--decode-payload-depth=3",
            ]
        )
        self.assertEqual(rc, 0, msg=f"stderr: {err}")
        payload = json.loads(out)
        self.assertIn("$schema", payload)
        self.assertIn("runs", payload)
        # No codeFlows expected (no payload findings) but the
        # document should still be well-formed.
        self.assertIsInstance(payload["runs"][0]["results"], list)


if __name__ == "__main__":
    unittest.main()
