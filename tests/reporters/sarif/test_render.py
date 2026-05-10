"""Tests for the public SARIF render() function.

Replaces the prior test_render_placeholder.py: that file
covered the placeholder body that lived inline in
__init__.py before Phase E. After Phase E, render() is a
thin wrapper that calls assemble_document() and falls back
to assemble_fallback_document() on exceptions. These tests
exercise both paths plus the package-level constant
re-exports.
"""

from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from pydepgate.engines.base import (
    ArtifactKind,
    ScanResult,
    ScanStatistics,
)
from pydepgate.reporters.sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_INFORMATION_URI,
    TOOL_NAME,
    TOOL_ORGANIZATION,
    render,
)

# ===========================================================================
# Fixtures
# ===========================================================================


def _empty_scan_result() -> ScanResult:
    """Construct an empty ScanResult sufficient for render().

    All required fields populated with sensible defaults; no
    findings, no diagnostics, no suppressions. The artifact_kind
    defaults to WHEEL so automationDetails.id is predictable in
    tests that assert it.
    """
    return ScanResult(
        artifact_identity="test.whl",
        artifact_kind=ArtifactKind.WHEEL,
        findings=(),
        skipped=(),
        statistics=ScanStatistics(),
    )


# ===========================================================================
# Constants are accessible at package level
# ===========================================================================


class TestPackageConstants(unittest.TestCase):
    """Tool-identity constants are importable from pydepgate.reporters.sarif.

    The constants live in _constants.py and are re-imported into
    __init__.py at package load time. Tests and downstream code
    consume them via the package-level imports for backward
    compatibility with the pre-Phase-E layout.
    """

    def test_tool_name_is_pydepgate(self):
        self.assertEqual(TOOL_NAME, "pydepgate")

    def test_tool_organization(self):
        self.assertEqual(TOOL_ORGANIZATION, "Nuclear Treestump")

    def test_tool_information_uri(self):
        self.assertEqual(
            TOOL_INFORMATION_URI,
            "https://github.com/nuclear-treestump/pydepgate",
        )

    def test_sarif_version(self):
        self.assertEqual(SARIF_VERSION, "2.1.0")

    def test_sarif_schema_uri(self):
        self.assertEqual(
            SARIF_SCHEMA_URI,
            "https://json.schemastore.org/sarif-2.1.0.json",
        )


# ===========================================================================
# Happy path: render() produces valid SARIF
# ===========================================================================


class TestRenderHappyPath(unittest.TestCase):
    """Calling render() with valid inputs writes valid SARIF."""

    def _render_and_parse(self, **kwargs) -> dict:
        """Helper: render to a StringIO and parse the result."""
        stream = io.StringIO()
        render(
            result=_empty_scan_result(),
            decoded_tree=None,
            stream=stream,
            **kwargs,
        )
        return json.loads(stream.getvalue())

    def test_output_is_valid_json(self):
        document = self._render_and_parse()
        self.assertIsInstance(document, dict)

    def test_output_ends_with_newline(self):
        stream = io.StringIO()
        render(
            result=_empty_scan_result(),
            decoded_tree=None,
            stream=stream,
        )
        self.assertTrue(stream.getvalue().endswith("\n"))

    def test_output_has_schema(self):
        document = self._render_and_parse()
        self.assertEqual(document["$schema"], SARIF_SCHEMA_URI)

    def test_output_has_version(self):
        document = self._render_and_parse()
        self.assertEqual(document["version"], "2.1.0")

    def test_tool_driver_name_is_pydepgate(self):
        document = self._render_and_parse()
        self.assertEqual(
            document["runs"][0]["tool"]["driver"]["name"],
            "pydepgate",
        )

    def test_results_array_present(self):
        document = self._render_and_parse()
        self.assertIn("results", document["runs"][0])
        self.assertEqual(document["runs"][0]["results"], [])

    def test_invocation_marked_successful(self):
        document = self._render_and_parse()
        invocation = document["runs"][0]["invocations"][0]
        self.assertEqual(invocation["executionSuccessful"], True)

    def test_automation_details_for_wheel(self):
        document = self._render_and_parse()
        self.assertEqual(
            document["runs"][0]["automationDetails"]["id"],
            "pydepgate/wheel/",
        )

    def test_original_uri_base_ids_present(self):
        document = self._render_and_parse()
        self.assertIn(
            "PROJECTROOT",
            document["runs"][0]["originalUriBaseIds"],
        )

    def test_srcroot_kwarg_propagates(self):
        document = self._render_and_parse(srcroot="/repo")
        self.assertEqual(
            document["runs"][0]["originalUriBaseIds"]["PROJECTROOT"]["uri"],
            "/repo",
        )

    def test_scan_mode_kwarg_propagates(self):
        document = self._render_and_parse(scan_mode="deep")
        self.assertEqual(
            document["runs"][0]["automationDetails"]["id"],
            "pydepgate/deep/",
        )


# ===========================================================================
# Fallback path: assemble_document raises -> render() falls back
# ===========================================================================


class TestRenderFallback(unittest.TestCase):
    """When assemble_document raises, render emits the fallback document.

    Patches the assemble_document binding inside the sarif package
    namespace (where render() looks it up) rather than the
    document.py definition site. The from-import in __init__.py
    creates a separate binding, and patching the original module
    location would not intercept render()'s call.
    """

    PATCH_TARGET = "pydepgate.reporters.sarif.assemble_document"

    def _render_with_assembly_failure(self, error: Exception) -> tuple[dict, str]:
        """Render with assemble_document mocked to raise.

        Returns (parsed_document, stderr_text). The stderr capture
        uses a separate StringIO so test output stays clean.
        """
        stream = io.StringIO()
        stderr_capture = io.StringIO()
        with patch(self.PATCH_TARGET, side_effect=error):
            with patch("sys.stderr", stderr_capture):
                render(
                    result=_empty_scan_result(),
                    decoded_tree=None,
                    stream=stream,
                )
        return json.loads(stream.getvalue()), stderr_capture.getvalue()

    def test_fallback_emitted_on_exception(self):
        document, _ = self._render_with_assembly_failure(RuntimeError("boom"))
        self.assertIsInstance(document, dict)

    def test_fallback_has_execution_successful_false(self):
        document, _ = self._render_with_assembly_failure(RuntimeError("boom"))
        invocation = document["runs"][0]["invocations"][0]
        self.assertEqual(invocation["executionSuccessful"], False)

    def test_fallback_includes_error_in_notification(self):
        document, _ = self._render_with_assembly_failure(
            RuntimeError("specific error text")
        )
        notification = document["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ][0]
        self.assertIn(
            "specific error text",
            notification["message"]["text"],
        )

    def test_fallback_writes_to_stderr(self):
        _, stderr_text = self._render_with_assembly_failure(RuntimeError("boom"))
        self.assertIn("SARIF assembly failed", stderr_text)

    def test_render_does_not_raise_on_assembly_failure(self):
        # The function catches all exceptions and emits the
        # fallback. This test asserts the no-raise contract.
        stream = io.StringIO()
        stderr_capture = io.StringIO()
        with patch(self.PATCH_TARGET, side_effect=RuntimeError("boom")):
            with patch("sys.stderr", stderr_capture):
                # If render raises, the test fails here.
                render(
                    result=_empty_scan_result(),
                    decoded_tree=None,
                    stream=stream,
                )

    def test_fallback_output_ends_with_newline(self):
        stream = io.StringIO()
        stderr_capture = io.StringIO()
        with patch(self.PATCH_TARGET, side_effect=RuntimeError("boom")):
            with patch("sys.stderr", stderr_capture):
                render(
                    result=_empty_scan_result(),
                    decoded_tree=None,
                    stream=stream,
                )
        self.assertTrue(stream.getvalue().endswith("\n"))

    def test_value_error_also_caught(self):
        # The except clause is bare Exception, so any subclass is
        # caught. Verify with a different exception type.
        document, _ = self._render_with_assembly_failure(ValueError("nope"))
        invocation = document["runs"][0]["invocations"][0]
        self.assertEqual(invocation["executionSuccessful"], False)


if __name__ == "__main__":
    unittest.main()
