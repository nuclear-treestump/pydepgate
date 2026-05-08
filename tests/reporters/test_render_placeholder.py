"""Tests for the Phase A SARIF render() placeholder.

The Phase A render() emits a valid SARIF 2.1.0 placeholder
document. These tests confirm the placeholder shape, tool
identity, and notification text. Phase E will replace the
placeholder body, at which point these tests are superseded
by tests against real findings.
"""

from __future__ import annotations

import io
import json
import unittest

from pydepgate.reporters.sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_INFORMATION_URI,
    TOOL_NAME,
    TOOL_ORGANIZATION,
    render,
)


class TestPlaceholderEmission(unittest.TestCase):
    """The placeholder must be valid, parseable SARIF 2.1.0."""

    def _render(self) -> dict:
        """Helper: run render and return the parsed document.

        Phase A render() does not dereference its result or
        decoded_tree arguments, so passing None is safe at
        this stage. Phase C and Phase D tests will pass real
        ScanResult and DecodedTree fixtures.
        """
        stream = io.StringIO()
        render(result=None, decoded_tree=None, stream=stream)
        return json.loads(stream.getvalue())

    def test_output_is_valid_json(self):
        document = self._render()
        assert isinstance(document, dict)

    def test_has_sarif_version(self):
        document = self._render()
        assert document["version"] == SARIF_VERSION
        assert document["version"] == "2.1.0"

    def test_has_schema_uri(self):
        document = self._render()
        assert document["$schema"] == SARIF_SCHEMA_URI

    def test_has_exactly_one_run(self):
        document = self._render()
        assert len(document["runs"]) == 1

    def test_tool_driver_name_is_pydepgate(self):
        document = self._render()
        driver = document["runs"][0]["tool"]["driver"]
        assert driver["name"] == TOOL_NAME
        assert driver["name"] == "pydepgate"

    def test_tool_driver_information_uri(self):
        document = self._render()
        driver = document["runs"][0]["tool"]["driver"]
        assert driver["informationUri"] == TOOL_INFORMATION_URI
        assert driver["informationUri"] == (
            "https://github.com/nuclear-treestump/pydepgate"
        )

    def test_tool_driver_organization(self):
        document = self._render()
        driver = document["runs"][0]["tool"]["driver"]
        assert driver["organization"] == TOOL_ORGANIZATION
        assert driver["organization"] == "Nuclear Treestump"

    def test_results_is_empty_array(self):
        document = self._render()
        assert document["runs"][0]["results"] == []

    def test_under_development_notification_present(self):
        document = self._render()
        notifications = document["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ]
        assert len(notifications) >= 1
        joined_text = " ".join(n["message"]["text"] for n in notifications)
        assert "under development" in joined_text

    def test_invocation_marked_successful(self):
        document = self._render()
        invocation = document["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True

    def test_output_ends_with_newline(self):
        stream = io.StringIO()
        render(result=None, decoded_tree=None, stream=stream)
        output = stream.getvalue()
        assert output.endswith("\n")


if __name__ == "__main__":
    unittest.main()
