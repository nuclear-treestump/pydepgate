"""Tests for the SARIF document assembler.

Covers `assemble_document()` and `assemble_fallback_document()`.
The happy-path tests construct synthetic ScanResult and DecodedTree
fixtures via the dataclass constructors and assert document shape.
The fallback tests assert the minimal valid SARIF that gets emitted
when the assembler is invoked directly with an error message.
"""

from __future__ import annotations

import unittest

from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.engines.base import (
    ArtifactKind,
    Finding,
    ScanContext,
    ScanResult,
    ScanStatistics,
    Severity,
    SuppressedFinding,
)
from pydepgate.enrichers.decode_payloads import (
    ChildFinding,
    DecodedNode,
    DecodedTree,
    STOP_LEAF_TERMINAL,
)
from pydepgate.parsers.pysource import SourceLocation
from pydepgate.reporters.sarif._constants import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_INFORMATION_URI,
    TOOL_NAME,
    TOOL_ORGANIZATION,
)
from pydepgate.reporters.sarif.document import (
    assemble_document,
    assemble_fallback_document,
)
from pydepgate.traffic_control.triage import FileKind

# ===========================================================================
# Fixtures
# ===========================================================================


def _make_signal(
    *,
    signal_id: str = "DENS010",
    analyzer: str = "density",
    confidence: Confidence = Confidence.HIGH,
    scope: Scope = Scope.MODULE,
    line: int = 42,
    column: int = 4,
    description: str = "test finding description",
    context: dict | None = None,
) -> Signal:
    """Construct a Signal for testing."""
    return Signal(
        analyzer=analyzer,
        signal_id=signal_id,
        confidence=confidence,
        scope=scope,
        location=SourceLocation(line=line, column=column),
        description=description,
        context=context if context is not None else {},
    )


def _make_scan_context(
    *,
    artifact_kind: ArtifactKind = ArtifactKind.WHEEL,
    artifact_identity: str = "test.whl",
    internal_path: str = "setup.py",
    file_kind: FileKind = FileKind.SETUP_PY,
) -> ScanContext:
    """Construct a ScanContext for testing."""
    return ScanContext(
        artifact_kind=artifact_kind,
        artifact_identity=artifact_identity,
        internal_path=internal_path,
        file_kind=file_kind,
        triage_reason="test",
    )


def _make_finding(
    *,
    signal: Signal | None = None,
    severity: Severity = Severity.HIGH,
    context: ScanContext | None = None,
) -> Finding:
    """Construct a Finding for testing."""
    return Finding(
        signal=signal if signal is not None else _make_signal(),
        severity=severity,
        context=context if context is not None else _make_scan_context(),
    )


def _make_scan_result(
    *,
    artifact_identity: str = "test.whl",
    artifact_kind: ArtifactKind = ArtifactKind.WHEEL,
    findings: tuple[Finding, ...] = (),
    diagnostics: tuple[str, ...] = (),
    suppressed_findings: tuple[SuppressedFinding, ...] = (),
) -> ScanResult:
    """Construct a ScanResult for testing."""
    return ScanResult(
        artifact_identity=artifact_identity,
        artifact_kind=artifact_kind,
        findings=findings,
        skipped=(),
        statistics=ScanStatistics(),
        diagnostics=diagnostics,
        suppressed_findings=suppressed_findings,
    )


def _make_decoded_node(
    *,
    outer_signal_id: str = "DENS010",
    outer_severity: str = "high",
    outer_location: str = "setup.py:7:0",
    chain: tuple[str, ...] = ("base64",),
    child_findings: tuple[ChildFinding, ...] = (),
    children: tuple[DecodedNode, ...] = (),
) -> DecodedNode:
    """Construct a DecodedNode for testing."""
    return DecodedNode(
        outer_signal_id=outer_signal_id,
        outer_severity=outer_severity,
        outer_location=outer_location,
        outer_length=4096,
        chain=chain,
        unwrap_status="completed",
        final_kind="python_source",
        final_size=100,
        indicators=(),
        pickle_warning=False,
        depth=0,
        stop_reason=STOP_LEAF_TERMINAL,
        triggered_by=(),
        child_findings=child_findings,
        children=children,
    )


def _make_decoded_tree(
    *,
    target: str = "test.whl",
    nodes: tuple[DecodedNode, ...] = (),
) -> DecodedTree:
    """Construct a DecodedTree for testing."""
    return DecodedTree(
        target=target,
        max_depth=3,
        nodes=nodes,
    )


# ===========================================================================
# assemble_document: top-level shape
# ===========================================================================


class TestTopLevelShape(unittest.TestCase):
    """The document has the required top-level structure."""

    def test_returns_dict(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertIsInstance(document, dict)

    def test_has_schema(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertEqual(document["$schema"], SARIF_SCHEMA_URI)

    def test_has_version(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertEqual(document["version"], SARIF_VERSION)
        self.assertEqual(document["version"], "2.1.0")

    def test_has_exactly_one_run(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertEqual(len(document["runs"]), 1)

    def test_run_has_required_subfields(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        run = document["runs"][0]
        for field in (
            "tool",
            "results",
            "invocations",
            "automationDetails",
            "originalUriBaseIds",
        ):
            with self.subTest(field=field):
                self.assertIn(field, run)


# ===========================================================================
# assemble_document: tool block
# ===========================================================================


class TestToolBlock(unittest.TestCase):
    """The tool block carries identity and the rules catalog."""

    def test_driver_name(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertEqual(document["runs"][0]["tool"]["driver"]["name"], TOOL_NAME)

    def test_driver_organization(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertEqual(
            document["runs"][0]["tool"]["driver"]["organization"],
            TOOL_ORGANIZATION,
        )

    def test_driver_information_uri(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertEqual(
            document["runs"][0]["tool"]["driver"]["informationUri"],
            TOOL_INFORMATION_URI,
        )

    def test_driver_semantic_version_present_and_string(self):
        # get_version() returns the package version. We do not
        # pin the value here because it changes per release; we
        # just verify it is populated and a non-empty string.
        result = _make_scan_result()
        document = assemble_document(result, None)
        version = document["runs"][0]["tool"]["driver"]["semanticVersion"]
        self.assertIsInstance(version, str)
        self.assertTrue(version)

    def test_driver_rules_present_and_non_empty(self):
        # The catalog comes from SIGNAL_EXPLANATIONS which is
        # always populated in the project. Ensure the rules array
        # is non-empty and a list.
        result = _make_scan_result()
        document = assemble_document(result, None)
        rules = document["runs"][0]["tool"]["driver"]["rules"]
        self.assertIsInstance(rules, list)
        self.assertGreater(len(rules), 0)

    def test_rules_sorted_by_id(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        rules = document["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        self.assertEqual(rule_ids, sorted(rule_ids))


# ===========================================================================
# assemble_document: results array
# ===========================================================================


class TestResultsArray(unittest.TestCase):
    """The results array combines ScanResult and DecodedTree findings."""

    def test_empty_when_no_findings_no_decoded_tree(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertEqual(document["runs"][0]["results"], [])

    def test_contains_phase_c_results_for_findings(self):
        finding = _make_finding(
            signal=_make_signal(signal_id="DENS010"),
        )
        result = _make_scan_result(findings=(finding,))
        document = assemble_document(result, None)
        results = document["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "DENS010")

    def test_contains_phase_d_results_for_decoded_tree(self):
        child_finding = ChildFinding(
            signal_id="STDLIB001",
            severity="high",
            line=5,
            column=0,
            description="os.system call",
        )
        node = _make_decoded_node(child_findings=(child_finding,))
        tree = _make_decoded_tree(nodes=(node,))
        result = _make_scan_result()
        document = assemble_document(result, tree)
        results = document["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "STDLIB001")

    def test_phase_c_results_come_before_phase_d_results(self):
        # Concatenation order: scan-result findings first, decoded
        # tree findings second. Per Q5 in the design doc.
        scan_finding = _make_finding(
            signal=_make_signal(signal_id="DENS010"),
        )
        child_finding = ChildFinding(
            signal_id="STDLIB001",
            severity="high",
            line=5,
            column=0,
            description="os.system",
        )
        node = _make_decoded_node(child_findings=(child_finding,))
        tree = _make_decoded_tree(nodes=(node,))
        result = _make_scan_result(findings=(scan_finding,))
        document = assemble_document(result, tree)
        results = document["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["ruleId"], "DENS010")
        self.assertEqual(results[1]["ruleId"], "STDLIB001")

    def test_findings_order_preserved(self):
        f1 = _make_finding(
            signal=_make_signal(signal_id="DENS010", line=1),
        )
        f2 = _make_finding(
            signal=_make_signal(signal_id="DENS011", line=2),
        )
        result = _make_scan_result(findings=(f1, f2))
        document = assemble_document(result, None)
        results = document["runs"][0]["results"]
        self.assertEqual(results[0]["ruleId"], "DENS010")
        self.assertEqual(results[1]["ruleId"], "DENS011")

    def test_decoded_tree_node_order_preserved(self):
        cf1 = ChildFinding(
            signal_id="STDLIB001",
            severity="high",
            line=5,
            column=0,
            description="x",
        )
        cf2 = ChildFinding(
            signal_id="DYN002",
            severity="high",
            line=7,
            column=0,
            description="y",
        )
        node1 = _make_decoded_node(child_findings=(cf1,))
        node2 = _make_decoded_node(child_findings=(cf2,))
        tree = _make_decoded_tree(nodes=(node1, node2))
        result = _make_scan_result()
        document = assemble_document(result, tree)
        results = document["runs"][0]["results"]
        self.assertEqual(results[0]["ruleId"], "STDLIB001")
        self.assertEqual(results[1]["ruleId"], "DYN002")

    def test_suppressed_findings_excluded(self):
        # Suppressed findings have their own audit channel via the
        # JSON output; they are intentionally absent from SARIF.
        scan_finding = _make_finding(
            signal=_make_signal(signal_id="DENS010"),
        )
        # Build a SuppressedFinding wrapping a different signal so
        # the exclusion is observable in the rule_ids list.
        would_be = _make_finding(
            signal=_make_signal(signal_id="DENS011"),
        )
        suppressed = SuppressedFinding(
            original_finding=would_be,
            suppressing_rule_id="USER_RULE_1",
            suppressing_rule_source="user",
            would_have_been=would_be,
        )
        result = _make_scan_result(
            findings=(scan_finding,),
            suppressed_findings=(suppressed,),
        )
        document = assemble_document(result, None)
        rule_ids = [r["ruleId"] for r in document["runs"][0]["results"]]
        self.assertIn("DENS010", rule_ids)
        self.assertNotIn("DENS011", rule_ids)


# ===========================================================================
# assemble_document: invocations
# ===========================================================================


class TestInvocations(unittest.TestCase):
    """The invocations entry records execution status and notifications."""

    def test_exactly_one_invocation(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertEqual(len(document["runs"][0]["invocations"]), 1)

    def test_execution_successful_true_on_happy_path(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        invocation = document["runs"][0]["invocations"][0]
        self.assertEqual(invocation["executionSuccessful"], True)

    def test_no_notifications_when_no_diagnostics(self):
        result = _make_scan_result(diagnostics=())
        document = assemble_document(result, None)
        invocation = document["runs"][0]["invocations"][0]
        self.assertNotIn("toolExecutionNotifications", invocation)

    def test_notifications_present_when_diagnostics(self):
        result = _make_scan_result(
            diagnostics=("parser failed on x.py",),
        )
        document = assemble_document(result, None)
        invocation = document["runs"][0]["invocations"][0]
        self.assertIn("toolExecutionNotifications", invocation)
        self.assertEqual(len(invocation["toolExecutionNotifications"]), 1)

    def test_each_notification_has_warning_level(self):
        result = _make_scan_result(
            diagnostics=("a", "b", "c"),
        )
        document = assemble_document(result, None)
        notifications = document["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ]
        for n in notifications:
            self.assertEqual(n["level"], "warning")

    def test_notification_text_matches_diagnostic(self):
        result = _make_scan_result(
            diagnostics=("custom diagnostic message",),
        )
        document = assemble_document(result, None)
        notification = document["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ][0]
        self.assertEqual(
            notification["message"]["text"],
            "custom diagnostic message",
        )

    def test_diagnostic_order_preserved(self):
        result = _make_scan_result(
            diagnostics=("first", "second", "third"),
        )
        document = assemble_document(result, None)
        notifications = document["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ]
        texts = [n["message"]["text"] for n in notifications]
        self.assertEqual(texts, ["first", "second", "third"])


# ===========================================================================
# assemble_document: automationDetails
# ===========================================================================


class TestAutomationDetails(unittest.TestCase):
    """automationDetails.id encodes the scan mode."""

    def test_id_format_for_wheel(self):
        result = _make_scan_result(artifact_kind=ArtifactKind.WHEEL)
        document = assemble_document(result, None)
        self.assertEqual(
            document["runs"][0]["automationDetails"]["id"],
            "pydepgate/wheel/",
        )

    def test_id_format_for_sdist(self):
        result = _make_scan_result(artifact_kind=ArtifactKind.SDIST)
        document = assemble_document(result, None)
        self.assertEqual(
            document["runs"][0]["automationDetails"]["id"],
            "pydepgate/sdist/",
        )

    def test_id_format_for_installed_env(self):
        # Per Q2: enum values verbatim, so installed_env not the
        # plan's hyphenated 'installed'.
        result = _make_scan_result(artifact_kind=ArtifactKind.INSTALLED_ENV)
        document = assemble_document(result, None)
        self.assertEqual(
            document["runs"][0]["automationDetails"]["id"],
            "pydepgate/installed_env/",
        )

    def test_id_format_for_loose_file(self):
        result = _make_scan_result(artifact_kind=ArtifactKind.LOOSE_FILE)
        document = assemble_document(result, None)
        self.assertEqual(
            document["runs"][0]["automationDetails"]["id"],
            "pydepgate/loose_file/",
        )

    def test_scan_mode_override(self):
        result = _make_scan_result(artifact_kind=ArtifactKind.WHEEL)
        document = assemble_document(result, None, scan_mode="deep")
        self.assertEqual(
            document["runs"][0]["automationDetails"]["id"],
            "pydepgate/deep/",
        )

    def test_id_has_trailing_slash(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertTrue(document["runs"][0]["automationDetails"]["id"].endswith("/"))


# ===========================================================================
# assemble_document: originalUriBaseIds
# ===========================================================================


class TestOriginalUriBaseIds(unittest.TestCase):
    """originalUriBaseIds is always emitted with PROJECTROOT entry."""

    def test_always_emitted(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertIn("originalUriBaseIds", document["runs"][0])

    def test_has_projectroot_key(self):
        result = _make_scan_result()
        document = assemble_document(result, None)
        self.assertIn(
            "PROJECTROOT",
            document["runs"][0]["originalUriBaseIds"],
        )

    def test_uri_empty_when_srcroot_none(self):
        result = _make_scan_result()
        document = assemble_document(result, None, srcroot=None)
        self.assertEqual(
            document["runs"][0]["originalUriBaseIds"]["PROJECTROOT"]["uri"],
            "",
        )

    def test_uri_matches_srcroot_when_provided(self):
        result = _make_scan_result()
        document = assemble_document(result, None, srcroot="/path/to/repo")
        self.assertEqual(
            document["runs"][0]["originalUriBaseIds"]["PROJECTROOT"]["uri"],
            "/path/to/repo",
        )


# ===========================================================================
# assemble_document: srcroot propagates to per-result use_srcroot
# ===========================================================================


class TestSrcrootPropagation(unittest.TestCase):
    """srcroot=None means use_srcroot=False on per-result calls."""

    def test_no_srcroot_no_uri_base_id_on_results(self):
        finding = _make_finding(
            signal=_make_signal(signal_id="DENS010"),
        )
        result = _make_scan_result(findings=(finding,))
        document = assemble_document(result, None, srcroot=None)
        artifact = document["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]
        self.assertNotIn("uriBaseId", artifact)

    def test_with_srcroot_results_get_uri_base_id(self):
        finding = _make_finding(
            signal=_make_signal(signal_id="DENS010"),
        )
        result = _make_scan_result(findings=(finding,))
        document = assemble_document(result, None, srcroot="/path/to/repo")
        artifact = document["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]
        self.assertEqual(artifact["uriBaseId"], "PROJECTROOT")


# ===========================================================================
# assemble_fallback_document
# ===========================================================================


class TestFallbackDocument(unittest.TestCase):
    """assemble_fallback_document produces a minimal valid document."""

    def test_returns_dict(self):
        document = assemble_fallback_document("test error")
        self.assertIsInstance(document, dict)

    def test_has_schema(self):
        document = assemble_fallback_document("test error")
        self.assertEqual(document["$schema"], SARIF_SCHEMA_URI)

    def test_has_version(self):
        document = assemble_fallback_document("test error")
        self.assertEqual(document["version"], "2.1.0")

    def test_has_exactly_one_run(self):
        document = assemble_fallback_document("test error")
        self.assertEqual(len(document["runs"]), 1)

    def test_tool_driver_has_identity(self):
        document = assemble_fallback_document("test error")
        driver = document["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], TOOL_NAME)
        self.assertEqual(driver["organization"], TOOL_ORGANIZATION)
        self.assertEqual(driver["informationUri"], TOOL_INFORMATION_URI)

    def test_tool_driver_has_no_rules(self):
        # The fallback omits the rules catalog because whatever
        # caused assemble_document to fail might also affect
        # make_rules_array.
        document = assemble_fallback_document("test error")
        driver = document["runs"][0]["tool"]["driver"]
        self.assertNotIn("rules", driver)

    def test_results_empty(self):
        document = assemble_fallback_document("test error")
        self.assertEqual(document["runs"][0]["results"], [])

    def test_execution_successful_false(self):
        document = assemble_fallback_document("test error")
        invocation = document["runs"][0]["invocations"][0]
        self.assertEqual(invocation["executionSuccessful"], False)

    def test_notification_with_error_level(self):
        document = assemble_fallback_document("test error")
        notification = document["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ][0]
        self.assertEqual(notification["level"], "error")

    def test_notification_includes_error_message(self):
        document = assemble_fallback_document("make_rules_array exploded")
        notification = document["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ][0]
        self.assertIn(
            "make_rules_array exploded",
            notification["message"]["text"],
        )

    def test_no_automation_details(self):
        document = assemble_fallback_document("test error")
        self.assertNotIn("automationDetails", document["runs"][0])

    def test_no_uri_base_ids(self):
        document = assemble_fallback_document("test error")
        self.assertNotIn("originalUriBaseIds", document["runs"][0])


# ===========================================================================
# Determinism
# ===========================================================================


class TestDeterminism(unittest.TestCase):
    """Same input produces same output."""

    def test_same_inputs_produce_same_document(self):
        finding = _make_finding(
            signal=_make_signal(signal_id="DENS010"),
        )
        result = _make_scan_result(findings=(finding,))
        a = assemble_document(result, None)
        b = assemble_document(result, None)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
