"""Tests for SARIF result generation from DecodedTree findings.

Covers `make_results_for_decoded_node()` and the helpers it
delegates to. Synthetic DecodedNode and ChildFinding fixtures are
constructed directly via the dataclass constructors; no real decode
pass is exercised here. The tree shapes mirror the structural cases
the production code path will encounter (single-layer, multi-layer,
nested) plus defensive edge cases (malformed locations, negative
columns, empty chains).
"""

from __future__ import annotations

import unittest

from pydepgate.enrichers.decode_payloads import (
    ChildFinding,
    DecodedNode,
    STOP_LEAF_TERMINAL,
)
from pydepgate.reporters.sarif.results import make_results_for_decoded_node

# Indices map covering the signal_ids used in fixtures. Real SARIF
# documents pull these from make_rules_array(); tests use a synthetic
# map so the test runs do not depend on the production catalog.
SAMPLE_INDICES = {
    "DENS010": 5,
    "DENS011": 6,
    "DYN001": 7,
    "DYN002": 8,
    "ENC001": 9,
    "STR001": 12,
    "STDLIB001": 20,
    "STDLIB002": 21,
}


def _make_child_finding(
    *,
    signal_id: str = "STDLIB001",
    severity: str = "high",
    line: int = 5,
    column: int = 0,
    description: str = "child finding description",
) -> ChildFinding:
    """Construct a ChildFinding for testing.

    Defaults match a typical inner-analyzer finding. Tests override
    specific fields per case.
    """
    return ChildFinding(
        signal_id=signal_id,
        severity=severity,
        line=line,
        column=column,
        description=description,
    )


def _make_decoded_node(
    *,
    outer_signal_id: str = "DENS010",
    outer_severity: str = "high",
    outer_location: str = "setup.py:7:0",
    outer_length: int = 4096,
    chain: tuple[str, ...] = ("base64",),
    unwrap_status: str = "completed",
    final_kind: str = "python_source",
    final_size: int = 100,
    indicators: tuple[str, ...] = (),
    pickle_warning: bool = False,
    depth: int = 0,
    stop_reason: str = STOP_LEAF_TERMINAL,
    triggered_by: tuple[str, ...] = (),
    child_findings: tuple[ChildFinding, ...] = (),
    children: tuple[DecodedNode, ...] = (),
) -> DecodedNode:
    """Construct a DecodedNode for testing.

    Defaults match a typical single-layer base64 decode of a
    high-entropy string. Tests override specific fields per case.
    """
    return DecodedNode(
        outer_signal_id=outer_signal_id,
        outer_severity=outer_severity,
        outer_location=outer_location,
        outer_length=outer_length,
        chain=chain,
        unwrap_status=unwrap_status,
        final_kind=final_kind,
        final_size=final_size,
        indicators=indicators,
        pickle_warning=pickle_warning,
        depth=depth,
        stop_reason=stop_reason,
        triggered_by=triggered_by,
        child_findings=child_findings,
        children=children,
    )


# ===========================================================================
# Empty trees
# ===========================================================================


class TestEmptyNode(unittest.TestCase):
    """Nodes without ChildFindings produce no results."""

    def test_no_child_findings_no_children_returns_empty(self):
        node = _make_decoded_node()
        results = make_results_for_decoded_node(node, SAMPLE_INDICES)
        self.assertEqual(results, [])

    def test_no_child_findings_with_empty_children_returns_empty(self):
        # A parent with sub-DecodedNodes that themselves have no
        # child_findings produces no results either. Decode-only
        # metadata (pickle warnings, DER classifications) does not
        # synthesize a SARIF result by design.
        empty_child = _make_decoded_node(depth=1)
        parent = _make_decoded_node(children=(empty_child,))
        results = make_results_for_decoded_node(parent, SAMPLE_INDICES)
        self.assertEqual(results, [])


# ===========================================================================
# Basic shape: one ChildFinding produces one result
# ===========================================================================


class TestSingleLayerChain(unittest.TestCase):
    """One outer + one decode layer + one child_finding -> one result."""

    def test_one_result_emitted(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        results = make_results_for_decoded_node(node, SAMPLE_INDICES)
        self.assertEqual(len(results), 1)

    def test_result_rule_id_is_child_finding_signal_id(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(signal_id="STDLIB001"),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(result["ruleId"], "STDLIB001")

    def test_result_rule_index_from_indices_map(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(signal_id="STDLIB001"),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(result["ruleIndex"], 20)

    def test_message_text_from_child_finding_description(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(description="exec call detected"),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(result["message"]["text"], "exec call detected")


class TestMultipleChildFindings(unittest.TestCase):
    """A node with multiple ChildFindings produces multiple results."""

    def test_two_child_findings_produce_two_results(self):
        cf_a = _make_child_finding(signal_id="STDLIB001", line=3)
        cf_b = _make_child_finding(signal_id="DYN002", line=7)
        node = _make_decoded_node(child_findings=(cf_a, cf_b))
        results = make_results_for_decoded_node(node, SAMPLE_INDICES)
        self.assertEqual(len(results), 2)

    def test_results_preserve_child_finding_order(self):
        cf_a = _make_child_finding(signal_id="STDLIB001", line=3)
        cf_b = _make_child_finding(signal_id="DYN002", line=7)
        node = _make_decoded_node(child_findings=(cf_a, cf_b))
        results = make_results_for_decoded_node(node, SAMPLE_INDICES)
        self.assertEqual(results[0]["ruleId"], "STDLIB001")
        self.assertEqual(results[1]["ruleId"], "DYN002")


# ===========================================================================
# Loud failures on bad inputs
# ===========================================================================


class TestRuleIdMissingFromIndices(unittest.TestCase):
    """Unknown signal_id raises KeyError to fail loudly."""

    def test_key_error_on_unknown_signal_id(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(signal_id="UNKNOWN_XYZ"),),
        )
        with self.assertRaises(KeyError):
            make_results_for_decoded_node(node, SAMPLE_INDICES)


# ===========================================================================
# Severity mapping
# ===========================================================================


class TestSeverityMapping(unittest.TestCase):
    """ChildFinding severity strings map to SARIF level via Severity enum."""

    def _result_for_severity(self, severity_str: str) -> dict:
        node = _make_decoded_node(
            child_findings=(_make_child_finding(severity=severity_str),),
        )
        return make_results_for_decoded_node(node, SAMPLE_INDICES)[0]

    def test_critical_to_error(self):
        result = self._result_for_severity("critical")
        self.assertEqual(result["level"], "error")

    def test_high_to_error(self):
        result = self._result_for_severity("high")
        self.assertEqual(result["level"], "error")

    def test_medium_to_warning(self):
        result = self._result_for_severity("medium")
        self.assertEqual(result["level"], "warning")

    def test_low_to_note(self):
        result = self._result_for_severity("low")
        self.assertEqual(result["level"], "note")

    def test_info_to_note(self):
        result = self._result_for_severity("info")
        self.assertEqual(result["level"], "note")

    def test_unknown_severity_string_raises_value_error(self):
        # Severity("nonsense") raises ValueError per the enum's
        # value-lookup contract. Loud failure is intentional: an
        # unmapped severity is a contract violation, not an event
        # the SARIF reporter should paper over.
        node = _make_decoded_node(
            child_findings=(_make_child_finding(severity="nonsense"),),
        )
        with self.assertRaises(ValueError):
            make_results_for_decoded_node(node, SAMPLE_INDICES)


# ===========================================================================
# Primary location: synthetic decoded URI for the inner finding
# ===========================================================================


class TestPrimaryLocation(unittest.TestCase):
    """The result's primary location is a synthetic decoded URI."""

    def test_uri_uses_pydepgate_decoded_scheme(self):
        node = _make_decoded_node(
            outer_location="setup.py:7:0",
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        loc = result["locations"][0]["physicalLocation"]
        self.assertTrue(loc["artifactLocation"]["uri"].startswith("pydepgate-decoded:"))

    def test_uri_includes_parent_path(self):
        node = _make_decoded_node(
            outer_location="litellm/_init_.py:7:0",
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertIn("litellm/_init_.py", uri)

    def test_uri_includes_layer_line_column_query(self):
        node = _make_decoded_node(
            outer_location="setup.py:7:0",
            chain=("base64", "zlib"),
            child_findings=(_make_child_finding(line=5, column=10),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertIn("layer=2", uri)
        self.assertIn("line=5", uri)
        self.assertIn("column=10", uri)

    def test_layer_count_in_uri_matches_chain_length(self):
        node = _make_decoded_node(
            chain=("base64", "zlib", "gzip"),
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertIn("layer=3", uri)

    def test_inner_finding_uri_has_no_uri_base_id(self):
        # Synthetic decoded URIs are never project-relative even
        # when use_srcroot is True. The make_artifact_location_for_decoded
        # helper does not emit uriBaseId.
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES, use_srcroot=True)[
            0
        ]
        artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
        self.assertNotIn("uriBaseId", artifact)

    def test_negative_column_omitted_from_uri(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(column=-1),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertNotIn("column=", uri)


# ===========================================================================
# Region: line and 1-indexed column
# ===========================================================================


class TestRegion(unittest.TestCase):
    """The result's region carries line and 1-indexed column."""

    def test_start_line_from_child_finding(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(line=42),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 42)

    def test_start_column_converted_to_1_indexed(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(column=4),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startColumn"], 5)

    def test_zero_column_becomes_column_1(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(column=0),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startColumn"], 1)

    def test_zero_line_falls_back_to_line_1(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(line=0),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 1)

    def test_negative_column_omitted_from_region(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(column=-1),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertNotIn("startColumn", region)


# ===========================================================================
# Properties: pydepgate-specific metadata
# ===========================================================================


class TestProperties(unittest.TestCase):
    """Properties carry SARIF and pydepgate-specific metadata."""

    def test_security_severity_present(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(severity="high"),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertIn("security-severity", result["properties"])

    def test_security_severity_matches_severity(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(severity="critical"),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(result["properties"]["security-severity"], "9.5")

    def test_security_severity_is_string(self):
        # SARIF spec requires security-severity as a string.
        node = _make_decoded_node(
            child_findings=(_make_child_finding(severity="medium"),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertIsInstance(result["properties"]["security-severity"], str)

    def test_analyzer_derived_from_signal_id_prefix(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(signal_id="STDLIB001"),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(
            result["properties"]["pydepgate.analyzer"],
            "suspicious-stdlib",
        )

    def test_via_decode_chain_is_chain_layers_list(self):
        node = _make_decoded_node(
            chain=("base64", "zlib"),
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(
            result["properties"]["pydepgate.via_decode_chain"],
            ["base64", "zlib"],
        )

    def test_outer_signal_id_for_top_level_node_is_own_id(self):
        # Top-level node (no ancestors): outer_signal_id property
        # is the node's own outer_signal_id.
        node = _make_decoded_node(
            outer_signal_id="DENS010",
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(
            result["properties"]["pydepgate.outer_signal_id"],
            "DENS010",
        )

    def test_decode_depth_matches_node_depth(self):
        node = _make_decoded_node(
            depth=2,
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(result["properties"]["pydepgate.decode_depth"], 2)

    def test_confidence_property_omitted(self):
        # ChildFinding has no analyzer-confidence field; the SARIF
        # emitter does not synthesize one.
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertNotIn("pydepgate.confidence", result["properties"])

    def test_scope_property_omitted(self):
        # Same rationale: ChildFinding has no scope field.
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertNotIn("pydepgate.scope", result["properties"])


# ===========================================================================
# Nested children: the recursive walk and ancestor chain
# ===========================================================================


class TestNestedChildren(unittest.TestCase):
    """Nested DecodedNodes contribute their chains to descendant codeFlows."""

    def _nested_tree(self) -> DecodedNode:
        # Parent: DENS010 at setup.py:7, decoded via base64.
        # Nested child: DENS011 at depth 1, decoded via zlib to
        # bytes carrying a STDLIB001 child finding.
        inner_finding = _make_child_finding(
            signal_id="STDLIB001",
            line=5,
            column=0,
            description="os.system call",
        )
        nested_child = _make_decoded_node(
            outer_signal_id="DENS011",
            outer_location="setup.py:7:0",
            chain=("zlib",),
            depth=1,
            child_findings=(inner_finding,),
        )
        parent = _make_decoded_node(
            outer_signal_id="DENS010",
            outer_location="setup.py:7:0",
            chain=("base64",),
            depth=0,
            children=(nested_child,),
        )
        return parent

    def test_nested_walk_produces_one_result_per_leaf_child_finding(self):
        parent = self._nested_tree()
        results = make_results_for_decoded_node(parent, SAMPLE_INDICES)
        self.assertEqual(len(results), 1)

    def test_nested_result_rule_id_is_innermost_signal_id(self):
        parent = self._nested_tree()
        result = make_results_for_decoded_node(parent, SAMPLE_INDICES)[0]
        self.assertEqual(result["ruleId"], "STDLIB001")

    def test_nested_outer_signal_id_property_is_root(self):
        # Even when the inner finding was reached via a nested
        # DecodedNode, the outer_signal_id property points at the
        # outermost ancestor (the trigger that started the chain).
        parent = self._nested_tree()
        result = make_results_for_decoded_node(parent, SAMPLE_INDICES)[0]
        self.assertEqual(
            result["properties"]["pydepgate.outer_signal_id"],
            "DENS010",
        )

    def test_nested_via_decode_chain_includes_all_layers(self):
        parent = self._nested_tree()
        result = make_results_for_decoded_node(parent, SAMPLE_INDICES)[0]
        self.assertEqual(
            result["properties"]["pydepgate.via_decode_chain"],
            ["base64", "zlib"],
        )

    def test_nested_decode_depth_is_inner_node_depth(self):
        parent = self._nested_tree()
        result = make_results_for_decoded_node(parent, SAMPLE_INDICES)[0]
        self.assertEqual(result["properties"]["pydepgate.decode_depth"], 1)

    def test_nested_code_flow_walks_all_ancestors(self):
        # 1-layer parent + 1-layer child + 1 inner finding =
        # 1 outer (parent) + 1 layer (parent.chain) + 1 outer
        # (child) + 1 layer (child.chain) + 1 inner = 5 steps.
        parent = self._nested_tree()
        result = make_results_for_decoded_node(parent, SAMPLE_INDICES)[0]
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(len(steps), 5)


# ===========================================================================
# codeFlows shape: thread flow location count per chain shape
# ===========================================================================


class TestCodeFlowShape(unittest.TestCase):
    """codeFlows array carries the per-step decode chain."""

    def test_one_code_flow_per_result(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(len(result["codeFlows"]), 1)

    def test_one_thread_flow_per_code_flow(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        self.assertEqual(len(result["codeFlows"][0]["threadFlows"]), 1)

    def test_single_layer_chain_has_three_steps(self):
        # 1 outer + 1 layer + 1 inner = 3 steps
        node = _make_decoded_node(
            chain=("base64",),
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(len(steps), 3)

    def test_two_layer_chain_has_four_steps(self):
        node = _make_decoded_node(
            chain=("base64", "zlib"),
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(len(steps), 4)

    def test_three_layer_chain_has_five_steps(self):
        node = _make_decoded_node(
            chain=("base64", "zlib", "gzip"),
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(len(steps), 5)

    def test_empty_chain_has_two_steps(self):
        # Degenerate: no decode layers, just outer + inner. Possible
        # when an inner finding fires on the bytes without any
        # transform applied.
        node = _make_decoded_node(
            chain=(),
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(len(steps), 2)

    def test_execution_order_is_monotonic_from_zero(self):
        node = _make_decoded_node(
            chain=("base64", "zlib"),
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        orders = [s["executionOrder"] for s in steps]
        self.assertEqual(orders, [0, 1, 2, 3])

    def test_nesting_level_increments_per_layer(self):
        # 1 outer (level 0) + 2 layers (levels 1, 2) + 1 inner
        # (level 2, deepest decoded payload).
        node = _make_decoded_node(
            chain=("base64", "zlib"),
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        levels = [s["nestingLevel"] for s in steps]
        self.assertEqual(levels, [0, 1, 2, 2])


# ===========================================================================
# codeFlows step shape per kind: outer, layer, inner finding
# ===========================================================================


class TestCodeFlowStepShapes(unittest.TestCase):
    """Each step kind carries the expected URI, region, and message."""

    def _result_with_two_layer_chain(self) -> dict:
        node = _make_decoded_node(
            outer_signal_id="DENS010",
            outer_location="setup.py:7:0",
            outer_length=4096,
            chain=("base64", "zlib"),
            child_findings=(
                _make_child_finding(
                    signal_id="STDLIB001",
                    line=5,
                    column=0,
                    description="os.system",
                ),
            ),
        )
        return make_results_for_decoded_node(node, SAMPLE_INDICES)[0]

    def test_outer_step_uses_real_artifact_path(self):
        result = self._result_with_two_layer_chain()
        outer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
        uri = outer_step["location"]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "setup.py")
        self.assertFalse(uri.startswith("pydepgate-decoded:"))

    def test_outer_step_message_includes_signal_id_and_length(self):
        result = self._result_with_two_layer_chain()
        outer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
        text = outer_step["location"]["message"]["text"]
        self.assertIn("DENS010", text)
        self.assertIn("4096", text)

    def test_layer_step_uses_synthetic_uri(self):
        result = self._result_with_two_layer_chain()
        layer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][1]
        uri = layer_step["location"]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertTrue(uri.startswith("pydepgate-decoded:"))
        self.assertIn("layer=1", uri)

    def test_layer_step_message_describes_layer_kind(self):
        result = self._result_with_two_layer_chain()
        layer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][1]
        text = layer_step["location"]["message"]["text"]
        self.assertIn("decode layer 1", text)
        self.assertIn("base64", text)

    def test_layer_step_has_no_region(self):
        # Decode layers represent transforms over the whole payload,
        # not positions within it. They have no region.
        result = self._result_with_two_layer_chain()
        layer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][1]
        physical = layer_step["location"]["physicalLocation"]
        self.assertNotIn("region", physical)

    def test_second_layer_step_uses_correct_layer_number(self):
        result = self._result_with_two_layer_chain()
        # Steps: 0 = outer, 1 = layer 1, 2 = layer 2, 3 = inner
        layer2_step = result["codeFlows"][0]["threadFlows"][0]["locations"][2]
        uri = layer2_step["location"]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertIn("layer=2", uri)
        text = layer2_step["location"]["message"]["text"]
        self.assertIn("decode layer 2", text)
        self.assertIn("zlib", text)

    def test_inner_finding_step_uses_synthetic_uri_with_full_coords(self):
        result = self._result_with_two_layer_chain()
        inner_step = result["codeFlows"][0]["threadFlows"][0]["locations"][3]
        uri = inner_step["location"]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertTrue(uri.startswith("pydepgate-decoded:"))
        self.assertIn("layer=2", uri)
        self.assertIn("line=5", uri)
        self.assertIn("column=0", uri)

    def test_inner_finding_step_has_region(self):
        result = self._result_with_two_layer_chain()
        inner_step = result["codeFlows"][0]["threadFlows"][0]["locations"][3]
        physical = inner_step["location"]["physicalLocation"]
        self.assertIn("region", physical)
        self.assertEqual(physical["region"]["startLine"], 5)
        self.assertEqual(physical["region"]["startColumn"], 1)

    def test_inner_finding_step_message_includes_signal_id(self):
        result = self._result_with_two_layer_chain()
        inner_step = result["codeFlows"][0]["threadFlows"][0]["locations"][3]
        text = inner_step["location"]["message"]["text"]
        self.assertIn("STDLIB001", text)
        self.assertIn("os.system", text)


# ===========================================================================
# srcroot handling: real-path steps only
# ===========================================================================


class TestSrcrootHandling(unittest.TestCase):
    """use_srcroot affects only outer-finding steps with real paths."""

    def test_outer_step_has_uri_base_id_when_use_srcroot(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES, use_srcroot=True)[
            0
        ]
        outer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
        artifact = outer_step["location"]["physicalLocation"]["artifactLocation"]
        self.assertEqual(artifact["uriBaseId"], "PROJECTROOT")

    def test_outer_step_no_uri_base_id_when_use_srcroot_false(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES, use_srcroot=False)[
            0
        ]
        outer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
        artifact = outer_step["location"]["physicalLocation"]["artifactLocation"]
        self.assertNotIn("uriBaseId", artifact)

    def test_layer_step_no_uri_base_id_even_with_srcroot(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES, use_srcroot=True)[
            0
        ]
        layer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][1]
        artifact = layer_step["location"]["physicalLocation"]["artifactLocation"]
        self.assertNotIn("uriBaseId", artifact)

    def test_inner_step_no_uri_base_id_even_with_srcroot(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES, use_srcroot=True)[
            0
        ]
        # 1-layer chain: inner step is at index 2.
        inner_step = result["codeFlows"][0]["threadFlows"][0]["locations"][2]
        artifact = inner_step["location"]["physicalLocation"]["artifactLocation"]
        self.assertNotIn("uriBaseId", artifact)


# ===========================================================================
# Fingerprints: stability and differentiation
# ===========================================================================


class TestFingerprints(unittest.TestCase):
    """partialFingerprints are stable, deterministic, and differentiating."""

    def test_format_24_hex_colon_1(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        fp = result["partialFingerprints"]["primaryLocationLineHash"]
        digest, version = fp.rsplit(":", 1)
        self.assertEqual(len(digest), 24)
        self.assertEqual(version, "1")
        self.assertTrue(all(c in "0123456789abcdef" for c in digest))

    def test_same_inputs_produce_same_fingerprint(self):
        # Stability: identical fixtures produce identical
        # fingerprints. This is the GitHub dedup invariant: re-scans
        # of the same artifact must not produce duplicate alerts.
        def _build() -> DecodedNode:
            return _make_decoded_node(
                child_findings=(_make_child_finding(),),
            )

        a = make_results_for_decoded_node(_build(), SAMPLE_INDICES)[0]
        b = make_results_for_decoded_node(_build(), SAMPLE_INDICES)[0]
        fp_a = a["partialFingerprints"]["primaryLocationLineHash"]
        fp_b = b["partialFingerprints"]["primaryLocationLineHash"]
        self.assertEqual(fp_a, fp_b)

    def test_different_chain_produces_different_fingerprint(self):
        node_a = _make_decoded_node(
            chain=("base64",),
            child_findings=(_make_child_finding(),),
        )
        node_b = _make_decoded_node(
            chain=("zlib",),
            child_findings=(_make_child_finding(),),
        )
        fp_a = make_results_for_decoded_node(node_a, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        fp_b = make_results_for_decoded_node(node_b, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        self.assertNotEqual(fp_a, fp_b)

    def test_different_signal_id_produces_different_fingerprint(self):
        node_a = _make_decoded_node(
            child_findings=(_make_child_finding(signal_id="STDLIB001"),),
        )
        node_b = _make_decoded_node(
            child_findings=(_make_child_finding(signal_id="DYN002"),),
        )
        fp_a = make_results_for_decoded_node(node_a, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        fp_b = make_results_for_decoded_node(node_b, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        self.assertNotEqual(fp_a, fp_b)

    def test_different_line_produces_different_fingerprint(self):
        node_a = _make_decoded_node(
            child_findings=(_make_child_finding(line=5),),
        )
        node_b = _make_decoded_node(
            child_findings=(_make_child_finding(line=15),),
        )
        fp_a = make_results_for_decoded_node(node_a, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        fp_b = make_results_for_decoded_node(node_b, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        self.assertNotEqual(fp_a, fp_b)

    def test_different_description_produces_different_fingerprint(self):
        node_a = _make_decoded_node(
            child_findings=(_make_child_finding(description="os.system call"),),
        )
        node_b = _make_decoded_node(
            child_findings=(_make_child_finding(description="subprocess.Popen call"),),
        )
        fp_a = make_results_for_decoded_node(node_a, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        fp_b = make_results_for_decoded_node(node_b, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        self.assertNotEqual(fp_a, fp_b)

    def test_different_outer_signal_id_produces_different_fingerprint(self):
        # Two child findings reached via different outer triggers
        # are distinct alerts even if the inner content is the same.
        node_a = _make_decoded_node(
            outer_signal_id="DENS010",
            child_findings=(_make_child_finding(),),
        )
        node_b = _make_decoded_node(
            outer_signal_id="DENS011",
            child_findings=(_make_child_finding(),),
        )
        fp_a = make_results_for_decoded_node(node_a, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        fp_b = make_results_for_decoded_node(node_b, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        self.assertNotEqual(fp_a, fp_b)

    def test_different_parent_path_produces_different_fingerprint(self):
        node_a = _make_decoded_node(
            outer_location="setup.py:7:0",
            child_findings=(_make_child_finding(),),
        )
        node_b = _make_decoded_node(
            outer_location="other.py:7:0",
            child_findings=(_make_child_finding(),),
        )
        fp_a = make_results_for_decoded_node(node_a, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        fp_b = make_results_for_decoded_node(node_b, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        self.assertNotEqual(fp_a, fp_b)

    def test_nested_chain_fingerprint_differs_from_flat(self):
        # Same inner finding reached via a flat chain (just zlib)
        # vs a nested chain (base64 -> zlib) produces different
        # fingerprints. Chain context participates in the hash so
        # alerts coming from genuinely different attack paths do
        # not collide.
        flat = _make_decoded_node(
            outer_signal_id="DENS010",
            chain=("zlib",),
            child_findings=(_make_child_finding(signal_id="STDLIB001"),),
        )
        nested_inner = _make_decoded_node(
            outer_signal_id="DENS011",
            chain=("zlib",),
            depth=1,
            child_findings=(_make_child_finding(signal_id="STDLIB001"),),
        )
        nested_parent = _make_decoded_node(
            outer_signal_id="DENS010",
            chain=("base64",),
            children=(nested_inner,),
        )
        fp_flat = make_results_for_decoded_node(flat, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        fp_nested = make_results_for_decoded_node(nested_parent, SAMPLE_INDICES)[0][
            "partialFingerprints"
        ]["primaryLocationLineHash"]
        self.assertNotEqual(fp_flat, fp_nested)


# ===========================================================================
# Required SARIF fields
# ===========================================================================


class TestRequiredFields(unittest.TestCase):
    """Every result has all SARIF-required fields."""

    REQUIRED_TOP_LEVEL = {
        "ruleId",
        "level",
        "message",
        "locations",
        "partialFingerprints",
        "codeFlows",
    }

    def test_required_top_level_fields_present(self):
        node = _make_decoded_node(
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        missing = self.REQUIRED_TOP_LEVEL - set(result.keys())
        self.assertFalse(missing, f"required SARIF fields missing: {missing}")

    def test_each_thread_flow_location_has_required_subfields(self):
        # Per the SARIF spec, threadFlowLocation requires either
        # 'location' or 'kind'/'kinds'. pydepgate's emission uses
        # 'location' on every step. executionOrder and nestingLevel
        # are not strictly required but every step carries them.
        node = _make_decoded_node(
            chain=("base64", "zlib"),
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        for step in steps:
            self.assertIn("location", step)
            self.assertIn("executionOrder", step)
            self.assertIn("nestingLevel", step)


# ===========================================================================
# Determinism
# ===========================================================================


class TestDeterminism(unittest.TestCase):
    """Repeated calls with the same input produce identical output."""

    def test_same_node_produces_identical_results(self):
        node = _make_decoded_node(
            chain=("base64", "zlib"),
            child_findings=(
                _make_child_finding(signal_id="STDLIB001", line=5),
                _make_child_finding(signal_id="DYN002", line=10),
            ),
        )
        a = make_results_for_decoded_node(node, SAMPLE_INDICES)
        b = make_results_for_decoded_node(node, SAMPLE_INDICES)
        self.assertEqual(a, b)


# ===========================================================================
# outer_location parsing edge cases
# ===========================================================================


class TestOuterLocationParsing(unittest.TestCase):
    """The outer_location parser handles paths with embedded colons."""

    def test_simple_path_parses(self):
        node = _make_decoded_node(
            outer_location="setup.py:7:0",
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        outer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
        artifact = outer_step["location"]["physicalLocation"]["artifactLocation"]
        self.assertEqual(artifact["uri"], "setup.py")

    def test_path_with_directory_parses(self):
        node = _make_decoded_node(
            outer_location="litellm/_init_.py:7:0",
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        outer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
        artifact = outer_step["location"]["physicalLocation"]["artifactLocation"]
        self.assertEqual(artifact["uri"], "litellm/_init_.py")

    def test_path_with_embedded_colon_survives(self):
        # Windows drive letters and URI-style internal paths can
        # contain colons. rpartition ensures only the trailing two
        # colons are interpreted as line/column separators.
        node = _make_decoded_node(
            outer_location="C:/path/setup.py:7:0",
            child_findings=(_make_child_finding(),),
        )
        result = make_results_for_decoded_node(node, SAMPLE_INDICES)[0]
        outer_step = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
        artifact = outer_step["location"]["physicalLocation"]["artifactLocation"]
        self.assertEqual(artifact["uri"], "C:/path/setup.py")

    def test_malformed_location_does_not_crash(self):
        # Defensive: a corrupted outer_location must not crash
        # SARIF emission. The fallback returns the whole string as
        # path with line=0 and column=0, which the region builder
        # then normalizes to startLine=1.
        node = _make_decoded_node(
            outer_location="malformed_no_colons",
            child_findings=(_make_child_finding(),),
        )
        results = make_results_for_decoded_node(node, SAMPLE_INDICES)
        self.assertEqual(len(results), 1)


# ===========================================================================
# Realistic chain shape: LiteLLM-style nested decode
# ===========================================================================


class TestRealisticChain(unittest.TestCase):
    """End-to-end test against a LiteLLM-shaped attack chain.

    Mirrors the structural shape of the LiteLLM 1.82.8 supply-chain
    attack: outer high-entropy string in a .pth file, decoded via
    base64 to Python source containing another base64 string, which
    decodes to malicious Python source containing os.system calls.
    """

    def _litellm_shaped_tree(self) -> DecodedNode:
        innermost = _make_child_finding(
            signal_id="STDLIB001",
            severity="critical",
            line=3,
            column=0,
            description="os.system invocation in decoded payload",
        )
        inner_node = _make_decoded_node(
            outer_signal_id="DENS010",
            outer_severity="high",
            outer_location="litellm_init.pth:1:0",
            outer_length=2048,
            chain=("base64",),
            depth=1,
            child_findings=(innermost,),
        )
        return _make_decoded_node(
            outer_signal_id="DENS010",
            outer_severity="high",
            outer_location="litellm_init.pth:1:0",
            outer_length=4096,
            chain=("base64",),
            depth=0,
            children=(inner_node,),
        )

    def test_one_result_for_innermost_finding(self):
        tree = self._litellm_shaped_tree()
        results = make_results_for_decoded_node(tree, SAMPLE_INDICES)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "STDLIB001")

    def test_severity_is_critical(self):
        tree = self._litellm_shaped_tree()
        result = make_results_for_decoded_node(tree, SAMPLE_INDICES)[0]
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["properties"]["security-severity"], "9.5")

    def test_full_chain_reflected_in_properties(self):
        tree = self._litellm_shaped_tree()
        result = make_results_for_decoded_node(tree, SAMPLE_INDICES)[0]
        self.assertEqual(
            result["properties"]["pydepgate.via_decode_chain"],
            ["base64", "base64"],
        )

    def test_root_outer_signal_id_in_properties(self):
        tree = self._litellm_shaped_tree()
        result = make_results_for_decoded_node(tree, SAMPLE_INDICES)[0]
        self.assertEqual(
            result["properties"]["pydepgate.outer_signal_id"],
            "DENS010",
        )

    def test_code_flow_walks_full_chain(self):
        # 1 outer (parent) + 1 layer (parent.chain[0]) + 1 outer
        # (child) + 1 layer (child.chain[0]) + 1 inner = 5 steps.
        tree = self._litellm_shaped_tree()
        result = make_results_for_decoded_node(tree, SAMPLE_INDICES)[0]
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(len(steps), 5)


if __name__ == "__main__":
    unittest.main()
