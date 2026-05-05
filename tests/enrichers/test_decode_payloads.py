"""
Tests for pydepgate.enrichers.decode_payloads.

Covers:
  - Helpers: _is_payload_bearing, _format_location, _to_child_finding,
    _extract_iocs, _signal_repr.
  - Dedup logic: _dedupe_payload_findings, _pick_primary_finding.
  - DecodedNode field defaults (the new triggered_by field).
  - Text and JSON renderers (single-signal and multi-signal display).
  - Driver integration with a mocked engine and patched unwrap, to
    verify the recursion shape and dedup-at-depth behavior.

Test fixtures use SimpleNamespace duck-typing rather than the real
Finding dataclass. The driver only accesses a small set of fields
(signal.signal_id, signal.location.line/column, signal.context dict,
signal.description, severity, context.internal_path, context.file_kind);
the fake matches that surface. If the real Finding gains new required
fields, these tests still pass because nothing in the driver iterates
fields generically.
"""

from __future__ import annotations

import hashlib
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from pydepgate.engines.base import Severity

from pydepgate.enrichers.decode_payloads import (
    ChildFinding,
    DecodedNode,
    DecodedTree,
    IOCData,
    STOP_DECODE_FAILED,
    STOP_DEPTH_LIMIT,
    STOP_LEAF_TERMINAL,
    STOP_NON_PYTHON,
    STOP_NO_FULL_VALUE,
    STOP_NO_INNER_FINDINGS,
    _dedupe_payload_findings,
    _extract_iocs,
    _format_location,
    _is_payload_bearing,
    _pick_primary_finding,
    _to_child_finding,
    decode_payloads,
    ChildFinding,
    DecodedNode,
    DecodedTree,
    IOCData,
    STOP_LEAF_TERMINAL,
    STOP_NO_INNER_FINDINGS,
    filter_tree_by_severity,
)

from pydepgate.reporters.decoded_tree import (
    text as render_text,
    json as render_decode_json,
    iocs as render_iocs,
    sources as render_sources,
)
from pydepgate.reporters.decoded_tree._helpers import _signal_repr
import json


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

def _fake_finding(
    *,
    signal_id: str = "DENS010",
    severity: Severity = Severity.HIGH,
    line: int = 10,
    column: int = 5,
    internal_path: str = "test.py",
    file_kind: Any = None,
    full_value: str | bytes | None = b"payload-data",
    decoded: dict | None = None,
    description: str = "test finding",
    length: int = 100,
) -> SimpleNamespace:
    """Build a duck-typed fake Finding for unit tests.

    Mirrors the fields decode_payloads accesses. Defaults make the
    finding payload-bearing (full_value and decoded both populated);
    pass full_value=None to suppress that.
    """
    if decoded is None and full_value is not None:
        decoded = {"final_kind": "python_source"}

    context_dict: dict[str, Any] = {"length": length}
    if full_value is not None:
        context_dict["_full_value"] = full_value
    if decoded is not None:
        context_dict["decoded"] = decoded

    return SimpleNamespace(
        signal=SimpleNamespace(
            signal_id=signal_id,
            location=SimpleNamespace(line=line, column=column),
            context=context_dict,
            description=description,
        ),
        severity=severity,
        context=SimpleNamespace(
            internal_path=internal_path,
            file_kind=file_kind,
            file_sha256=None,
            file_sha512=None,
        ),
    )


def _fake_finding_no_payload(
    *,
    signal_id: str = "DYN002",
    severity: Severity = Severity.HIGH,
    line: int = 10,
    column: int = 0,
    internal_path: str = "test.py",
    description: str = "exec call",
) -> SimpleNamespace:
    """Build a fake Finding without a payload (for leaf/non-bearing tests)."""
    return SimpleNamespace(
        signal=SimpleNamespace(
            signal_id=signal_id,
            location=SimpleNamespace(line=line, column=column),
            context={},
            description=description,
        ),
        severity=severity,
        context=SimpleNamespace(
            internal_path=internal_path,
            file_kind=None,
            file_sha256=None,
            file_sha512=None,
        ),
    )



def _fake_unwrap_result(
    *,
    chain: tuple = (),
    status: str = "completed",
    final_kind: str = "python_source",
    final_bytes: bytes = b"",
    indicators: tuple[str, ...] = (),
    pickle_warning: bool = False,
) -> SimpleNamespace:
    """Build a fake UnwrapResult for patching unwrap()."""
    return SimpleNamespace(
        chain=chain,
        status=status,
        final_kind=final_kind,
        final_bytes=final_bytes,
        indicators=indicators,
        pickle_warning=pickle_warning,
    )


def _fake_layer(kind: str) -> SimpleNamespace:
    """A Layer-shaped object (only .kind is read by the driver)."""
    return SimpleNamespace(kind=kind)


class _MockEngine:
    """Mock engine for testing decode_payloads recursion.

    Maps decoded bytes (exact-match) to the findings the engine
    should produce when re-scanning those bytes. Records all calls
    so tests can assert on the synthetic_path and forced_file_kind
    that the driver passed.
    """

    def __init__(self, response_for_bytes: dict[bytes, list]) -> None:
        self.response_for_bytes = response_for_bytes
        self.calls: list = []

    def _scan_one_file(self, inp) -> SimpleNamespace:
        self.calls.append(inp)
        findings = self.response_for_bytes.get(inp.content, [])
        return SimpleNamespace(findings=findings)


def _fake_scan_result(
    findings: list,
    *,
    identity: str = "test-target.tar.gz",
) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_identity=identity,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# _is_payload_bearing
# ---------------------------------------------------------------------------

class IsPayloadBearingTests(unittest.TestCase):

    def test_returns_true_when_both_keys_present(self):
        finding = _fake_finding(
            full_value=b"x",
            decoded={"final_kind": "python_source"},
        )
        self.assertTrue(_is_payload_bearing(finding))

    def test_returns_false_when_full_value_missing(self):
        finding = SimpleNamespace(
            signal=SimpleNamespace(
                signal_id="DENS010",
                location=SimpleNamespace(line=10, column=5),
                context={"decoded": {"final_kind": "python_source"}},
                description="x",
            ),
            severity=Severity.HIGH,
            context=SimpleNamespace(internal_path="t.py", file_kind=None),
        )
        self.assertFalse(_is_payload_bearing(finding))

    def test_returns_false_when_decoded_missing(self):
        finding = SimpleNamespace(
            signal=SimpleNamespace(
                signal_id="DENS010",
                location=SimpleNamespace(line=10, column=5),
                context={"_full_value": b"x"},
                description="x",
            ),
            severity=Severity.HIGH,
            context=SimpleNamespace(internal_path="t.py", file_kind=None),
        )
        self.assertFalse(_is_payload_bearing(finding))

    def test_returns_false_when_context_empty(self):
        finding = _fake_finding_no_payload()
        self.assertFalse(_is_payload_bearing(finding))


# ---------------------------------------------------------------------------
# _format_location
# ---------------------------------------------------------------------------

class FormatLocationTests(unittest.TestCase):

    def test_basic_format(self):
        finding = _fake_finding(
            internal_path="foo/bar.py", line=42, column=7,
        )
        self.assertEqual(_format_location(finding), "foo/bar.py:42:7")

    def test_zero_column(self):
        finding = _fake_finding(internal_path="x.py", line=1, column=0)
        self.assertEqual(_format_location(finding), "x.py:1:0")

    def test_path_with_subdirs(self):
        finding = _fake_finding(
            internal_path="litellm/proxy/proxy_server.py",
            line=130, column=14,
        )
        self.assertEqual(
            _format_location(finding),
            "litellm/proxy/proxy_server.py:130:14",
        )


# ---------------------------------------------------------------------------
# _to_child_finding
# ---------------------------------------------------------------------------

class ToChildFindingTests(unittest.TestCase):

    def test_basic_conversion(self):
        finding = _fake_finding_no_payload(
            signal_id="DYN002",
            severity=Severity.HIGH,
            line=100,
            column=4,
            description="exec call",
        )
        child = _to_child_finding(finding)
        self.assertEqual(child.signal_id, "DYN002")
        self.assertEqual(child.severity, "high")
        self.assertEqual(child.line, 100)
        self.assertEqual(child.column, 4)
        self.assertEqual(child.description, "exec call")

    def test_severity_enum_lowered_to_string(self):
        finding = _fake_finding_no_payload(severity=Severity.CRITICAL)
        child = _to_child_finding(finding)
        self.assertEqual(child.severity, "critical")


# ---------------------------------------------------------------------------
# _extract_iocs
# ---------------------------------------------------------------------------

class ExtractIOCsTests(unittest.TestCase):

    def test_python_source_includes_decoded_source(self):
        full_value = b"encoded-payload"
        final_bytes = b"import os\nos.system('ls')\n"
        ioc = _extract_iocs(full_value, final_bytes, "python_source")

        self.assertEqual(
            ioc.original_sha256,
            hashlib.sha256(full_value).hexdigest(),
        )
        self.assertEqual(
            ioc.decoded_sha256,
            hashlib.sha256(final_bytes).hexdigest(),
        )
        self.assertEqual(
            ioc.decoded_source,
            "import os\nos.system('ls')\n",
        )
        self.assertIsNotNone(ioc.extract_timestamp)

    def test_non_python_omits_decoded_source(self):
        ioc = _extract_iocs(b"x", b"\x00\x01\x02\x03", "binary_unknown")
        self.assertIsNone(ioc.decoded_source)

    def test_pem_terminal_omits_decoded_source(self):
        ioc = _extract_iocs(
            b"x", b"-----BEGIN RSA PRIVATE KEY-----\n", "pem_key",
        )
        self.assertIsNone(ioc.decoded_source)

    def test_str_full_value_hashes_consistently_with_bytes(self):
        text = "encoded-payload"
        ioc_str = _extract_iocs(text, b"x", "python_source")
        ioc_bytes = _extract_iocs(text.encode("utf-8"), b"x", "python_source")
        self.assertEqual(ioc_str.original_sha256, ioc_bytes.original_sha256)
        self.assertEqual(ioc_str.original_sha512, ioc_bytes.original_sha512)

    def test_includes_sha512(self):
        ioc = _extract_iocs(b"x", b"y", "python_source")
        self.assertEqual(
            ioc.original_sha512,
            hashlib.sha512(b"x").hexdigest(),
        )
        self.assertEqual(
            ioc.decoded_sha512,
            hashlib.sha512(b"y").hexdigest(),
        )

    def test_extract_timestamp_is_iso8601(self):
        ioc = _extract_iocs(b"x", b"y", "python_source")
        # ISO format includes 'T' separator and timezone marker
        self.assertIn("T", ioc.extract_timestamp)
        self.assertTrue(
            ioc.extract_timestamp.endswith("+00:00")
            or ioc.extract_timestamp.endswith("Z")
        )

    def test_invalid_utf8_in_decoded_source_falls_back_to_replace(self):
        # Bytes that aren't valid UTF-8: errors='replace' should still
        # produce a string. The function does not raise.
        invalid_utf8 = b"\xff\xfe\xfd valid text"
        ioc = _extract_iocs(b"x", invalid_utf8, "python_source")
        self.assertIsInstance(ioc.decoded_source, str)


# ---------------------------------------------------------------------------
# _dedupe_payload_findings (the main new behavior)
# ---------------------------------------------------------------------------

class DedupePayloadFindingsTests(unittest.TestCase):

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(_dedupe_payload_findings([]), [])

    def test_filters_non_payload_bearing(self):
        no_payload = _fake_finding_no_payload()
        result = _dedupe_payload_findings([no_payload])
        self.assertEqual(result, [])

    def test_single_finding_produces_single_group(self):
        finding = _fake_finding()
        result = _dedupe_payload_findings([finding])
        self.assertEqual(len(result), 1)
        primary, triggered_by = result[0]
        self.assertIs(primary, finding)
        self.assertEqual(triggered_by, ("DENS010",))

    def test_two_findings_same_payload_dedupe_to_one_group(self):
        # The canonical case: DENS010 and DENS011 both fire on the
        # same long base64 string at the same line:col.
        f1 = _fake_finding(signal_id="DENS010", full_value=b"same-payload")
        f2 = _fake_finding(signal_id="DENS011", full_value=b"same-payload")
        result = _dedupe_payload_findings([f1, f2])

        self.assertEqual(len(result), 1)
        primary, triggered_by = result[0]
        # Both HIGH severity; alphabetical wins, DENS010 < DENS011.
        self.assertEqual(primary.signal.signal_id, "DENS010")
        self.assertEqual(triggered_by, ("DENS010", "DENS011"))

    def test_findings_at_different_lines_not_deduped(self):
        f1 = _fake_finding(line=10)
        f2 = _fake_finding(line=20)
        result = _dedupe_payload_findings([f1, f2])
        self.assertEqual(len(result), 2)

    def test_findings_at_different_columns_not_deduped(self):
        f1 = _fake_finding(column=5)
        f2 = _fake_finding(column=10)
        result = _dedupe_payload_findings([f1, f2])
        self.assertEqual(len(result), 2)

    def test_findings_with_different_payloads_not_deduped(self):
        # Same location, different _full_value content -> different
        # SHA256 hashes -> different keys -> different groups.
        f1 = _fake_finding(full_value=b"payload-A")
        f2 = _fake_finding(full_value=b"payload-B")
        result = _dedupe_payload_findings([f1, f2])
        self.assertEqual(len(result), 2)

    def test_findings_at_different_paths_not_deduped(self):
        f1 = _fake_finding(internal_path="a.py")
        f2 = _fake_finding(internal_path="b.py")
        result = _dedupe_payload_findings([f1, f2])
        self.assertEqual(len(result), 2)

    def test_str_and_bytes_full_value_hash_consistently(self):
        # str gets utf-8 encoded before hashing; equivalent bytes
        # hash to the same value -> same dedup group.
        f_str = _fake_finding(signal_id="DENS010", full_value="payload-x")
        f_bytes = _fake_finding(signal_id="DENS011", full_value=b"payload-x")
        result = _dedupe_payload_findings([f_str, f_bytes])

        self.assertEqual(len(result), 1)
        _, triggered_by = result[0]
        self.assertEqual(triggered_by, ("DENS010", "DENS011"))

    def test_preserves_first_appearance_order(self):
        f_late_pos = _fake_finding(line=99)
        f_early_pos = _fake_finding(line=10)
        # f_late_pos appears first in input even though its line is
        # higher; the result preserves the input order.
        result = _dedupe_payload_findings([f_late_pos, f_early_pos])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0][0].signal.location.line, 99)
        self.assertEqual(result[1][0].signal.location.line, 10)

    def test_triggered_by_is_sorted_alphabetically(self):
        # Three findings at same location, signal_ids in arbitrary order.
        f_z = _fake_finding(signal_id="ZZZ999")
        f_a = _fake_finding(signal_id="AAA001")
        f_m = _fake_finding(signal_id="MMM005")
        result = _dedupe_payload_findings([f_z, f_a, f_m])
        self.assertEqual(len(result), 1)
        _, triggered_by = result[0]
        self.assertEqual(triggered_by, ("AAA001", "MMM005", "ZZZ999"))

    def test_duplicate_signal_ids_collapse_in_triggered_by(self):
        # Same signal_id firing twice (e.g. due to engine quirk where
        # an analyzer fires the same signal at the same line:col).
        # The set deduplication in triggered_by means we only get one
        # entry, not two.
        f1 = _fake_finding(signal_id="DENS010")
        f2 = _fake_finding(signal_id="DENS010")
        result = _dedupe_payload_findings([f1, f2])
        _, triggered_by = result[0]
        self.assertEqual(triggered_by, ("DENS010",))

    def test_full_value_is_none_filters_out(self):
        # Defensive: _full_value KEY is present but VALUE is None.
        # Should be filtered rather than crashing the hash step.
        finding = SimpleNamespace(
            signal=SimpleNamespace(
                signal_id="DENS010",
                location=SimpleNamespace(line=10, column=5),
                context={"_full_value": None, "decoded": {}},
                description="x",
            ),
            severity=Severity.HIGH,
            context=SimpleNamespace(internal_path="t.py", file_kind=None),
        )
        result = _dedupe_payload_findings([finding])
        self.assertEqual(result, [])

    def test_three_groups_with_internal_dedup(self):
        # Three different payloads, two of which have multiple
        # signals firing on them. Expected: three groups, with
        # triggered_by sets matching the inputs.
        # Group 1: location (foo.py, 10, 5) hashing payload-A
        g1_a = _fake_finding(
            signal_id="DENS010", line=10, column=5,
            internal_path="foo.py", full_value=b"payload-A",
        )
        g1_b = _fake_finding(
            signal_id="DENS011", line=10, column=5,
            internal_path="foo.py", full_value=b"payload-A",
        )
        # Group 2: location (foo.py, 20, 0) hashing payload-B
        g2 = _fake_finding(
            signal_id="DENS010", line=20, column=0,
            internal_path="foo.py", full_value=b"payload-B",
        )
        # Group 3: location (bar.py, 5, 0) hashing payload-C, with
        # three signals firing on it.
        g3_a = _fake_finding(
            signal_id="DENS010", line=5, column=0,
            internal_path="bar.py", full_value=b"payload-C",
        )
        g3_b = _fake_finding(
            signal_id="DENS011", line=5, column=0,
            internal_path="bar.py", full_value=b"payload-C",
        )
        g3_c = _fake_finding(
            signal_id="DENS050", line=5, column=0,
            internal_path="bar.py", full_value=b"payload-C",
        )

        result = _dedupe_payload_findings([g1_a, g1_b, g2, g3_a, g3_b, g3_c])
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0][1], ("DENS010", "DENS011"))
        self.assertEqual(result[1][1], ("DENS010",))
        self.assertEqual(result[2][1], ("DENS010", "DENS011", "DENS050"))


# ---------------------------------------------------------------------------
# _pick_primary_finding
# ---------------------------------------------------------------------------

class PickPrimaryFindingTests(unittest.TestCase):

    def test_single_finding_returned_directly(self):
        f = _fake_finding(signal_id="DENS010")
        self.assertIs(_pick_primary_finding([f]), f)

    def test_higher_severity_wins_over_lower(self):
        # CRITICAL beats LOW even when LOW's signal_id is alphabetically
        # earlier (severity is the dominant key).
        low = _fake_finding(signal_id="AAA999", severity=Severity.LOW)
        critical = _fake_finding(signal_id="ZZZ001", severity=Severity.CRITICAL)
        self.assertIs(_pick_primary_finding([low, critical]), critical)

    def test_alphabetical_tie_break_within_severity(self):
        f_b = _fake_finding(signal_id="DENS011", severity=Severity.HIGH)
        f_a = _fake_finding(signal_id="DENS010", severity=Severity.HIGH)
        self.assertIs(_pick_primary_finding([f_b, f_a]), f_a)

    def test_severity_order_critical_high_medium_low_info(self):
        findings_by_sev = {
            Severity.INFO: _fake_finding(
                signal_id="A", severity=Severity.INFO,
            ),
            Severity.LOW: _fake_finding(
                signal_id="A", severity=Severity.LOW,
            ),
            Severity.MEDIUM: _fake_finding(
                signal_id="A", severity=Severity.MEDIUM,
            ),
            Severity.HIGH: _fake_finding(
                signal_id="A", severity=Severity.HIGH,
            ),
            Severity.CRITICAL: _fake_finding(
                signal_id="A", severity=Severity.CRITICAL,
            ),
        }
        all_findings = list(findings_by_sev.values())
        winner = _pick_primary_finding(all_findings)
        self.assertIs(winner, findings_by_sev[Severity.CRITICAL])

    def test_high_beats_medium(self):
        high = _fake_finding(signal_id="ZZ", severity=Severity.HIGH)
        medium = _fake_finding(signal_id="AA", severity=Severity.MEDIUM)
        self.assertIs(_pick_primary_finding([medium, high]), high)


# ---------------------------------------------------------------------------
# _signal_repr
# ---------------------------------------------------------------------------

class SignalReprTests(unittest.TestCase):

    def test_single_signal_returns_outer_signal_id(self):
        node = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010",),
        )
        self.assertEqual(_signal_repr(node), "DENS010")

    def test_two_signals_joined_with_plus(self):
        node = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010", "DENS011"),
        )
        self.assertEqual(_signal_repr(node), "DENS010+DENS011")

    def test_three_signals_joined(self):
        node = _make_node(
            outer_signal_id="A",
            triggered_by=("A", "B", "C"),
        )
        self.assertEqual(_signal_repr(node), "A+B+C")

    def test_empty_triggered_by_falls_back_to_outer(self):
        # Legacy callers that construct a DecodedNode without
        # triggered_by get the empty tuple default; renderer must
        # still produce a sensible string.
        node = _make_node(outer_signal_id="LEGACY", triggered_by=())
        self.assertEqual(_signal_repr(node), "LEGACY")


# ---------------------------------------------------------------------------
# DecodedNode field defaults
# ---------------------------------------------------------------------------

class DecodedNodeFieldDefaultTests(unittest.TestCase):

    def test_default_triggered_by_is_empty_tuple(self):
        node = DecodedNode(
            outer_signal_id="X",
            outer_severity="low",
            outer_location="x.py:1:0",
            outer_length=0,
            chain=(),
            unwrap_status="completed",
            final_kind="python_source",
            final_size=0,
            indicators=(),
            pickle_warning=False,
            depth=0,
            stop_reason=STOP_NO_INNER_FINDINGS,
        )
        self.assertEqual(node.triggered_by, ())

    def test_explicit_triggered_by_preserved(self):
        node = DecodedNode(
            outer_signal_id="DENS010",
            outer_severity="high",
            outer_location="x.py:1:0",
            outer_length=0,
            chain=(),
            unwrap_status="completed",
            final_kind="python_source",
            final_size=0,
            indicators=(),
            pickle_warning=False,
            depth=0,
            stop_reason=STOP_NO_INNER_FINDINGS,
            triggered_by=("DENS010", "DENS011"),
        )
        self.assertEqual(node.triggered_by, ("DENS010", "DENS011"))

    def test_node_is_frozen(self):
        node = _make_node()
        with self.assertRaises(Exception):
            node.outer_signal_id = "changed"


# ---------------------------------------------------------------------------
# render_text
# ---------------------------------------------------------------------------

class RenderTextTests(unittest.TestCase):

    def test_empty_tree(self):
        tree = DecodedTree(target="foo.tar.gz", max_depth=3, nodes=())
        out = render_text(tree)
        self.assertIn("decoded payload report for foo.tar.gz", out)
        self.assertIn("max recursion depth: 3", out)
        self.assertIn("(no payload-bearing findings", out)

    def test_single_node_renders_signal_id(self):
        node = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010",),
        )
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        # Header line: 'foo.py:10:5 (DENS010, length 100)'
        self.assertIn("(DENS010, length 100)", out)
        # No '+' in the signal id portion since only one signal.
        # We slice out the part right after '(DENS010' to confirm it
        # ends with ',' (i.e. no '+ANOTHER').
        idx = out.find("(DENS010")
        self.assertEqual(out[idx + len("(DENS010")], ",")

    def test_multi_signal_node_renders_with_plus(self):
        node = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010", "DENS011"),
        )
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        self.assertIn("(DENS010+DENS011, length 100)", out)

    def test_three_signals_render_with_plusses(self):
        node = _make_node(
            outer_signal_id="A",
            triggered_by=("A", "B", "C"),
        )
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        self.assertIn("(A+B+C, length 100)", out)

    def test_stop_reason_depth_limit_annotated(self):
        node = _make_node(stop_reason=STOP_DEPTH_LIMIT)
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        self.assertIn("recursion depth limit reached", out)

    def test_stop_reason_non_python_annotated(self):
        node = _make_node(
            stop_reason=STOP_NON_PYTHON,
            final_kind="pem_key",
            chain=("base64",),
        )
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        self.assertIn("not Python source", out)

    def test_stop_reason_decode_failed_annotated(self):
        node = _make_node(
            stop_reason=STOP_DECODE_FAILED,
            unwrap_status="exhausted_budget",
        )
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        self.assertIn("decode failed", out)
        self.assertIn("exhausted_budget", out)

    def test_indicators_listed(self):
        node = _make_node(indicators=("subprocess", "os.system"))
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        self.assertIn("subprocess", out)
        self.assertIn("os.system", out)

    def test_pickle_warning_appears_when_set(self):
        node = _make_node(pickle_warning=True)
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        self.assertIn("pickle", out.lower())
        self.assertIn("not deserialized", out.lower())

    def test_child_findings_listed(self):
        cf = ChildFinding(
            signal_id="DYN002",
            severity="high",
            line=15,
            column=0,
            description="exec call",
        )
        node = _make_node(child_findings=(cf,))
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        self.assertIn("DYN002 high at line 15:0", out)
        self.assertIn("exec call", out)

    def test_nested_children_render_under_outer(self):
        inner = _make_node(
            outer_signal_id="DENS011",
            triggered_by=("DENS011",),
            outer_location="foo.py:20:0",
            depth=1,
        )
        outer = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010",),
            outer_location="foo.py:10:0",
            children=(inner,),
        )
        tree = DecodedTree(target="x", max_depth=3, nodes=(outer,))
        out = render_text(tree)
        self.assertIn("(DENS010, length 100)", out)
        self.assertIn("DENS011 high at line", out)

    def test_nested_multi_signal_child_renders_with_plus(self):
        inner = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010", "DENS011"),
            outer_location="foo.py:20:0",
            depth=1,
        )
        outer = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010",),
            outer_location="foo.py:10:0",
            children=(inner,),
        )
        tree = DecodedTree(target="x", max_depth=3, nodes=(outer,))
        out = render_text(tree)
        # The inner child's connector line should show 'DENS010+DENS011'
        self.assertIn("DENS010+DENS011 high at line", out)

    def test_iocs_section_omitted_by_default(self):
        node = _make_node()
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree)
        self.assertNotIn("IOC (INDICATORS OF COMPROMISE)", out)

    def test_iocs_section_included_when_requested(self):
        ioc = IOCData(
            original_sha256="a" * 64,
            decoded_sha256="b" * 64,
            decoded_source="x = 1\n",
            extract_timestamp="2026-04-29T12:00:00+00:00",
        )
        node = _make_node(ioc_data=ioc)
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_text(tree, include_iocs=True)
        self.assertIn("IOC (INDICATORS OF COMPROMISE)", out)
        self.assertIn("a" * 64, out)  # original_sha256
        self.assertIn("b" * 64, out)  # decoded_sha256


# ---------------------------------------------------------------------------
# render_json
# ---------------------------------------------------------------------------

class RenderJSONTests(unittest.TestCase):

    def test_empty_tree_produces_valid_json(self):
        tree = DecodedTree(target="foo", max_depth=3, nodes=())
        out = render_decode_json(tree)
        parsed = json.loads(out)
        self.assertEqual(parsed["target"], "foo")
        self.assertEqual(parsed["max_depth"], 3)
        self.assertEqual(parsed["nodes"], [])

    def test_node_includes_triggered_by(self):
        node = _make_node(triggered_by=("DENS010", "DENS011"))
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        parsed = json.loads(render_decode_json(tree))
        self.assertEqual(
            parsed["nodes"][0]["triggered_by"],
            ["DENS010", "DENS011"],
        )

    def test_node_includes_outer_signal_id(self):
        node = _make_node(outer_signal_id="DENS010")
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        parsed = json.loads(render_decode_json(tree))
        self.assertEqual(parsed["nodes"][0]["outer_signal_id"], "DENS010")

    def test_node_serializes_all_basic_fields(self):
        node = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010",),
            outer_location="foo.py:10:5",
            outer_length=100,
            chain=("base64",),
            final_kind="python_source",
            final_size=2048,
            indicators=("subprocess",),
            pickle_warning=False,
            depth=0,
            stop_reason=STOP_LEAF_TERMINAL,
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        parsed = json.loads(render_decode_json(tree))
        n = parsed["nodes"][0]
        self.assertEqual(n["outer_signal_id"], "DENS010")
        self.assertEqual(n["triggered_by"], ["DENS010"])
        self.assertEqual(n["outer_location"], "foo.py:10:5")
        self.assertEqual(n["outer_length"], 100)
        self.assertEqual(n["chain"], ["base64"])
        self.assertEqual(n["final_kind"], "python_source")
        self.assertEqual(n["final_size"], 2048)
        self.assertEqual(n["indicators"], ["subprocess"])
        self.assertFalse(n["pickle_warning"])
        self.assertEqual(n["depth"], 0)
        self.assertEqual(n["stop_reason"], STOP_LEAF_TERMINAL)

    def test_ioc_data_included_when_present(self):
        ioc = IOCData(
            original_sha256="abc",
            decoded_sha256="def",
            decoded_source="x = 1",
            extract_timestamp="2026-04-29T12:00:00+00:00",
        )
        node = _make_node(ioc_data=ioc)
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        parsed = json.loads(render_decode_json(tree))
        self.assertIn("ioc_data", parsed["nodes"][0])
        self.assertEqual(
            parsed["nodes"][0]["ioc_data"]["original_sha256"], "abc",
        )
        self.assertEqual(
            parsed["nodes"][0]["ioc_data"]["decoded_source"], "x = 1",
        )

    def test_ioc_data_omitted_when_none(self):
        node = _make_node(ioc_data=None)
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        parsed = json.loads(render_decode_json(tree))
        self.assertNotIn("ioc_data", parsed["nodes"][0])

    def test_recursive_children_serialize(self):
        inner = _make_node(outer_signal_id="DENS011", depth=1)
        outer = _make_node(outer_signal_id="DENS010", children=(inner,))
        tree = DecodedTree(target="x", max_depth=3, nodes=(outer,))
        parsed = json.loads(render_decode_json(tree))
        self.assertEqual(len(parsed["nodes"][0]["children"]), 1)
        self.assertEqual(
            parsed["nodes"][0]["children"][0]["outer_signal_id"],
            "DENS011",
        )

    def test_child_findings_serialize(self):
        cf = ChildFinding(
            signal_id="DYN002",
            severity="high",
            line=15,
            column=0,
            description="exec call",
        )
        node = _make_node(child_findings=(cf,))
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        parsed = json.loads(render_decode_json(tree))
        cfs = parsed["nodes"][0]["child_findings"]
        self.assertEqual(len(cfs), 1)
        self.assertEqual(cfs[0]["signal_id"], "DYN002")
        self.assertEqual(cfs[0]["severity"], "high")
        self.assertEqual(cfs[0]["line"], 15)
        self.assertEqual(cfs[0]["column"], 0)
        self.assertEqual(cfs[0]["description"], "exec call")


# ---------------------------------------------------------------------------
# decode_payloads driver (integration with mock engine, patched unwrap)
# ---------------------------------------------------------------------------

class DecodePayloadsDriverTests(unittest.TestCase):

    def test_empty_findings_produces_empty_tree(self):
        result = _fake_scan_result([])
        engine = _MockEngine({})
        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
        )
        self.assertEqual(tree.nodes, ())
        self.assertEqual(tree.target, "test-target.tar.gz")
        self.assertEqual(tree.max_depth, 3)

    def test_non_payload_bearing_findings_filtered(self):
        leaf = _fake_finding_no_payload()
        result = _fake_scan_result([leaf])
        engine = _MockEngine({})
        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
        )
        self.assertEqual(tree.nodes, ())
        # Engine never called (no payload-bearing findings).
        self.assertEqual(engine.calls, [])

    @patch("pydepgate.enrichers.decode_payloads.unwrap")
    def test_single_payload_finding_produces_one_node(self, mock_unwrap):
        # unwrap returns python_source with no inner findings.
        decoded_bytes = b"x = 1\n"
        mock_unwrap.return_value = _fake_unwrap_result(
            chain=(_fake_layer("base64"),),
            status="completed",
            final_kind="python_source",
            final_bytes=decoded_bytes,
        )
        finding = _fake_finding(
            signal_id="DENS010",
            full_value=b"encoded-payload",
        )
        result = _fake_scan_result([finding])
        # Engine returns no inner findings for the decoded bytes.
        engine = _MockEngine({decoded_bytes: []})

        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
        )
        self.assertEqual(len(tree.nodes), 1)
        node = tree.nodes[0]
        self.assertEqual(node.outer_signal_id, "DENS010")
        self.assertEqual(node.triggered_by, ("DENS010",))
        self.assertEqual(node.chain, ("base64",))
        # No inner findings -> stop reason is no_inner_findings
        self.assertEqual(node.stop_reason, STOP_NO_INNER_FINDINGS)

    @patch("pydepgate.enrichers.decode_payloads.unwrap")
    def test_two_findings_same_payload_dedupe_at_top_level(self, mock_unwrap):
        # DENS010 and DENS011 both fire on the same _full_value at the
        # same location. The driver should produce ONE node, not two,
        # with both signal_ids in triggered_by.
        decoded_bytes = b"x = 1\n"
        mock_unwrap.return_value = _fake_unwrap_result(
            chain=(_fake_layer("base64"),),
            status="completed",
            final_kind="python_source",
            final_bytes=decoded_bytes,
        )
        f1 = _fake_finding(signal_id="DENS010", full_value=b"same-payload")
        f2 = _fake_finding(signal_id="DENS011", full_value=b"same-payload")
        result = _fake_scan_result([f1, f2])
        engine = _MockEngine({decoded_bytes: []})

        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
        )
        self.assertEqual(len(tree.nodes), 1)
        self.assertEqual(tree.nodes[0].triggered_by, ("DENS010", "DENS011"))
        # Engine called exactly once (for the deduped payload),
        # not twice.
        self.assertEqual(len(engine.calls), 1)

    @patch("pydepgate.enrichers.decode_payloads.unwrap")
    def test_depth_limit_stops_recursion(self, mock_unwrap):
        # max_depth=0 means we never call the engine; the outer
        # finding is recorded as a depth_limit leaf.
        mock_unwrap.return_value = _fake_unwrap_result(
            chain=(_fake_layer("base64"),),
            status="completed",
            final_kind="python_source",
            final_bytes=b"x = 1\n",
        )
        finding = _fake_finding(full_value=b"payload")
        result = _fake_scan_result([finding])
        engine = _MockEngine({})

        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=0,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
        )
        self.assertEqual(len(tree.nodes), 1)
        self.assertEqual(tree.nodes[0].stop_reason, STOP_DEPTH_LIMIT)
        # Engine never invoked when depth limit hit at top level.
        self.assertEqual(engine.calls, [])

    @patch("pydepgate.enrichers.decode_payloads.unwrap")
    def test_non_python_terminal_stops_recursion(self, mock_unwrap):
        mock_unwrap.return_value = _fake_unwrap_result(
            chain=(_fake_layer("base64"),),
            status="completed",
            final_kind="pem_key",
            final_bytes=b"-----BEGIN RSA PRIVATE KEY-----\n...",
        )
        finding = _fake_finding(full_value=b"payload")
        result = _fake_scan_result([finding])
        engine = _MockEngine({})

        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
        )
        self.assertEqual(len(tree.nodes), 1)
        self.assertEqual(tree.nodes[0].stop_reason, STOP_NON_PYTHON)
        self.assertEqual(tree.nodes[0].final_kind, "pem_key")
        # Engine not called for non-Python terminals.
        self.assertEqual(engine.calls, [])

    @patch("pydepgate.enrichers.decode_payloads.unwrap")
    def test_decode_failed_stops_recursion(self, mock_unwrap):
        mock_unwrap.return_value = _fake_unwrap_result(
            chain=(),
            status="decode_error",
            final_kind="binary_unknown",
            final_bytes=b"",
        )
        finding = _fake_finding(full_value=b"garbage")
        result = _fake_scan_result([finding])
        engine = _MockEngine({})

        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
        )
        self.assertEqual(len(tree.nodes), 1)
        self.assertEqual(tree.nodes[0].stop_reason, STOP_DECODE_FAILED)
        self.assertEqual(engine.calls, [])

    @patch("pydepgate.enrichers.decode_payloads.unwrap")
    def test_recursive_dedup_at_inner_layer(self, mock_unwrap):
        # Outer payload decodes to inner Python source. The inner
        # scan returns two findings firing on the same inner payload
        # (DENS010 and DENS011). The child node should be ONE node
        # with both in triggered_by.
        outer_decoded = b"# inner payload follows\n"
        inner_decoded = b"import os\nos.system('rm -rf /')\n"

        # First call: outer payload -> python_source
        # Second call: inner payload -> python_source with leaf finding
        def unwrap_side_effect(value, *, max_depth, max_budget):
            if value == b"outer-payload":
                return _fake_unwrap_result(
                    chain=(_fake_layer("base64"),),
                    status="completed",
                    final_kind="python_source",
                    final_bytes=outer_decoded,
                )
            elif value == b"inner-payload":
                return _fake_unwrap_result(
                    chain=(_fake_layer("base64"),),
                    status="completed",
                    final_kind="python_source",
                    final_bytes=inner_decoded,
                )
            else:
                return _fake_unwrap_result(
                    chain=(),
                    status="decode_error",
                    final_kind="binary_unknown",
                    final_bytes=b"",
                )

        mock_unwrap.side_effect = unwrap_side_effect

        # Outer finding's payload is 'outer-payload'.
        outer_finding = _fake_finding(
            signal_id="DENS010",
            full_value=b"outer-payload",
        )
        # Engine response for outer_decoded: two findings on the
        # same inner payload (the dedup case).
        inner_f1 = _fake_finding(
            signal_id="DENS010",
            full_value=b"inner-payload",
            line=2, column=0,
        )
        inner_f2 = _fake_finding(
            signal_id="DENS011",
            full_value=b"inner-payload",
            line=2, column=0,
        )
        # Engine response for inner_decoded: one leaf finding (no
        # further payload).
        inner_leaf = _fake_finding_no_payload(
            signal_id="DYN002",
            line=2, column=0,
            description="os.system call",
        )

        engine = _MockEngine({
            outer_decoded: [inner_f1, inner_f2],
            inner_decoded: [inner_leaf],
        })
        result = _fake_scan_result([outer_finding])

        tree = decode_payloads(
            result,
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
        )
        # One outer node, one inner node (deduped from two findings).
        self.assertEqual(len(tree.nodes), 1)
        outer_node = tree.nodes[0]
        self.assertEqual(len(outer_node.children), 1)
        inner_node = outer_node.children[0]
        # The inner node has both signals in triggered_by.
        self.assertEqual(inner_node.triggered_by, ("DENS010", "DENS011"))
        # The inner scan was called once (deduped), not twice.
        # Engine was called twice total: once for outer_decoded,
        # once for inner_decoded.
        self.assertEqual(len(engine.calls), 2)

    @patch("pydepgate.enrichers.decode_payloads.unwrap")
    def test_inner_leaf_findings_collected_as_child_findings(self, mock_unwrap):
        outer_decoded = b"import subprocess\n"
        mock_unwrap.return_value = _fake_unwrap_result(
            chain=(_fake_layer("base64"),),
            status="completed",
            final_kind="python_source",
            final_bytes=outer_decoded,
        )
        outer_finding = _fake_finding(full_value=b"outer-payload")
        # Engine returns two leaf findings (no payloads) on the
        # decoded bytes.
        leaf1 = _fake_finding_no_payload(signal_id="STDLIB001", line=1)
        leaf2 = _fake_finding_no_payload(signal_id="DYN002", line=2)
        engine = _MockEngine({outer_decoded: [leaf1, leaf2]})

        tree = decode_payloads(
            _fake_scan_result([outer_finding]),
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
        )
        node = tree.nodes[0]
        # No recursive children, two leaf child findings.
        self.assertEqual(node.children, ())
        self.assertEqual(len(node.child_findings), 2)
        self.assertEqual(
            {cf.signal_id for cf in node.child_findings},
            {"STDLIB001", "DYN002"},
        )

    @patch("pydepgate.enrichers.decode_payloads.unwrap")
    def test_extract_iocs_populates_ioc_data(self, mock_unwrap):
        decoded_bytes = b"x = 1\n"
        mock_unwrap.return_value = _fake_unwrap_result(
            chain=(_fake_layer("base64"),),
            status="completed",
            final_kind="python_source",
            final_bytes=decoded_bytes,
        )
        finding = _fake_finding(full_value=b"encoded-payload")
        engine = _MockEngine({decoded_bytes: []})

        tree = decode_payloads(
            _fake_scan_result([finding]),
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
            extract_iocs=True,
        )
        node = tree.nodes[0]
        self.assertIsNotNone(node.ioc_data)
        self.assertEqual(
            node.ioc_data.original_sha256,
            hashlib.sha256(b"encoded-payload").hexdigest(),
        )
        self.assertEqual(
            node.ioc_data.decoded_sha256,
            hashlib.sha256(decoded_bytes).hexdigest(),
        )

    @patch("pydepgate.enrichers.decode_payloads.unwrap")
    def test_extract_iocs_false_leaves_ioc_data_none(self, mock_unwrap):
        decoded_bytes = b"x = 1\n"
        mock_unwrap.return_value = _fake_unwrap_result(
            chain=(_fake_layer("base64"),),
            status="completed",
            final_kind="python_source",
            final_bytes=decoded_bytes,
        )
        finding = _fake_finding(full_value=b"encoded-payload")
        engine = _MockEngine({decoded_bytes: []})

        tree = decode_payloads(
            _fake_scan_result([finding]),
            engine=engine,
            max_depth=3,
            peek_min_length=80,
            peek_max_depth=4,
            peek_max_budget=10_000_000,
            extract_iocs=False,
        )
        self.assertIsNone(tree.nodes[0].ioc_data)
        
def _make_ioc(
    *,
    original_sha256: str = "a" * 64,
    original_sha512: str = "a" * 128,
    decoded_sha256: str = "b" * 64,
    decoded_sha512: str = "b" * 128,
    decoded_source: str | None = None,
    extract_timestamp: str = "2026-04-29T12:00:00+00:00",
) -> IOCData:
    return IOCData(
        original_sha256=original_sha256,
        original_sha512=original_sha512,
        decoded_sha256=decoded_sha256,
        decoded_sha512=decoded_sha512,
        decoded_source=decoded_source,
        extract_timestamp=extract_timestamp,
    )
 
 
def _make_node(
    *,
    outer_signal_id: str = "DENS010",
    outer_severity: str = "high",
    triggered_by: tuple[str, ...] = ("DENS010",),
    outer_location: str = "foo.py:10:5",
    chain: tuple[str, ...] = ("base64",),
    final_kind: str = "python_source",
    final_size: int = 0,
    children: tuple[DecodedNode, ...] = (),
    child_findings: tuple[ChildFinding, ...] = (),
    stop_reason: str = STOP_LEAF_TERMINAL,
    indicators: tuple[str, ...] = (),
    pickle_warning: bool = False,
    depth: int = 0,
    ioc_data: IOCData | None = None,
    outer_length: int = 100,
    unwrap_status: str = "completed",
) -> DecodedNode:
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
        ioc_data=ioc_data,
    )
 
 
# ---------------------------------------------------------------------------
# render_sources
# ---------------------------------------------------------------------------
 
class RenderSourcesTests(unittest.TestCase):
 
    def test_empty_tree_produces_stub(self):
        tree = DecodedTree(target="foo.whl", max_depth=3, nodes=())
        out = render_sources(tree)
        self.assertIn("decoded source dumps for foo.whl", out)
        self.assertIn("no decoded python_source terminals", out)
 
    def test_tree_with_no_ioc_data_produces_stub(self):
        node = _make_node(ioc_data=None)
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_sources(tree)
        self.assertIn("no decoded python_source terminals", out)
 
    def test_tree_with_ioc_but_no_decoded_source_produces_stub(self):
        # A non-python_source terminal: ioc_data exists but
        # decoded_source is None.
        ioc = _make_ioc(decoded_source=None)
        node = _make_node(final_kind="pem_key", ioc_data=ioc)
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_sources(tree)
        self.assertIn("no decoded python_source terminals", out)
 
    def test_single_python_source_node_renders(self):
        ioc = _make_ioc(decoded_source="import os\nos.system('ls')\n")
        node = _make_node(
            outer_location="foo.py:10:5",
            chain=("base64",),
            final_kind="python_source",
            final_size=27,
            ioc_data=ioc,
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        out = render_sources(tree)
 
        self.assertIn("# Source #1: foo.py:10:5 (DENS010)", out)
        self.assertIn("# chain: base64 -> python_source (27 bytes)", out)
        self.assertIn("# original SHA256:", out)
        self.assertIn("# decoded SHA256:", out)
        # Source body, line-numbered.
        self.assertIn("    1: import os", out)
        self.assertIn("    2: os.system('ls')", out)
 
    def test_multi_signal_node_uses_plus_in_header(self):
        ioc = _make_ioc(decoded_source="x = 1\n")
        node = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010", "DENS011"),
            ioc_data=ioc,
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        out = render_sources(tree)
        self.assertIn("(DENS010+DENS011)", out)
 
    def test_multiple_python_source_nodes_each_get_block(self):
        ioc1 = _make_ioc(decoded_source="x = 1\n", decoded_sha256="1" * 64)
        ioc2 = _make_ioc(decoded_source="y = 2\n", decoded_sha256="2" * 64)
        n1 = _make_node(outer_location="a.py:1:0", ioc_data=ioc1)
        n2 = _make_node(outer_location="b.py:5:0", ioc_data=ioc2)
        tree = DecodedTree(target="t", max_depth=3, nodes=(n1, n2))
        out = render_sources(tree)
 
        self.assertIn("# Source #1: a.py:1:0", out)
        self.assertIn("# Source #2: b.py:5:0", out)
        self.assertIn("1: x = 1", out)
        self.assertIn("1: y = 2", out)
 
    def test_recursive_children_collected(self):
        inner_ioc = _make_ioc(decoded_source="exec('evil')\n")
        inner = _make_node(
            outer_signal_id="DENS011",
            outer_location="foo.py:20:0",
            depth=1,
            ioc_data=inner_ioc,
        )
        outer_ioc = _make_ioc(decoded_source="# outer\n")
        outer = _make_node(
            outer_signal_id="DENS010",
            outer_location="foo.py:10:0",
            children=(inner,),
            ioc_data=outer_ioc,
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(outer,))
        out = render_sources(tree)
 
        # Both the outer and inner should appear, in DFS order.
        outer_pos = out.find("# Source #1: foo.py:10:0")
        inner_pos = out.find("# Source #2: foo.py:20:0")
        self.assertGreater(outer_pos, -1)
        self.assertGreater(inner_pos, -1)
        self.assertLess(outer_pos, inner_pos)
 
 
# ---------------------------------------------------------------------------
# render_iocs
# ---------------------------------------------------------------------------
 
class RenderIocsTests(unittest.TestCase):
 
    def test_empty_tree_produces_stub(self):
        tree = DecodedTree(target="foo.whl", max_depth=3, nodes=())
        out = render_iocs(tree)
        self.assertIn("# IOC hash records for foo.whl", out)
        self.assertIn("no IOC data extracted", out)
 
    def test_tree_with_no_ioc_data_produces_stub(self):
        node = _make_node(ioc_data=None)
        tree = DecodedTree(target="x", max_depth=3, nodes=(node,))
        out = render_iocs(tree)
        self.assertIn("no IOC data extracted", out)
 
    def test_single_node_produces_all_hash_lines(self):
        ioc = _make_ioc(
            original_sha256="o" * 64,
            original_sha512="O" * 128,
            decoded_sha256="d" * 64,
            decoded_sha512="D" * 128,
        )
        node = _make_node(
            outer_location="foo.py:10:5",
            chain=("base64",),
            final_size=42,
            ioc_data=ioc,
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        out = render_iocs(tree)
 
        self.assertIn(f"original_sha256 {'o' * 64}", out)
        self.assertIn(f"original_sha512 {'O' * 128}", out)
        self.assertIn(f"decoded_sha256  {'d' * 64}", out)
        self.assertIn(f"decoded_sha512  {'D' * 128}", out)
 
    def test_hash_lines_have_two_token_shape(self):
        # Important for grep/awk: lines starting with hash type
        # have exactly TYPE + whitespace + HASH.
        ioc = _make_ioc()
        node = _make_node(ioc_data=ioc)
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        out = render_iocs(tree)
 
        for line in out.splitlines():
            if line.startswith("decoded_sha256 "):
                tokens = line.split()
                self.assertEqual(len(tokens), 2)
                # Type prefix has no spaces.
                self.assertEqual(tokens[0], "decoded_sha256")
                # Hash is hex-only.
                self.assertEqual(len(tokens[1]), 64)
                self.assertTrue(all(c in "0123456789abcdef" for c in tokens[1]))
 
    def test_chain_summary_appears_when_chain_set(self):
        ioc = _make_ioc()
        node = _make_node(
            chain=("base64", "zlib"),
            final_kind="python_source",
            final_size=1024,
            ioc_data=ioc,
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        out = render_iocs(tree)
        self.assertIn("chain: base64 -> zlib -> python_source (1024 bytes)", out)
 
    def test_extracted_timestamp_included(self):
        ioc = _make_ioc(extract_timestamp="2026-04-29T12:34:56+00:00")
        node = _make_node(ioc_data=ioc)
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        out = render_iocs(tree)
        self.assertIn("extracted: 2026-04-29T12:34:56+00:00", out)
 
    def test_multi_signal_header_uses_plus(self):
        ioc = _make_ioc()
        node = _make_node(
            outer_signal_id="DENS010",
            triggered_by=("DENS010", "DENS011"),
            ioc_data=ioc,
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        out = render_iocs(tree)
        self.assertIn("(DENS010+DENS011)", out)
 
    def test_multiple_nodes_all_appear_dfs_order(self):
        n1 = _make_node(
            outer_location="a.py:1:0",
            ioc_data=_make_ioc(decoded_sha256="1" * 64),
        )
        inner = _make_node(
            outer_location="a.py:5:0",
            depth=1,
            ioc_data=_make_ioc(decoded_sha256="2" * 64),
        )
        n2 = _make_node(
            outer_location="a.py:10:0",
            children=(inner,),
            ioc_data=_make_ioc(decoded_sha256="3" * 64),
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(n1, n2))
        out = render_iocs(tree)
 
        self.assertIn("# IOC #1: a.py:1:0", out)
        self.assertIn("# IOC #2: a.py:10:0", out)
        self.assertIn("# IOC #3: a.py:5:0", out)
 
 
# ---------------------------------------------------------------------------
# filter_tree_by_severity
# ---------------------------------------------------------------------------
 
class FilterTreeBySeverityTests(unittest.TestCase):
 
    def test_none_min_severity_returns_tree_unchanged(self):
        node = _make_node(outer_severity="low")
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        result = filter_tree_by_severity(tree, None)
        self.assertIs(result, tree)
 
    def test_threshold_below_info_acts_as_no_filter(self):
        # An int rank of 0 (or unknown string) means "no filter"
        # because INFO is the lowest defined level.
        node = _make_node(outer_severity="info")
        tree = DecodedTree(target="t", max_depth=3, nodes=(node,))
        result = filter_tree_by_severity(tree, "garbage")
        # garbage maps to rank 0, which the function treats as
        # "return original tree".
        self.assertIs(result, tree)
 
    def test_critical_threshold_drops_high(self):
        high_node = _make_node(outer_severity="high")
        tree = DecodedTree(target="t", max_depth=3, nodes=(high_node,))
        result = filter_tree_by_severity(tree, "critical")
        self.assertEqual(result.nodes, ())
 
    def test_critical_threshold_keeps_critical(self):
        crit_node = _make_node(outer_severity="critical")
        tree = DecodedTree(target="t", max_depth=3, nodes=(crit_node,))
        result = filter_tree_by_severity(tree, "critical")
        self.assertEqual(len(result.nodes), 1)
 
    def test_low_threshold_keeps_everything(self):
        n1 = _make_node(outer_severity="low")
        n2 = _make_node(outer_severity="critical")
        tree = DecodedTree(target="t", max_depth=3, nodes=(n1, n2))
        result = filter_tree_by_severity(tree, "low")
        self.assertEqual(len(result.nodes), 2)
 
    def test_keep_low_parent_when_critical_descendant(self):
        # Core "keep for context" rule: a low-severity outer finding
        # whose decoded payload contains a critical inner finding
        # must stay so the chain is preserved.
        crit_child = _make_node(outer_severity="critical", depth=1)
        low_parent = _make_node(
            outer_severity="low",
            children=(crit_child,),
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(low_parent,))
        result = filter_tree_by_severity(tree, "high")
 
        self.assertEqual(len(result.nodes), 1)
        self.assertEqual(result.nodes[0].outer_severity, "low")
        self.assertEqual(len(result.nodes[0].children), 1)
        self.assertEqual(
            result.nodes[0].children[0].outer_severity, "critical",
        )
 
    def test_keep_low_parent_when_high_child_finding(self):
        # The same "keep for context" rule for child_findings (leaf,
        # non-recursive findings).
        cf_high = ChildFinding(
            signal_id="DYN002",
            severity="high",
            line=15, column=0,
            description="exec call",
        )
        low_parent = _make_node(
            outer_severity="low",
            child_findings=(cf_high,),
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(low_parent,))
        result = filter_tree_by_severity(tree, "high")
 
        self.assertEqual(len(result.nodes), 1)
        self.assertEqual(result.nodes[0].outer_severity, "low")
        # The high child_finding survives.
        self.assertEqual(len(result.nodes[0].child_findings), 1)
 
    def test_strict_filter_on_child_findings(self):
        # child_findings are filtered strictly by their own severity.
        # A critical parent does NOT promote its low-severity
        # child_findings.
        cf_low = ChildFinding(
            signal_id="X1", severity="low", line=1, column=0, description="x",
        )
        cf_high = ChildFinding(
            signal_id="X2", severity="high", line=2, column=0, description="x",
        )
        crit_parent = _make_node(
            outer_severity="critical",
            child_findings=(cf_low, cf_high),
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(crit_parent,))
        result = filter_tree_by_severity(tree, "high")
 
        self.assertEqual(len(result.nodes), 1)
        # Only the high one survives.
        self.assertEqual(len(result.nodes[0].child_findings), 1)
        self.assertEqual(
            result.nodes[0].child_findings[0].signal_id, "X2",
        )
 
    def test_drop_low_parent_when_only_low_descendants(self):
        # If neither own severity nor any descendant meets threshold,
        # the node is dropped entirely.
        low_child = _make_node(outer_severity="low", depth=1)
        low_parent = _make_node(
            outer_severity="low",
            children=(low_child,),
        )
        tree = DecodedTree(target="t", max_depth=3, nodes=(low_parent,))
        result = filter_tree_by_severity(tree, "high")
        self.assertEqual(result.nodes, ())
 
    def test_accepts_severity_enum(self):
        crit_node = _make_node(outer_severity="critical")
        tree = DecodedTree(target="t", max_depth=3, nodes=(crit_node,))
        result = filter_tree_by_severity(tree, Severity.CRITICAL)
        self.assertEqual(len(result.nodes), 1)
 
    def test_accepts_severity_string_case_insensitive(self):
        crit_node = _make_node(outer_severity="critical")
        tree = DecodedTree(target="t", max_depth=3, nodes=(crit_node,))
        result_upper = filter_tree_by_severity(tree, "CRITICAL")
        result_lower = filter_tree_by_severity(tree, "critical")
        self.assertEqual(len(result_upper.nodes), 1)
        self.assertEqual(len(result_lower.nodes), 1)
 
    def test_returns_new_tree_does_not_mutate_original(self):
        # Frozen dataclasses can't be mutated anyway, but the function
        # should still return a different object when filtering occurs.
        low_node = _make_node(outer_severity="low")
        tree = DecodedTree(target="t", max_depth=3, nodes=(low_node,))
        result = filter_tree_by_severity(tree, "high")
        self.assertIsNot(result, tree)
        # Original tree still has its node.
        self.assertEqual(len(tree.nodes), 1)
        # Filtered tree does not.
        self.assertEqual(result.nodes, ())
 
    def test_target_and_max_depth_preserved(self):
        crit_node = _make_node(outer_severity="critical")
        tree = DecodedTree(target="my-target.whl", max_depth=5, nodes=(crit_node,))
        result = filter_tree_by_severity(tree, "high")
        self.assertEqual(result.target, "my-target.whl")
        self.assertEqual(result.max_depth, 5)
 
    def test_deeply_nested_keep_for_context(self):
        # Five levels deep, only the deepest is critical. Every
        # ancestor should be kept.
        depth4 = _make_node(outer_severity="critical", depth=4)
        depth3 = _make_node(outer_severity="low", depth=3, children=(depth4,))
        depth2 = _make_node(outer_severity="low", depth=2, children=(depth3,))
        depth1 = _make_node(outer_severity="low", depth=1, children=(depth2,))
        depth0 = _make_node(outer_severity="low", depth=0, children=(depth1,))
        tree = DecodedTree(target="t", max_depth=5, nodes=(depth0,))
 
        result = filter_tree_by_severity(tree, "critical")
 
        # Walk the chain: each level should have exactly one child.
        n = result.nodes[0]
        for expected_severity in ["low", "low", "low", "low", "critical"]:
            self.assertEqual(n.outer_severity, expected_severity)
            if expected_severity == "critical":
                break
            self.assertEqual(len(n.children), 1)
            n = n.children[0]

if __name__ == "__main__":
    unittest.main()