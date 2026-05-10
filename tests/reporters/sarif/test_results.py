"""Tests for SARIF result generation."""

from __future__ import annotations

import unittest

from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.engines.base import Severity
from pydepgate.parsers.pysource import SourceLocation
from pydepgate.reporters.sarif.results import make_result

# Fixture indices map. Real SARIF documents pull these
# from Phase B's make_rules_array(); tests use a small
# synthetic map to keep fixture data independent.
SAMPLE_INDICES = {
    "DENS010": 5,
    "DYN002": 7,
    "STR001": 12,
    "STDLIB001": 20,
}


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
    """Construct a synthetic Signal for testing.

    Defaults match a typical density-analyzer finding at
    module scope. Tests override specific fields per case.
    """
    return Signal(
        analyzer=analyzer,
        signal_id=signal_id,
        confidence=confidence,
        scope=scope,
        location=SourceLocation(line=line, column=column),
        description=description,
        context=context if context is not None else {},
    )


class TestBasicShape(unittest.TestCase):
    """make_result returns a well-formed dict."""

    def test_returns_dict(self):
        signal = _make_signal()
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertIsInstance(result, dict)

    def test_rule_id_is_signal_id(self):
        signal = _make_signal(signal_id="DENS010")
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["ruleId"], "DENS010")

    def test_rule_index_from_indices_map(self):
        signal = _make_signal(signal_id="DENS010")
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["ruleIndex"], 5)

    def test_message_text_from_description(self):
        signal = _make_signal(description="bad pattern detected")
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["message"]["text"], "bad pattern detected")

    def test_unknown_signal_id_raises_key_error(self):
        # If the indices map is missing the signal_id, we
        # want a loud failure rather than malformed SARIF.
        signal = _make_signal(signal_id="UNKNOWN_SIGNAL")
        with self.assertRaises(KeyError):
            make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)


class TestLevelMapping(unittest.TestCase):
    """All severity values produce the expected SARIF level."""

    def test_critical_produces_error(self):
        signal = _make_signal()
        result = make_result(signal, Severity.CRITICAL, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["level"], "error")

    def test_high_produces_error(self):
        signal = _make_signal()
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["level"], "error")

    def test_medium_produces_warning(self):
        signal = _make_signal()
        result = make_result(signal, Severity.MEDIUM, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["level"], "warning")

    def test_low_produces_note(self):
        signal = _make_signal()
        result = make_result(signal, Severity.LOW, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["level"], "note")

    def test_info_produces_note(self):
        signal = _make_signal()
        result = make_result(signal, Severity.INFO, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["level"], "note")


class TestLocation(unittest.TestCase):
    """Physical location, region, and URI handling."""

    def test_one_location_emitted_per_result(self):
        signal = _make_signal()
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(len(result["locations"]), 1)

    def test_artifact_location_uri_from_internal_path(self):
        signal = _make_signal()
        result = make_result(
            signal,
            Severity.HIGH,
            "litellm/_init_.py",
            SAMPLE_INDICES,
        )
        loc = result["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "litellm/_init_.py")

    def test_use_srcroot_adds_uri_base_id(self):
        signal = _make_signal()
        result = make_result(
            signal,
            Severity.HIGH,
            "setup.py",
            SAMPLE_INDICES,
            use_srcroot=True,
        )
        artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
        self.assertEqual(artifact["uriBaseId"], "PROJECTROOT")

    def test_no_srcroot_omits_uri_base_id(self):
        signal = _make_signal()
        result = make_result(
            signal,
            Severity.HIGH,
            "setup.py",
            SAMPLE_INDICES,
            use_srcroot=False,
        )
        artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
        self.assertNotIn("uriBaseId", artifact)

    def test_synthetic_decoded_path_routes_to_decoded_uri(self):
        signal = _make_signal()
        result = make_result(
            signal,
            Severity.HIGH,
            "setup.py<decoded:layer1@line7>",
            SAMPLE_INDICES,
        )
        artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
        self.assertTrue(artifact["uri"].startswith("pydepgate-decoded:"))

    def test_synthetic_decoded_path_omits_uri_base_id(self):
        # Decoded paths are virtual, never relative to a
        # project root, so use_srcroot=True must not add
        # uriBaseId for them.
        signal = _make_signal()
        result = make_result(
            signal,
            Severity.HIGH,
            "setup.py<decoded:layer1@line7>",
            SAMPLE_INDICES,
            use_srcroot=True,
        )
        artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
        self.assertNotIn("uriBaseId", artifact)


class TestRegion(unittest.TestCase):
    """region.startLine and region.startColumn handling."""

    def test_start_line_from_signal_location(self):
        signal = _make_signal(line=42)
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 42)

    def test_start_column_converted_to_1_indexed(self):
        # Pydepgate column comes from ast.col_offset (0-based).
        # SARIF column is 1-based.
        signal = _make_signal(column=4)
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startColumn"], 5)

    def test_zero_column_converts_to_column_1(self):
        signal = _make_signal(column=0)
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startColumn"], 1)

    def test_zero_line_falls_back_to_line_1(self):
        # SARIF requires startLine >= 1 when region is
        # present. Whole-file findings (line=0) get
        # startLine=1 as a fallback.
        signal = _make_signal(line=0, column=0)
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 1)

    def test_negative_line_falls_back_to_line_1(self):
        # Defensive: negative lines should not appear, but
        # if they do, normalize to 1 rather than emitting
        # invalid SARIF.
        signal = _make_signal(line=-5, column=0)
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 1)


class TestFingerprints(unittest.TestCase):
    """partialFingerprints construction."""

    def test_has_primary_location_line_hash(self):
        signal = _make_signal()
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_fingerprint_format_is_hex_colon_version(self):
        signal = _make_signal()
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        fp = result["partialFingerprints"]["primaryLocationLineHash"]
        digest, version = fp.rsplit(":", 1)
        self.assertEqual(len(digest), 24)
        self.assertEqual(version, "1")

    def test_full_value_differentiates_fingerprints(self):
        signal_a = _make_signal(context={"_full_value": "value-a"})
        signal_b = _make_signal(context={"_full_value": "value-b"})
        result_a = make_result(signal_a, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        result_b = make_result(signal_b, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        fp_a = result_a["partialFingerprints"]["primaryLocationLineHash"]
        fp_b = result_b["partialFingerprints"]["primaryLocationLineHash"]
        self.assertNotEqual(fp_a, fp_b)

    def test_fallback_to_description_when_no_full_value(self):
        signal = _make_signal(description="unique description", context={})
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        fp = result["partialFingerprints"]["primaryLocationLineHash"]
        self.assertTrue(fp.endswith(":1"))

    def test_bytes_full_value_handled_without_crash(self):
        signal = _make_signal(context={"_full_value": b"binary value"})
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        fp = result["partialFingerprints"]["primaryLocationLineHash"]
        self.assertTrue(fp.endswith(":1"))

    def test_invalid_utf8_bytes_handled_without_crash(self):
        # _full_value can contain arbitrary bytes including
        # invalid UTF-8 sequences. The decode helper uses
        # errors='replace' to avoid crashes on malformed
        # input.
        signal = _make_signal(context={"_full_value": b"\xff\xfe\xfd invalid"})
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        fp = result["partialFingerprints"]["primaryLocationLineHash"]
        self.assertTrue(fp.endswith(":1"))

    def test_non_string_full_value_handled_via_str(self):
        # If _full_value is somehow neither str nor bytes,
        # str() coercion is the fallback.
        signal = _make_signal(context={"_full_value": 12345})
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        fp = result["partialFingerprints"]["primaryLocationLineHash"]
        self.assertTrue(fp.endswith(":1"))


class TestProperties(unittest.TestCase):
    """properties dict carries SARIF and pydepgate metadata."""

    def test_security_severity_present(self):
        signal = _make_signal()
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertIn("security-severity", result["properties"])

    def test_security_severity_matches_severity(self):
        signal = _make_signal()
        result = make_result(signal, Severity.CRITICAL, "setup.py", SAMPLE_INDICES)
        # Severity.CRITICAL maps to "9.5" via severity.py.
        self.assertEqual(result["properties"]["security-severity"], "9.5")

    def test_security_severity_is_string(self):
        # SARIF spec requires security-severity as a string.
        signal = _make_signal()
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertIsInstance(result["properties"]["security-severity"], str)

    def test_analyzer_property(self):
        signal = _make_signal(analyzer="density")
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["properties"]["pydepgate.analyzer"], "density")

    def test_confidence_property_uses_enum_name(self):
        signal = _make_signal(confidence=Confidence.HIGH)
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["properties"]["pydepgate.confidence"], "HIGH")

    def test_scope_property_uses_enum_name(self):
        signal = _make_signal(scope=Scope.MODULE)
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["properties"]["pydepgate.scope"], "MODULE")

    def test_definite_confidence_handled(self):
        # DEFINITE is the highest confidence value; verify
        # the .name lookup works for all enum members.
        signal = _make_signal(confidence=Confidence.DEFINITE)
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["properties"]["pydepgate.confidence"], "DEFINITE")

    def test_function_scope_handled(self):
        signal = _make_signal(scope=Scope.FUNCTION)
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(result["properties"]["pydepgate.scope"], "FUNCTION")


class TestDeterminism(unittest.TestCase):
    """Repeated calls produce identical output."""

    def test_same_inputs_produce_same_output(self):
        signal = _make_signal()
        a = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        b = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        self.assertEqual(a, b)


class TestRequiredFields(unittest.TestCase):
    """Every result must carry the SARIF-required fields."""

    REQUIRED_TOP_LEVEL_FIELDS = {
        "ruleId",
        "level",
        "message",
        "locations",
        "partialFingerprints",
    }

    def test_required_fields_present(self):
        signal = _make_signal()
        result = make_result(signal, Severity.HIGH, "setup.py", SAMPLE_INDICES)
        missing = self.REQUIRED_TOP_LEVEL_FIELDS - set(result.keys())
        self.assertFalse(missing, f"required SARIF fields missing: {missing}")


if __name__ == "__main__":
    unittest.main()
