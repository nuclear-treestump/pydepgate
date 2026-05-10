"""Tests for the SARIF rule descriptor generation."""

from __future__ import annotations

import unittest

from pydepgate.engines.base import Severity
from pydepgate.rules.explanations import SIGNAL_EXPLANATIONS
from pydepgate.reporters.sarif.rules import (
    ANALYZER_BY_PREFIX,
    BASE_TAGS,
    DEFAULT_SEVERITY_FALLBACK,
    INITIAL_PRECISION,
    analyzer_for_signal,
    make_rule_descriptor,
    make_rules_array,
)

# Expected analyzer prefixes per the audit. If a new analyzer
# is added with a new prefix, this constant and
# ANALYZER_BY_PREFIX both need updates. The
# test_all_known_signal_prefixes_resolve test enforces this.
EXPECTED_PREFIXES = {"DENS", "DYN", "ENC", "STR", "STDLIB"}


class TestAnalyzerLookup(unittest.TestCase):
    """analyzer_for_signal resolves analyzer names from prefixes."""

    def test_dens_prefix_resolves_to_density(self):
        self.assertEqual(analyzer_for_signal("DENS010"), "density")

    def test_dyn_prefix_resolves_to_dynamic_execution(self):
        self.assertEqual(analyzer_for_signal("DYN001"), "dynamic-execution")

    def test_enc_prefix_resolves_to_encoding_abuse(self):
        self.assertEqual(analyzer_for_signal("ENC001"), "encoding-abuse")

    def test_str_prefix_resolves_to_string_ops(self):
        self.assertEqual(analyzer_for_signal("STR001"), "string-ops")

    def test_stdlib_prefix_resolves_to_suspicious_stdlib(self):
        self.assertEqual(analyzer_for_signal("STDLIB001"), "suspicious-stdlib")

    def test_underscore_in_signal_id_does_not_break_prefix(self):
        # DYN006_PRECURSOR has an underscore but the prefix
        # extraction stops at the first digit.
        self.assertEqual(
            analyzer_for_signal("DYN006_PRECURSOR"),
            "dynamic-execution",
        )

    def test_unknown_prefix_returns_unknown(self):
        # Defensive default for unmapped prefixes.
        self.assertEqual(analyzer_for_signal("XXX001"), "unknown")

    def test_no_alphabetic_prefix_returns_unknown(self):
        # A signal_id starting with a digit (or empty) has
        # no extractable prefix.
        self.assertEqual(analyzer_for_signal("123ABC"), "unknown")
        self.assertEqual(analyzer_for_signal(""), "unknown")

    def test_every_known_signal_resolves_to_known_analyzer(self):
        # Every signal in SIGNAL_EXPLANATIONS must resolve
        # to a non-'unknown' analyzer. This catches missing
        # ANALYZER_BY_PREFIX entries when new analyzers ship.
        for signal_id in SIGNAL_EXPLANATIONS:
            with self.subTest(signal_id=signal_id):
                analyzer = analyzer_for_signal(signal_id)
                self.assertNotEqual(
                    analyzer,
                    "unknown",
                    f"signal {signal_id} has no analyzer mapping",
                )

    def test_analyzer_by_prefix_covers_expected_prefixes(self):
        self.assertEqual(set(ANALYZER_BY_PREFIX.keys()), EXPECTED_PREFIXES)


class TestMakeRuleDescriptorFields(unittest.TestCase):
    """make_rule_descriptor produces well-formed SARIF entries."""

    def _example_explanation(self) -> dict:
        return {
            "description": "First sentence. Second sentence.",
            "why_it_matters": "Reason this matters.",
            "common_evasions": ["evasion-one", "evasion-two"],
        }

    def test_id_is_signal_id_verbatim(self):
        descriptor = make_rule_descriptor(
            "DENS010", self._example_explanation(), Severity.HIGH
        )
        self.assertEqual(descriptor["id"], "DENS010")

    def test_name_format_is_analyzer_slash_signal_lower(self):
        descriptor = make_rule_descriptor(
            "DENS010", self._example_explanation(), Severity.HIGH
        )
        self.assertEqual(descriptor["name"], "density/dens010")

    def test_short_description_is_first_sentence(self):
        descriptor = make_rule_descriptor(
            "X001",
            {
                "description": "First sentence. Second sentence.",
                "why_it_matters": "Why.",
            },
            Severity.MEDIUM,
        )
        self.assertEqual(descriptor["shortDescription"]["text"], "First sentence.")

    def test_short_description_handles_no_period(self):
        # Description without sentence-ending period falls
        # back to the full text.
        descriptor = make_rule_descriptor(
            "X001",
            {
                "description": "no period here",
                "why_it_matters": "Why.",
            },
            Severity.MEDIUM,
        )
        self.assertEqual(descriptor["shortDescription"]["text"], "no period here")

    def test_full_description_is_complete_text(self):
        descriptor = make_rule_descriptor(
            "X001",
            {
                "description": "First sentence. Second sentence.",
                "why_it_matters": "Why.",
            },
            Severity.MEDIUM,
        )
        self.assertEqual(
            descriptor["fullDescription"]["text"],
            "First sentence. Second sentence.",
        )


class TestHelpFields(unittest.TestCase):
    """help.text and help.markdown formatting."""

    def _example_explanation(self) -> dict:
        return {
            "description": "Pattern X detected.",
            "why_it_matters": "Pattern X is dangerous.",
            "common_evasions": ["trick1", "trick2"],
        }

    def test_help_text_contains_description(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.MEDIUM
        )
        self.assertIn("Pattern X detected.", descriptor["help"]["text"])

    def test_help_text_contains_why_it_matters_section(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.MEDIUM
        )
        text = descriptor["help"]["text"]
        self.assertIn("Why it matters:", text)
        self.assertIn("Pattern X is dangerous.", text)

    def test_help_text_includes_common_evasions(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.MEDIUM
        )
        text = descriptor["help"]["text"]
        self.assertIn("Common evasions:", text)
        self.assertIn("trick1", text)
        self.assertIn("trick2", text)

    def test_help_markdown_uses_bold_section_headers(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.MEDIUM
        )
        markdown = descriptor["help"]["markdown"]
        self.assertIn("**Why it matters:**", markdown)
        self.assertIn("**Common evasions:**", markdown)

    def test_help_markdown_uses_inline_code_for_evasions(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.MEDIUM
        )
        markdown = descriptor["help"]["markdown"]
        self.assertIn("`trick1`", markdown)
        self.assertIn("`trick2`", markdown)

    def test_help_omits_evasions_section_when_absent(self):
        descriptor = make_rule_descriptor(
            "X001",
            {
                "description": "Desc.",
                "why_it_matters": "Why.",
            },
            Severity.MEDIUM,
        )
        text = descriptor["help"]["text"]
        markdown = descriptor["help"]["markdown"]
        self.assertNotIn("Common evasions", text)
        self.assertNotIn("Common evasions", markdown)


class TestSeverityAndProperties(unittest.TestCase):
    """defaultConfiguration and properties propagation."""

    def _example_explanation(self) -> dict:
        return {
            "description": "Pattern.",
            "why_it_matters": "Reason.",
        }

    def test_default_configuration_level_for_critical(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.CRITICAL
        )
        self.assertEqual(descriptor["defaultConfiguration"]["level"], "error")

    def test_default_configuration_level_for_medium(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.MEDIUM
        )
        self.assertEqual(descriptor["defaultConfiguration"]["level"], "warning")

    def test_default_configuration_level_for_info(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.INFO
        )
        self.assertEqual(descriptor["defaultConfiguration"]["level"], "note")

    def test_security_severity_for_critical_is_above_9(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.CRITICAL
        )
        value = float(descriptor["properties"]["security-severity"])
        self.assertGreaterEqual(value, 9.0)

    def test_security_severity_returns_string(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.HIGH
        )
        # SARIF security-severity is required to be a string.
        self.assertIsInstance(descriptor["properties"]["security-severity"], str)

    def test_properties_tags_include_base_tags(self):
        descriptor = make_rule_descriptor(
            "DENS010", self._example_explanation(), Severity.HIGH
        )
        tags = descriptor["properties"]["tags"]
        for base_tag in BASE_TAGS:
            self.assertIn(base_tag, tags)

    def test_properties_tags_include_analyzer_tag(self):
        descriptor = make_rule_descriptor(
            "DENS010", self._example_explanation(), Severity.HIGH
        )
        tags = descriptor["properties"]["tags"]
        self.assertIn("analyzer/density", tags)

    def test_properties_precision_is_initial_value(self):
        descriptor = make_rule_descriptor(
            "X001", self._example_explanation(), Severity.MEDIUM
        )
        self.assertEqual(descriptor["properties"]["precision"], INITIAL_PRECISION)


class TestMakeRulesArray(unittest.TestCase):
    """make_rules_array produces the full sorted catalog."""

    def test_returns_tuple_of_list_and_dict(self):
        rules, indices = make_rules_array()
        self.assertIsInstance(rules, list)
        self.assertIsInstance(indices, dict)

    def test_one_rule_per_known_signal_id(self):
        rules, _ = make_rules_array()
        rule_ids = [r["id"] for r in rules]
        self.assertEqual(set(rule_ids), set(SIGNAL_EXPLANATIONS.keys()))

    def test_rules_are_sorted_by_signal_id(self):
        rules, _ = make_rules_array()
        rule_ids = [r["id"] for r in rules]
        self.assertEqual(rule_ids, sorted(rule_ids))

    def test_indices_match_array_positions(self):
        rules, indices = make_rules_array()
        for index, rule in enumerate(rules):
            self.assertEqual(indices[rule["id"]], index)

    def test_every_rule_has_an_index_entry(self):
        rules, indices = make_rules_array()
        for rule in rules:
            self.assertIn(rule["id"], indices)

    def test_known_signal_count_matches_audit(self):
        # Per the project audit, 29 signal_ids exist. If a
        # new signal is added, this assertion needs updating
        # along with related documentation.
        rules, _ = make_rules_array()
        self.assertEqual(len(rules), 30)

    def test_dens010_descriptor_well_formed(self):
        rules, indices = make_rules_array()
        descriptor = rules[indices["DENS010"]]
        self.assertEqual(descriptor["id"], "DENS010")
        self.assertEqual(descriptor["name"], "density/dens010")
        self.assertIn("analyzer/density", descriptor["properties"]["tags"])

    def test_dyn006_precursor_descriptor_present(self):
        # Edge case: signal_id with underscore.
        rules, indices = make_rules_array()
        self.assertIn("DYN006_PRECURSOR", indices)
        descriptor = rules[indices["DYN006_PRECURSOR"]]
        self.assertEqual(descriptor["id"], "DYN006_PRECURSOR")
        self.assertEqual(
            descriptor["name"],
            "dynamic-execution/dyn006_precursor",
        )

    def test_every_rule_has_required_sarif_fields(self):
        rules, _ = make_rules_array()
        required_fields = {
            "id",
            "name",
            "shortDescription",
            "fullDescription",
            "help",
            "defaultConfiguration",
            "properties",
        }
        for rule in rules:
            with self.subTest(rule_id=rule["id"]):
                missing = required_fields - set(rule.keys())
                self.assertFalse(
                    missing,
                    f"rule {rule['id']} missing fields: {missing}",
                )

    def test_every_rule_has_valid_sarif_level(self):
        rules, _ = make_rules_array()
        valid_levels = {"none", "note", "warning", "error"}
        for rule in rules:
            with self.subTest(rule_id=rule["id"]):
                level = rule["defaultConfiguration"]["level"]
                self.assertIn(level, valid_levels)


class TestDeterminism(unittest.TestCase):
    """Repeated calls produce identical output."""

    def test_same_rules_each_call(self):
        rules_a, indices_a = make_rules_array()
        rules_b, indices_b = make_rules_array()
        self.assertEqual(rules_a, rules_b)
        self.assertEqual(indices_a, indices_b)


class TestDefaultSeverityFromRules(unittest.TestCase):
    """Default severities derive from the actual default rule set."""

    def test_dyn001_has_no_default_rule_uses_fallback(self):
        # Per pydepgate.rules.groups.dynamic, DYN001 has an
        # explanation but no default rule. The catalog
        # falls back to DEFAULT_SEVERITY_FALLBACK (MEDIUM
        # = 'warning').
        rules, indices = make_rules_array()
        descriptor = rules[indices["DYN001"]]
        self.assertEqual(descriptor["defaultConfiguration"]["level"], "warning")

    def test_dyn002_has_default_rules_uses_max_severity(self):
        # DYN002 has two default rules: HIGH in setup.py and
        # CRITICAL in .pth. The max is CRITICAL (= 'error').
        rules, indices = make_rules_array()
        descriptor = rules[indices["DYN002"]]
        self.assertEqual(descriptor["defaultConfiguration"]["level"], "error")

    def test_fallback_severity_is_medium(self):
        # Sanity check on the fallback constant.
        self.assertEqual(DEFAULT_SEVERITY_FALLBACK, Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
