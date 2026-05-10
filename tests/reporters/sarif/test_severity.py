"""Tests for the SARIF severity mapping."""

from __future__ import annotations
import unittest

from pydepgate.engines.base import Severity
from pydepgate.reporters.sarif.severity import (
    SARIF_LEVEL_BY_SEVERITY,
    SECURITY_SEVERITY_BY_SEVERITY,
    SEVERITY_RANK,
    max_severity,
    severity_rank,
    to_sarif_level,
    to_security_severity,
)


class TestSarifLevelMapping(unittest.TestCase):
    """Pydepgate Severity to SARIF level (note / warning / error)."""

    def test_critical_maps_to_error(self):
        assert to_sarif_level(Severity.CRITICAL) == "error"

    def test_high_maps_to_error(self):
        assert to_sarif_level(Severity.HIGH) == "error"

    def test_medium_maps_to_warning(self):
        assert to_sarif_level(Severity.MEDIUM) == "warning"

    def test_low_maps_to_note(self):
        assert to_sarif_level(Severity.LOW) == "note"

    def test_info_maps_to_note(self):
        assert to_sarif_level(Severity.INFO) == "note"

    def test_all_five_severities_map_to_valid_sarif_levels(self):
        valid_levels = {"none", "note", "warning", "error"}
        for severity in Severity:
            assert to_sarif_level(severity) in valid_levels

    def test_mapping_table_covers_every_severity_member(self):
        for severity in Severity:
            assert severity in SARIF_LEVEL_BY_SEVERITY


class TestSecuritySeverityMapping(unittest.TestCase):
    """Pydepgate Severity to GitHub security-severity numeric (string)."""

    def test_critical_displays_as_critical_in_github(self):
        # GitHub band: >= 9.0 displays 'critical'
        value = float(to_security_severity(Severity.CRITICAL))
        assert value >= 9.0

    def test_high_displays_as_high_in_github(self):
        # GitHub band: 7.0 to 8.9 displays 'high'
        value = float(to_security_severity(Severity.HIGH))
        assert 7.0 <= value <= 8.9

    def test_medium_displays_as_medium_in_github(self):
        # GitHub band: 4.0 to 6.9 displays 'medium'
        value = float(to_security_severity(Severity.MEDIUM))
        assert 4.0 <= value <= 6.9

    def test_low_displays_as_low_in_github(self):
        # GitHub band: 0.1 to 3.9 displays 'low'
        value = float(to_security_severity(Severity.LOW))
        assert 0.1 <= value <= 3.9

    def test_info_displays_as_low_in_github_below_low(self):
        info = float(to_security_severity(Severity.INFO))
        low = float(to_security_severity(Severity.LOW))
        assert 0.1 <= info <= 3.9
        assert info < low

    def test_severity_ordering_preserved_in_numerics(self):
        ordered = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        values = [float(to_security_severity(s)) for s in ordered]
        assert values == sorted(values)

    def test_returns_string_per_sarif_spec(self):
        # SARIF security-severity is a string per the OASIS
        # spec and the GitHub subset documentation.
        for severity in Severity:
            value = to_security_severity(severity)
            assert isinstance(value, str)
            # Must be parseable as float.
            float(value)

    def test_mapping_table_covers_every_severity_member(self):
        for severity in Severity:
            assert severity in SECURITY_SEVERITY_BY_SEVERITY


class TestMappingTableConsistency(unittest.TestCase):
    """The two mapping tables must agree about which severities exist."""

    def test_same_keys_in_both_tables(self):
        assert set(SARIF_LEVEL_BY_SEVERITY.keys()) == set(
            SECURITY_SEVERITY_BY_SEVERITY.keys()
        )

    def test_both_tables_cover_every_severity_member(self):
        for severity in Severity:
            assert severity in SARIF_LEVEL_BY_SEVERITY
            assert severity in SECURITY_SEVERITY_BY_SEVERITY


class TestSeverityRanking(unittest.TestCase):
    """severity_rank and max_severity provide explicit ordering."""

    def test_rank_increases_with_severity(self):
        ranks = [
            severity_rank(Severity.INFO),
            severity_rank(Severity.LOW),
            severity_rank(Severity.MEDIUM),
            severity_rank(Severity.HIGH),
            severity_rank(Severity.CRITICAL),
        ]
        self.assertEqual(ranks, sorted(ranks))

    def test_critical_has_highest_rank(self):
        critical_rank = severity_rank(Severity.CRITICAL)
        for severity in Severity:
            if severity is Severity.CRITICAL:
                continue
            self.assertGreater(critical_rank, severity_rank(severity))

    def test_info_has_lowest_rank(self):
        info_rank = severity_rank(Severity.INFO)
        for severity in Severity:
            if severity is Severity.INFO:
                continue
            self.assertLess(info_rank, severity_rank(severity))

    def test_rank_table_covers_every_severity_member(self):
        for severity in Severity:
            self.assertIn(severity, SEVERITY_RANK)

    def test_max_severity_picks_higher_rank(self):
        self.assertIs(
            max_severity(Severity.LOW, Severity.HIGH),
            Severity.HIGH,
        )
        self.assertIs(
            max_severity(Severity.HIGH, Severity.LOW),
            Severity.HIGH,
        )

    def test_max_severity_returns_critical_against_anything(self):
        for other in Severity:
            self.assertIs(
                max_severity(Severity.CRITICAL, other),
                Severity.CRITICAL,
            )
            self.assertIs(
                max_severity(other, Severity.CRITICAL),
                Severity.CRITICAL,
            )

    def test_max_severity_ties_return_first_argument(self):
        # Determinism contract: when both severities are
        # equal, the function returns the first argument.
        self.assertIs(
            max_severity(Severity.HIGH, Severity.HIGH),
            Severity.HIGH,
        )


if __name__ == "__main__":
    unittest.main()
