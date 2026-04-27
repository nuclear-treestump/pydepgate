"""Tests for the density map renderer (cli/density_map.py)."""

import re
import unittest

from pydepgate.analyzers.base import Confidence, Scope, Signal
from pydepgate.visualizers.density_map import (
    _BLOCKS,
    _N_LEVELS,
    _SEVERITY_FG,
    _SEVERITY_LABEL,
    _build_buckets,
    _centered_border,
    _finding_count_to_fill,
    _render_bar_rows,
    _render_legend_row,
    render_density_map,
)
from pydepgate.engines.base import (
    ArtifactKind,
    Finding,
    ScanContext,
    Severity,
)
from pydepgate.parsers.pysource import SourceLocation
from pydepgate.traffic_control.triage import FileKind


# =============================================================================
# Helpers
# =============================================================================

def _make_finding(line: int, severity: Severity = Severity.MEDIUM) -> Finding:
    """Build a minimal Finding at a given line/severity for map tests."""
    signal = Signal(
        analyzer="test_analyzer",
        signal_id="TEST001",
        confidence=Confidence.MEDIUM,
        scope=Scope.MODULE,
        location=SourceLocation(line=line, column=0),
        description="test",
        context={},
    )
    context = ScanContext(
        artifact_kind=ArtifactKind.LOOSE_FILE,
        artifact_identity="test",
        internal_path="setup.py",
        file_kind=FileKind.SETUP_PY,
        triage_reason="test",
    )
    return Finding(signal=signal, severity=severity, context=context)


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from a string."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


# =============================================================================
# Tier 1: Public API short-circuits
# =============================================================================

class ShortCircuitTests(unittest.TestCase):
    """The renderer is meant to bail out cheaply when the map is not meaningful."""

    def test_empty_findings_returns_empty_string(self):
        result = render_density_map("setup.py", [], total_lines=100, color=True)
        self.assertEqual(result, "")

    def test_color_false_returns_empty_string(self):
        # Even with findings, no-color means no map (the visualization is
        # not meaningful in monochrome).
        findings = [_make_finding(line=10)]
        result = render_density_map(
            "setup.py", findings, total_lines=100, color=False
        )
        self.assertEqual(result, "")

    def test_color_false_and_empty_findings_returns_empty_string(self):
        result = render_density_map("setup.py", [], total_lines=100, color=False)
        self.assertEqual(result, "")


# =============================================================================
# Tier 2: Structural shape of normal rendering
# =============================================================================

class RenderingShapeTests(unittest.TestCase):
    """When the renderer does emit output, the shape should be sensible."""

    def test_normal_render_returns_non_empty_string(self):
        findings = [_make_finding(line=i, severity=Severity.MEDIUM)
                    for i in (10, 25, 50, 80)]
        result = render_density_map(
            "setup.py", findings, total_lines=100, color=True
        )
        self.assertNotEqual(result, "")

    def test_normal_render_produces_multiline_output(self):
        findings = [_make_finding(line=i) for i in (10, 50, 80)]
        result = render_density_map(
            "setup.py", findings, total_lines=100, color=True, n_rows=6
        )
        # 6 bar rows + 1 legend row + 2 borders = 9 lines minimum.
        # Trailing newline produces one extra empty entry on split, so
        # we check >=9 non-empty lines.
        non_empty = [ln for ln in result.split("\n") if ln]
        self.assertGreaterEqual(len(non_empty), 9)

    def test_n_rows_controls_bar_height(self):
        findings = [_make_finding(line=i) for i in (10, 50, 80)]
        for n_rows in (3, 6, 10):
            with self.subTest(n_rows=n_rows):
                result = render_density_map(
                    "setup.py", findings, total_lines=100,
                    color=True, n_rows=n_rows,
                )
                non_empty = [ln for ln in result.split("\n") if ln]
                # 2 borders + n_rows bars + 1 legend.
                self.assertEqual(len(non_empty), 2 + n_rows + 1)

    def test_top_and_bottom_borders_present(self):
        findings = [_make_finding(line=10)]
        result = render_density_map(
            "setup.py", findings, total_lines=100, color=True
        )
        lines = result.split("\n")
        # Top border starts with corner and contains horizontal dashes.
        self.assertTrue(lines[0].startswith("\u250c"))   # top-left corner
        self.assertIn("\u2500", lines[0])                 # horizontal
        # Find the bottom border (last non-empty line).
        non_empty = [ln for ln in lines if ln]
        self.assertTrue(non_empty[-1].startswith("\u2514"))  # bottom-left corner

    def test_filename_appears_in_top_border(self):
        findings = [_make_finding(line=10)]
        result = render_density_map(
            "uniquename.py", findings, total_lines=100, color=True
        )
        # Filename is in plain text in the top border, no ANSI codes
        # inside the border itself, so a simple substring check works.
        self.assertIn("uniquename.py", result)

    def test_finding_count_appears_in_bottom_border(self):
        findings = [_make_finding(line=i) for i in (10, 25, 50)]
        result = render_density_map(
            "setup.py", findings, total_lines=100, color=True
        )
        self.assertIn("3 findings", result)

    def test_finding_count_singular_for_one_finding(self):
        findings = [_make_finding(line=10)]
        result = render_density_map(
            "setup.py", findings, total_lines=100, color=True
        )
        self.assertIn("1 finding", result)
        self.assertNotIn("1 findings", result)

    def test_long_filename_is_truncated_with_ellipsis(self):
        # Construct a path far longer than any reasonable terminal width.
        long_name = "a/very/deeply/nested/path/to/some/" + ("x" * 200) + ".py"
        findings = [_make_finding(line=10)]
        result = render_density_map(
            long_name, findings, total_lines=100, color=True
        )
        # The renderer should preserve the END of the filename (the
        # interesting tail) and prefix it with a single-character
        # ellipsis. The full original string must NOT appear.
        self.assertNotIn(long_name, result)
        self.assertIn("\u2026", result)
        # The .py extension should still be visible.
        self.assertIn(".py", result)


# =============================================================================
# Tier 3: Bucket logic
# =============================================================================

class BuildBucketsTests(unittest.TestCase):

    def test_buckets_have_correct_count(self):
        findings = [_make_finding(line=10)]
        buckets = _build_buckets(findings, total_lines=100, n_buckets=20)
        self.assertEqual(len(buckets), 20)

    def test_finding_lands_in_proportional_bucket(self):
        # Line 50 of 100 should land near the middle of 10 buckets.
        findings = [_make_finding(line=50)]
        buckets = _build_buckets(findings, total_lines=100, n_buckets=10)
        nonzero = [i for i, b in enumerate(buckets) if b.count > 0]
        # Should be roughly the middle bucket.
        self.assertEqual(len(nonzero), 1)
        self.assertIn(nonzero[0], (4, 5))

    def test_finding_at_first_line_lands_in_first_bucket(self):
        findings = [_make_finding(line=1)]
        buckets = _build_buckets(findings, total_lines=100, n_buckets=10)
        self.assertEqual(buckets[0].count, 1)
        for b in buckets[1:]:
            self.assertEqual(b.count, 0)

    def test_finding_past_total_lines_clamps_to_last_bucket(self):
        # Out-of-range line numbers should clamp, not raise or wrap.
        findings = [_make_finding(line=999)]
        buckets = _build_buckets(findings, total_lines=100, n_buckets=10)
        self.assertEqual(buckets[-1].count, 1)

    def test_zero_total_lines_does_not_crash(self):
        findings = [_make_finding(line=5)]
        # Pathological input: total_lines=0. Should clamp to 1 internally.
        buckets = _build_buckets(findings, total_lines=0, n_buckets=10)
        # All findings should land in the last bucket since their line
        # number is greater than the clamped total of 1.
        self.assertEqual(sum(b.count for b in buckets), 1)

    def test_multiple_findings_same_bucket_accumulate(self):
        # Three findings at the same line.
        findings = [_make_finding(line=50) for _ in range(3)]
        buckets = _build_buckets(findings, total_lines=100, n_buckets=10)
        total = sum(b.count for b in buckets)
        self.assertEqual(total, 3)
        # All three should share one bucket.
        nonzero = [b for b in buckets if b.count > 0]
        self.assertEqual(len(nonzero), 1)
        self.assertEqual(nonzero[0].count, 3)

    def test_bucket_worst_severity_tracks_max(self):
        # A bucket containing LOW + MEDIUM + CRITICAL should report CRITICAL.
        findings = [
            _make_finding(line=50, severity=Severity.LOW),
            _make_finding(line=51, severity=Severity.MEDIUM),
            _make_finding(line=52, severity=Severity.CRITICAL),
        ]
        buckets = _build_buckets(findings, total_lines=100, n_buckets=10)
        # Find the bucket they all landed in.
        target = next(b for b in buckets if b.count > 0)
        self.assertEqual(target.count, 3)
        self.assertEqual(target.worst, Severity.CRITICAL)

    def test_empty_buckets_default_to_info_severity(self):
        # An empty bucket has no findings, but worst defaults to INFO
        # so consumers don't have to handle None.
        findings = [_make_finding(line=50)]
        buckets = _build_buckets(findings, total_lines=100, n_buckets=10)
        for b in buckets:
            if b.count == 0:
                self.assertEqual(b.worst, Severity.INFO)


# =============================================================================
# Tier 4: Fill-level math
# =============================================================================

class FillLevelTests(unittest.TestCase):

    def test_zero_count_yields_zero_fill(self):
        self.assertEqual(_finding_count_to_fill(0, 10, 6), 0)

    def test_zero_max_count_yields_zero_fill(self):
        # Even if asked for a non-zero count when max_count is zero
        # (a corner case), don't divide by zero.
        self.assertEqual(_finding_count_to_fill(0, 0, 6), 0)

    def test_nonzero_count_yields_at_least_one(self):
        # The whole point of the log scale: even one finding among many
        # should still produce a visible bar.
        self.assertGreaterEqual(_finding_count_to_fill(1, 100, 6), 1)

    def test_max_count_yields_full_fill(self):
        # A bucket holding the maximum should fill the bar to the top.
        n_rows = 6
        max_fill = n_rows * (_N_LEVELS - 1)
        self.assertEqual(
            _finding_count_to_fill(50, 50, n_rows),
            max_fill,
        )

    def test_log_scale_compresses_large_differences(self):
        # 1 finding versus 100 findings: linear scale would give
        # 1/100 = 1% bar, log scale gives much more.
        n_rows = 6
        small = _finding_count_to_fill(1, 100, n_rows)
        large = _finding_count_to_fill(100, 100, n_rows)
        # Single finding should produce > 10% of max (log compression),
        # not the ~1% a linear scale would give.
        self.assertGreater(small, large * 0.10)


# =============================================================================
# Tier 5: Bar row rendering
# =============================================================================

class RenderBarRowsTests(unittest.TestCase):

    def _bucket(self, count, severity=Severity.MEDIUM):
        from pydepgate.visualizers.density_map import _Bucket
        return _Bucket(count=count, worst=severity)

    def test_returns_n_rows_strings(self):
        buckets = [self._bucket(0), self._bucket(5), self._bucket(2)]
        rows = _render_bar_rows(buckets, n_rows=6, color=False)
        self.assertEqual(len(rows), 6)

    def test_no_color_omits_ansi_codes(self):
        buckets = [self._bucket(5, Severity.CRITICAL)]
        rows = _render_bar_rows(buckets, n_rows=6, color=False)
        for row in rows:
            self.assertNotIn("\x1b[", row)

    def test_color_true_includes_ansi_codes_for_filled_cells(self):
        buckets = [self._bucket(5, Severity.CRITICAL)]
        rows = _render_bar_rows(buckets, n_rows=6, color=True)
        joined = "".join(rows)
        # CRITICAL color is bright red.
        critical_fg = _SEVERITY_FG[Severity.CRITICAL]
        self.assertIn(critical_fg, joined)

    def test_empty_bucket_produces_only_spaces(self):
        buckets = [self._bucket(0)]
        rows = _render_bar_rows(buckets, n_rows=6, color=False)
        # Every row should be a single space (the cell is empty).
        for row in rows:
            self.assertEqual(row, " ")

    def test_bottom_row_fills_first(self):
        # A small fill should appear at the bottom row, not the top.
        buckets = [self._bucket(1)]
        rows = _render_bar_rows(buckets, n_rows=6, color=False)
        # Top row should be a space; bottom row should not be.
        self.assertEqual(rows[0], " ")
        self.assertNotEqual(rows[-1], " ")
        self.assertIn(rows[-1], _BLOCKS)

    def test_severity_determines_color_per_column(self):
        buckets = [
            self._bucket(5, Severity.LOW),
            self._bucket(5, Severity.CRITICAL),
        ]
        rows = _render_bar_rows(buckets, n_rows=6, color=True)
        joined = "".join(rows)
        # Both severity colors should appear since each column uses its own.
        self.assertIn(_SEVERITY_FG[Severity.LOW], joined)
        self.assertIn(_SEVERITY_FG[Severity.CRITICAL], joined)


# =============================================================================
# Tier 6: Legend row
# =============================================================================

class RenderLegendRowTests(unittest.TestCase):

    def _bucket(self, count, severity=Severity.MEDIUM):
        from pydepgate.visualizers.density_map import _Bucket
        return _Bucket(count=count, worst=severity)

    def test_legend_length_matches_bucket_count_when_no_color(self):
        buckets = [self._bucket(0), self._bucket(3), self._bucket(0)]
        legend = _render_legend_row(buckets, color=False)
        # No ANSI codes in non-color mode, so length is exact.
        self.assertEqual(len(legend), 3)

    def test_empty_bucket_produces_dot(self):
        buckets = [self._bucket(0)]
        legend = _render_legend_row(buckets, color=False)
        self.assertEqual(legend, "\u00b7")  # middle dot

    def test_filled_bucket_produces_severity_label(self):
        buckets = [self._bucket(5, Severity.CRITICAL)]
        legend = _render_legend_row(buckets, color=False)
        self.assertEqual(legend, _SEVERITY_LABEL[Severity.CRITICAL])

    def test_each_severity_has_distinct_label(self):
        # The dict mapping severity → label must be well-formed for the
        # legend to be readable.
        labels = set(_SEVERITY_LABEL.values())
        self.assertEqual(len(labels), len(_SEVERITY_LABEL))

    def test_color_legend_includes_ansi_codes(self):
        buckets = [self._bucket(5, Severity.CRITICAL)]
        legend = _render_legend_row(buckets, color=True)
        self.assertIn("\x1b[", legend)
        # And the label letter still appears within.
        stripped = _strip_ansi(legend)
        self.assertEqual(stripped, _SEVERITY_LABEL[Severity.CRITICAL])

    def test_mixed_buckets_produce_mixed_legend(self):
        buckets = [
            self._bucket(0),
            self._bucket(3, Severity.HIGH),
            self._bucket(0),
            self._bucket(1, Severity.LOW),
        ]
        legend = _render_legend_row(buckets, color=False)
        expected = (
            "\u00b7"
            + _SEVERITY_LABEL[Severity.HIGH]
            + "\u00b7"
            + _SEVERITY_LABEL[Severity.LOW]
        )
        self.assertEqual(legend, expected)


# =============================================================================
# Tier 7: Border helper
# =============================================================================

class CenteredBorderTests(unittest.TestCase):

    def test_label_is_centered(self):
        border = _centered_border("\u250c", "\u2510", "x", inner_width=10)
        # Total length should be inner_width + 2 (for the corners).
        # Label is " x ", so 7 dashes split 3/4 around it.
        self.assertEqual(len(border), 12)
        self.assertTrue(border.startswith("\u250c"))
        self.assertTrue(border.endswith("\u2510"))
        self.assertIn(" x ", border)

    def test_long_label_does_not_overflow(self):
        # Label longer than inner_width: no negative dash counts.
        border = _centered_border("\u250c", "\u2510", "x" * 20, inner_width=10)
        # Should not crash. The label may exceed inner_width; that is
        # the caller's responsibility to truncate (renderer does this).
        self.assertIn("xxxx", border)


# =============================================================================
# Tier 8: End-to-end integration
# =============================================================================

class EndToEndTests(unittest.TestCase):

    def test_severity_color_from_finding_propagates_to_output(self):
        findings = [_make_finding(line=10, severity=Severity.CRITICAL)]
        result = render_density_map(
            "setup.py", findings, total_lines=100, color=True
        )
        # The CRITICAL severity color must appear somewhere in the output.
        self.assertIn(_SEVERITY_FG[Severity.CRITICAL], result)

    def test_each_finding_severity_appears_when_distributed(self):
        # Spread findings of every severity across the file so each
        # lands in its own bucket.
        findings = [
            _make_finding(line=5,  severity=Severity.LOW),
            _make_finding(line=30, severity=Severity.MEDIUM),
            _make_finding(line=60, severity=Severity.HIGH),
            _make_finding(line=90, severity=Severity.CRITICAL),
        ]
        result = render_density_map(
            "setup.py", findings, total_lines=100, color=True
        )
        for sev in (Severity.LOW, Severity.MEDIUM,
                    Severity.HIGH, Severity.CRITICAL):
            self.assertIn(_SEVERITY_FG[sev], result)

    def test_total_lines_none_falls_back_to_max_finding_line(self):
        # When the caller doesn't know the line count, the renderer
        # should still produce a sensible (non-empty) map using the
        # max finding line as a proxy.
        findings = [_make_finding(line=i) for i in (10, 30, 80)]
        result = render_density_map(
            "setup.py", findings, total_lines=None, color=True
        )
        self.assertNotEqual(result, "")
        # Every finding still ends up in some bucket.
        self.assertIn("3 findings", result)

    def test_total_lines_zero_falls_back_to_max_finding_line(self):
        # Defensive: same as None.
        findings = [_make_finding(line=10)]
        result = render_density_map(
            "setup.py", findings, total_lines=0, color=True
        )
        self.assertNotEqual(result, "")

    def test_output_ends_with_newline(self):
        findings = [_make_finding(line=10)]
        result = render_density_map(
            "setup.py", findings, total_lines=100, color=True
        )
        self.assertTrue(result.endswith("\n"))


if __name__ == "__main__":
    unittest.main()