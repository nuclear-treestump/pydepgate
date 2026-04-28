"""
Tests for `pydepgate.visualizers.peek_render`.

Covers the summary and verbose renderers, the hex-dump formatter,
color escape insertion, and edge cases (empty chain, missing keys,
malformed input).
"""

import unittest

from pydepgate.visualizers.peek_render import (
    ANSI,
    PLAIN,
    ColorScheme,
    render_decoded_block,
)


def _example_decoded_block(
    *,
    layers=2,
    final_kind="python_source",
    indicators=("subprocess",),
    pickle_warning=False,
    status="completed",
    continues_as=None,
):
    """Build a synthetic decoded block for tests."""
    chain = [
        {"kind": "base64", "input_size": 200, "output_size": 150},
        {"kind": "zlib", "input_size": 150, "output_size": 893},
        {"kind": "base64", "input_size": 893, "output_size": 670},
    ][:layers]
    block = {
        "chain": chain,
        "layers_count": layers,
        "final_kind": final_kind,
        "final_bytes_size": 893,
        "unwrap_status": status,
        "preview_hex": "696d706f72742073756270726f636573730a696d706f7274206f730a",
        "preview_text": "import subprocess.import os.",
        "preview_truncated": True,
        "indicators": list(indicators),
        "pickle_warning": pickle_warning,
    }
    if continues_as is not None:
        block["continues_as"] = continues_as
    return block


# ===========================================================================
# Summary renderer
# ===========================================================================

class SummaryRendererTests(unittest.TestCase):

    def test_basic_chain_appears_in_output(self):
        block = _example_decoded_block(layers=2)
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        self.assertIn("base64 -> zlib", out)
        self.assertIn("python_source", out)

    def test_layer_count_pluralizes(self):
        single = _example_decoded_block(layers=1)
        plural = _example_decoded_block(layers=2)
        out_single = render_decoded_block(single, verbose=False, color=PLAIN)
        out_plural = render_decoded_block(plural, verbose=False, color=PLAIN)
        self.assertIn("1 layer)", out_single)
        self.assertIn("2 layers", out_plural)

    def test_indicators_appear_when_present(self):
        block = _example_decoded_block(indicators=("subprocess", "urllib"))
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        self.assertIn("subprocess", out)
        self.assertIn("urllib", out)

    def test_no_indicator_line_when_empty(self):
        block = _example_decoded_block(indicators=())
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        self.assertNotIn("indicators:", out)

    def test_pickle_warning_appears(self):
        block = _example_decoded_block(pickle_warning=True)
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        self.assertIn("WARNING", out)
        self.assertIn("pickle", out)

    def test_no_pickle_warning_when_false(self):
        block = _example_decoded_block(pickle_warning=False)
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        self.assertNotIn("WARNING", out)

    def test_status_shown_when_not_completed(self):
        block = _example_decoded_block(
            status="exhausted_depth", continues_as="zlib",
        )
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        self.assertIn("exhausted_depth", out)
        self.assertIn("would continue as", out)
        self.assertIn("zlib", out)

    def test_completed_status_not_repeated(self):
        block = _example_decoded_block(status="completed")
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        # Don't pollute the summary with "completed" since it's the
        # default case.
        self.assertNotIn("completed", out)


# ===========================================================================
# Verbose renderer
# ===========================================================================

class VerboseRendererTests(unittest.TestCase):

    def test_per_layer_breakdown_shown(self):
        block = _example_decoded_block(layers=3)
        out = render_decoded_block(block, verbose=True, color=PLAIN)
        self.assertIn("layer 1: base64", out)
        self.assertIn("layer 2: zlib", out)
        self.assertIn("layer 3: base64", out)
        # Sizes should be present for each layer.
        self.assertIn("200 -> 150", out)
        self.assertIn("150 -> 893", out)

    def test_final_form_summary(self):
        block = _example_decoded_block()
        out = render_decoded_block(block, verbose=True, color=PLAIN)
        self.assertIn("final form:", out)
        self.assertIn("python_source", out)
        self.assertIn("893 bytes", out)
        self.assertIn("preview truncated", out)

    def test_full_indicator_list(self):
        block = _example_decoded_block(
            indicators=("subprocess", "urllib", "os.system"),
        )
        out = render_decoded_block(block, verbose=True, color=PLAIN)
        # Verbose mode renders one indicator per line as a bullet.
        self.assertIn("- subprocess", out)
        self.assertIn("- urllib", out)
        self.assertIn("- os.system", out)

    def test_hex_dump_present(self):
        block = _example_decoded_block()
        out = render_decoded_block(block, verbose=True, color=PLAIN)
        self.assertIn("hex preview:", out)
        # Offset column should appear.
        self.assertIn("00000000", out)
        # Gutter chars should show printable ASCII.
        self.assertIn("|import subproces", out)

    def test_hex_dump_alignment_for_short_input(self):
        # A 5-byte hex string should still produce a single row with
        # padding so the gutter aligns.
        block = _example_decoded_block()
        block["preview_hex"] = "1234567890"  # 5 bytes
        block["preview_text"] = ".4Vx."
        out = render_decoded_block(block, verbose=True, color=PLAIN)
        # The row should pad with spaces to full 16-byte width.
        self.assertIn("00000000", out)
        # The pipe-delimited gutter must close even on short rows.
        self.assertEqual(out.count("|"), 2)

    def test_pickle_warning_at_bottom_in_red(self):
        block = _example_decoded_block(pickle_warning=True)
        out_plain = render_decoded_block(block, verbose=True, color=PLAIN)
        out_ansi = render_decoded_block(block, verbose=True, color=ANSI)
        self.assertIn("pickle", out_plain)
        # ANSI version should include the red escape.
        self.assertIn("\033[31;1m", out_ansi)

    def test_continues_as_callout_when_exhausted(self):
        block = _example_decoded_block(
            status="exhausted_depth", continues_as="zlib",
        )
        out = render_decoded_block(block, verbose=True, color=PLAIN)
        self.assertIn("chain continues as: zlib", out)
        self.assertIn("depth limit reached", out)


# ===========================================================================
# Color scheme application
# ===========================================================================

class ColorSchemeTests(unittest.TestCase):

    def test_plain_has_no_escape_codes(self):
        block = _example_decoded_block()
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        self.assertNotIn("\033[", out)

    def test_ansi_inserts_bold_for_label(self):
        block = _example_decoded_block()
        out = render_decoded_block(block, verbose=False, color=ANSI)
        self.assertIn("\033[1m", out)
        self.assertIn("\033[0m", out)

    def test_none_color_treated_as_plain(self):
        block = _example_decoded_block()
        out = render_decoded_block(block, verbose=False, color=None)
        self.assertNotIn("\033[", out)

    def test_custom_color_scheme(self):
        custom = ColorScheme(
            bold_pre="<b>", bold_post="</b>",
            red_pre="<r>", red_post="</r>",
        )
        block = _example_decoded_block(pickle_warning=True)
        out = render_decoded_block(block, verbose=False, color=custom)
        self.assertIn("<b>", out)
        self.assertIn("<r>", out)


# ===========================================================================
# Edge cases
# ===========================================================================

class EdgeCaseTests(unittest.TestCase):

    def test_empty_chain(self):
        block = _example_decoded_block(layers=0)
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        # Should still produce something coherent, not crash.
        self.assertIn("decoded chain", out)

    def test_missing_keys_do_not_crash(self):
        # Renderer must tolerate a partially-populated block.
        block = {"layers_count": 1}
        out = render_decoded_block(block, verbose=False, color=PLAIN)
        self.assertTrue(out.endswith("\n"))

    def test_non_mapping_returns_empty(self):
        out = render_decoded_block(None, verbose=False)
        self.assertEqual(out, "")

    def test_indent_applied_to_every_line(self):
        block = _example_decoded_block(
            indicators=("subprocess",),
            pickle_warning=True,
        )
        out = render_decoded_block(
            block, verbose=False, color=PLAIN, indent=">>> ",
        )
        for line in out.splitlines():
            if line:
                self.assertTrue(
                    line.startswith(">>> "),
                    msg=f"line not indented: {line!r}",
                )

    def test_malformed_hex_does_not_crash(self):
        block = _example_decoded_block()
        block["preview_hex"] = "abc"   # odd length, malformed
        out = render_decoded_block(block, verbose=True, color=PLAIN)
        self.assertIn("malformed", out)


if __name__ == "__main__":
    unittest.main()