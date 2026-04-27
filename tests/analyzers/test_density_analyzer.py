"""Tests for pydepgate.analyzers.density_analyzer."""

from __future__ import annotations

import unittest

from pydepgate.analyzers.density_analyzer import (
    CodeDensityAnalyzer,
    _shannon_entropy,
    _vowel_ratio,
    _max_ast_depth,
)
from pydepgate.analyzers.base import Confidence, Scope
from pydepgate.parsers.pysource import SourceLocation, parse_python_source


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _analyze(source: str) -> list:
    """Parse source and run the analyzer, return list of signals."""
    parsed = parse_python_source(source.encode("utf-8"), "<test>")
    analyzer = CodeDensityAnalyzer()
    return list(analyzer.analyze_python(parsed))


def _ids(signals: list) -> list[str]:
    return [s.signal_id for s in signals]


def _by_id(signals: list, signal_id: str) -> list:
    return [s for s in signals if s.signal_id == signal_id]


# A 128-char string where every base64-alphabet char appears twice.
# Entropy = log2(64) = 6.0 bits/char; well above all DENS010 thresholds.
# Length 128 is above the 80-char DENS010/DENS011 minimum but below the
# 200-char DENS010-HIGH minimum, so it will fire DENS010 at MEDIUM.
_HIGH_ENTROPY_B64 = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 2
)
assert len(_HIGH_ENTROPY_B64) == 128


# =============================================================================
# Utility-function tests (pure functions, easy to nail down)
# =============================================================================

class ShannonEntropyTests(unittest.TestCase):

    def test_empty_string_is_zero(self):
        self.assertEqual(_shannon_entropy(""), 0.0)

    def test_single_repeated_char_is_zero(self):
        self.assertEqual(_shannon_entropy("aaaa"), 0.0)

    def test_uniform_distribution_matches_log2(self):
        # 4 distinct chars, equal frequency: entropy = log2(4) = 2.0
        self.assertAlmostEqual(_shannon_entropy("abcd"), 2.0, places=6)

    def test_high_entropy_string_above_threshold(self):
        self.assertGreaterEqual(_shannon_entropy(_HIGH_ENTROPY_B64), 5.5)


class VowelRatioTests(unittest.TestCase):

    def test_all_vowels(self):
        self.assertEqual(_vowel_ratio("aeiou"), 1.0)

    def test_no_vowels(self):
        self.assertEqual(_vowel_ratio("xyz_btn"), 0.0)

    def test_mixed(self):
        # "hello" -> 2 vowels in 5 chars
        self.assertAlmostEqual(_vowel_ratio("hello"), 0.4, places=6)

    def test_empty(self):
        self.assertEqual(_vowel_ratio(""), 0.0)


class MaxAstDepthTests(unittest.TestCase):

    def test_flat_module_depth_low(self):
        import ast
        tree = ast.parse("x = 1\n")
        # Module -> Assign -> targets/value etc. Depth should be modest.
        self.assertGreaterEqual(_max_ast_depth(tree), 2)
        self.assertLess(_max_ast_depth(tree), 8)

    def test_deeply_nested_lists_increase_depth(self):
        import ast
        # 10 levels of nesting -> depth grows accordingly.
        tree = ast.parse("x = " + "[" * 10 + "1" + "]" * 10 + "\n")
        self.assertGreater(_max_ast_depth(tree), 10)


# =============================================================================
# Clean-code baseline (no signals)
# =============================================================================

class CleanCodeTests(unittest.TestCase):

    def test_simple_code_no_signals(self):
        source = (
            "def add(a, b):\n"
            "    return a + b\n"
        )
        signals = _analyze(source)
        self.assertEqual(signals, [])

    def test_short_strings_below_entropy_minimum(self):
        # Below _MIN_LEN_FOR_ENTROPY (80); should not fire DENS010.
        source = "x = 'hello world this is a normal string'\n"
        self.assertEqual(_ids(_analyze(source)), [])

    def test_normal_identifiers_no_dens020(self):
        source = (
            "def calculate_total(items, tax_rate):\n"
            "    return sum(items) * (1 + tax_rate)\n"
        )
        self.assertNotIn("DENS020", _ids(_analyze(source)))


# =============================================================================
# DENS001: token density per line
# =============================================================================

class TokenDensityTests(unittest.TestCase):

    def test_dense_line_fires_dens001_medium(self):
        # 30 numbers in a list -> ~62 tokens (numbers + commas + brackets).
        # Well over the 50-token MEDIUM threshold, well under 100-HIGH.
        nums = ", ".join(str(i) for i in range(30))
        source = f"x = [{nums}]\n"
        signals = _analyze(source)
        dens001 = _by_id(signals, "DENS001")
        self.assertEqual(len(dens001), 1)
        self.assertEqual(dens001[0].confidence, Confidence.MEDIUM)
        self.assertEqual(dens001[0].location.line, 1)

    def test_very_dense_line_fires_dens001_high(self):
        # 60 numbers -> ~122 tokens. Over the 100-token HIGH threshold.
        nums = ", ".join(str(i) for i in range(60))
        source = f"x = [{nums}]\n"
        signals = _analyze(source)
        dens001 = _by_id(signals, "DENS001")
        self.assertEqual(len(dens001), 1)
        self.assertEqual(dens001[0].confidence, Confidence.HIGH)

    def test_short_lines_do_not_fire(self):
        source = "x = 1\ny = 2\nz = x + y\n"
        self.assertNotIn("DENS001", _ids(_analyze(source)))


# =============================================================================
# DENS002: semicolon chaining
# =============================================================================

class SemicolonTests(unittest.TestCase):

    def test_single_semicolon_fires_medium(self):
        source = "a = 1; b = 2\n"
        signals = _analyze(source)
        dens002 = _by_id(signals, "DENS002")
        self.assertEqual(len(dens002), 1)
        self.assertEqual(dens002[0].confidence, Confidence.MEDIUM)
        self.assertEqual(dens002[0].context["semicolon_count"], 1)
        self.assertEqual(dens002[0].context["statement_count"], 2)

    def test_three_semicolons_fires_high(self):
        source = "a = 1; b = 2; c = 3; d = 4\n"
        signals = _analyze(source)
        dens002 = _by_id(signals, "DENS002")
        self.assertEqual(len(dens002), 1)
        self.assertEqual(dens002[0].confidence, Confidence.HIGH)

    def test_no_semicolon_does_not_fire(self):
        source = "a = 1\nb = 2\n"
        self.assertNotIn("DENS002", _ids(_analyze(source)))

    def test_semicolon_inside_string_does_not_fire(self):
        # Tokenizer reports the semicolon as part of the STRING token,
        # not as an OP. So this should not fire DENS002.
        source = "x = 'a;b;c;d'\n"
        self.assertNotIn("DENS002", _ids(_analyze(source)))


# =============================================================================
# DENS010: high-entropy string literal
# =============================================================================

class StringEntropyTests(unittest.TestCase):

    def test_high_entropy_string_fires_dens010(self):
        source = f"x = '{_HIGH_ENTROPY_B64}'\n"
        signals = _analyze(source)
        dens010 = _by_id(signals, "DENS010")
        self.assertEqual(len(dens010), 1)
        # 128 chars at entropy 6.0 -> MEDIUM (length under 200 for HIGH).
        self.assertEqual(dens010[0].confidence, Confidence.MEDIUM)

    def test_long_high_entropy_string_fires_high(self):
        # 256 chars meets both >=200 length and >=5.8 entropy.
        long_payload = _HIGH_ENTROPY_B64 * 2  # 256 chars, entropy still 6.0
        source = f"x = '{long_payload}'\n"
        signals = _analyze(source)
        dens010 = _by_id(signals, "DENS010")
        self.assertEqual(len(dens010), 1)
        self.assertEqual(dens010[0].confidence, Confidence.HIGH)

    def test_low_entropy_long_string_does_not_fire(self):
        # 200 'a's: entropy 0.0. Should not fire even though long.
        source = "x = '" + "a" * 200 + "'\n"
        self.assertNotIn("DENS010", _ids(_analyze(source)))

    def test_short_high_entropy_string_does_not_fire(self):
        # Below the 80-char minimum.
        source = "x = 'AbC123XyZ'\n"
        self.assertNotIn("DENS010", _ids(_analyze(source)))

    def test_dens010_includes_entropy_in_context(self):
        source = f"x = '{_HIGH_ENTROPY_B64}'\n"
        sig = _by_id(_analyze(source), "DENS010")[0]
        self.assertIn("entropy", sig.context)
        self.assertGreater(sig.context["entropy"], 5.0)
        self.assertEqual(sig.context["length"], 128)


# =============================================================================
# DENS011: base64-alphabet string
# =============================================================================

class Base64AlphabetTests(unittest.TestCase):

    def test_b64_alphabet_string_fires_dens011(self):
        source = f"x = '{_HIGH_ENTROPY_B64}'\n"
        signals = _analyze(source)
        dens011 = _by_id(signals, "DENS011")
        self.assertEqual(len(dens011), 1)
        self.assertEqual(dens011[0].confidence, Confidence.MEDIUM)

    def test_b64_string_missing_digits_does_not_fire(self):
        # Letters only, no digits: not flagged (could be a long word).
        source = "x = '" + "AbCdEfGhIjKlMnOpQrStUvWxYz" * 4 + "'\n"
        self.assertNotIn("DENS011", _ids(_analyze(source)))

    def test_b64_string_with_non_alphabet_char_does_not_fire(self):
        # A space in the middle disqualifies it.
        s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabc 123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        source = f"x = '{s}'\n"
        self.assertNotIn("DENS011", _ids(_analyze(source)))


# =============================================================================
# DENS020: low-vowel-ratio identifier
# =============================================================================

class VowelRatioIdentifierTests(unittest.TestCase):

    def test_long_vowelless_identifier_fires(self):
        # 11 chars, 0 vowels -> ratio 0.0, length >= 10 means MEDIUM.
        source = "xyz_btn_grd = 1\nprint(xyz_btn_grd)\n"
        signals = _analyze(source)
        dens020 = _by_id(signals, "DENS020")
        # Multiple Name nodes will fire (assignment target, print arg).
        self.assertGreater(len(dens020), 0)
        sig = dens020[0]
        self.assertEqual(sig.context["identifier"], "xyz_btn_grd")
        self.assertEqual(sig.confidence, Confidence.MEDIUM)

    def test_short_low_vowel_identifier_does_not_fire(self):
        # 4 chars, below _MIN_LEN_FOR_VOWEL_CHECK (6).
        source = "xyz = 1\n"
        self.assertNotIn("DENS020", _ids(_analyze(source)))

    def test_dunder_skipped(self):
        source = "__xyz__ = 1\n"
        self.assertNotIn("DENS020", _ids(_analyze(source)))

    def test_skip_listed_identifier_not_flagged(self):
        # 'cls' is in _SKIP_IDENTIFIERS but is too short anyway. Use
        # a real skip-list entry that would otherwise trigger.
        source = "ptr = 1\n"
        # ptr is too short (3 chars) AND in skip list, so does not fire.
        self.assertNotIn("DENS020", _ids(_analyze(source)))

    def test_normal_identifiers_do_not_fire(self):
        source = "calculate_average = 1\nresult_value = 2\n"
        self.assertNotIn("DENS020", _ids(_analyze(source)))


# =============================================================================
# DENS021: confusable single character
# =============================================================================

class ConfusableSingleCharTests(unittest.TestCase):

    def test_lowercase_l_fires(self):
        source = "l = 1\n"
        signals = _analyze(source)
        dens021 = _by_id(signals, "DENS021")
        self.assertEqual(len(dens021), 1)
        self.assertEqual(dens021[0].context["identifier"], "l")
        self.assertEqual(dens021[0].confidence, Confidence.LOW)

    def test_capital_o_fires(self):
        source = "O = 1\n"
        self.assertIn("DENS021", _ids(_analyze(source)))

    def test_capital_i_fires(self):
        source = "I = 1\n"
        self.assertIn("DENS021", _ids(_analyze(source)))

    def test_two_char_name_does_not_fire(self):
        source = "ll = 1\n"
        self.assertNotIn("DENS021", _ids(_analyze(source)))

    def test_normal_short_name_does_not_fire(self):
        source = "i = 0\nx = 1\n"
        self.assertNotIn("DENS021", _ids(_analyze(source)))


# =============================================================================
# DENS030: invisible Unicode
# =============================================================================

class InvisibleUnicodeTests(unittest.TestCase):

    def test_zero_width_space_fires(self):
        source = "x = 1\u200b + 2\n"
        signals = _analyze(source)
        dens030 = _by_id(signals, "DENS030")
        self.assertEqual(len(dens030), 1)
        self.assertEqual(dens030[0].confidence, Confidence.HIGH)
        self.assertIn("ZERO WIDTH SPACE", dens030[0].context["unicode_name"])

    def test_rtl_override_fires_definite(self):
        # U+202E is the highest-risk codepoint (Trojan Source).
        source = "x = 'safe\u202emalicious'\n"
        signals = _analyze(source)
        dens030 = _by_id(signals, "DENS030")
        self.assertEqual(len(dens030), 1)
        self.assertEqual(dens030[0].confidence, Confidence.DEFINITE)

    def test_multiple_invisibles_on_same_line_only_fire_once(self):
        source = "x = 1\u200b + 2\u200b + 3\u200b\n"
        signals = _analyze(source)
        dens030 = _by_id(signals, "DENS030")
        # All three are on line 1; we deduplicate per line.
        self.assertEqual(len(dens030), 1)

    def test_multiple_invisibles_across_lines_fire_separately(self):
        source = "x = 1\u200b\ny = 2\u200b\n"
        signals = _analyze(source)
        dens030 = _by_id(signals, "DENS030")
        self.assertEqual(len(dens030), 2)
        lines = sorted(s.location.line for s in dens030)
        self.assertEqual(lines, [1, 2])


# =============================================================================
# DENS031: Unicode homoglyphs
# =============================================================================

class HomoglyphTests(unittest.TestCase):

    def test_cyrillic_a_fires(self):
        # \u0430 is Cyrillic 'a', visually identical to ASCII 'a'.
        source = "x\u0430 = 1\n"
        signals = _analyze(source)
        dens031 = _by_id(signals, "DENS031")
        self.assertEqual(len(dens031), 1)
        self.assertEqual(dens031[0].context["ascii_lookalike"], "a")
        self.assertEqual(dens031[0].confidence, Confidence.DEFINITE)

    def test_greek_omicron_fires(self):
        # \u03bf is Greek omicron, looks like ASCII 'o'.
        source = "f\u03bfo = 1\n"
        self.assertIn("DENS031", _ids(_analyze(source)))

    def test_pure_ascii_does_not_fire(self):
        source = "exec_safe_thing = 1\n"
        self.assertNotIn("DENS031", _ids(_analyze(source)))


# =============================================================================
# DENS040: disproportionate AST depth
# =============================================================================

class AstDepthTests(unittest.TestCase):

    def test_deeply_nested_one_liner_fires(self):
        # Produce >5 lines (else _MIN_LINE_COUNT_FOR_DEPTH skips us)
        # but with disproportionately deep AST. We pad with trivial lines.
        # 50 levels of list nesting on line 1 -> AST depth ~100.
        nesting = "[" * 50 + "1" + "]" * 50
        # Five trivial lines so line_count >= 5.
        source = (
            f"x = {nesting}\n"
            "y = 1\n"
            "z = 2\n"
            "w = 3\n"
            "v = 4\n"
        )
        signals = _analyze(source)
        dens040 = _by_id(signals, "DENS040")
        self.assertEqual(len(dens040), 1)

    def test_normal_balanced_code_does_not_fire(self):
        # Wide rather than deep: many short statements.
        source = "\n".join(f"x{i} = {i}" for i in range(20)) + "\n"
        self.assertNotIn("DENS040", _ids(_analyze(source)))

    def test_tiny_file_does_not_fire(self):
        # _MIN_LINE_COUNT_FOR_DEPTH = 5; a 2-line file should be skipped.
        nesting = "[" * 50 + "1" + "]" * 50
        source = f"x = {nesting}\n"
        self.assertNotIn("DENS040", _ids(_analyze(source)))


# =============================================================================
# DENS041: deep lambda/comprehension nesting
# =============================================================================

class NestedLambdaTests(unittest.TestCase):

    def test_four_deep_lambda_fires(self):
        # Threshold is > 3 levels.
        source = "f = lambda a: lambda b: lambda c: lambda d: a+b+c+d\n"
        signals = _analyze(source)
        dens041 = _by_id(signals, "DENS041")
        self.assertGreaterEqual(len(dens041), 1)

    def test_two_deep_lambda_does_not_fire(self):
        source = "f = lambda a: lambda b: a + b\n"
        self.assertNotIn("DENS041", _ids(_analyze(source)))

    def test_nested_comprehensions_fire(self):
        source = "x = [[[[i for i in r] for r in m] for m in g] for g in d]\n"
        signals = _analyze(source)
        self.assertIn("DENS041", _ids(signals))


# =============================================================================
# DENS042: large integer literal arrays
# =============================================================================

class IntegerArrayTests(unittest.TestCase):

    def test_byte_range_list_fires(self):
        # 30 ints all 0-255: ratio 1.0, count 30, both above threshold.
        ints = ", ".join(str(i) for i in range(30))
        source = f"shellcode = [{ints}]\n"
        signals = _analyze(source)
        dens042 = _by_id(signals, "DENS042")
        self.assertEqual(len(dens042), 1)
        self.assertEqual(dens042[0].context["element_count"], 30)
        self.assertEqual(dens042[0].context["byte_range_count"], 30)

    def test_byte_range_tuple_fires(self):
        ints = ", ".join(str(i) for i in range(30))
        source = f"shellcode = ({ints},)\n"
        self.assertIn("DENS042", _ids(_analyze(source)))

    def test_short_list_does_not_fire(self):
        ints = ", ".join(str(i) for i in range(10))
        source = f"x = [{ints}]\n"
        self.assertNotIn("DENS042", _ids(_analyze(source)))

    def test_out_of_range_list_does_not_fire(self):
        # 30 large ints, all > 255: ratio 0.0.
        ints = ", ".join(str(i * 1000) for i in range(30))
        source = f"x = [{ints}]\n"
        self.assertNotIn("DENS042", _ids(_analyze(source)))

    def test_mixed_types_below_ratio_threshold_does_not_fire(self):
        # 30 elements, only 10 are byte-range ints (33%, below 80%).
        ints = ", ".join(str(i) for i in range(10))
        strs = ", ".join(f"'{i}'" for i in range(20))
        source = f"x = [{ints}, {strs}]\n"
        self.assertNotIn("DENS042", _ids(_analyze(source)))


# =============================================================================
# DENS050: high-entropy docstring
# =============================================================================

class DocstringEntropyTests(unittest.TestCase):

    def test_high_entropy_module_docstring_fires(self):
        # _HIGH_ENTROPY_B64 is 128 chars, entropy 6.0 -> well above
        # the 5.2 docstring threshold and 60-char minimum.
        source = f'"""{_HIGH_ENTROPY_B64}"""\nx = 1\n'
        signals = _analyze(source)
        dens050 = _by_id(signals, "DENS050")
        self.assertEqual(len(dens050), 1)
        self.assertEqual(dens050[0].confidence, Confidence.HIGH)

    def test_normal_docstring_does_not_fire(self):
        source = (
            '"""This module computes the answer to life, the universe, '
            'and everything in a clean and readable way."""\n'
            "x = 1\n"
        )
        self.assertNotIn("DENS050", _ids(_analyze(source)))

    def test_high_entropy_function_docstring_fires(self):
        source = (
            "def f():\n"
            f'    """{_HIGH_ENTROPY_B64}"""\n'
            "    return 1\n"
        )
        signals = _analyze(source)
        self.assertIn("DENS050", _ids(signals))

    def test_high_entropy_docstring_does_not_also_fire_dens010(self):
        """The docstring fix: a docstring should ONLY fire DENS050,
        not also DENS010 for the same string."""
        source = f'"""{_HIGH_ENTROPY_B64}"""\nx = 1\n'
        signals = _analyze(source)
        dens050 = _by_id(signals, "DENS050")
        dens010 = _by_id(signals, "DENS010")
        # DENS050 fires; DENS010 must not fire on the same docstring.
        self.assertEqual(len(dens050), 1)
        self.assertEqual(
            len(dens010), 0,
            "docstring fired both DENS050 and DENS010; the visit_Expr "
            "branch is double-emitting",
        )


# =============================================================================
# DENS051: __doc__ passed to a callable
# =============================================================================

class DynamicDocTests(unittest.TestCase):

    def test_exec_doc_fires(self):
        source = "exec(__doc__)\n"
        signals = _analyze(source)
        dens051 = _by_id(signals, "DENS051")
        self.assertEqual(len(dens051), 1)
        self.assertEqual(dens051[0].context["callee"], "exec")
        self.assertEqual(dens051[0].context["reference"], "__doc__")
        self.assertEqual(dens051[0].confidence, Confidence.HIGH)

    def test_attribute_doc_fires(self):
        source = "exec(some_module.__doc__)\n"
        signals = _analyze(source)
        dens051 = _by_id(signals, "DENS051")
        self.assertEqual(len(dens051), 1)
        self.assertIn("__doc__", dens051[0].context["reference"])

    def test_unrelated_dunder_does_not_fire(self):
        source = "x = __name__\n"
        self.assertNotIn("DENS051", _ids(_analyze(source)))

    def test_doc_without_call_does_not_fire(self):
        source = "x = __doc__\n"
        self.assertNotIn("DENS051", _ids(_analyze(source)))


# =============================================================================
# Robustness
# =============================================================================

class RobustnessTests(unittest.TestCase):

    def test_unparseable_source_still_runs_token_layer(self):
        # Token-density and Unicode layers should still run on
        # source that fails to parse.
        nums = ", ".join(str(i) for i in range(60))
        source = f"x = [{nums}]\ndef (\n"   # syntax error on line 2
        signals = _analyze(source)
        # DENS001 should still fire from the token layer.
        self.assertIn("DENS001", _ids(signals))

    def test_empty_source_produces_no_signals(self):
        self.assertEqual(_analyze(""), [])

    def test_random_bytes_does_not_crash(self):
        import os
        for _ in range(20):
            blob = os.urandom(256)
            try:
                src = blob.decode("utf-8")
            except UnicodeDecodeError:
                continue
            try:
                signals = _analyze(src)
            except Exception as exc:
                self.fail(f"analyzer crashed on random input: {exc!r}")
            self.assertIsInstance(signals, list)


# =============================================================================
# .pth exec line entry point
# =============================================================================

class PthExecLineTests(unittest.TestCase):

    def _analyze_pth(self, line: str, line_no: int = 1) -> list:
        analyzer = CodeDensityAnalyzer()
        loc = SourceLocation(line=line_no, column=0)
        return list(analyzer.analyze_pth_exec_line(line, loc))

    def test_pth_dense_line_fires_dens001(self):
        nums = ", ".join(str(i) for i in range(60))
        # .pth exec lines normally start with "import "
        line = f"import sys; sys.x = [{nums}]"
        signals = self._analyze_pth(line)
        self.assertIn("DENS001", _ids(signals))

    def test_pth_semicolon_chain_fires_dens002(self):
        line = "import os; import sys; os.system('foo')"
        signals = self._analyze_pth(line)
        self.assertIn("DENS002", _ids(signals))

    def test_pth_b64_string_fires(self):
        line = f"import x; x.payload = '{_HIGH_ENTROPY_B64}'"
        signals = self._analyze_pth(line)
        self.assertIn("DENS010", _ids(signals))
        # Location should be re-stamped to the .pth line number we
        # passed in (5), not 1 from the inline parse.
        signals = self._analyze_pth(line, line_no=5)
        for sig in signals:
            if sig.signal_id in ("DENS010", "DENS011"):
                self.assertEqual(sig.location.line, 5)

    def test_pth_invisible_unicode_fires(self):
        line = "import\u200b sys"
        signals = self._analyze_pth(line)
        self.assertIn("DENS030", _ids(signals))

    def test_pth_does_not_emit_dens020_or_dens050(self):
        # The .pth path is intentionally narrower: no identifier
        # checks (no namespace context) and no docstring checks
        # (single-line statements).
        line = "import xyz_btn_grd_qrt"  # would fire DENS020 in Python mode
        signals = self._analyze_pth(line)
        self.assertNotIn("DENS020", _ids(signals))
        self.assertNotIn("DENS050", _ids(signals))


# =============================================================================
# Cross-signal: scope is recorded
# =============================================================================

class ScopeReportingTests(unittest.TestCase):

    def test_module_scope_reported_for_module_level_string(self):
        source = f"x = '{_HIGH_ENTROPY_B64}'\n"
        sig = _by_id(_analyze(source), "DENS010")[0]
        self.assertEqual(sig.scope, Scope.MODULE)

    def test_function_scope_reported(self):
        source = (
            "def f():\n"
            f"    x = '{_HIGH_ENTROPY_B64}'\n"
        )
        sig = _by_id(_analyze(source), "DENS010")[0]
        self.assertEqual(sig.scope, Scope.FUNCTION)


if __name__ == "__main__":
    unittest.main()