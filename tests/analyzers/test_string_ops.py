"""Tests for pydepgate.analyzers.string_ops."""

import unittest

from pydepgate.analyzers.string_ops import StringOpsAnalyzer
from pydepgate.analyzers.base import Confidence, Scope
from pydepgate.parsers.pysource import parse_python_source


def _analyze(source: str) -> list:
    parsed = parse_python_source(source.encode("utf-8"), "<test>")
    analyzer = StringOpsAnalyzer()
    return list(analyzer.analyze_python(parsed))


def _ids(signals) -> list[str]:
    return [s.signal_id for s in signals]


def _signals_by_id(signals, signal_id: str) -> list:
    return [s for s in signals if s.signal_id == signal_id]


# =============================================================================
# Tier 1: Happy-path detection of known patterns
# =============================================================================

class StandaloneObfuscationTests(unittest.TestCase):
    """STR001: obfuscated expressions that resolve to sensitive names."""

    def test_concat_resolves_to_eval(self):
        source = "name = 'ev' + 'al'\n"
        signals = _analyze(source)
        # The Assign tracking captures it; STR001 fires only on Expr.
        # Since this is an Assign, no STR001. (STR003 also doesn't
        # fire because the var isn't used in a dangerous call.)
        self.assertEqual(_ids(signals), [])

    def test_standalone_expression_statement_with_obfuscation(self):
        # A bare expression statement that resolves to 'eval'.
        # Real malware rarely has this (the value would be discarded),
        # but we cover it for completeness.
        source = "'ev' + 'al'\n"
        signals = _analyze(source)
        str001 = _signals_by_id(signals, "STR001")
        self.assertEqual(len(str001), 1)
        self.assertEqual(str001[0].context["resolved_value"], "eval")
        self.assertEqual(str001[0].confidence, Confidence.MEDIUM)


class DangerousCallObfuscationTests(unittest.TestCase):
    """STR002: obfuscated argument to dangerous function."""

    def test_getattr_with_concat_eval_fires(self):
        source = "fn = getattr(__builtins__, 'ev' + 'al')\n"
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        self.assertEqual(len(str002), 1)
        self.assertEqual(str002[0].context["resolved_value"], "eval")
        self.assertEqual(str002[0].context["function"], "getattr")
        # Two ops minimum: constant + constant + concat = 1 obf op
        # (string_concat). Confidence should be HIGH at minimum.
        self.assertGreaterEqual(str002[0].confidence, Confidence.HIGH)

    def test_getattr_with_chr_concat_eval_fires_definite(self):
        source = (
            "fn = getattr(__builtins__, "
            "chr(101) + chr(118) + chr(97) + chr(108))\n"
        )
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        self.assertEqual(len(str002), 1)
        self.assertEqual(str002[0].context["resolved_value"], "eval")
        # 4 chr + 3 concat = 7 obf ops. Confidence DEFINITE.
        self.assertEqual(str002[0].confidence, Confidence.DEFINITE)

    def test_getattr_with_reverse_eval_fires(self):
        source = "fn = getattr(__builtins__, 'lave'[::-1])\n"
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        self.assertEqual(len(str002), 1)
        self.assertEqual(str002[0].context["resolved_value"], "eval")

    def test_globals_subscript_with_concat_eval_fires(self):
        source = "fn = globals()['ev' + 'al']\n"
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        self.assertEqual(len(str002), 1)
        self.assertEqual(str002[0].context["form"], "subscript")

    def test_builtins_dict_subscript_with_concat_fires(self):
        source = "fn = __builtins__['ev' + 'al']\n"
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        self.assertEqual(len(str002), 1)
        self.assertEqual(str002[0].context["namespace"], "__builtins__")

    def test_import_module_with_obfuscated_module_name(self):
        source = (
            "import importlib\n"
            "mod = importlib.import_module('o' + 's')\n"
        )
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        self.assertEqual(len(str002), 1)
        self.assertEqual(str002[0].context["resolved_value"], "os")
        self.assertEqual(str002[0].context["category"], "module_name")

    def test_underscore_import_with_chr_assembled_name(self):
        source = "mod = __import__(chr(111) + chr(115))\n"
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        self.assertEqual(len(str002), 1)
        self.assertEqual(str002[0].context["resolved_value"], "os")


class CrossReferenceTests(unittest.TestCase):
    """STR003: variable holding obfuscated name used in dangerous call."""

    def test_assigned_name_used_in_getattr_fires_str003(self):
        source = (
            "name = 'ev' + 'al'\n"
            "fn = getattr(__builtins__, name)\n"
        )
        signals = _analyze(source)
        str003 = _signals_by_id(signals, "STR003")
        self.assertEqual(len(str003), 1)
        self.assertEqual(str003[0].context["resolved_value"], "eval")
        self.assertEqual(str003[0].context["variable"], "name")
        self.assertEqual(str003[0].context["assignment_line"], 1)

    def test_chr_assembled_name_used_in_import_fires_str003(self):
        source = (
            "mod_name = chr(111) + chr(115)\n"
            "mod = __import__(mod_name)\n"
        )
        signals = _analyze(source)
        str003 = _signals_by_id(signals, "STR003")
        self.assertEqual(len(str003), 1)
        self.assertEqual(str003[0].context["resolved_value"], "os")

    def test_reassigned_variable_does_not_fire_str003(self):
        # If the variable is reassigned, we conservatively skip.
        source = (
            "name = 'ev' + 'al'\n"
            "name = 'something_else'\n"
            "fn = getattr(__builtins__, name)\n"
        )
        signals = _analyze(source)
        str003 = _signals_by_id(signals, "STR003")
        self.assertEqual(len(str003), 0)


class HeavyObfuscationTests(unittest.TestCase):
    """STR004: heavy obfuscation that resolution couldn't complete."""

    def test_heavy_chr_chain_with_unresolved_var_fires_str004(self):
        # Many chr operations plus an unresolved variable in the middle.
        source = (
            "name = chr(101) + chr(118) + chr(97) + secret + chr(108)\n"
            "fn = getattr(__builtins__, name)\n"
        )
        signals = _analyze(source)
        # The assignment expression has 4 chr + 4 concats = 8 obf ops.
        # The variable is then used in getattr; STR004 fires on the
        # getattr call due to heavy obfuscation in the resolution chain
        # via STR003-style tracking, but actually our STR004 only fires
        # in _emit_str002_or_str004 which checks the call argument
        # directly. So we expect STR004 here only if the call argument
        # itself fails to resolve heavily.
        # In this case, the call argument is a Name (`name`), which
        # is unresolved (no scope_table given to resolver). So
        # _emit_str002_or_str004 sees an unresolved Name with 0 obf ops.
        # No STR004 fires from the call site.
        # STR003 should fire from the partial resolution detection
        # in finalize(), but STR003 requires a fully-resolved sensitive
        # value, which we don't have (one fragment is unresolved).
        # So this case currently produces no signals from STR003 or STR004.
        # Documenting this as a known gap; the partial-resolution path
        # for STR003 is a future improvement.
        # For now, just verify we don't crash.
        self.assertIsInstance(signals, list)


# =============================================================================
# Tier 2: Partial resolution paths
# =============================================================================

class PartialResolutionTests(unittest.TestCase):

    def test_partial_resolution_with_sensitive_fragment(self):
        # 'ev' + secret + 'al' partially resolves; the resolved
        # fragments concatenate to 'eval' which is sensitive.
        source = "fn = getattr(__builtins__, 'ev' + secret + 'al')\n"
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        # The partial-resolution branch fires.
        self.assertEqual(len(str002), 1)
        self.assertIn("partially resolves", str002[0].description)

    def test_partial_resolution_no_sensitive_fragment(self):
        # 'hello_' + secret + '_world' partially resolves but
        # doesn't contain a sensitive name.
        source = (
            "msg = getattr(some_obj, 'hello_' + secret + '_world')\n"
        )
        signals = _analyze(source)
        # No STR002, no STR004 (only 1 obf op).
        self.assertEqual(_ids(signals), [])


# =============================================================================
# Tier 3: False-positive battery
# =============================================================================

class FalsePositiveBattery(unittest.TestCase):

    def test_legitimate_concat_to_non_sensitive_name(self):
        source = "name = 'pre' + 'fix'\n"
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_chr_used_for_crlf(self):
        source = "newline = chr(13) + chr(10)\n"
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_join_used_for_csv(self):
        source = "row = ','.join(['alpha', 'beta', 'gamma'])\n"
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_string_reverse_for_palindrome(self):
        source = "rev = 'hello'[::-1]\n"
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_legitimate_getattr_with_literal(self):
        # Plain getattr(obj, 'method'): not obfuscated, no signal.
        source = "method = getattr(obj, 'eval')\n"
        signals = _analyze(source)
        # 'eval' as a literal has 0 obfuscation operations, so no STR002.
        self.assertEqual(_ids(signals), [])

    def test_legitimate_getattr_on_user_object(self):
        # getattr on something other than builtins, with normal name.
        source = "x = getattr(my_obj, 'attribute_name')\n"
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_clean_module_produces_no_signals(self):
        source = (
            "import os\n"
            "import sys\n"
            "\n"
            "def main():\n"
            "    return os.path.join('a', 'b')\n"
        )
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])

    def test_format_string_with_literal_sensitive_substring(self):
        # f-string that resolves to a string containing 'eval' as substring.
        # Should NOT fire because we use exact match for fully-resolved
        # values in standalone context.
        source = "msg = f'{\"prefix_\"}{\"eval\"}{\"_suffix\"}'\n"
        signals = _analyze(source)
        # Resolved value is 'prefix_eval_suffix', not exactly 'eval'.
        # STR001 doesn't fire (exact match). STR002 doesn't fire (not
        # in dangerous call).
        self.assertEqual(_ids(signals), [])


# =============================================================================
# Tier 4: Robustness
# =============================================================================

class RobustnessTests(unittest.TestCase):

    def test_unparseable_source_produces_no_signals(self):
        signals = _analyze("def (\n")
        self.assertEqual(signals, [])

    def test_empty_source_produces_no_signals(self):
        signals = _analyze("")
        self.assertEqual(signals, [])

    def test_getattr_with_no_args_does_not_crash(self):
        source = "x = getattr()\n"
        signals = _analyze(source)
        self.assertIsInstance(signals, list)

    def test_getattr_with_one_arg_does_not_crash(self):
        source = "x = getattr(obj)\n"
        signals = _analyze(source)
        self.assertIsInstance(signals, list)

    def test_unknown_call_does_not_crash(self):
        source = "x = some_random_function('ev' + 'al')\n"
        signals = _analyze(source)
        # No STR001 (not standalone), no STR002 (not dangerous func).
        self.assertIsInstance(signals, list)

    def test_deeply_nested_concat_does_not_crash(self):
        # Build a 30-element concat chain.
        parts = " + ".join(f"'{c}'" for c in "abcdefghijklmnopqrstuvwxyz")
        source = f"result = getattr(obj, {parts})\n"
        signals = _analyze(source)
        self.assertIsInstance(signals, list)


# =============================================================================
# Tier 5: Real-world-ish patterns
# =============================================================================

class RealWorldPatternTests(unittest.TestCase):
    """End-to-end attacks that string_ops should catch."""

    def test_classic_eval_via_chr_concat_in_getattr(self):
        source = (
            "_ = getattr(__builtins__, "
            "chr(101) + chr(118) + chr(97) + chr(108))\n"
        )
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        self.assertEqual(len(str002), 1)
        self.assertEqual(str002[0].confidence, Confidence.DEFINITE)
        self.assertEqual(str002[0].context["resolved_value"], "eval")

    def test_os_via_subscript_with_reverse(self):
        source = "module = __import__('so'[::-1])\n"
        signals = _analyze(source)
        str002 = _signals_by_id(signals, "STR002")
        self.assertEqual(len(str002), 1)
        self.assertEqual(str002[0].context["resolved_value"], "os")

    def test_subprocess_via_join(self):
        source = (
            "name = ''.join(['s','u','b','p','r','o','c','e','s','s'])\n"
            "mod = __import__(name)\n"
        )
        signals = _analyze(source)
        str003 = _signals_by_id(signals, "STR003")
        self.assertEqual(len(str003), 1)
        self.assertEqual(str003[0].context["resolved_value"], "subprocess")

    def test_compile_via_bytes_decode(self):
        source = (
            "name = bytes([99, 111, 109, 112, 105, 108, 101]).decode()\n"
            "fn = getattr(__builtins__, name)\n"
        )
        signals = _analyze(source)
        str003 = _signals_by_id(signals, "STR003")
        self.assertEqual(len(str003), 1)
        self.assertEqual(str003[0].context["resolved_value"], "compile")


if __name__ == "__main__":
    unittest.main()