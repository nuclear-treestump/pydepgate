"""Tests for pydepgate.analyzers.dynamic_execution."""

import unittest

from pydepgate.analyzers.dynamic_execution import DynamicExecutionAnalyzer
from pydepgate.analyzers.base import Confidence, Scope
from pydepgate.parsers.pysource import parse_python_source


def _analyze(source: str) -> list:
    parsed = parse_python_source(source.encode("utf-8"), "<test>")
    analyzer = DynamicExecutionAnalyzer()
    return list(analyzer.analyze_python(parsed))


def _ids(signals) -> list[str]:
    return [s.signal_id for s in signals]


# =============================================================================
# Tier 1: Happy-path detection
# Does the analyzer fire on the obvious patterns?
# =============================================================================

class HappyPathDirectExecTests(unittest.TestCase):

    def test_module_level_exec_with_literal_fires_dyn001(self):
        signals = _analyze("exec('print(1)')\n")
        self.assertIn("DYN001", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "DYN001")
        self.assertEqual(sig.confidence, Confidence.MEDIUM)
        self.assertEqual(sig.scope, Scope.MODULE)

    def test_module_level_exec_with_variable_fires_dyn002(self):
        source = "x = get_payload()\nexec(x)\n"
        signals = _analyze(source)
        self.assertIn("DYN002", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "DYN002")
        self.assertEqual(sig.confidence, Confidence.HIGH)

    def test_module_level_eval_with_call_argument_fires_dyn002(self):
        source = "result = eval(some_function())\n"
        signals = _analyze(source)
        self.assertIn("DYN002", _ids(signals))

    def test_module_level_eval_with_fstring_fires_dyn002(self):
        # f-strings are dynamic by construction.
        source = "x = 1\neval(f'print({x})')\n"
        signals = _analyze(source)
        self.assertIn("DYN002", _ids(signals))

    def test_module_level_exec_with_binop_fires_dyn002(self):
        source = "exec('print(' + str(1) + ')')\n"
        signals = _analyze(source)
        self.assertIn("DYN002", _ids(signals))

    def test_function_level_exec_with_variable_fires_dyn003(self):
        source = (
            "def runner(code):\n"
            "    exec(code)\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN003", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "DYN003")
        self.assertEqual(sig.confidence, Confidence.MEDIUM)

    def test_function_level_exec_with_literal_does_not_fire(self):
        # Literal exec inside a function is too common in legit code
        # (test fixtures, config evaluators) to flag at MEDIUM.
        source = (
            "def setup():\n"
            "    exec('x = 1')\n"
        )
        signals = _analyze(source)
        self.assertEqual(_ids(signals), [])


class HappyPathDynamicImportTests(unittest.TestCase):

    def test_underscore_import_with_variable_fires_dyn004(self):
        source = "name = 'os'\n__import__(name)\n"
        signals = _analyze(source)
        self.assertIn("DYN004", _ids(signals))

    def test_importlib_with_variable_fires_dyn004(self):
        source = (
            "import importlib\n"
            "name = 'os'\n"
            "importlib.import_module(name)\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN004", _ids(signals))

    def test_underscore_import_with_literal_does_not_fire(self):
        # Static import via __import__ is legitimate (sometimes used
        # for conditional imports of optional dependencies).
        source = "__import__('os')\n"
        signals = _analyze(source)
        self.assertNotIn("DYN004", _ids(signals))


class HappyPathBuiltinsAccessTests(unittest.TestCase):

    def test_getattr_builtins_eval_fires_dyn005(self):
        source = "fn = getattr(__builtins__, 'eval')\n"
        signals = _analyze(source)
        self.assertIn("DYN005", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "DYN005")
        self.assertEqual(sig.confidence, Confidence.DEFINITE)
        self.assertEqual(sig.context["form"], "getattr")
        self.assertEqual(sig.context["primitive"], "eval")

    def test_getattr_builtins_module_form_fires_dyn005(self):
        source = (
            "import builtins\n"
            "fn = getattr(builtins, 'exec')\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN005", _ids(signals))

    def test_globals_subscript_eval_fires_dyn005(self):
        source = "fn = globals()['eval']\n"
        signals = _analyze(source)
        self.assertIn("DYN005", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "DYN005")
        self.assertEqual(sig.context["form"], "subscript")
        self.assertEqual(sig.context["namespace"], "globals")

    def test_locals_subscript_exec_fires_dyn005(self):
        source = (
            "def f():\n"
            "    fn = locals()['exec']\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN005", _ids(signals))

    def test_vars_subscript_compile_fires_dyn005(self):
        source = "fn = vars()['compile']\n"
        signals = _analyze(source)
        self.assertIn("DYN005", _ids(signals))


class HappyPathCompileThenExecTests(unittest.TestCase):

    def test_compile_then_exec_fires_dyn006(self):
        source = (
            "code = compile(payload, '<str>', 'exec')\n"
            "exec(code)\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN006", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "DYN006")
        self.assertEqual(sig.confidence, Confidence.DEFINITE)
        self.assertEqual(sig.context["variable"], "code")

    def test_compile_with_exec_mode_fires_precursor(self):
        # Even without a following exec, mode='exec' is a precursor signal.
        source = "code = compile('print(1)', '<str>', 'exec')\n"
        signals = _analyze(source)
        self.assertIn("DYN006_PRECURSOR", _ids(signals))

    def test_compile_with_eval_mode_does_not_fire_precursor(self):
        # mode='eval' produces a code object but for expressions only;
        # treated separately.
        source = "code = compile('1 + 1', '<str>', 'eval')\n"
        signals = _analyze(source)
        self.assertNotIn("DYN006_PRECURSOR", _ids(signals))

    def test_compile_then_eval_fires_dyn006(self):
        source = (
            "code = compile(expr, '<str>', 'eval')\n"
            "result = eval(code)\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN006", _ids(signals))


class HappyPathAliasedShapeTests(unittest.TestCase):

    def test_aliased_call_with_decode_argument_fires_dyn007(self):
        source = (
            "import base64\n"
            "e(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN007", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "DYN007")
        self.assertEqual(sig.confidence, Confidence.HIGH)
        self.assertEqual(sig.context["outer_call"], "e")
        self.assertEqual(sig.context["decode_function"], "base64.b64decode")

    def test_aliased_zlib_decompress_fires_dyn007(self):
        source = (
            "import zlib\n"
            "runner(zlib.decompress(b'compressed'))\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN007", _ids(signals))


# =============================================================================
# Tier 2: Evasion battery
# Patterns that try to hide what they're doing. The analyzer should
# either catch them or fail gracefully without crashing.
# =============================================================================

class EvasionAliasingTests(unittest.TestCase):

    def test_simple_alias_caught_by_dyn007(self):
        # The classic alias-and-call evasion. We can't resolve `e`,
        # but DYN007 catches it via the call shape.
        source = (
            "import base64\n"
            "e = exec\n"
            "e(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN007", _ids(signals))

    def test_module_alias_call(self):
        # exec via a module-level alias. The call uses the alias name
        # which we can't resolve as an exec primitive; DYN007 catches
        # the shape if the argument is a decode call.
        source = (
            "import base64\n"
            "from builtins import exec as run\n"
            "run(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN007", _ids(signals))

    def test_attribute_alias_call(self):
        # exec stored as an attribute of an object. DYN007 catches
        # the shape if the inner call is a decode.
        source = (
            "import base64\n"
            "obj.runner(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN007", _ids(signals))


class EvasionBuiltinsTests(unittest.TestCase):

    def test_builtins_dict_form(self):
        # __builtins__ as a dict (which it is in __main__):
        # __builtins__['eval'](...).
        source = "__builtins__['eval']('1+1')\n"
        signals = _analyze(source)
        # This is a Subscript on Name('__builtins__'), not on a Call.
        # The current implementation only catches Subscript on Call.
        # Document this gap; future work can extend _check_namespace_subscript.
        # For now, assert the call to eval (as a result of subscript) is
        # NOT caught directly.
        # Check the test surfaces this case so we know about the gap.
        # If a future version adds detection, change this assertion.
        self.assertNotIn("DYN005", _ids(signals))
        # Note: this is a known gap. Documented in the analyzer comments.

    def test_double_indirection(self):
        # Resolve the exec primitive through two layers of indirection.
        source = (
            "g = globals\n"
            "fn = g()['eval']\n"
        )
        signals = _analyze(source)
        # We catch globals()['eval'] only when globals is called directly.
        # Through `g()`, the analyzer can't resolve g. Known gap.
        self.assertNotIn("DYN005", _ids(signals))


class EvasionStringObfuscationTests(unittest.TestCase):
    """String-obfuscation evasion is the next analyzer's job, but
    we should verify dynamic_execution doesn't crash on these."""

    def test_chr_concatenation_does_not_crash(self):
        source = (
            "name = chr(101) + chr(118) + chr(97) + chr(108)\n"
            "fn = getattr(__builtins__, name)\n"
        )
        # The getattr argument is not a literal, so DYN005 doesn't fire.
        # (string_obfuscation analyzer will catch the chr build elsewhere.)
        signals = _analyze(source)
        self.assertNotIn("DYN005", _ids(signals))
        # Critical: didn't crash.
        self.assertIsInstance(signals, list)

    def test_string_split_does_not_crash(self):
        source = "fn = getattr(__builtins__, 'ev' + 'al')\n"
        # The attr argument is a BinOp, not a literal, so DYN005 doesn't fire.
        signals = _analyze(source)
        self.assertNotIn("DYN005", _ids(signals))
        self.assertIsInstance(signals, list)


class EvasionTwoStepReassignTests(unittest.TestCase):

    def test_compile_then_reassign_then_exec_still_flags(self):
        # Attacker tries to confuse the cross-reference pass by
        # reassigning the variable. We currently flag conservatively.
        source = (
            "code = compile(payload, '<str>', 'exec')\n"
            "code = code\n"  # confuse step
            "exec(code)\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN006", _ids(signals))

    def test_compile_in_one_function_exec_in_another(self):
        # Cross-function compile-then-exec. Our v0.1 detection is
        # within-file, not cross-scope-aware. The variable name
        # match catches this even though it spans functions.
        source = (
            "def make():\n"
            "    return compile(payload, '<str>', 'exec')\n"
            "code = make()\n"
            "exec(code)\n"
        )
        signals = _analyze(source)
        # The compile() is inside a function (return), not a module-level
        # assignment to a name. Our tracker only sees `name = compile(...)`
        # patterns. Document the gap.
        # If analysis improves to track function returns, change this.
        self.assertNotIn("DYN006", _ids(signals))


class EvasionSyntaxLayoutTests(unittest.TestCase):

    def test_exec_call_on_one_line_with_semicolons(self):
        # Sometimes attackers cram everything onto one line.
        source = "import os; payload=get(); exec(payload)\n"
        signals = _analyze(source)
        self.assertIn("DYN002", _ids(signals))

    def test_exec_inside_walrus(self):
        # Walrus operator: exec inside an expression.
        source = (
            "if (result := exec(get_payload())):\n"
            "    pass\n"
        )
        signals = _analyze(source)
        self.assertIn("DYN002", _ids(signals))

    def test_exec_inside_lambda(self):
        # exec inside a lambda. The lambda body counts as function scope.
        source = "fn = lambda: exec(payload)\n"
        signals = _analyze(source)
        # Lambda is technically a function. Our scope tracker doesn't
        # currently descend into Lambda; the visit_Call still fires
        # but reports MODULE scope. This is a known imprecision.
        # The signal still fires, just with the wrong scope.
        self.assertTrue(
            "DYN002" in _ids(signals) or "DYN003" in _ids(signals)
        )


# =============================================================================
# Tier 3: False-positive battery
# Patterns that look superficially suspicious but are legitimate.
# These should NOT produce signals.
# =============================================================================

class FalsePositiveBattery(unittest.TestCase):

    def test_legitimate_compile_with_eval_mode_no_following_exec(self):
        # compile(..., 'eval') is for expressions. Without a following
        # eval, this is just compiling code for caching. Should not fire
        # DYN006 (no following exec) but does fire... nothing in v0.1.
        source = (
            "expr = compile('x + 1', '<str>', 'eval')\n"
            "# expr is used elsewhere, not exec'd here\n"
        )
        signals = _analyze(source)
        # mode='eval' doesn't trigger PRECURSOR (we only flag mode='exec').
        self.assertNotIn("DYN006_PRECURSOR", _ids(signals))
        self.assertNotIn("DYN006", _ids(signals))

    def test_function_with_legitimate_eval_use(self):
        # Some libraries legitimately use eval for expression parsing.
        # Inside a function with a non-literal argument, DYN003 fires
        # at MEDIUM. That's correct: it's a real signal, the rules
        # layer can downgrade it for specific known-good packages.
        source = (
            "def parse_expr(s):\n"
            "    return eval(s)\n"
        )
        signals = _analyze(source)
        # We DO fire DYN003. This is intentional. The point of this
        # test is to confirm it's MEDIUM, not HIGH.
        self.assertIn("DYN003", _ids(signals))
        sig = next(s for s in signals if s.signal_id == "DYN003")
        self.assertEqual(sig.confidence, Confidence.MEDIUM)

    def test_print_with_decoded_data_does_not_fire_dyn007(self):
        # print(base64.b64decode(...)) is not an attack; print is
        # whitelisted in the DYN007 outer-call check.
        source = (
            "import base64\n"
            "print(base64.b64decode('aGVsbG8='))\n"
        )
        signals = _analyze(source)
        self.assertNotIn("DYN007", _ids(signals))

    def test_len_of_decoded_does_not_fire_dyn007(self):
        source = (
            "import base64\n"
            "size = len(base64.b64decode(payload))\n"
        )
        signals = _analyze(source)
        self.assertNotIn("DYN007", _ids(signals))

    def test_static_string_compile_no_exec_fires_only_precursor(self):
        # compile() with a string literal but mode='exec' is a precursor.
        source = "code = compile('print(1)', '<str>', 'exec')\n"
        signals = _analyze(source)
        # Precursor fires. DYN001 fires because it's compile() at module
        # scope with a literal first argument.
        self.assertIn("DYN006_PRECURSOR", _ids(signals))
        self.assertIn("DYN001", _ids(signals))

    def test_clean_module_produces_no_signals(self):
        source = (
            "import os\n"
            "import sys\n"
            "\n"
            "def main():\n"
            "    return os.path.join('a', 'b')\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    main()\n"
        )
        signals = _analyze(source)
        self.assertEqual(signals, [])

    def test_normal_function_definitions_produce_no_signals(self):
        source = (
            "def foo(x, y):\n"
            "    z = x + y\n"
            "    return z\n"
            "\n"
            "class Bar:\n"
            "    def method(self):\n"
            "        return self.foo()\n"
        )
        signals = _analyze(source)
        self.assertEqual(signals, [])


# =============================================================================
# Robustness tests
# =============================================================================

class RobustnessTests(unittest.TestCase):

    def test_unparseable_source_produces_no_signals(self):
        source = "def (\n"
        signals = _analyze(source)
        self.assertEqual(signals, [])

    def test_empty_source_produces_no_signals(self):
        signals = _analyze("")
        self.assertEqual(signals, [])

    def test_exec_with_no_arguments_does_not_crash(self):
        # exec() with no args is a syntax error in some forms but
        # could appear as a stub. Test we handle it gracefully.
        source = "def f():\n    exec()\n"
        signals = _analyze(source)
        # No signals; we require args[0] to fire.
        self.assertEqual(signals, [])

    def test_getattr_with_no_arguments_does_not_crash(self):
        source = "x = getattr()\n"
        signals = _analyze(source)
        self.assertEqual(signals, [])

    def test_subscript_with_non_literal_does_not_crash(self):
        source = "x = globals()[some_var]\n"
        signals = _analyze(source)
        self.assertEqual(signals, [])

    def test_deeply_nested_calls_do_not_crash(self):
        # Stress test the recursion in get_qualified_name.
        source = "a.b.c.d.e.f.g.h.i.j(arg)\n"
        signals = _analyze(source)
        self.assertIsInstance(signals, list)


if __name__ == "__main__":
    unittest.main()