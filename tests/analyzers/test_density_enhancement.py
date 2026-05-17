"""
Tests for DENS051 prose-aware suppression.

DENS051 fires when __doc__ is passed to a callable. The signal's
threat model is "payload hidden in a docstring then exec'd."
False positives appear in libraries that legitimately reformat
their docstrings (sphinx-style documentation tooling).

This module verifies the new behavior: when the actual docstring
content can be resolved and classifies as plain ASCII prose,
suppress the finding. When the content classifies as encoded,
binary, Python source, or is unresolvable, emit as before.
"""

import unittest

from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.parsers.pysource import parse_python_source


def _scan(source: str) -> list:
    """Run the analyzer over a source string and return signals."""
    parsed = parse_python_source(source.encode("utf-8"), "test.py")
    analyzer = CodeDensityAnalyzer()
    return list(analyzer.analyze_python(parsed))


def _dens051_signals(signals) -> list:
    """Filter to DENS051 signals only."""
    return [s for s in signals if s.signal_id == "DENS051"]


# =============================================================================


class BareDocAtModuleLevelTests(unittest.TestCase):
    """Bare `__doc__` reference at module top level resolves to the
    module's docstring."""

    def test_prose_module_docstring_suppresses(self):
        source = '''
"""This module computes things. It is documentation and nothing more."""

def main():
    pass

print(__doc__)
'''
        signals = _dens051_signals(_scan(source))
        self.assertEqual(
            len(signals),
            0,
            msg=(
                f"DENS051 should be suppressed for prose module docstring; "
                f"got {len(signals)} signals"
            ),
        )

    def test_encoded_module_docstring_emits(self):
        source = '''
"""QWxsIHRoZSB3b3JsZHMgYSBzdGFnZSBhbmQgYWxsIHRoZSBtZW4gYW5kIHdvbWVuIGFyZSBtZXJlbHk="""

print(__doc__)
'''
        signals = _dens051_signals(_scan(source))
        self.assertGreaterEqual(
            len(signals),
            1,
            msg="DENS051 should emit for base64-shaped module docstring",
        )

    def test_python_source_module_docstring_emits(self):
        source = '''
"""import os
os.system('rm -rf /')
exec(open('/tmp/payload').read())
def helper():
    return __import__('subprocess')"""

print(__doc__)
'''
        signals = _dens051_signals(_scan(source))
        self.assertGreaterEqual(
            len(signals),
            1,
            msg="DENS051 should emit for Python-source-shaped module docstring",
        )

    def test_no_module_docstring_emits(self):
        # Bare __doc__ with no module docstring is unresolvable to a
        # non-None string; conservative emit.
        source = """
print(__doc__)
"""
        signals = _dens051_signals(_scan(source))
        self.assertGreaterEqual(
            len(signals),
            1,
            msg="DENS051 should emit when module has no docstring",
        )


class BareDocInsideFunctionTests(unittest.TestCase):
    """Inside a function body, bare __doc__ resolves to the module's
    docstring (per Python's runtime semantics)."""

    def test_function_body_uses_module_doc(self):
        source = '''
"""Module-level documentation as prose text."""

def show_help():
    """Function-local docstring, also prose, but not what __doc__ resolves to."""
    print(__doc__)
'''
        signals = _dens051_signals(_scan(source))
        # Bare __doc__ in function body resolves to module; module
        # docstring is prose; suppress.
        self.assertEqual(
            len(signals),
            0,
            msg="DENS051 should suppress: bare __doc__ in function body resolves to prose module docstring",
        )

    def test_function_body_with_encoded_module_doc(self):
        source = '''
"""QWxsIHRoZSB3b3JsZHMgYSBzdGFnZSBhbmQgYWxsIHRoZSBtZW4gYW5kIHdvbWVuIGFyZSBtZXJlbHk="""

def boot():
    exec(__doc__)
'''
        signals = _dens051_signals(_scan(source))
        self.assertGreaterEqual(
            len(signals),
            1,
            msg="DENS051 should emit: encoded module docstring referenced from function",
        )


class BareDocInsideClassTests(unittest.TestCase):
    """Inside a class body but not nested in a method, bare __doc__
    resolves to the class's docstring."""

    def test_class_body_uses_class_doc(self):
        source = '''
"""Module docstring, prose."""

class Widget:
    """Widget is a documentation prose class docstring."""
    print(__doc__)
'''
        signals = _dens051_signals(_scan(source))
        self.assertEqual(
            len(signals),
            0,
            msg="DENS051 should suppress: bare __doc__ in class body resolves to prose class docstring",
        )

    def test_method_body_falls_through_to_module(self):
        source = '''
"""Module docstring, prose, treated as resolution target for the method-internal __doc__."""

class Widget:
    """Class docstring, also prose but not the resolution target."""

    def helper(self):
        print(__doc__)
'''
        signals = _dens051_signals(_scan(source))
        # Inside a function nested in a class, bare __doc__ falls
        # through to module. Module is prose. Suppress.
        self.assertEqual(
            len(signals),
            0,
            msg="DENS051 should suppress: method-internal __doc__ resolves to prose module docstring",
        )


class AttributeDocReferenceTests(unittest.TestCase):
    """`.__doc__` where obj is a top-level definition."""

    def test_resolved_function_with_prose_doc_suppresses(self):
        source = '''
def some_function():
    """A documentation string for some_function, written as ordinary prose."""
    pass

print(some_function.__doc__)
'''
        signals = _dens051_signals(_scan(source))
        self.assertEqual(
            len(signals),
            0,
            msg="DENS051 should suppress when obj.__doc__ resolves to prose function docstring",
        )

    def test_resolved_class_with_prose_doc_suppresses(self):
        source = '''
class Widget:
    """Widget class documentation written as prose for sphinx."""

    def method(self):
        pass

format(Widget.__doc__)
'''
        signals = _dens051_signals(_scan(source))
        self.assertEqual(
            len(signals),
            0,
            msg="DENS051 should suppress when obj.__doc__ resolves to prose class docstring",
        )

    def test_resolved_function_with_encoded_doc_emits(self):
        source = '''
def payload_carrier():
    """QWxsIHRoZSB3b3JsZHMgYSBzdGFnZSBhbmQgYWxsIHRoZSBtZW4gYW5kIHdvbWVuIGFyZSBtZXJlbHk="""

exec(payload_carrier.__doc__)
'''
        signals = _dens051_signals(_scan(source))
        self.assertGreaterEqual(
            len(signals),
            1,
            msg="DENS051 should emit for encoded docstring resolved via attribute access",
        )

    def test_unresolvable_attribute_emits(self):
        # `some_imported_thing` is not defined at module top level.
        # The analyzer can't resolve its docstring. Conservative emit.
        source = """
from somewhere import some_imported_thing

exec(some_imported_thing.__doc__)
"""
        signals = _dens051_signals(_scan(source))
        self.assertGreaterEqual(
            len(signals),
            1,
            msg="DENS051 should emit when obj.__doc__ refers to an unresolvable name",
        )


class ScipyStyleDocformatTests(unittest.TestCase):
    """Realistic regression: the scipy `docformat()` pattern that
    motivated this work."""

    def test_scipy_pattern_suppresses(self):
        source = '''
"""Module-level explanatory documentation for the multivariate stats module.

This module provides classes for the multivariate normal distribution
and related operations. Each class includes parameter documentation
and worked examples for end users."""

class multivariate_normal_gen:
    """Generator class for the multivariate normal distribution. See module
    docstring for the broader context and parameter explanations."""

    def __init__(self):
        pass

    def _process_parameters(self):
        pass

multivariate_normal_gen.__doc__ = docformat(multivariate_normal_gen.__doc__, mvn_docdict_params)
'''
        signals = _dens051_signals(_scan(source))
        # The class docstring is prose. The .__doc__ reference
        # resolves to it. Should suppress.
        self.assertEqual(
            len(signals),
            0,
            msg=(
                "DENS051 should suppress the scipy docformat() "
                "pattern when class docstring is prose"
            ),
        )


if __name__ == "__main__":
    unittest.main()
