"""Tests for pydepgate.analyzers.encoding_abuse."""

import unittest

from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.analyzers.base import Confidence, Scope
from pydepgate.parsers.pysource import parse_python_source


def _analyze(source: str) -> list:
    """Helper: parse source and run the analyzer, return list of signals."""
    parsed = parse_python_source(source.encode("utf-8"), "<test>")
    analyzer = EncodingAbuseAnalyzer()
    return list(analyzer.analyze_python(parsed))


class EncodingAbuseDetectionTests(unittest.TestCase):

    def test_clean_code_produces_no_signals(self):
        source = "x = 1 + 2\ny = str(x)\n"
        signals = _analyze(source)
        self.assertEqual(signals, [])

    def test_plain_base64_decode_produces_no_signal(self):
        # Using b64decode is fine; executing the result is not.
        source = (
            "import base64\n"
            "data = base64.b64decode('aGVsbG8=')\n"
            "print(data)\n"
        )
        signals = _analyze(source)
        self.assertEqual(signals, [])

    def test_exec_base64_literal_fires_definite(self):
        # Decoded payload is 'print(1)', inert.
        source = (
            "import base64\n"
            "exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        signals = _analyze(source)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].signal_id, "ENC001")
        self.assertEqual(signals[0].scope, Scope.MODULE)
        # Short literal won't trigger payload heuristic.
        # Confidence should be HIGH, not DEFINITE.
        self.assertEqual(signals[0].confidence, Confidence.HIGH)

    def test_exec_long_base64_literal_fires_definite(self):
        # Long literal that looks like a payload.
        long_payload = "A" * 80
        source = (
            f"import base64\n"
            f"exec(base64.b64decode('{long_payload}'))\n"
        )
        signals = _analyze(source)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].confidence, Confidence.DEFINITE)
        self.assertTrue(signals[0].context["has_payload_literal"])

    def test_eval_zlib_decompress_fires(self):
        source = (
            "import zlib\n"
            "eval(zlib.decompress(b'x\\x9c...'))\n"
        )
        signals = _analyze(source)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].context["decode_module"], "zlib")

    def test_compile_with_hex_decode_fires(self):
        source = (
            "import binascii\n"
            "compile(binascii.unhexlify('6162'), '<str>', 'exec')\n"
        )
        signals = _analyze(source)
        self.assertEqual(len(signals), 1)

    def test_decode_inside_function_uses_function_scope(self):
        source = (
            "import base64\n"
            "def evil():\n"
            "    exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        signals = _analyze(source)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].scope, Scope.FUNCTION)

    def test_decode_inside_nested_function(self):
        source = (
            "import base64\n"
            "def outer():\n"
            "    def inner():\n"
            "        exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        signals = _analyze(source)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].scope, Scope.NESTED_FUNCTION)

    def test_decode_inside_class_body(self):
        source = (
            "import base64\n"
            "class Evil:\n"
            "    exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        signals = _analyze(source)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].scope, Scope.CLASS_BODY)

    def test_location_is_reported(self):
        source = (
            "import base64\n"
            "\n"
            "exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        signals = _analyze(source)
        self.assertEqual(signals[0].location.line, 3)

    def test_unparseable_source_produces_no_signals(self):
        source = "def (\n"  # Syntax error.
        signals = _analyze(source)
        self.assertEqual(signals, [])


class EncodingAbuseNonTriggersTests(unittest.TestCase):
    """Patterns that should NOT fire encoding_abuse signals."""

    def test_string_concatenation_is_not_a_payload_literal(self):
        # Not an encoded string, just normal concatenation.
        source = (
            "s = 'hello' + ' ' + 'world'\n"
        )
        signals = _analyze(source)
        self.assertEqual(signals, [])

    def test_ordinary_hex_is_not_a_signal(self):
        source = "x = 0xdeadbeef\n"
        signals = _analyze(source)
        self.assertEqual(signals, [])

    def test_exec_without_decode_is_different_concern(self):
        # Bare exec() is suspicious but caught by a different analyzer.
        source = "exec('print(1)')\n"
        signals = _analyze(source)
        self.assertEqual(signals, [])