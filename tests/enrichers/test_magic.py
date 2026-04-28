"""
Unit tests for `pydepgate.enrichers._magic`.

Each detection predicate is exercised in isolation with positive
and negative inputs. The top-level `detect_format` is tested with
inputs of each shape to verify the priority ordering and the
str-vs-bytes branching. `scan_indicators` is tested against
synthetic ASCII Python content.
"""

import unittest

from pydepgate.enrichers._magic import (
    FormatDetection,
    detect_format,
    is_base64,
    is_bzip2,
    is_elf,
    is_gzip,
    is_hex_0x_list,
    is_lzma,
    is_pe,
    is_pickle,
    is_png,
    is_pure_hex,
    is_zip,
    is_zlib,
    looks_like_python,
    scan_indicators,
)


# ===========================================================================
# Binary magic predicates
# ===========================================================================

class BinaryMagicPredicateTests(unittest.TestCase):

    def test_zlib_low_compression(self):
        self.assertTrue(is_zlib(b"\x78\x01" + b"\x00" * 100))

    def test_zlib_default_compression(self):
        self.assertTrue(is_zlib(b"\x78\x9c" + b"\x00" * 100))

    def test_zlib_best_compression(self):
        self.assertTrue(is_zlib(b"\x78\xda" + b"\x00" * 100))

    def test_zlib_negative_random_bytes(self):
        self.assertFalse(is_zlib(b"\x00\x00\x00"))

    def test_gzip_positive(self):
        self.assertTrue(is_gzip(b"\x1f\x8b\x08\x00rest"))

    def test_gzip_wrong_method(self):
        # Third byte must be 0x08; other gzip methods are not
        # actually used in practice but we accept only 0x08 here.
        self.assertFalse(is_gzip(b"\x1f\x8b\x07rest"))

    def test_bzip2_positive_with_level(self):
        self.assertTrue(is_bzip2(b"BZh9data"))
        self.assertTrue(is_bzip2(b"BZh1data"))

    def test_bzip2_negative_no_level(self):
        # "BZh" must be followed by a level digit '1'-'9'.
        self.assertFalse(is_bzip2(b"BZh0data"))
        self.assertFalse(is_bzip2(b"BZhAdata"))

    def test_lzma_positive(self):
        self.assertTrue(is_lzma(b"\xfd\x37\x7a\x58\x5a\x00rest"))

    def test_pe_positive(self):
        self.assertTrue(is_pe(b"MZ\x90\x00"))

    def test_pe_negative(self):
        self.assertFalse(is_pe(b"AB\x90\x00"))

    def test_elf_positive(self):
        self.assertTrue(is_elf(b"\x7fELFrest"))

    def test_png_positive(self):
        self.assertTrue(is_png(b"\x89PNG\r\n\x1a\nrest"))

    def test_zip_positive(self):
        self.assertTrue(is_zip(b"PK\x03\x04rest"))

    def test_pickle_protocol_2(self):
        self.assertTrue(is_pickle(b"\x80\x02moredata"))

    def test_pickle_protocol_4(self):
        self.assertTrue(is_pickle(b"\x80\x04moredata"))

    def test_pickle_negative_unknown_proto_byte(self):
        # 0x80 is required; 0x7f or anything else is rejected.
        self.assertFalse(is_pickle(b"\x7f\x02"))

    def test_pickle_negative_too_short(self):
        self.assertFalse(is_pickle(b"\x80"))


# ===========================================================================
# Text-encoding alphabet predicates
# ===========================================================================

class TextEncodingPredicateTests(unittest.TestCase):

    def test_base64_positive_typical(self):
        # "Hello world! This is a longer base64-encoded string."
        s = "SGVsbG8gd29ybGQhIFRoaXMgaXMgYSBsb25nZXIgYmFzZTY0LWVuY29kZWQgc3RyaW5nLg=="
        self.assertTrue(is_base64(s))

    def test_base64_url_safe(self):
        s = "SGVsbG8td29ybGRfYmFzZTY0LXVybC1zYWZl"
        self.assertTrue(is_base64(s))

    def test_base64_negative_too_short(self):
        self.assertFalse(is_base64("SGVsbG8="))

    def test_base64_negative_outside_alphabet(self):
        s = "Hello@World#" * 10
        self.assertFalse(is_base64(s))

    def test_base64_rejects_pure_hex(self):
        # Pure-hex alphabet is a subset of base64 alphabet, but
        # is_base64 rejects pure-hex inputs so the priority order
        # in detect_format goes hex -> base64 correctly.
        s = "deadbeef0123456789abcdef" * 4
        self.assertFalse(is_base64(s))

    def test_pure_hex_positive(self):
        self.assertTrue(is_pure_hex("deadbeef0123456789abcdef"))

    def test_pure_hex_negative_odd_length(self):
        self.assertFalse(is_pure_hex("deadbee"))

    def test_pure_hex_negative_too_short(self):
        self.assertFalse(is_pure_hex("dead"))

    def test_pure_hex_with_whitespace(self):
        # Whitespace is stripped before alphabet check.
        self.assertTrue(is_pure_hex("dead beef 0123 4567 89ab cdef"))

    def test_hex_0x_list_positive_comma(self):
        self.assertTrue(is_hex_0x_list(
            "0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00"
        ))

    def test_hex_0x_list_positive_space(self):
        self.assertTrue(is_hex_0x_list(
            "0x4d 0x5a 0x90 0x00 0x03 0x00 0x00 0x00"
        ))

    def test_hex_0x_list_positive_mixed_separators(self):
        self.assertTrue(is_hex_0x_list(
            "0x4d, 0x5a 0x90,0x00, 0x03 0x00, 0x00 0x00"
        ))

    def test_hex_0x_list_negative_too_few_tokens(self):
        self.assertFalse(is_hex_0x_list("0x4d, 0x5a, 0x90"))

    def test_hex_0x_list_negative_invalid_token(self):
        self.assertFalse(is_hex_0x_list(
            "0x4d, 0xZZ, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00"
        ))

    def test_hex_0x_list_negative_no_prefix(self):
        # Pure hex form is detected by is_pure_hex, not is_hex_0x_list.
        self.assertFalse(is_hex_0x_list(
            "4d, 5a, 90, 00, 03, 00, 00, 00"
        ))


# ===========================================================================
# Python-source heuristic
# ===========================================================================

class LooksLikePythonTests(unittest.TestCase):

    def test_typical_python_source(self):
        text = (
            "import subprocess\n"
            "import os\n"
            "def main():\n"
            "    subprocess.run(['echo', 'hi'])\n"
            "main()\n"
        )
        self.assertTrue(looks_like_python(text))

    def test_module_with_class(self):
        text = (
            "class Worker:\n"
            "    def __init__(self):\n"
            "        self.value = 42\n"
        )
        self.assertTrue(looks_like_python(text))

    def test_negative_english_prose(self):
        text = "The quick brown fox jumps over the lazy dog. " * 50
        self.assertFalse(looks_like_python(text))

    def test_negative_json(self):
        text = '{"key": "value", "count": 42, "items": [1, 2, 3]}\n' * 20
        self.assertFalse(looks_like_python(text))

    def test_negative_empty(self):
        self.assertFalse(looks_like_python(""))

    def test_negative_high_nonprintable_fraction(self):
        # Has a Python token but is mostly non-printable; rejected.
        text = "import os" + "\x01\x02\x03\x04" * 100
        self.assertFalse(looks_like_python(text))


# ===========================================================================
# Top-level detect_format priority and routing
# ===========================================================================

class DetectFormatStrTests(unittest.TestCase):
    """str inputs route to text-encoding detection."""

    def test_str_base64(self):
        s = "SGVsbG8gd29ybGQhIFRoaXMgaXMgYSBsb25nZXIgYmFzZTY0LWVuY29kZWQu"
        d = detect_format(s)
        self.assertEqual(d.kind, "base64")
        self.assertFalse(d.is_terminal)

    def test_str_pure_hex(self):
        s = "deadbeef0123456789abcdef"
        d = detect_format(s)
        self.assertEqual(d.kind, "hex")
        self.assertFalse(d.is_terminal)

    def test_str_hex_0x_list(self):
        s = "0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00"
        d = detect_format(s)
        self.assertEqual(d.kind, "hex_0x_list")
        self.assertFalse(d.is_terminal)

    def test_str_python_source(self):
        s = "import os\ndef foo():\n    return 1\n"
        d = detect_format(s)
        self.assertEqual(d.kind, "python_source")
        self.assertTrue(d.is_terminal)

    def test_str_ascii_fallback(self):
        s = "Hello, world! This is just plain English text. "
        d = detect_format(s)
        self.assertEqual(d.kind, "ascii_text")
        self.assertTrue(d.is_terminal)


class DetectFormatBytesTests(unittest.TestCase):
    """bytes inputs route to binary magic first."""

    def test_bytes_pickle_takes_priority(self):
        # 0x80 0x02 ... so pickle wins.
        d = detect_format(b"\x80\x02more pickle stuff")
        self.assertEqual(d.kind, "pickle_data")
        self.assertTrue(d.is_terminal)

    def test_bytes_zlib(self):
        d = detect_format(b"\x78\x9c" + b"\x00" * 50)
        self.assertEqual(d.kind, "zlib")
        self.assertFalse(d.is_terminal)

    def test_bytes_gzip(self):
        d = detect_format(b"\x1f\x8b\x08\x00" + b"\x00" * 50)
        self.assertEqual(d.kind, "gzip")
        self.assertFalse(d.is_terminal)

    def test_bytes_pe(self):
        d = detect_format(b"MZ" + b"\x00" * 50)
        self.assertEqual(d.kind, "pe_executable")
        self.assertTrue(d.is_terminal)

    def test_bytes_elf(self):
        d = detect_format(b"\x7fELF" + b"\x00" * 50)
        self.assertEqual(d.kind, "elf_executable")
        self.assertTrue(d.is_terminal)

    def test_bytes_png(self):
        d = detect_format(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
        self.assertEqual(d.kind, "png_image")
        self.assertTrue(d.is_terminal)

    def test_bytes_zip(self):
        d = detect_format(b"PK\x03\x04" + b"\x00" * 50)
        self.assertEqual(d.kind, "zip_archive")
        self.assertTrue(d.is_terminal)

    def test_bytes_ascii_falls_back_to_text_encoding(self):
        # ASCII bytes with base64-shaped content; should detect b64.
        s = b"SGVsbG8gd29ybGQhIFRoaXMgaXMgYSBsb25nZXIgYmFzZTY0LWVuY29kZWQu"
        d = detect_format(s)
        self.assertEqual(d.kind, "base64")
        self.assertFalse(d.is_terminal)

    def test_bytes_ascii_python_source(self):
        s = b"import subprocess\ndef run():\n    pass\n"
        d = detect_format(s)
        self.assertEqual(d.kind, "python_source")
        self.assertTrue(d.is_terminal)

    def test_bytes_unrecognized_terminal(self):
        # Random binary; nothing matches.
        s = b"\x01\x02\x03\x04\x05\xff\xfe\xfd\xfc"
        d = detect_format(s)
        self.assertEqual(d.kind, "binary_unknown")
        self.assertTrue(d.is_terminal)


# ===========================================================================
# Indicator scanning
# ===========================================================================

class ScanIndicatorsTests(unittest.TestCase):

    def test_finds_subprocess(self):
        text = "import subprocess\nsubprocess.run(['ls'])"
        indicators = scan_indicators(text)
        self.assertIn("subprocess", indicators)

    def test_finds_multiple(self):
        text = (
            "import subprocess\n"
            "import urllib\n"
            "subprocess.run(['curl', 'http://...'])\n"
        )
        indicators = scan_indicators(text)
        self.assertIn("subprocess", indicators)
        self.assertIn("urllib", indicators)

    def test_finds_in_bytes(self):
        data = b"import subprocess\nimport os.system\n"
        indicators = scan_indicators(data)
        self.assertIn("subprocess", indicators)
        self.assertIn("os.system", indicators)

    def test_returns_empty_for_clean_input(self):
        text = "x = 1 + 2\ny = str(x)\nprint(y)\n"
        self.assertEqual(scan_indicators(text), ())

    def test_handles_non_ascii_bytes(self):
        data = b"\xff\xfe\xfd subprocess \xfc\xfb"
        indicators = scan_indicators(data)
        self.assertIn("subprocess", indicators)

    def test_indicators_in_encounter_order(self):
        # Test stability of return order for stable test output.
        text = (
            "import urllib\nimport subprocess\nimport os.system\n"
        )
        indicators = scan_indicators(text)
        # Order is by the constant tuple in _magic.py; subprocess
        # comes before urllib in the constant, so subprocess
        # appears first regardless of source order.
        self.assertEqual(
            indicators[:3],
            ("subprocess", "urllib", "os.system"),
        )


if __name__ == "__main__":
    unittest.main()