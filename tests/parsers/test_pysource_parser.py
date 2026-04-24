"""Tests for pydepgate.parsers.pysource."""

import os
import pathlib
import unittest

from pydepgate.parsers.pysource import (
    Comment,
    ParseStatus,
    SourceLocation,
    parse_python_source,
)


FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures" / "pysource"


class ParserSafetyTests(unittest.TestCase):
    """Parser must never execute content from input bytes."""

    def test_does_not_execute_import(self):
        evil = b"import sys\nsys.PYDEPGATE_PYSRC_PWNED = True\n"
        parse_python_source(evil, "<test>")
        import sys
        self.assertFalse(
            hasattr(sys, "PYDEPGATE_PYSRC_PWNED"),
            "parser executed input. critical safety failure",
        )

    def test_does_not_execute_module_level_code(self):
        evil = b"import os\nos.system('touch /tmp/pydepgate_pysrc_pwned')\n"
        parse_python_source(evil, "<test>")
        self.assertFalse(
            pathlib.Path("/tmp/pydepgate_pysrc_pwned").exists(),
            "parser had a filesystem side effect",
        )

    def test_handles_random_bytes(self):
        for _ in range(100):
            result = parse_python_source(os.urandom(256), "<fuzz>")
            self.assertIsNotNone(result)
            # Status should reflect the failure, not propagate an exception.
            self.assertIn(result.status, list(ParseStatus))

    def test_handles_null_bytes(self):
        # ast.parse raises ValueError on null bytes; we should catch it.
        result = parse_python_source(b"x = 1\nimport \x00os\n", "<test>")
        self.assertEqual(result.status, ParseStatus.SYNTAX_ERROR)

    def test_handles_empty_source(self):
        result = parse_python_source(b"", "<test>")
        self.assertEqual(result.status, ParseStatus.OK)
        self.assertEqual(result.line_count, 0)
        self.assertEqual(result.comments, ())


class ParseStatusTests(unittest.TestCase):
    def test_valid_source_is_ok(self):
        result = parse_python_source(b"x = 1\n", "<test>")
        self.assertEqual(result.status, ParseStatus.OK)
        self.assertIsNotNone(result.ast_tree)

    def test_syntax_error_is_reported(self):
        result = parse_python_source(b"def (\n", "<test>")
        self.assertEqual(result.status, ParseStatus.SYNTAX_ERROR)
        self.assertIsNone(result.ast_tree)
        self.assertIn("line", result.diagnostic)

    def test_syntax_error_still_returns_partial_comments(self):
        # Even though parsing fails, the tokenizer may have seen comments.
        source = b"# header comment\ndef (\n"
        result = parse_python_source(source, "<test>")
        self.assertEqual(result.status, ParseStatus.SYNTAX_ERROR)
        self.assertEqual(len(result.comments), 1)
        self.assertIn("header comment", result.comments[0].text)


class CommentExtractionTests(unittest.TestCase):
    def test_simple_comment(self):
        result = parse_python_source(b"# hello\n", "<test>")
        self.assertEqual(len(result.comments), 1)
        self.assertEqual(result.comments[0].text, "# hello")
        self.assertEqual(result.comments[0].location.line, 1)

    def test_multiple_comments(self):
        source = b"# one\nx = 1  # inline\n# three\n"
        result = parse_python_source(source, "<test>")
        self.assertEqual(len(result.comments), 3)
        self.assertEqual(result.comments[0].location.line, 1)
        self.assertEqual(result.comments[1].location.line, 2)
        self.assertEqual(result.comments[2].location.line, 3)

    def test_inline_comment_column(self):
        # The '#' in "x = 1  # inline" should be at column 7.
        source = b"x = 1  # inline\n"
        result = parse_python_source(source, "<test>")
        self.assertEqual(len(result.comments), 1)
        self.assertEqual(result.comments[0].location.column, 7)

    def test_no_comments_in_clean_code(self):
        source = b"def f():\n    return 1\n"
        result = parse_python_source(source, "<test>")
        self.assertEqual(result.comments, ())


class ShebangTests(unittest.TestCase):
    def test_shebang_detected_on_line_one(self):
        source = b"#!/usr/bin/env python\nimport os\n"
        result = parse_python_source(source, "<test>")
        self.assertIsNotNone(result.shebang)
        self.assertTrue(result.shebang.is_shebang)
        self.assertEqual(result.shebang.location.line, 1)

    def test_shebang_not_detected_on_line_two(self):
        # A '#!' on line 2 is just a comment, not a shebang.
        source = b"# first line\n#!/usr/bin/env python\n"
        result = parse_python_source(source, "<test>")
        self.assertIsNone(result.shebang)
        # But both comments should still be extracted.
        self.assertEqual(len(result.comments), 2)

    def test_regular_comment_not_shebang(self):
        source = b"# regular comment\n"
        result = parse_python_source(source, "<test>")
        self.assertIsNone(result.shebang)
        self.assertFalse(result.comments[0].is_shebang)


class EncodingDeclarationTests(unittest.TestCase):
    def test_encoding_declaration_on_line_one(self):
        source = b"# -*- coding: utf-8 -*-\nx = 1\n"
        result = parse_python_source(source, "<test>")
        self.assertIsNotNone(result.encoding_declaration)
        self.assertEqual(result.encoding_declaration.encoding_name, "utf-8")

    def test_encoding_declaration_on_line_two(self):
        source = b"#!/usr/bin/env python\n# -*- coding: utf-8 -*-\nx = 1\n"
        result = parse_python_source(source, "<test>")
        self.assertIsNotNone(result.encoding_declaration)
        self.assertEqual(result.encoding_declaration.location.line, 2)

    def test_encoding_declaration_equals_form(self):
        source = b"# coding=latin-1\nx = 1\n"
        result = parse_python_source(source, "<test>")
        self.assertIsNotNone(result.encoding_declaration)
        self.assertEqual(result.encoding_declaration.encoding_name, "latin-1")

    def test_encoding_declaration_not_detected_after_line_two(self):
        # PEP 263 only allows encoding declarations in the first two lines.
        source = b"x = 1\ny = 2\n# -*- coding: utf-8 -*-\n"
        result = parse_python_source(source, "<test>")
        self.assertIsNone(result.encoding_declaration)

    def test_suspicious_encoding_still_extracted(self):
        # An unusual but valid text codec. Declaring this encoding is
        # legitimate (some legacy packages do) but unusual enough that
        # an analyzer should flag it for review. We're testing that the
        # parser extracts the declaration, not that the encoding is
        # suspicious. that's an analyzer's job.
        source = b"# -*- coding: koi8-r -*-\nx = 1\n"
        result = parse_python_source(source, "<test>")
        self.assertIsNotNone(result.encoding_declaration)
        self.assertEqual(result.encoding_declaration.encoding_name, "koi8-r")

    def test_invalid_encoding_falls_back_to_manual_scan(self):
        # Non-text codecs like rot_13 cause tokenize to fail in Python 3.12+.
        # The parser's fallback scan should still extract the declaration
        # so the analyzer can flag it. this is the whole point, since a
        # declaration that CPython rejects is more suspicious, not less.
        source = b"# -*- coding: rot_13 -*-\nx = 1\n"
        result = parse_python_source(source, "<test>")
        # The declaration should surface even though tokenize couldn't
        # process the file normally.
        self.assertIsNotNone(result.encoding_declaration)
        self.assertEqual(result.encoding_declaration.encoding_name, "rot_13")

class DocstringVsCommentTests(unittest.TestCase):
    """Docstrings are AST nodes, not comments. verify we don't confuse them."""

    def test_module_docstring_is_not_a_comment(self):
        source = b'"""Module docstring."""\nx = 1\n'
        result = parse_python_source(source, "<test>")
        self.assertEqual(result.comments, ())
        self.assertIsNotNone(result.ast_tree)

    def test_triple_quoted_string_is_not_a_comment(self):
        source = b'x = """not a comment"""\n'
        result = parse_python_source(source, "<test>")
        self.assertEqual(result.comments, ())


class SizeAndLineCountTests(unittest.TestCase):
    def test_size_matches_input(self):
        source = b"x = 1\n"
        result = parse_python_source(source, "<test>")
        self.assertEqual(result.size_bytes, len(source))

    def test_line_count_trailing_newline(self):
        result = parse_python_source(b"x = 1\ny = 2\n", "<test>")
        self.assertEqual(result.line_count, 2)

    def test_line_count_no_trailing_newline(self):
        result = parse_python_source(b"x = 1\ny = 2", "<test>")
        self.assertEqual(result.line_count, 2)

    def test_line_count_empty_source(self):
        result = parse_python_source(b"", "<test>")
        self.assertEqual(result.line_count, 0)


if __name__ == "__main__":
    unittest.main()