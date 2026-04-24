"""Tests for pydepgate.parsers.pth."""

import json
import pathlib
import unittest

from pydepgate.parsers.pth import LineKind, parse_pth


FIXTURES_DIR = pathlib.Path(__file__).parent.parent / "fixtures" / "pth"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"


class ParserSafetyTests(unittest.TestCase):
    """The parser must never execute content from input bytes."""

    def test_does_not_execute_import(self):
        # If the parser executed this, it would set a global.
        # If it doesn't, the global stays unset.
        evil = b"import sys; sys.PYDEPGATE_WAS_PWNED = True\n"
        parse_pth(evil, "<test>")
        self.assertFalse(
            hasattr(__import__("sys"), "PYDEPGATE_WAS_PWNED"),
            "parser executed input — this is a critical safety failure",
        )

    def test_does_not_touch_filesystem(self):
        # An attacker might try to trick a parser into opening files.
        # parse_pth takes bytes directly, so it shouldn't touch disk.
        evil = b"import os; os.system('touch /tmp/pydepgate_pwned')\n"
        parse_pth(evil, "<test>")
        self.assertFalse(
            pathlib.Path("/tmp/pydepgate_pwned").exists(),
            "parser had a filesystem side effect",
        )

    def test_handles_arbitrary_bytes_without_raising(self):
        # Fuzzing-lite: random bytes should produce a ParsedPth, not crash.
        import os
        for _ in range(100):
            result = parse_pth(os.urandom(200), "<fuzz>")
            self.assertIsNotNone(result)


class ClassificationTests(unittest.TestCase):
    """Lines must be classified exactly as site.addpackage() would."""

    def test_blank_line(self):
        result = parse_pth(b"\n", "<test>")
        self.assertEqual(result.lines[0].kind, LineKind.BLANK)

    def test_comment_line(self):
        result = parse_pth(b"# this is a comment\n", "<test>")
        self.assertEqual(result.lines[0].kind, LineKind.COMMENT)

    def test_indented_comment_is_comment(self):
        # site.py strips before checking for '#'
        result = parse_pth(b"   # indented comment\n", "<test>")
        self.assertEqual(result.lines[0].kind, LineKind.COMMENT)

    def test_import_with_space_is_exec(self):
        result = parse_pth(b"import os\n", "<test>")
        self.assertEqual(result.lines[0].kind, LineKind.EXEC)

    def test_import_with_tab_is_exec(self):
        result = parse_pth(b"import\tos\n", "<test>")
        self.assertEqual(result.lines[0].kind, LineKind.EXEC)

    def test_leading_whitespace_before_import_is_path(self):
        # This is the subtle one. site.py does NOT strip before the
        # import check, so '    import os' is classified as a path
        # by Python and will NOT be exec'd. We match that.
        result = parse_pth(b"    import os\n", "<test>")
        self.assertEqual(result.lines[0].kind, LineKind.PATH)

    def test_from_import_is_path_not_exec(self):
        # site.py only exec's lines starting with 'import ' or 'import\t'.
        # 'from X import Y' starts with 'from ' and is treated as a path.
        result = parse_pth(b"from os import path\n", "<test>")
        self.assertEqual(result.lines[0].kind, LineKind.PATH)

    def test_simple_path(self):
        result = parse_pth(b"/some/path/here\n", "<test>")
        self.assertEqual(result.lines[0].kind, LineKind.PATH)

    def test_line_numbers_are_one_indexed(self):
        result = parse_pth(b"\n# comment\nimport os\n", "<test>")
        self.assertEqual(result.lines[0].line_number, 1)
        self.assertEqual(result.lines[1].line_number, 2)
        self.assertEqual(result.lines[2].line_number, 3)


class LineEndingTests(unittest.TestCase):
    def test_unix_line_endings(self):
        result = parse_pth(b"a\nb\nc\n", "<test>")
        self.assertEqual(len(result.lines), 3)

    def test_windows_line_endings(self):
        result = parse_pth(b"a\r\nb\r\nc\r\n", "<test>")
        self.assertEqual(len(result.lines), 3)
        # Raw should not include \r either
        self.assertEqual(result.lines[0].raw, "a")

    def test_mixed_line_endings(self):
        result = parse_pth(b"a\nb\r\nc\rd\n", "<test>")
        # splitlines handles all three
        self.assertEqual(len(result.lines), 4)


class EncodingTests(unittest.TestCase):
    def test_utf8_success(self):
        result = parse_pth("héllo\n".encode("utf-8"), "<test>")
        self.assertEqual(result.encoding_used, "utf-8")
        self.assertEqual(result.decode_notes, ())

    def test_utf8_failure_falls_back_to_latin1(self):
        # 0xff is invalid as UTF-8 start byte
        result = parse_pth(b"\xff\xfe\xff\n", "<test>")
        self.assertIn("latin-1", result.encoding_used)
        self.assertEqual(len(result.decode_notes), 1)


class ManifestTests(unittest.TestCase):
    """Parser output must match the manifest for every fixture."""

    @classmethod
    def setUpClass(cls):
        with open(MANIFEST_PATH) as f:
            cls.manifest = json.load(f)

    def test_all_fixtures_present(self):
        for name in self.manifest["fixtures"]:
            fixture_path = FIXTURES_DIR / name
            self.assertTrue(
                fixture_path.exists(),
                f"fixture {name} listed in manifest but missing on disk",
            )

    def test_fixtures_match_manifest(self):
        for name, expected in self.manifest["fixtures"].items():
            fixture_path = FIXTURES_DIR / name
            content = fixture_path.read_bytes()
            result = parse_pth(content, str(fixture_path))

            with self.subTest(fixture=name):
                if "expected_size_bytes" in expected:
                    self.assertEqual(
                        result.size_bytes,
                        expected["expected_size_bytes"],
                    )
                if "expected_exec_count" in expected:
                    self.assertEqual(
                        len(result.exec_lines),
                        expected["expected_exec_count"],
                    )
                if "expected_path_count" in expected:
                    self.assertEqual(
                        len(result.path_lines),
                        expected["expected_path_count"],
                    )
                if "expected_encoding_used" in expected:
                    self.assertEqual(
                        result.encoding_used,
                        expected["expected_encoding_used"],
                    )


if __name__ == "__main__":
    unittest.main()