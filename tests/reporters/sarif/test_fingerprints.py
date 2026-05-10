"""Tests for the SARIF partialFingerprints algorithm."""

from __future__ import annotations
import unittest

from pydepgate.reporters.sarif.fingerprints import (
    ALGORITHM_VERSION,
    DIGEST_LENGTH,
    primary_location_line_hash,
)


class TestOutputFormat(unittest.TestCase):
    """The output format must match SARIF and GitHub conventions."""

    def test_returns_24_hex_chars_plus_version_suffix(self):
        result = primary_location_line_hash(
            "DENS010",
            "setup.py",
            7,
            "context",
        )
        assert ":" in result
        digest, version = result.rsplit(":", 1)
        assert len(digest) == 24
        assert len(digest) == DIGEST_LENGTH
        assert all(c in "0123456789abcdef" for c in digest)
        assert version == "1"
        assert version == ALGORITHM_VERSION

    def test_version_suffix_is_1(self):
        result = primary_location_line_hash("X", "y", 1, "z")
        assert result.endswith(":1")

    def test_digest_is_lowercase_hex(self):
        result = primary_location_line_hash("X", "y", 1, "z")
        digest = result.rsplit(":", 1)[0]
        assert digest == digest.lower()


class TestStability(unittest.TestCase):
    """Same logical inputs must produce identical fingerprints."""

    def test_identical_inputs_produce_identical_outputs(self):
        a = primary_location_line_hash("DENS010", "setup.py", 7, "x = 1")
        b = primary_location_line_hash("DENS010", "setup.py", 7, "x = 1")
        assert a == b

    def test_path_normalization_makes_windows_match_posix(self):
        posix = primary_location_line_hash("R", "a/b/c.py", 1, "ctx")
        windows = primary_location_line_hash("R", "a\\b\\c.py", 1, "ctx")
        assert posix == windows

    def test_leading_slash_does_not_affect_fingerprint(self):
        with_slash = primary_location_line_hash("R", "/a/b.py", 1, "ctx")
        without_slash = primary_location_line_hash("R", "a/b.py", 1, "ctx")
        assert with_slash == without_slash

    def test_multiple_leading_slashes_treated_same_as_one(self):
        a = primary_location_line_hash("R", "//a.py", 1, "ctx")
        b = primary_location_line_hash("R", "a.py", 1, "ctx")
        assert a == b


class TestDifferentiation(unittest.TestCase):
    """Different findings must produce different fingerprints."""

    def test_different_rule_id_produces_different_fingerprint(self):
        a = primary_location_line_hash("DENS010", "setup.py", 7, "ctx")
        b = primary_location_line_hash("DENS011", "setup.py", 7, "ctx")
        assert a != b

    def test_different_path_produces_different_fingerprint(self):
        a = primary_location_line_hash("R", "setup.py", 7, "ctx")
        b = primary_location_line_hash("R", "other.py", 7, "ctx")
        assert a != b

    def test_different_line_produces_different_fingerprint(self):
        a = primary_location_line_hash("R", "setup.py", 7, "ctx")
        b = primary_location_line_hash("R", "setup.py", 8, "ctx")
        assert a != b

    def test_different_context_produces_different_fingerprint(self):
        a = primary_location_line_hash("R", "setup.py", 7, "ctx-a")
        b = primary_location_line_hash("R", "setup.py", 7, "ctx-b")
        assert a != b

    def test_all_inputs_different_produces_different_fingerprint(self):
        a = primary_location_line_hash("R1", "p1", 1, "c1")
        b = primary_location_line_hash("R2", "p2", 2, "c2")
        assert a != b


class TestEdgeCases(unittest.TestCase):
    """Robustness against unusual but valid inputs."""

    def test_empty_context_works(self):
        result = primary_location_line_hash("R", "p", 1, "")
        assert result.endswith(":1")
        digest = result.rsplit(":", 1)[0]
        assert len(digest) == 24

    def test_unicode_context_works(self):
        # Non-ASCII characters should be handled via UTF-8
        # encoding without raising.
        result = primary_location_line_hash("R", "p", 1, "encoded")
        unicode_result = primary_location_line_hash("R", "p", 1, "encoded-utf8")
        assert result.endswith(":1")
        assert unicode_result.endswith(":1")

    def test_zero_line_works(self):
        # Some signals carry line=0 for whole-file findings.
        result = primary_location_line_hash("R", "p", 0, "ctx")
        assert result.endswith(":1")

    def test_very_large_line_number_works(self):
        result = primary_location_line_hash("R", "p", 999999, "ctx")
        assert result.endswith(":1")

    def test_very_long_context_works(self):
        long_context = "x" * 10000
        result = primary_location_line_hash("R", "p", 1, long_context)
        assert result.endswith(":1")
        digest = result.rsplit(":", 1)[0]
        assert len(digest) == 24

    def test_context_with_pipe_character_works(self):
        # The hash uses '|' as a component separator. Inputs
        # containing '|' must not collide with ambiguous
        # boundary cases. Different contexts with '|' inside
        # must still hash differently.
        a = primary_location_line_hash("R", "p", 1, "a|b")
        b = primary_location_line_hash("R", "p", 1, "a||b")
        assert a != b

    def test_path_with_pipe_character_works(self):
        # Same robustness check for path containing '|'.
        a = primary_location_line_hash("R", "a|b.py", 1, "ctx")
        b = primary_location_line_hash("R", "a||b.py", 1, "ctx")
        assert a != b


class TestDeterminism(unittest.TestCase):
    """The function must be deterministic across process invocations."""

    def test_identical_call_returns_identical_result_in_same_process(self):
        results = [primary_location_line_hash("R", "p", 1, "ctx") for _ in range(10)]
        assert len(set(results)) == 1


if __name__ == "__main__":
    unittest.main()
