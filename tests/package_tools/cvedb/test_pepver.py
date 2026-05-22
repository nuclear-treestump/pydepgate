"""Tests for pydepgate.package_tools.cvedb._pepver."""

from __future__ import annotations

import pickle
import unittest

from pydepgate.package_tools.cvedb import _pepver


class ParseVersionTests(unittest.TestCase):
    def test_parse_plain_release(self):
        version = _pepver.parse_version("1.2.3")

        self.assertIsNotNone(version)
        assert version is not None
        self.assertEqual(version.epoch, 0)
        self.assertEqual(version.release, (1, 2, 3))
        self.assertIsNone(version.pre)
        self.assertIsNone(version.post)
        self.assertIsNone(version.dev)
        self.assertIsNone(version.local)
        self.assertEqual(version.canonical, "1.2.3")

    def test_parse_epoch(self):
        version = _pepver.parse_version("2!1.0")

        self.assertIsNotNone(version)
        assert version is not None
        self.assertEqual(version.epoch, 2)
        self.assertEqual(version.canonical, "2!1.0")

    def test_parse_pre_release_aliases(self):
        self.assertEqual(_pepver.canonicalize_version("1.0alpha1"), "1.0a1")
        self.assertEqual(_pepver.canonicalize_version("1.0beta2"), "1.0b2")
        self.assertEqual(_pepver.canonicalize_version("1.0c3"), "1.0rc3")
        self.assertEqual(_pepver.canonicalize_version("1.0preview4"), "1.0rc4")

    def test_parse_implicit_pre_release_number(self):
        self.assertEqual(_pepver.canonicalize_version("1.0a"), "1.0a0")

    def test_parse_post_release_aliases(self):
        self.assertEqual(_pepver.canonicalize_version("1.0-1"), "1.0.post1")
        self.assertEqual(_pepver.canonicalize_version("1.0rev2"), "1.0.post2")
        self.assertEqual(_pepver.canonicalize_version("1.0r3"), "1.0.post3")

    def test_parse_implicit_post_release_number(self):
        self.assertEqual(_pepver.canonicalize_version("1.0.post"), "1.0.post0")

    def test_parse_dev_release(self):
        self.assertEqual(_pepver.canonicalize_version("1.0.dev"), "1.0.dev0")
        self.assertEqual(_pepver.canonicalize_version("1.0dev5"), "1.0.dev5")

    def test_parse_local_version(self):
        version = _pepver.parse_version("1.0+ABC.001.sha")

        self.assertIsNotNone(version)
        assert version is not None
        self.assertEqual(version.local, ("abc", 1, "sha"))
        self.assertEqual(version.canonical, "1.0+abc.1.sha")
        self.assertEqual(version.public, "1.0")

    def test_parse_leading_v_and_whitespace(self):
        self.assertEqual(_pepver.canonicalize_version("  v1.0  "), "1.0")

    def test_reject_unparseable_versions(self):
        invalid = (
            "",
            "not-a-version",
            "1.0..1",
            "1_0",
            "1.0+",
            "1.0+abc..def",
            "1.0-",
        )

        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(_pepver.parse_version(value))
                self.assertIsNone(_pepver.canonicalize_version(value))


class CompareVersionTests(unittest.TestCase):
    def assertOlder(self, left: str, right: str) -> None:
        self.assertEqual(_pepver.compare_versions(left, right), -1)
        self.assertEqual(_pepver.compare_versions(right, left), 1)

    def assertSame(self, left: str, right: str) -> None:
        self.assertEqual(_pepver.compare_versions(left, right), 0)
        self.assertEqual(_pepver.compare_versions(right, left), 0)

    def test_release_trailing_zeroes_compare_equal(self):
        self.assertSame("1.0", "1.0.0")
        self.assertSame("1", "1.0.0.0")

    def test_epoch_orders_before_release(self):
        self.assertOlder("1.999", "1!0")

    def test_dev_pre_final_post_ordering(self):
        ordered = (
            "1.0.dev1",
            "1.0a1.dev1",
            "1.0a1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0.post1.dev1",
            "1.0.post1",
        )

        for left, right in zip(ordered, ordered[1:]):
            with self.subTest(left=left, right=right):
                self.assertOlder(left, right)

    def test_pre_release_aliases_compare_equal(self):
        self.assertSame("1.0c1", "1.0rc1")
        self.assertSame("1.0preview1", "1.0rc1")
        self.assertSame("1.0alpha1", "1.0a1")

    def test_post_release_aliases_compare_equal(self):
        self.assertSame("1.0-1", "1.0.post1")
        self.assertSame("1.0rev1", "1.0.post1")

    def test_local_versions_order_after_public_version(self):
        self.assertOlder("1.0", "1.0+abc")

    def test_local_version_text_sorts_before_numeric(self):
        self.assertOlder("1.0+abc", "1.0+1")

    def test_local_version_segments_are_compared_in_order(self):
        self.assertOlder("1.0+abc.1", "1.0+abc.2")
        self.assertOlder("1.0+abc", "1.0+abc.1")

    def test_unparseable_compare_returns_none(self):
        self.assertIsNone(_pepver.compare_versions("1.0", "nope"))
        self.assertIsNone(_pepver.compare_versions("nope", "1.0"))


class RangeEvaluationTests(unittest.TestCase):
    def test_version_inside_introduced_fixed_range(self):
        self.assertIs(
            _pepver.version_in_range(
                "1.5",
                introduced="1.0",
                fixed="2.0",
            ),
            True,
        )

    def test_introduced_is_inclusive(self):
        self.assertIs(
            _pepver.version_in_range(
                "1.0",
                introduced="1.0",
                fixed="2.0",
            ),
            True,
        )

    def test_fixed_is_exclusive(self):
        self.assertIs(
            _pepver.version_in_range(
                "2.0",
                introduced="1.0",
                fixed="2.0",
            ),
            False,
        )

    def test_last_affected_is_inclusive(self):
        self.assertIs(
            _pepver.version_in_range(
                "2.0",
                introduced="1.0",
                last_affected="2.0",
            ),
            True,
        )
        self.assertIs(
            _pepver.version_in_range(
                "2.0.post1",
                introduced="1.0",
                last_affected="2.0",
            ),
            False,
        )

    def test_introduced_zero_means_no_lower_bound(self):
        self.assertIs(
            _pepver.version_in_range("0.1", introduced="0", fixed="1.0"),
            True,
        )

    def test_empty_bounds_match_parseable_version(self):
        self.assertIs(_pepver.version_in_range("1.0"), True)

    def test_unparseable_candidate_returns_none(self):
        self.assertIsNone(_pepver.version_in_range("not-a-version", fixed="2.0"))

    def test_unparseable_bound_returns_none(self):
        self.assertIsNone(_pepver.version_in_range("1.0", fixed="not-a-version"))
        self.assertIsNone(_pepver.version_in_range("1.0", introduced="not-a-version"))
        self.assertIsNone(
            _pepver.version_in_range("1.0", last_affected="not-a-version")
        )


class ConveniencePredicateTests(unittest.TestCase):
    def test_is_prerelease(self):
        self.assertIs(_pepver.is_prerelease("1.0a1"), True)
        self.assertIs(_pepver.is_prerelease("1.0.dev1"), True)
        self.assertIs(_pepver.is_prerelease("1.0"), False)
        self.assertIsNone(_pepver.is_prerelease("nope"))

    def test_is_postrelease(self):
        self.assertIs(_pepver.is_postrelease("1.0.post1"), True)
        self.assertIs(_pepver.is_postrelease("1.0"), False)
        self.assertIsNone(_pepver.is_postrelease("nope"))

    def test_parsed_version_is_pickle_safe(self):
        version = _pepver.parse_version("1!2.0rc1.post2.dev3+local.4")

        restored = pickle.loads(pickle.dumps(version))

        self.assertEqual(restored, version)


if __name__ == "__main__":
    unittest.main()
