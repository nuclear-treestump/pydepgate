"""Tests for pydepgate.package_tools.metadata.

Coverage:

  * PEP 503 style package-name normalization.
  * Wheel filename parsing with and without a build tag.
  * Core METADATA identity extraction.
  * WHEEL metadata extraction.
  * direct_url.json extraction as declared artifact data.
  * Filename fallback when core metadata is absent or unusable.
  * Mismatch and ambiguity warnings for defensive callers.
"""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from pydepgate.package_tools.metadata import (
    IDENTITY_SOURCE_CORE_METADATA,
    IDENTITY_SOURCE_WHEEL_FILENAME,
    MAX_CORE_METADATA_BYTES,
    normalize_package_name,
    parse_wheel_filename,
    read_package_metadata,
    read_wheel_metadata,
)


def _build_wheel(path: Path, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)


class NormalizePackageNameTests(unittest.TestCase):
    def test_normalizes_case_and_separators(self):
        self.assertEqual(normalize_package_name(" Demo_Pkg.Name "), "demo-pkg-name")

    def test_collapses_separator_runs(self):
        self.assertEqual(normalize_package_name("a--b__c..d"), "a-b-c-d")


class WheelFilenameTests(unittest.TestCase):
    def test_parse_without_build_tag(self):
        info = parse_wheel_filename("demo_pkg-1.2.3-py3-none-any.whl")

        self.assertIsNotNone(info)
        self.assertEqual(info.distribution, "demo_pkg")
        self.assertEqual(info.version, "1.2.3")
        self.assertIsNone(info.build_tag)
        self.assertEqual(info.python_tag, "py3")
        self.assertEqual(info.abi_tag, "none")
        self.assertEqual(info.platform_tag, "any")

    def test_parse_with_build_tag(self):
        info = parse_wheel_filename("demo-1.2.3-2-py3-none-any.whl")

        self.assertIsNotNone(info)
        self.assertEqual(info.distribution, "demo")
        self.assertEqual(info.version, "1.2.3")
        self.assertEqual(info.build_tag, "2")

    def test_rejects_non_wheel_filename(self):
        self.assertIsNone(parse_wheel_filename("demo-1.2.3.tar.gz"))

    def test_rejects_wrong_component_count(self):
        self.assertIsNone(parse_wheel_filename("demo-1.2.3-py3-any.whl"))

    def test_rejects_non_numeric_version_start(self):
        self.assertIsNone(parse_wheel_filename("not-a-normal-wheel-name.whl"))


class ReadWheelMetadataTests(unittest.TestCase):
    def test_dispatch_reads_wheel_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo-1.0-py3-none-any.whl"
            _build_wheel(
                path,
                {
                    "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
                },
            )

            meta = read_package_metadata(path)

        self.assertEqual(meta.name, "demo")
        self.assertEqual(meta.version, "1.0")

    def test_dispatch_rejects_unsupported_artifact_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.txt"
            path.write_text("not a wheel")

            with self.assertRaises(ValueError):
                read_package_metadata(path)

    def test_reads_core_metadata_identity_and_package_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo_pkg-1.2.3-py3-none-any.whl"
            _build_wheel(
                path,
                {
                    "demo_pkg-1.2.3.dist-info/METADATA": (
                        b"Metadata-Version: 2.1\n"
                        b"Name: Demo.Pkg\n"
                        b"Version: 1.2.3\n"
                        b"Summary: Example package\n"
                        b"Requires-Python: >=3.11\n"
                        b"Requires-Dist: requests >=2\n"
                        b"Requires-Dist: packaging\n"
                        b"Provides-Extra: test\n"
                        b"Project-URL: Homepage, https://example.test\n"
                    ),
                    "demo_pkg-1.2.3.dist-info/WHEEL": (
                        b"Wheel-Version: 1.0\n"
                        b"Generator: pydepgate-test\n"
                        b"Root-Is-Purelib: true\n"
                        b"Tag: py3-none-any\n"
                    ),
                },
            )

            meta = read_wheel_metadata(path)

        self.assertEqual(meta.name, "Demo.Pkg")
        self.assertEqual(meta.normalized_name, "demo-pkg")
        self.assertEqual(meta.version, "1.2.3")
        self.assertEqual(meta.identity_source, IDENTITY_SOURCE_CORE_METADATA)
        self.assertEqual(meta.identity_key, ("demo-pkg", "1.2.3"))
        self.assertEqual(
            meta.candidate_lookup_keys,
            (("Demo.Pkg", "1.2.3"), ("demo-pkg", "1.2.3")),
        )
        self.assertEqual(meta.summary, "Example package")
        self.assertEqual(meta.requires_python, ">=3.11")
        self.assertEqual(meta.requires_dist, ("requests >=2", "packaging"))
        self.assertEqual(meta.provides_extra, ("test",))
        self.assertEqual(meta.project_urls, ("Homepage, https://example.test",))
        self.assertEqual(meta.wheel_version, "1.0")
        self.assertEqual(meta.wheel_generator, "pydepgate-test")
        self.assertTrue(meta.root_is_purelib)
        self.assertEqual(meta.wheel_tags, ("py3-none-any",))
        self.assertEqual(meta.warnings, ())

    def test_reads_direct_url_as_declared_artifact_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo-1.0-py3-none-any.whl"
            direct_url = {
                "url": "https://example.test/demo-1.0.tar.gz",
                "archive_info": {"hashes": {"sha256": "abc123"}},
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": "main",
                    "commit_id": "deadbeef",
                },
                "dir_info": {"editable": False},
            }
            _build_wheel(
                path,
                {
                    "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
                    "demo-1.0.dist-info/direct_url.json": json.dumps(
                        direct_url,
                    ).encode("utf-8"),
                },
            )

            meta = read_wheel_metadata(path)

        self.assertIsNotNone(meta.direct_url)
        self.assertEqual(meta.direct_url.url, "https://example.test/demo-1.0.tar.gz")
        self.assertEqual(meta.direct_url.vcs, "git")
        self.assertEqual(meta.direct_url.requested_revision, "main")
        self.assertEqual(meta.direct_url.commit_id, "deadbeef")
        self.assertFalse(meta.direct_url.dir_info_editable)
        self.assertEqual(meta.direct_url.archive_hashes, (("sha256", "abc123"),))

    def test_falls_back_to_filename_when_metadata_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo-1.0-py3-none-any.whl"
            _build_wheel(path, {"demo/__init__.py": b""})

            meta = read_wheel_metadata(path)

        self.assertEqual(meta.name, "demo")
        self.assertEqual(meta.version, "1.0")
        self.assertEqual(meta.identity_source, IDENTITY_SOURCE_WHEEL_FILENAME)
        self.assertTrue(any("no root .dist-info/METADATA" in w for w in meta.warnings))

    def test_falls_back_to_filename_when_metadata_is_oversized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo-1.0-py3-none-any.whl"
            _build_wheel(
                path,
                {
                    "demo-1.0.dist-info/METADATA": b"A" * (MAX_CORE_METADATA_BYTES + 1),
                },
            )

            meta = read_wheel_metadata(path)

        self.assertEqual(meta.name, "demo")
        self.assertEqual(meta.version, "1.0")
        self.assertEqual(meta.identity_source, IDENTITY_SOURCE_WHEEL_FILENAME)
        self.assertTrue(any("declared size" in w for w in meta.warnings))

    def test_core_metadata_wins_but_mismatch_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo-1.0-py3-none-any.whl"
            _build_wheel(
                path,
                {
                    "demo-1.0.dist-info/METADATA": b"Name: other\nVersion: 2.0\n",
                },
            )

            meta = read_wheel_metadata(path)

        self.assertEqual(meta.name, "other")
        self.assertEqual(meta.version, "2.0")
        self.assertEqual(meta.identity_source, IDENTITY_SOURCE_CORE_METADATA)
        self.assertTrue(any("name does not match" in w for w in meta.warnings))
        self.assertTrue(any("version does not match" in w for w in meta.warnings))

    def test_multiple_metadata_members_selects_filename_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo-1.0-py3-none-any.whl"
            _build_wheel(
                path,
                {
                    "other-1.0.dist-info/METADATA": b"Name: other\nVersion: 1.0\n",
                    "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
                },
            )

            meta = read_wheel_metadata(path)

        self.assertEqual(meta.name, "demo")
        self.assertEqual(meta.version, "1.0")
        self.assertEqual(meta.metadata_path, "demo-1.0.dist-info/METADATA")
        self.assertTrue(any("multiple root" in w for w in meta.warnings))
        self.assertTrue(any("matching the wheel filename" in w for w in meta.warnings))

    def test_multiple_metadata_members_without_match_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo-1.0-py3-none-any.whl"
            _build_wheel(
                path,
                {
                    "alpha-1.0.dist-info/METADATA": b"Name: alpha\nVersion: 1.0\n",
                    "bravo-1.0.dist-info/METADATA": b"Name: bravo\nVersion: 1.0\n",
                },
            )

            meta = read_wheel_metadata(path)

        self.assertEqual(meta.name, "demo")
        self.assertEqual(meta.version, "1.0")
        self.assertEqual(meta.identity_source, IDENTITY_SOURCE_WHEEL_FILENAME)
        self.assertIsNone(meta.metadata_path)
        self.assertTrue(any("no METADATA member matches" in w for w in meta.warnings))

    def test_unparseable_filename_can_still_use_core_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "not-a-normal-wheel-name.whl"
            _build_wheel(
                path,
                {
                    "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
                },
            )

            meta = read_wheel_metadata(path)

        self.assertEqual(meta.name, "demo")
        self.assertEqual(meta.version, "1.0")
        self.assertEqual(meta.identity_source, IDENTITY_SOURCE_CORE_METADATA)
        self.assertTrue(any("could not be parsed" in w for w in meta.warnings))


if __name__ == "__main__":
    unittest.main()
