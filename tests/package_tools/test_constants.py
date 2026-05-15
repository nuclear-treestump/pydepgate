"""Tests for pydepgate.package_tools.cvedb.constants.

These are sanity checks on the constants module. The constants
themselves do not change at runtime, but tests catch typos and
malformed URLs/strings at the test-run boundary so they cannot
slip into a release. The test cost is negligible and the
"silent constant drift" failure mode is annoying enough to
warrant the coverage.
"""

from __future__ import annotations

import unittest
from urllib.parse import urlparse

from pydepgate.package_tools.cvedb import constants


class TestOsvUrls(unittest.TestCase):
    def test_all_zip_url_is_https(self):
        parsed = urlparse(constants.OSV_PYPI_ALL_ZIP_URL)
        self.assertEqual(parsed.scheme, "https")

    def test_all_zip_url_targets_osv_storage(self):
        parsed = urlparse(constants.OSV_PYPI_ALL_ZIP_URL)
        self.assertEqual(
            parsed.netloc,
            "osv-vulnerabilities.storage.googleapis.com",
        )

    def test_all_zip_url_path_targets_pypi(self):
        parsed = urlparse(constants.OSV_PYPI_ALL_ZIP_URL)
        self.assertTrue(parsed.path.startswith("/PyPI/"))
        self.assertTrue(parsed.path.endswith("/all.zip"))

    def test_modified_id_csv_url_is_https(self):
        parsed = urlparse(constants.OSV_PYPI_MODIFIED_ID_CSV_URL)
        self.assertEqual(parsed.scheme, "https")

    def test_modified_id_csv_url_targets_pypi(self):
        parsed = urlparse(constants.OSV_PYPI_MODIFIED_ID_CSV_URL)
        self.assertTrue(parsed.path.endswith("/modified_id.csv"))


class TestContentTypes(unittest.TestCase):
    def test_all_zip_content_types_nonempty(self):
        self.assertTrue(len(constants.OSV_PYPI_ALL_ZIP_ACCEPTED_CONTENT_TYPES) > 0)

    def test_modified_id_csv_content_types_nonempty(self):
        self.assertTrue(
            len(constants.OSV_PYPI_MODIFIED_ID_CSV_ACCEPTED_CONTENT_TYPES) > 0
        )

    def test_all_zip_content_types_include_octet_stream(self):
        # GCS frequently serves zips as octet-stream; this entry
        # is load-bearing for HEAD validation against the real
        # endpoint.
        self.assertIn(
            "application/octet-stream",
            constants.OSV_PYPI_ALL_ZIP_ACCEPTED_CONTENT_TYPES,
        )


class TestSizeBounds(unittest.TestCase):
    def test_modified_id_csv_min_below_max(self):
        self.assertLess(
            constants.OSV_PYPI_MODIFIED_ID_CSV_MIN_SIZE,
            constants.OSV_PYPI_MODIFIED_ID_CSV_MAX_SIZE,
        )

    def test_modified_id_csv_min_size_positive(self):
        self.assertGreater(constants.OSV_PYPI_MODIFIED_ID_CSV_MIN_SIZE, 0)


class TestFilenames(unittest.TestCase):
    def test_db_filename_has_db_extension(self):
        self.assertTrue(constants.CVE_DB_FILENAME.endswith(".db"))

    def test_import_zip_filename_has_zip_extension(self):
        self.assertTrue(constants.CVE_DB_IMPORT_ZIP_FILENAME.endswith(".zip"))

    def test_filenames_have_no_path_separators(self):
        # The filenames must remain bare names; the cache dir is
        # composed at use time via pydepgate_cache_dir() / FILENAME.
        # An accidental / or \\ in the filename would silently
        # change the on-disk layout.
        self.assertNotIn("/", constants.CVE_DB_FILENAME)
        self.assertNotIn("\\", constants.CVE_DB_FILENAME)
        self.assertNotIn("/", constants.CVE_DB_IMPORT_ZIP_FILENAME)
        self.assertNotIn("\\", constants.CVE_DB_IMPORT_ZIP_FILENAME)


class TestAttribution(unittest.TestCase):
    def test_attribution_line_nonempty(self):
        self.assertTrue(len(constants.OSV_DATA_ATTRIBUTION_LINE) > 0)

    def test_attribution_line_mentions_source(self):
        self.assertIn("OSV", constants.OSV_DATA_ATTRIBUTION_LINE)

    def test_attribution_line_mentions_license(self):
        self.assertIn(
            constants.OSV_DATA_LICENSE,
            constants.OSV_DATA_ATTRIBUTION_LINE,
        )

    def test_attribution_line_mentions_source_url(self):
        self.assertIn(
            constants.OSV_DATA_SOURCE_URL,
            constants.OSV_DATA_ATTRIBUTION_LINE,
        )

    def test_license_url_is_https(self):
        self.assertTrue(constants.OSV_DATA_LICENSE_URL.startswith("https://"))


class TestSchemaVersion(unittest.TestCase):
    def test_schema_version_positive(self):
        self.assertGreaterEqual(constants.CVE_DB_SCHEMA_VERSION, 1)


if __name__ == "__main__":
    unittest.main()
