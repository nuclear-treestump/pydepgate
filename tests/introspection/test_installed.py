"""Tests for pydepgate.introspection.installed."""

import unittest

from pydepgate.introspection.installed import (
    InstalledPackageNotFound,
    find_package,
    iter_installed_package_files,
)


class FindPackageTests(unittest.TestCase):

    def test_find_pip(self):
        # pip is always installed.
        dist = find_package("pip")
        self.assertEqual(dist.metadata["Name"].lower(), "pip")

    def test_find_nonexistent_package(self):
        with self.assertRaises(InstalledPackageNotFound):
            find_package("definitely-not-a-real-package-xyzzy-12345")


class IterInstalledPackageFilesTests(unittest.TestCase):

    def test_pip_has_files(self):
        files = list(iter_installed_package_files("pip"))
        # pip is large; should have many files.
        self.assertGreater(len(files), 10)

    def test_pip_has_python_source(self):
        files = list(iter_installed_package_files("pip"))
        py_files = [f for f in files if f.internal_path.endswith(".py")]
        self.assertGreater(len(py_files), 0)

    def test_pydepgate_is_installed(self):
        # We installed pydepgate in editable mode at the start.
        # This tests the introspection against our own package.
        files = list(iter_installed_package_files("pydepgate"))
        # Editable installs may have 0 files in dist.files (the files
        # live at the editable source location). We tolerate both.
        # The important property is that this doesn't crash.
        self.assertIsInstance(files, list)


class InstalledEngineIntegrationTests(unittest.TestCase):

    def test_scan_installed_pip_is_clean(self):
        """pip has no encoding_abuse signals."""
        from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
        from pydepgate.engines.static import StaticEngine

        engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])
        result = engine.scan_installed("pip")
        # pip is benign; should produce no findings.
        self.assertEqual(result.findings, ())
        # But it should scan plenty of files.
        self.assertGreater(result.statistics.files_total, 0)

    def test_scan_installed_nonexistent_package(self):
        from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
        from pydepgate.engines.static import StaticEngine

        engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])
        result = engine.scan_installed("definitely-not-real-xyzzy-12345")
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.diagnostics), 1)
        self.assertIn("not installed", result.diagnostics[0])


if __name__ == "__main__":
    unittest.main()