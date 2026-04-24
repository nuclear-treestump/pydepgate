"""Tests for pydepgate.parsers.sdist."""

import io
import pathlib
import tarfile
import tempfile
import unittest

from pydepgate.parsers.sdist import (
    SdistEntry,
    SkippedEntry,
    is_sdist,
    iter_sdist_files,
    iter_sdist_files_with_diagnostics,
)


def _build_sdist(path: pathlib.Path, entries: dict[str, bytes]) -> None:
    """Build a gzipped tarball with the given entries.

    Adds a conventional top-level directory to match real sdist shape.
    """
    with tarfile.open(path, "w:gz") as tf:
        for name, content in entries.items():
            info = tarfile.TarInfo(name=f"sample-1.0/{name}")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))


class SdistEnumerationTests(unittest.TestCase):

    def test_iter_simple_sdist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "sample-1.0.tar.gz"
            _build_sdist(path, {
                "setup.py": b"from setuptools import setup\nsetup()\n",
                "sample/__init__.py": b"",
            })
            entries = list(iter_sdist_files(path))
            self.assertEqual(len(entries), 2)
            paths = {e.internal_path for e in entries}
            # The top-level sample-1.0/ prefix should be stripped.
            self.assertIn("setup.py", paths)
            self.assertIn("sample/__init__.py", paths)

    def test_unsafe_path_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evil.tar.gz"
            with tarfile.open(path, "w:gz") as tf:
                info = tarfile.TarInfo(name="../evil.py")
                info.size = 10
                tf.addfile(info, io.BytesIO(b"0123456789"))
            entries = list(iter_sdist_files_with_diagnostics(path))
            skipped = [e for e in entries if isinstance(e, SkippedEntry)]
            self.assertEqual(len(skipped), 1)

    def test_is_sdist_on_tarball(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "sample-1.0.tar.gz"
            _build_sdist(path, {"setup.py": b"setup()\n"})
            self.assertTrue(is_sdist(path))


class SdistEngineIntegrationTests(unittest.TestCase):

    def test_scan_sdist_with_malicious_setup(self):
        from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
        from pydepgate.engines.static import StaticEngine

        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evil-1.0.tar.gz"
            _build_sdist(path, {
                "setup.py": (
                    b"import base64\n"
                    b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
                    b"from setuptools import setup\n"
                    b"setup()\n"
                ),
            })

            engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])
            result = engine.scan_sdist(path)

            self.assertEqual(len(result.findings), 1)
            self.assertEqual(
                result.findings[0].context.internal_path, "setup.py"
            )


if __name__ == "__main__":
    unittest.main()