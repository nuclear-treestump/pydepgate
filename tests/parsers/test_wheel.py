"""Tests for pydepgate.parsers.wheel."""

import io
import pathlib
import tempfile
import unittest
import zipfile

from pydepgate.parsers.wheel import (
    MAX_FILE_SIZE_BYTES,
    SkippedEntry,
    WheelEntry,
    is_wheel,
    iter_wheel_files,
    iter_wheel_files_with_diagnostics,
)


def _build_wheel(path: pathlib.Path, entries: dict[str, bytes]) -> None:
    """Helper: construct a wheel with the given entries."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)


class WheelEnumerationTests(unittest.TestCase):

    def test_iter_simple_wheel(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "sample-1.0-py3-none-any.whl"
            _build_wheel(path, {
                "sample/__init__.py": b"print('hi')\n",
                "sample/utils.py": b"def f(): pass\n",
                "sample-1.0.dist-info/METADATA": b"Name: sample\n",
            })
            entries = list(iter_wheel_files(path))
            self.assertEqual(len(entries), 3)
            paths = {e.internal_path for e in entries}
            self.assertIn("sample/__init__.py", paths)

    def test_unsafe_path_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evil.whl"
            _build_wheel(path, {
                "../evil.pth": b"import os; os.system('touch /tmp/pwn')\n",
                "legitimate.py": b"pass\n",
            })
            entries = list(iter_wheel_files_with_diagnostics(path))
            # Should have one legitimate entry and one skipped.
            wheel_entries = [e for e, _ in entries if isinstance(e, WheelEntry)]
            skipped = [e for e, _ in entries if isinstance(e, SkippedEntry)]
            self.assertEqual(len(wheel_entries), 1)
            self.assertEqual(len(skipped), 1)
            self.assertIn("unsafe path", skipped[0].reason)

    def test_absolute_path_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evil.whl"
            _build_wheel(path, {
                "/etc/evil.pth": b"payload\n",
            })
            entries = list(iter_wheel_files_with_diagnostics(path))
            skipped = [e for e, _ in entries if isinstance(e, SkippedEntry)]
            self.assertEqual(len(skipped), 1)

    def test_empty_wheel_yields_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "empty.whl"
            _build_wheel(path, {})
            entries = list(iter_wheel_files(path))
            self.assertEqual(entries, [])

    def test_is_wheel_on_valid_wheel(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "sample-1.0.whl"
            _build_wheel(path, {"sample/__init__.py": b""})
            self.assertTrue(is_wheel(path))

    def test_is_wheel_on_non_wheel(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "not_a_wheel.txt"
            path.write_bytes(b"hello")
            self.assertFalse(is_wheel(path))


class WheelEngineIntegrationTests(unittest.TestCase):
    """The engine scans wheels end-to-end."""

    def test_scan_wheel_with_malicious_pth(self):
        from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
        from pydepgate.engines.static import StaticEngine

        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evil-1.0-py3-none-any.whl"
            _build_wheel(path, {
                "evil-1.0.dist-info/METADATA": b"Name: evil\n",
                "evil_init.pth": (
                    b"import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"
                ),
            })

            engine = StaticEngine(analyzers=[EncodingAbuseAnalyzer()])
            result = engine.scan_wheel(path)

            self.assertEqual(len(result.findings), 1)
            self.assertEqual(
                result.findings[0].signal.analyzer, "encoding_abuse"
            )
            # The finding should identify which file inside the wheel
            # it came from.
            self.assertEqual(
                result.findings[0].context.internal_path, "evil_init.pth"
            )


if __name__ == "__main__":
    unittest.main()