"""Tests for pydepgate.platform.paths.

Coverage:

  * XDG environment variables always win when set.
  * Platform-specific fallbacks (Linux, macOS, Windows, BSD).
  * Tilde expansion in environment-variable values.
  * pydepgate-namespaced helpers correctly compose with the
    XDG bases.
  * ensure_directory creates, is idempotent, and refuses to
    overwrite a non-directory.

Test strategy: patch os.environ and sys.platform at the
function-call boundary. Path.home() is patched directly so
the test does not depend on $HOME being set sanely on the
test runner.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pydepgate.pdgplatform import paths


class TestXdgCacheHome(unittest.TestCase):
    def test_xdg_cache_home_env_var_wins(self):
        with mock.patch.dict(
            os.environ,
            {"XDG_CACHE_HOME": "/custom/cache"},
            clear=False,
        ):
            self.assertEqual(paths.xdg_cache_home(), Path("/custom/cache"))

    def test_xdg_cache_home_env_var_wins_on_macos(self):
        # XDG always wins, regardless of platform. A developer
        # who exports XDG_CACHE_HOME on macOS to test Linux-like
        # behavior gets what they asked for.
        with (
            mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": "/custom/cache"},
                clear=False,
            ),
            mock.patch("sys.platform", "darwin"),
        ):
            self.assertEqual(paths.xdg_cache_home(), Path("/custom/cache"))

    def test_xdg_cache_home_tilde_expanded(self):
        env = {"XDG_CACHE_HOME": "~/mycache", "HOME": "/home/test"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "linux"),
        ):
            self.assertEqual(paths.xdg_cache_home(), Path("/home/test/mycache"))

    def test_linux_fallback(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_CACHE_HOME"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "linux"),
            mock.patch.object(Path, "home", return_value=Path("/home/test")),
        ):
            self.assertEqual(paths.xdg_cache_home(), Path("/home/test/.cache"))

    def test_macos_fallback(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_CACHE_HOME"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "darwin"),
            mock.patch.object(Path, "home", return_value=Path("/Users/test")),
        ):
            self.assertEqual(
                paths.xdg_cache_home(),
                Path("/Users/test/Library/Caches"),
            )

    def test_windows_with_localappdata(self):
        env = {"LOCALAPPDATA": "C:\\Users\\test\\AppData\\Local"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "win32"),
        ):
            self.assertEqual(
                paths.xdg_cache_home(),
                Path("C:\\Users\\test\\AppData\\Local"),
            )

    def test_windows_without_localappdata(self):
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("XDG_CACHE_HOME", "LOCALAPPDATA")
        }
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "win32"),
            mock.patch.object(Path, "home", return_value=Path("C:\\Users\\test")),
        ):
            self.assertEqual(
                paths.xdg_cache_home(),
                Path("C:\\Users\\test") / "AppData" / "Local",
            )

    def test_bsd_uses_posix_default(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_CACHE_HOME"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "freebsd14"),
            mock.patch.object(Path, "home", return_value=Path("/home/test")),
        ):
            self.assertEqual(paths.xdg_cache_home(), Path("/home/test/.cache"))


class TestXdgConfigHome(unittest.TestCase):
    def test_xdg_config_home_env_var_wins(self):
        with mock.patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": "/custom/config"},
            clear=False,
        ):
            self.assertEqual(paths.xdg_config_home(), Path("/custom/config"))

    def test_linux_fallback(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "linux"),
            mock.patch.object(Path, "home", return_value=Path("/home/test")),
        ):
            self.assertEqual(
                paths.xdg_config_home(),
                Path("/home/test/.config"),
            )

    def test_macos_fallback(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "darwin"),
            mock.patch.object(Path, "home", return_value=Path("/Users/test")),
        ):
            self.assertEqual(
                paths.xdg_config_home(),
                Path("/Users/test/Library/Application Support"),
            )

    def test_windows_with_appdata(self):
        env = {"APPDATA": "C:\\Users\\test\\AppData\\Roaming"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "win32"),
        ):
            self.assertEqual(
                paths.xdg_config_home(),
                Path("C:\\Users\\test\\AppData\\Roaming"),
            )

    def test_windows_without_appdata(self):
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("XDG_CONFIG_HOME", "APPDATA")
        }
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "win32"),
            mock.patch.object(Path, "home", return_value=Path("C:\\Users\\test")),
        ):
            self.assertEqual(
                paths.xdg_config_home(), Path("C:\\Users\\test") / "AppData" / "Roaming"
            )


class TestXdgDataHome(unittest.TestCase):
    def test_xdg_data_home_env_var_wins(self):
        with mock.patch.dict(
            os.environ,
            {"XDG_DATA_HOME": "/custom/data"},
            clear=False,
        ):
            self.assertEqual(paths.xdg_data_home(), Path("/custom/data"))

    def test_linux_fallback(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_DATA_HOME"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "linux"),
            mock.patch.object(Path, "home", return_value=Path("/home/test")),
        ):
            self.assertEqual(
                paths.xdg_data_home(),
                Path("/home/test/.local/share"),
            )

    def test_macos_fallback(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_DATA_HOME"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "darwin"),
            mock.patch.object(Path, "home", return_value=Path("/Users/test")),
        ):
            self.assertEqual(
                paths.xdg_data_home(),
                Path("/Users/test/Library/Application Support"),
            )

    def test_windows_with_localappdata(self):
        env = {"LOCALAPPDATA": "C:\\Users\\test\\AppData\\Local"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.platform", "win32"),
        ):
            self.assertEqual(
                paths.xdg_data_home(),
                Path("C:\\Users\\test\\AppData\\Local"),
            )


class TestPydepgateDirs(unittest.TestCase):
    def test_pydepgate_cache_dir_is_namespaced(self):
        with mock.patch.dict(
            os.environ,
            {"XDG_CACHE_HOME": "/cache"},
            clear=False,
        ):
            self.assertEqual(
                paths.pydepgate_cache_dir(),
                Path("/cache/pydepgate"),
            )

    def test_pydepgate_config_dir_is_namespaced(self):
        with mock.patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": "/config"},
            clear=False,
        ):
            self.assertEqual(
                paths.pydepgate_config_dir(),
                Path("/config/pydepgate"),
            )

    def test_pydepgate_data_dir_is_namespaced(self):
        with mock.patch.dict(
            os.environ,
            {"XDG_DATA_HOME": "/data"},
            clear=False,
        ):
            self.assertEqual(
                paths.pydepgate_data_dir(),
                Path("/data/pydepgate"),
            )

    def test_pydepgate_cache_dir_does_not_create(self):
        # Resolving the path must not have filesystem side
        # effects. Callers create explicitly via ensure_directory.
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                result = paths.pydepgate_cache_dir()
                self.assertFalse(result.exists())


class TestEnsureDirectory(unittest.TestCase):
    def test_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "new_dir"
            self.assertFalse(target.exists())
            result = paths.ensure_directory(target)
            self.assertTrue(target.is_dir())
            self.assertEqual(result, target)

    def test_creates_parent_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a" / "b" / "c"
            paths.ensure_directory(target)
            self.assertTrue(target.is_dir())

    def test_idempotent_on_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "exists"
            target.mkdir()
            # Should not raise on a directory that already exists.
            paths.ensure_directory(target)
            self.assertTrue(target.is_dir())

    def test_raises_when_path_is_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "blocker"
            blocker.write_text("not a directory")
            with self.assertRaises((FileExistsError, NotADirectoryError, OSError)):
                paths.ensure_directory(blocker)


if __name__ == "__main__":
    unittest.main()
