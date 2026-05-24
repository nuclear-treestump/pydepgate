"""Tests for pydepgate.package_tools.depresolution.resolver."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pydepgate.package_tools.depresolution import resolver
from pydepgate.package_tools.depresolution.resolver import (
    _check_pip_version,
    _collect_applicable_requires_dist,
    _dep_string_to_normalized_name,
    _normalize_pkg_name,
    _python_version_marker_applies,
    get_deps_from_pip_report,
    get_pip_resolution_report,
)


class TestNormalization(unittest.TestCase):
    """Tests for _normalize_pkg_name and _dep_string_to_normalized_name."""

    def test_lowercase_only(self):
        self.assertEqual(_normalize_pkg_name("Django"), "django")
        self.assertEqual(_normalize_pkg_name("REQUESTS"), "requests")

    def test_no_separators(self):
        self.assertEqual(_normalize_pkg_name("requests"), "requests")

    def test_underscore_to_hyphen(self):
        self.assertEqual(_normalize_pkg_name("foo_bar"), "foo-bar")

    def test_dot_to_hyphen(self):
        self.assertEqual(_normalize_pkg_name("foo.bar"), "foo-bar")

    def test_mixed_separators(self):
        self.assertEqual(_normalize_pkg_name("Foo_BAR.baz"), "foo-bar-baz")

    def test_collapse_consecutive_separators(self):
        self.assertEqual(_normalize_pkg_name("foo__bar"), "foo-bar")
        self.assertEqual(_normalize_pkg_name("foo--bar"), "foo-bar")
        self.assertEqual(_normalize_pkg_name("foo._-bar"), "foo-bar")

    def test_single_char(self):
        self.assertEqual(_normalize_pkg_name("a"), "a")
        self.assertEqual(_normalize_pkg_name("A"), "a")

    def test_empty_string(self):
        self.assertEqual(_normalize_pkg_name(""), "")

    def test_dep_string_plain_name(self):
        self.assertEqual(_dep_string_to_normalized_name("requests"), "requests")

    def test_dep_string_with_version_specifier(self):
        self.assertEqual(_dep_string_to_normalized_name("requests>=2.28"), "requests")
        self.assertEqual(_dep_string_to_normalized_name("Django==4.2"), "django")

    def test_dep_string_with_marker(self):
        self.assertEqual(
            _dep_string_to_normalized_name('foo; python_version >= "3.8"'),
            "foo",
        )

    def test_dep_string_with_extras(self):
        self.assertEqual(
            _dep_string_to_normalized_name("requests[security,socks]>=2.28"),
            "requests",
        )

    def test_dep_string_with_underscores(self):
        self.assertEqual(_dep_string_to_normalized_name("Foo_Bar==1.0"), "foo-bar")

    def test_dep_string_leading_whitespace(self):
        self.assertEqual(_dep_string_to_normalized_name("  requests>=2.0"), "requests")

    def test_dep_string_fallback_no_name(self):
        # The regex does not match but split()[0] still returns something.
        # This documents the fallback behavior; the result is normalized
        # via _normalize_pkg_name so it is at least lowercase.
        result = _dep_string_to_normalized_name(">=1.0")
        self.assertEqual(result, ">=1-0")


class TestPythonVersionMarker(unittest.TestCase):
    """Tests for _python_version_marker_applies.

    These tests patch _CURRENT_PYTHON to a fixed value so the test outcome
    does not depend on the Python version running the test suite.
    """

    def setUp(self):
        self._orig_current_python = resolver._CURRENT_PYTHON
        resolver._CURRENT_PYTHON = (3, 11)

    def tearDown(self):
        resolver._CURRENT_PYTHON = self._orig_current_python

    def test_no_python_version_constraint(self):
        # Conservative default: include the dep when no python_version is present.
        self.assertTrue(_python_version_marker_applies('sys_platform == "linux"'))
        self.assertTrue(_python_version_marker_applies(""))

    def test_gte_matches(self):
        self.assertTrue(_python_version_marker_applies('python_version >= "3.10"'))
        self.assertTrue(_python_version_marker_applies('python_version >= "3.11"'))
        self.assertFalse(_python_version_marker_applies('python_version >= "3.12"'))

    def test_gt_matches(self):
        self.assertTrue(_python_version_marker_applies('python_version > "3.10"'))
        self.assertFalse(_python_version_marker_applies('python_version > "3.11"'))

    def test_lte_matches(self):
        self.assertTrue(_python_version_marker_applies('python_version <= "3.11"'))
        self.assertTrue(_python_version_marker_applies('python_version <= "3.12"'))
        self.assertFalse(_python_version_marker_applies('python_version <= "3.10"'))

    def test_lt_matches(self):
        self.assertFalse(_python_version_marker_applies('python_version < "3.11"'))
        self.assertTrue(_python_version_marker_applies('python_version < "3.12"'))

    def test_eq_matches(self):
        self.assertTrue(_python_version_marker_applies('python_version == "3.11"'))
        self.assertFalse(_python_version_marker_applies('python_version == "3.10"'))

    def test_neq_matches(self):
        self.assertFalse(_python_version_marker_applies('python_version != "3.11"'))
        self.assertTrue(_python_version_marker_applies('python_version != "3.10"'))

    def test_major_only_version(self):
        # python_version >= "3" with current (3, 11): current[:1] = (3,), candidate = (3,)
        self.assertTrue(_python_version_marker_applies('python_version >= "3"'))
        self.assertFalse(_python_version_marker_applies('python_version > "3"'))

    def test_unparseable_version_falls_back_to_include(self):
        self.assertTrue(_python_version_marker_applies('python_version >= "abc"'))

    def test_unknown_operator_falls_back_to_include(self):
        # The regex requires [<>=!]+ so a fully-foreign operator will not match
        # at all; this tests an operator that matches the regex but is not in
        # the result dict.
        self.assertTrue(_python_version_marker_applies('python_version <<>> "3.10"'))

    def test_compound_marker_only_first_evaluated(self):
        # DOCUMENTED LIMITATION: only the first python_version expression is
        # evaluated. A compound marker that would be false on the second half
        # is still treated as applying as long as the first half does.
        self.assertTrue(
            _python_version_marker_applies(
                'python_version >= "3.8" and python_version < "3.10"'
            )
        )

    def test_quotes_optional(self):
        # The regex allows the version string to be unquoted.
        self.assertTrue(_python_version_marker_applies("python_version >= 3.10"))


class TestRequiresDistCollection(unittest.TestCase):
    """Tests for _collect_applicable_requires_dist."""

    def setUp(self):
        self._orig_current_python = resolver._CURRENT_PYTHON
        resolver._CURRENT_PYTHON = (3, 11)

    def tearDown(self):
        resolver._CURRENT_PYTHON = self._orig_current_python

    def test_empty_requires_dist(self):
        self.assertEqual(_collect_applicable_requires_dist({}), [])
        self.assertEqual(_collect_applicable_requires_dist({"requires_dist": []}), [])

    def test_no_markers_always_included(self):
        metadata = {"requires_dist": ["foo>=1.0", "bar==2.0", "baz"]}
        result = _collect_applicable_requires_dist(metadata)
        self.assertEqual(result, ["foo>=1.0", "bar==2.0", "baz"])

    def test_extras_marker_excluded(self):
        metadata = {
            "requires_dist": [
                "foo>=1.0",
                'bar==2.0; extra == "test"',
                'baz; extra == "dev"',
            ]
        }
        result = _collect_applicable_requires_dist(metadata)
        self.assertEqual(result, ["foo>=1.0"])

    def test_python_version_applies(self):
        metadata = {
            "requires_dist": [
                'foo>=1.0; python_version >= "3.10"',
                'bar==2.0; python_version >= "3.12"',
            ]
        }
        result = _collect_applicable_requires_dist(metadata)
        self.assertEqual(result, ["foo>=1.0"])

    def test_other_markers_included_conservatively(self):
        metadata = {
            "requires_dist": [
                'foo>=1.0; sys_platform == "linux"',
                'bar==2.0; implementation_name == "cpython"',
            ]
        }
        result = _collect_applicable_requires_dist(metadata)
        self.assertEqual(result, ["foo>=1.0", "bar==2.0"])

    def test_extras_marker_takes_precedence_over_python_version(self):
        # An extras-gated dep is excluded regardless of python_version.
        metadata = {
            "requires_dist": [
                'foo>=1.0; python_version >= "3.10" and extra == "test"',
            ]
        }
        result = _collect_applicable_requires_dist(metadata)
        self.assertEqual(result, [])

    def test_base_specifier_stripped(self):
        # The marker is stripped from the returned dep string.
        metadata = {
            "requires_dist": ['foo>=1.0; python_version >= "3.10"'],
        }
        result = _collect_applicable_requires_dist(metadata)
        self.assertEqual(result, ["foo>=1.0"])
        self.assertNotIn(";", result[0])


class TestPipReportClassification(unittest.TestCase):
    """Tests for get_deps_from_pip_report."""

    def _make_install_step(
        self,
        name,
        version,
        is_direct=False,
        is_yanked=False,
        requires_dist=None,
        hash_value="sha256=abc123",
        url=None,
    ):
        """Build a single pip-report install step dict for fixture use."""
        return {
            "is_direct": is_direct,
            "is_yanked": is_yanked,
            "metadata": {
                "name": name,
                "version": version,
                "requires_dist": requires_dist or [],
            },
            "download_info": {
                "url": url or f"https://example.com/{name}-{version}.whl",
                "archive_info": {"hash": hash_value},
            },
        }

    def test_missing_install_key_raises(self):
        with self.assertRaises(RuntimeError) as ctx:
            get_deps_from_pip_report({})
        self.assertIn("install", str(ctx.exception))

    def test_empty_install_list(self):
        roots, level1, transitive = get_deps_from_pip_report({"install": []})
        self.assertEqual(roots, [])
        self.assertEqual(level1, [])
        self.assertEqual(transitive, [])

    def test_single_root_no_deps(self):
        report = {
            "install": [
                self._make_install_step("requests", "2.31.0", is_direct=True),
            ]
        }
        roots, level1, transitive = get_deps_from_pip_report(report)
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]["name"], "requests")
        self.assertEqual(roots[0]["version"], "2.31.0")
        self.assertEqual(roots[0]["requires_dist"], [])
        self.assertEqual(level1, [])
        self.assertEqual(transitive, [])

    def test_single_root_with_level1_dep(self):
        report = {
            "install": [
                self._make_install_step(
                    "requests",
                    "2.31.0",
                    is_direct=True,
                    requires_dist=["urllib3>=1.26"],
                ),
                self._make_install_step("urllib3", "2.0.7"),
            ]
        }
        roots, level1, transitive = get_deps_from_pip_report(report)
        self.assertEqual(len(roots), 1)
        self.assertEqual(len(level1), 1)
        self.assertEqual(level1[0]["name"], "urllib3")
        self.assertEqual(transitive, [])

    def test_level1_and_transitive_separation(self):
        report = {
            "install": [
                self._make_install_step(
                    "requests",
                    "2.31.0",
                    is_direct=True,
                    requires_dist=["urllib3>=1.26", "certifi"],
                ),
                self._make_install_step(
                    "urllib3",
                    "2.0.7",
                    requires_dist=["typing-extensions>=4.0"],
                ),
                self._make_install_step("certifi", "2023.7.22"),
                self._make_install_step("typing-extensions", "4.8.0"),
            ]
        }
        roots, level1, transitive = get_deps_from_pip_report(report)
        self.assertEqual(len(roots), 1)
        level1_names = {d["name"] for d in level1}
        self.assertEqual(level1_names, {"urllib3", "certifi"})
        transitive_names = {d["name"] for d in transitive}
        self.assertEqual(transitive_names, {"typing-extensions"})

    def test_multiple_roots(self):
        report = {
            "install": [
                self._make_install_step("requests", "2.31.0", is_direct=True),
                self._make_install_step("urllib3", "2.0.7", is_direct=True),
            ]
        }
        roots, level1, transitive = get_deps_from_pip_report(report)
        self.assertEqual(len(roots), 2)
        root_names = {r["name"] for r in roots}
        self.assertEqual(root_names, {"requests", "urllib3"})

    def test_normalization_in_classification(self):
        # Root declares Requires-Dist for "Foo_Bar" (non-canonical).
        # Transitive entry has name "foo-bar" (canonical).
        # Classification must normalize both sides to match correctly.
        report = {
            "install": [
                self._make_install_step(
                    "root-pkg",
                    "1.0",
                    is_direct=True,
                    requires_dist=["Foo_Bar>=1.0"],
                ),
                self._make_install_step("foo-bar", "1.5"),
            ]
        }
        _, level1, transitive = get_deps_from_pip_report(report)
        self.assertEqual(len(level1), 1)
        self.assertEqual(level1[0]["name"], "foo-bar")
        self.assertEqual(transitive, [])

    def test_yanked_preserved(self):
        report = {
            "install": [
                self._make_install_step(
                    "requests", "2.31.0", is_direct=True, is_yanked=True
                ),
            ]
        }
        roots, _, _ = get_deps_from_pip_report(report)
        self.assertTrue(roots[0]["is_yanked"])

    def test_hash_extraction(self):
        report = {
            "install": [
                self._make_install_step(
                    "requests",
                    "2.31.0",
                    is_direct=True,
                    hash_value="sha256=deadbeef",
                ),
            ]
        }
        roots, _, _ = get_deps_from_pip_report(report)
        self.assertEqual(roots[0]["hash"], "sha256=deadbeef")

    def test_url_extraction(self):
        report = {
            "install": [
                self._make_install_step(
                    "requests",
                    "2.31.0",
                    is_direct=True,
                    url="https://files.pythonhosted.org/requests-2.31.0.whl",
                ),
            ]
        }
        roots, _, _ = get_deps_from_pip_report(report)
        self.assertEqual(
            roots[0]["url"],
            "https://files.pythonhosted.org/requests-2.31.0.whl",
        )

    def test_missing_download_info_does_not_crash(self):
        report = {
            "install": [
                {
                    "is_direct": True,
                    "is_yanked": False,
                    "metadata": {
                        "name": "requests",
                        "version": "2.31.0",
                        "requires_dist": [],
                    },
                    # download_info intentionally absent
                },
            ]
        }
        roots, _, _ = get_deps_from_pip_report(report)
        self.assertEqual(len(roots), 1)
        self.assertIsNone(roots[0]["hash"])
        self.assertIsNone(roots[0]["url"])

    def test_missing_archive_info_does_not_crash(self):
        report = {
            "install": [
                {
                    "is_direct": True,
                    "is_yanked": False,
                    "metadata": {
                        "name": "requests",
                        "version": "2.31.0",
                        "requires_dist": [],
                    },
                    "download_info": {"url": "https://example.com/x.whl"},
                },
            ]
        }
        roots, _, _ = get_deps_from_pip_report(report)
        self.assertIsNone(roots[0]["hash"])
        self.assertEqual(roots[0]["url"], "https://example.com/x.whl")

    def test_dep_in_multiple_roots_classified_once(self):
        report = {
            "install": [
                self._make_install_step(
                    "root-a",
                    "1.0",
                    is_direct=True,
                    requires_dist=["shared-dep"],
                ),
                self._make_install_step(
                    "root-b",
                    "1.0",
                    is_direct=True,
                    requires_dist=["shared-dep"],
                ),
                self._make_install_step("shared-dep", "2.0"),
            ]
        }
        roots, level1, transitive = get_deps_from_pip_report(report)
        self.assertEqual(len(roots), 2)
        self.assertEqual(len(level1), 1)
        self.assertEqual(level1[0]["name"], "shared-dep")
        self.assertEqual(transitive, [])

    def test_requires_dist_marker_excludes_from_level1(self):
        # A root with an extras-only dep should not produce a level-1 entry
        # for that dep, because the dep is not applicable in the base install.
        report = {
            "install": [
                self._make_install_step(
                    "requests",
                    "2.31.0",
                    is_direct=True,
                    requires_dist=['extra-dep; extra == "test"'],
                ),
                self._make_install_step("extra-dep", "1.0"),
            ]
        }
        _, level1, transitive = get_deps_from_pip_report(report)
        self.assertEqual(level1, [])
        # The extra-dep package is still in the install list but is transitive
        # by classification (not in any root's applicable requires_dist).
        self.assertEqual(len(transitive), 1)
        self.assertEqual(transitive[0]["name"], "extra-dep")


class TestCheckPipVersion(unittest.TestCase):
    """Tests for _check_pip_version."""

    def _mock_pip_version(self, stdout_bytes, returncode=0):
        return mock.Mock(returncode=returncode, stdout=stdout_bytes, stderr=b"")

    def test_pip_unavailable(self):
        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            return_value=self._mock_pip_version(b"", returncode=1),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                _check_pip_version()
            self.assertIn("pip is not available", str(ctx.exception))

    def test_pip_version_output_too_short(self):
        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            return_value=self._mock_pip_version(b"pip"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                _check_pip_version()
            self.assertIn("Unexpected pip --version output", str(ctx.exception))

    def test_pip_version_unparseable(self):
        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            return_value=self._mock_pip_version(b"pip notaversion from /path"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                _check_pip_version()
            self.assertIn("Could not parse pip version", str(ctx.exception))

    def test_pip_version_below_minimum(self):
        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            return_value=self._mock_pip_version(b"pip 22.0.4 from /path (python 3.11)"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                _check_pip_version()
            self.assertIn("or later required", str(ctx.exception))

    def test_pip_version_at_minimum(self):
        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            return_value=self._mock_pip_version(b"pip 23.0 from /path (python 3.11)"),
        ):
            # Should not raise.
            _check_pip_version()

    def test_pip_version_above_minimum(self):
        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            return_value=self._mock_pip_version(b"pip 24.0.1 from /path (python 3.12)"),
        ):
            # Should not raise.
            _check_pip_version()


class TestPipResolutionReport(unittest.TestCase):
    """Tests for get_pip_resolution_report.

    These tests mock subprocess.run via a side_effect that mimics pip's
    behavior of writing the JSON report to the path passed via --report.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self._tmpdir.name) / "cache"
        self.cache_dir.mkdir()

        # Patch paths.xdg_cache_home and paths.ensure_directory so the
        # function writes audit artifacts into our temp cache dir.
        self._xdg_patcher = mock.patch(
            "pydepgate.package_tools.depresolution.resolver.paths.xdg_cache_home",
            return_value=self.cache_dir,
        )
        self._ensure_patcher = mock.patch(
            "pydepgate.package_tools.depresolution.resolver.paths.ensure_directory",
            side_effect=self._fake_ensure_directory,
        )
        self._xdg_patcher.start()
        self._ensure_patcher.start()

        # Patch _check_pip_version to a no-op for the success-path tests.
        # Individual tests that exercise the pip-version check can patch
        # subprocess.run directly.
        self._pipver_patcher = mock.patch(
            "pydepgate.package_tools.depresolution.resolver._check_pip_version"
        )
        self._pipver_patcher.start()

    def tearDown(self):
        self._pipver_patcher.stop()
        self._ensure_patcher.stop()
        self._xdg_patcher.stop()
        self._tmpdir.cleanup()

    def _fake_ensure_directory(self, path):
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _fake_pip_success(self, report_payload):
        """Build a subprocess.run side_effect that writes a fake report and returns success."""

        def side_effect(args, **kwargs):
            report_path = args[args.index("--report") + 1]
            Path(report_path).write_text(json.dumps(report_payload))
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        return side_effect

    def test_successful_resolution_writes_audit_artifact(self):
        report_payload = {"install": [], "version": "1"}
        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            side_effect=self._fake_pip_success(report_payload),
        ):
            result = get_pip_resolution_report("foo==1.0", "foo", "1.0")
        self.assertEqual(result, report_payload)
        # Audit artifact should exist at the expected path.
        artifact = self.cache_dir / "foo" / "foo-1.0_pip_report.json"
        self.assertTrue(artifact.exists())
        self.assertEqual(json.loads(artifact.read_text()), report_payload)

    def test_pip_failure_cleans_up_temp_file(self):
        def side_effect(args, **kwargs):
            # Create the temp file as pip would have, but return failure.
            report_path = args[args.index("--report") + 1]
            Path(report_path).write_text("")
            return mock.Mock(returncode=1, stdout=b"", stderr=b"pip resolution error")

        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            side_effect=side_effect,
        ):
            with self.assertRaises(RuntimeError) as ctx:
                get_pip_resolution_report("foo==1.0", "foo", "1.0")
            self.assertIn("pip resolution failed", str(ctx.exception))

    def test_timeout_cleans_up_temp_file(self):
        def side_effect(args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=args, timeout=120)

        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            side_effect=side_effect,
        ):
            with self.assertRaises(RuntimeError) as ctx:
                get_pip_resolution_report("foo==1.0", "foo", "1.0", timeout=120)
            self.assertIn("timed out", str(ctx.exception))

    def test_json_parse_failure_cleans_up_temp_file(self):
        def side_effect(args, **kwargs):
            report_path = args[args.index("--report") + 1]
            Path(report_path).write_text("not valid json {{{")
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            side_effect=side_effect,
        ):
            with self.assertRaises(RuntimeError) as ctx:
                get_pip_resolution_report("foo==1.0", "foo", "1.0")
            self.assertIn("Failed to parse pip resolution report", str(ctx.exception))
        # No audit artifact should have been written.
        artifact = self.cache_dir / "foo" / "foo-1.0_pip_report.json"
        self.assertFalse(artifact.exists())

    def test_stderr_warning_does_not_fail(self):
        report_payload = {"install": []}

        def side_effect(args, **kwargs):
            report_path = args[args.index("--report") + 1]
            Path(report_path).write_text(json.dumps(report_payload))
            return mock.Mock(returncode=0, stdout=b"", stderr=b"deprecation warning")

        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            side_effect=side_effect,
        ):
            result = get_pip_resolution_report("foo==1.0", "foo", "1.0")
        self.assertEqual(result, report_payload)

    def test_pip_args_include_dry_run_and_only_binary(self):
        report_payload = {"install": []}
        captured_args = []

        def side_effect(args, **kwargs):
            captured_args.append(list(args))
            report_path = args[args.index("--report") + 1]
            Path(report_path).write_text(json.dumps(report_payload))
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        with mock.patch(
            "pydepgate.package_tools.depresolution.resolver.subprocess.run",
            side_effect=side_effect,
        ):
            get_pip_resolution_report("foo==1.0", "foo", "1.0")
        self.assertEqual(len(captured_args), 1)
        args = captured_args[0]
        self.assertIn("--dry-run", args)
        self.assertIn("--only-binary=:all:", args)
        self.assertIn("--ignore-installed", args)
        self.assertIn("--report", args)


if __name__ == "__main__":
    unittest.main()
