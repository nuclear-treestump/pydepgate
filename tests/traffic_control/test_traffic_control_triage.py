"""Tests for pydepgate.scope (traffic control)."""

import unittest
from pydepgate.traffic_control.triage import FileKind, triage


class TriageTests(unittest.TestCase):

    def test_top_level_setup_py(self):
        decision = triage("setup.py")
        self.assertEqual(decision.kind, FileKind.SETUP_PY)

    def test_vendored_setup_py_is_skipped(self):
        decision = triage("vendor/foo/setup.py")
        self.assertEqual(decision.kind, FileKind.SKIP)
        self.assertIn("not at artifact root", decision.reason)

    def test_pth_file_in_root(self):
        decision = triage("mypackage.pth")
        self.assertEqual(decision.kind, FileKind.PTH)

    def test_pth_file_deep(self):
        decision = triage("nested/path/some.pth")
        self.assertEqual(decision.kind, FileKind.PTH)

    def test_top_level_init(self):
        decision = triage("mypackage/__init__.py")
        self.assertEqual(decision.kind, FileKind.INIT_PY)

    def test_deep_init_is_skipped(self):
        decision = triage("mypackage/sub/__init__.py")
        self.assertEqual(decision.kind, FileKind.SKIP)

    def test_sitecustomize_at_root(self):
        decision = triage("sitecustomize.py")
        self.assertEqual(decision.kind, FileKind.SITECUSTOMIZE)

    def test_sitecustomize_deep(self):
        # Even deep sitecustomize is suspicious.
        decision = triage("mypackage/hidden/sitecustomize.py")
        self.assertEqual(decision.kind, FileKind.SITECUSTOMIZE)

    def test_entry_points_in_dist_info(self):
        decision = triage("mypackage-1.0.0.dist-info/entry_points.txt")
        self.assertEqual(decision.kind, FileKind.ENTRY_POINTS)

    def test_entry_points_not_in_metadata_dir(self):
        decision = triage("mypackage/entry_points.txt")
        self.assertEqual(decision.kind, FileKind.SKIP)

    def test_tests_directory_excluded(self):
        decision = triage("tests/test_foo.py")
        self.assertEqual(decision.kind, FileKind.SKIP)
        self.assertIn("tests", decision.reason)

    def test_init_in_tests_directory_excluded(self):
        decision = triage("tests/__init__.py")
        self.assertEqual(decision.kind, FileKind.SKIP)

    def test_random_py_file_is_skipped(self):
        decision = triage("mypackage/utils.py")
        self.assertEqual(decision.kind, FileKind.SKIP)

    def test_binary_extension_is_skipped(self):
        decision = triage("mypackage/native.so")
        self.assertEqual(decision.kind, FileKind.SKIP)

    def test_path_with_leading_slash(self):
        decision = triage("/setup.py")
        self.assertEqual(decision.kind, FileKind.SETUP_PY)

    def test_path_with_backslashes(self):
        decision = triage("mypackage\\__init__.py")
        self.assertEqual(decision.kind, FileKind.INIT_PY)