"""
Tests for the triage module's deep_mode parameter.

deep_mode=False (the default) preserves all existing triage behavior.
deep_mode=True upgrades three specific SKIP cases to LIBRARY_PY:
  - "not a known startup vector" fallthrough for .py files
  - deeper __init__.py files (currently "only depth 1 analyzed")
  - setup.py not at artifact root (currently "likely vendored")

In all three cases, the upgrade only applies when the file is not
inside an excluded directory and has a recognized extension.
"""

import unittest

from pydepgate.traffic_control.triage import FileKind, triage


# =============================================================================
# Tier 1: deep_mode=False preserves existing behavior
# =============================================================================

class DefaultModeUnchangedTests(unittest.TestCase):
    """deep_mode defaults to False; existing scan behavior is unchanged."""

    def test_random_py_skipped_in_default_mode(self):
        decision = triage("mymod/util.py")
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_deeper_init_skipped_in_default_mode(self):
        decision = triage("mymod/sub/__init__.py")
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_vendored_setup_py_skipped_in_default_mode(self):
        decision = triage("vendored/setup.py")
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_default_keyword_argument_matches_no_argument(self):
        # Defensive: passing deep_mode=False explicitly should give
        # the same answer as not passing it at all.
        path = "mymod/util.py"
        self.assertEqual(triage(path), triage(path, deep_mode=False))


# =============================================================================
# Tier 2: deep_mode=True upgrades the right SKIP cases to LIBRARY_PY
# =============================================================================

class DeepModeUpgradesTests(unittest.TestCase):
    """The three SKIP-paths that legitimately become LIBRARY_PY."""

    def test_random_py_becomes_library_in_deep_mode(self):
        decision = triage("mymod/util.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.LIBRARY_PY)

    def test_deeper_init_becomes_library_in_deep_mode(self):
        decision = triage("mymod/sub/__init__.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.LIBRARY_PY)

    def test_very_deep_init_becomes_library_in_deep_mode(self):
        decision = triage("a/b/c/d/__init__.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.LIBRARY_PY)

    def test_vendored_setup_py_becomes_library_in_deep_mode(self):
        decision = triage("vendor/dep/setup.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.LIBRARY_PY)

    def test_deeply_nested_py_becomes_library_in_deep_mode(self):
        decision = triage("a/b/c/d/e/module.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.LIBRARY_PY)


# =============================================================================
# Tier 3: deep_mode preserves correct skips
# =============================================================================

class DeepModePreservesSkipsTests(unittest.TestCase):
    """deep_mode does NOT mean 'scan everything indiscriminately'.

    Files inside excluded directories and files with excluded
    extensions still skip. The whole reason these are excluded is
    that they shouldn't be scanned regardless of mode.
    """

    def test_tests_directory_still_skipped(self):
        decision = triage("mymod/tests/test_foo.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_docs_directory_still_skipped(self):
        decision = triage("mymod/docs/conf.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_pycache_directory_still_skipped(self):
        decision = triage("mymod/__pycache__/foo.cpython-310.pyc",
                          deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_excluded_extension_still_skipped(self):
        # A .json file is non-Python; the density analyzer can't read it.
        decision = triage("mymod/data.json", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_compiled_python_still_skipped(self):
        decision = triage("mymod/foo.pyc", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_native_extension_still_skipped(self):
        decision = triage("mymod/_native.so", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_init_py_inside_metadata_dir_still_skipped(self):
        decision = triage("pkg-1.0.dist-info/__init__.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_init_py_inside_excluded_dir_still_skipped(self):
        decision = triage("tests/__init__.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_deeper_init_inside_excluded_dir_still_skipped(self):
        decision = triage("mymod/tests/subdir/__init__.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)

    def test_setup_py_in_examples_directory_still_skipped(self):
        # examples/ is an excluded directory; even with deep mode,
        # vendored setup.py inside it should not be scanned.
        decision = triage("examples/setup.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SKIP)


# =============================================================================
# Tier 4: deep_mode does not change in-scope decisions
# =============================================================================

class DeepModePreservesInScopeKindsTests(unittest.TestCase):
    """Existing FileKind classifications for startup vectors are untouched."""

    def test_setup_py_at_root_still_setup_py(self):
        decision = triage("setup.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SETUP_PY)

    def test_top_level_init_still_init_py(self):
        decision = triage("mymod/__init__.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.INIT_PY)

    def test_pth_file_still_pth(self):
        decision = triage("foo.pth", deep_mode=True)
        self.assertIs(decision.kind, FileKind.PTH)

    def test_sitecustomize_still_sitecustomize(self):
        decision = triage("sitecustomize.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.SITECUSTOMIZE)

    def test_usercustomize_still_usercustomize(self):
        decision = triage("usercustomize.py", deep_mode=True)
        self.assertIs(decision.kind, FileKind.USERCUSTOMIZE)

    def test_entry_points_still_entry_points(self):
        decision = triage("pkg-1.0.dist-info/entry_points.txt", deep_mode=True)
        self.assertIs(decision.kind, FileKind.ENTRY_POINTS)


# =============================================================================
# Tier 5: TriageDecision payload correctness
# =============================================================================

class DeepModeDecisionPayloadTests(unittest.TestCase):
    """LIBRARY_PY decisions carry a sensible reason and depth."""

    def test_library_py_reason_mentions_deep_mode(self):
        # The reason string is surfaced in diagnostics; users
        # debugging a "why was this scanned?" question deserve an
        # explanation that mentions deep mode.
        decision = triage("mymod/util.py", deep_mode=True)
        self.assertIn("deep mode", decision.reason.lower())

    def test_library_py_preserves_internal_path(self):
        decision = triage("mymod/sub/util.py", deep_mode=True)
        self.assertEqual(decision.internal_path, "mymod/sub/util.py")

    def test_library_py_records_correct_depth(self):
        decision = triage("a/b/c/d.py", deep_mode=True)
        self.assertEqual(decision.depth, 3)

    def test_deep_init_reason_mentions_deep_mode(self):
        decision = triage("mymod/sub/__init__.py", deep_mode=True)
        self.assertIn("deep mode", decision.reason.lower())

    def test_vendored_setup_reason_mentions_deep_mode(self):
        decision = triage("vendor/dep/setup.py", deep_mode=True)
        self.assertIn("deep mode", decision.reason.lower())


if __name__ == "__main__":
    unittest.main()