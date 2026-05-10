"""Tests for the SARIF URI scheme."""

from __future__ import annotations
import unittest

from pydepgate.reporters.sarif.uris import (
    DECODED_URI_SCHEME,
    SRCROOT_BASE_ID,
    make_artifact_location,
    make_artifact_location_for_decoded,
)


class TestRealPaths(unittest.TestCase):
    """artifactLocation for real on-disk and artifact-internal paths."""

    def test_relative_path_passes_through_unchanged(self):
        result = make_artifact_location("litellm/_init_.py")
        assert result == {"uri": "litellm/_init_.py"}

    def test_windows_separators_normalized_to_forward_slash(self):
        result = make_artifact_location("litellm\\_init_.py")
        assert result == {"uri": "litellm/_init_.py"}

    def test_mixed_separators_all_become_forward_slash(self):
        result = make_artifact_location("a\\b/c.py")
        assert result == {"uri": "a/b/c.py"}

    def test_single_leading_slash_stripped(self):
        result = make_artifact_location("/setup.py")
        assert result == {"uri": "setup.py"}

    def test_multiple_leading_slashes_stripped(self):
        result = make_artifact_location("///a/b.py")
        assert result == {"uri": "a/b.py"}

    def test_use_srcroot_adds_uriBaseId(self):
        result = make_artifact_location("setup.py", use_srcroot=True)
        assert result == {
            "uri": "setup.py",
            "uriBaseId": SRCROOT_BASE_ID,
        }
        assert result["uriBaseId"] == "PROJECTROOT"

    def test_use_srcroot_false_omits_uriBaseId(self):
        result = make_artifact_location("setup.py", use_srcroot=False)
        assert "uriBaseId" not in result

    def test_use_srcroot_default_is_false(self):
        result = make_artifact_location("setup.py")
        assert "uriBaseId" not in result


class TestSyntheticDecodedPaths(unittest.TestCase):
    """artifactLocation for synthetic decoded payload locations."""

    def test_decoded_uri_uses_pydepgate_decoded_scheme(self):
        result = make_artifact_location_for_decoded(
            parent_path="setup.py",
            coords={"layer": 1, "line": 7},
        )
        assert result["uri"].startswith(f"{DECODED_URI_SCHEME}:")
        assert result["uri"].startswith("pydepgate-decoded:")

    def test_decoded_uri_includes_parent_path(self):
        result = make_artifact_location_for_decoded(
            parent_path="setup.py",
            coords={"layer": 1, "line": 7},
        )
        assert "setup.py" in result["uri"]

    def test_decoded_uri_includes_coords_as_query(self):
        result = make_artifact_location_for_decoded(
            parent_path="setup.py",
            coords={"layer": 1, "line": 7},
        )
        assert "layer=1" in result["uri"]
        assert "line=7" in result["uri"]
        # Query string follows a '?' after the path.
        assert "?" in result["uri"]

    def test_decoded_uri_without_coords_omits_query_string(self):
        result = make_artifact_location_for_decoded(
            parent_path="setup.py",
            coords={},
        )
        assert result == {"uri": "pydepgate-decoded:setup.py"}
        assert "?" not in result["uri"]

    def test_decoded_uri_url_encodes_special_chars_in_path(self):
        result = make_artifact_location_for_decoded(
            parent_path="path with spaces.py",
            coords={"layer": 1},
        )
        # Spaces become %20 under URL encoding.
        assert "%20" in result["uri"]

    def test_decoded_uri_no_uriBaseId(self):
        # Synthetic paths are not relative to any project
        # root, so they never carry uriBaseId.
        result = make_artifact_location_for_decoded(
            parent_path="setup.py",
            coords={"layer": 1},
        )
        assert "uriBaseId" not in result

    def test_decoded_uri_normalizes_windows_separators(self):
        result = make_artifact_location_for_decoded(
            parent_path="src\\setup.py",
            coords={"layer": 1},
        )
        assert "src/setup.py" in result["uri"]
        assert "\\" not in result["uri"]

    def test_decoded_uri_strips_leading_slash(self):
        result = make_artifact_location_for_decoded(
            parent_path="/setup.py",
            coords={},
        )
        assert result == {"uri": "pydepgate-decoded:setup.py"}

    def test_coord_values_coerced_to_strings(self):
        # Integer values are coerced via str(); floats too.
        result = make_artifact_location_for_decoded(
            parent_path="x.py",
            coords={"layer": 2, "depth": 1.5},
        )
        assert "layer=2" in result["uri"]
        assert "depth=1.5" in result["uri"]


class TestSyntheticDetectionInRealPathFunction(unittest.TestCase):
    """make_artifact_location() detects synthetic paths and routes them."""

    def test_decoded_marker_routes_to_decoded_scheme(self):
        # When a caller passes a synthetic path string to the
        # general entry point, it should still produce a
        # pydepgate-decoded URI (not a malformed real URI).
        result = make_artifact_location("setup.py<decoded:layer1@line7>")
        assert result["uri"].startswith("pydepgate-decoded:")

    def test_decoded_marker_short_circuits_srcroot(self):
        # Synthetic paths never get uriBaseId even when
        # use_srcroot is True; they are not in any project
        # root.
        result = make_artifact_location(
            "setup.py<decoded:layer1@line7>",
            use_srcroot=True,
        )
        assert "uriBaseId" not in result


if __name__ == "__main__":
    unittest.main()
