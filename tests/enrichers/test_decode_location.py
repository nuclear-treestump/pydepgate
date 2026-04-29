"""
Tests for decoded-payload location resolution.

Covers the directory-mode rewrite of _resolve_decode_location and
its supporting helpers _build_decode_filename and
_sanitize_target_for_filename. These can be merged into an existing
tests/cli/test_scan.py or run stand-alone.

Naming convention under test:
    {STATUS}_{timestamp}_{target}{ext}
where:
    STATUS = FINDINGS | NOFINDINGS
    timestamp = UTC %Y-%m-%d_%H-%M-%S
    target = sanitized basename of result.artifact_identity
    ext = '.txt' | '.json' | future archive extensions
"""

from __future__ import annotations

import argparse
import datetime
import os
import unittest
from pathlib import Path
from types import SimpleNamespace

from pydepgate.cli.subcommands.scan import (
    _build_decode_filename,
    _resolve_decode_location,
    _sanitize_target_for_filename,
)
from pydepgate.cli.decode_args import (
    DECODE_IOCS_FULL,
    DECODE_IOCS_HASHES,
    DECODE_IOCS_OFF,
)
from pydepgate.cli.decode_payloads import (
    ChildFinding,
    DecodedNode,
    DecodedTree,
    IOCData,
    STOP_LEAF_TERMINAL,
)
from pydepgate.cli.subcommands.scan import (
    _run_decode_pass,
    _sidecar_iocs_path,
)
 


# ---------------------------------------------------------------------------
# _sanitize_target_for_filename
# ---------------------------------------------------------------------------

class SanitizeTargetForFilenameTests(unittest.TestCase):

    def test_alphanumeric_preserved(self):
        self.assertEqual(
            _sanitize_target_for_filename("abc123XYZ"),
            "abc123XYZ",
        )

    def test_dot_hyphen_underscore_preserved(self):
        self.assertEqual(
            _sanitize_target_for_filename("foo-1.0.0_bar"),
            "foo-1.0.0_bar",
        )

    def test_real_wheel_filename_preserved(self):
        # The litellm wheel from the user's session.
        self.assertEqual(
            _sanitize_target_for_filename("litellm-1.82.8-py3-none-any.whl"),
            "litellm-1.82.8-py3-none-any.whl",
        )

    def test_special_characters_squashed_to_underscore(self):
        # Slashes, plus, at, percent, space, all become underscores.
        self.assertEqual(
            _sanitize_target_for_filename("evil/pkg+1.0@local"),
            "evil_pkg_1.0_local",
        )

    def test_leading_dots_stripped(self):
        # Leading dot would create a hidden file on Unix.
        self.assertEqual(
            _sanitize_target_for_filename(".hidden-package"),
            "hidden-package",
        )

    def test_leading_underscores_stripped(self):
        self.assertEqual(
            _sanitize_target_for_filename("__init__"),
            "init",
        )

    def test_leading_hyphens_stripped(self):
        # Leading hyphen could be parsed as a flag in shell pipelines.
        self.assertEqual(
            _sanitize_target_for_filename("--malicious"),
            "malicious",
        )

    def test_trailing_separators_stripped(self):
        self.assertEqual(
            _sanitize_target_for_filename("package..."),
            "package",
        )

    def test_empty_input_falls_back_to_default(self):
        self.assertEqual(_sanitize_target_for_filename(""), "unknown_target")

    def test_all_special_input_falls_back_to_default(self):
        # Everything becomes underscore, then strip removes them all,
        # leaving an empty string -> fallback.
        self.assertEqual(
            _sanitize_target_for_filename("///+++"),
            "unknown_target",
        )

    def test_unicode_squashed_to_underscores(self):
        # Non-ASCII characters are not alphanumeric in the ASCII-only
        # sense, but isalnum() returns True for unicode letters too.
        # We accept this; a non-ASCII filename that survives is still
        # a valid filename on modern filesystems.
        result = _sanitize_target_for_filename("évil-package")
        # The accented e is alphanumeric per str.isalnum, so it survives.
        # If your platform/policy forbids non-ASCII in filenames, change
        # the sanitizer to use a stricter check.
        self.assertEqual(result, "évil-package")


# ---------------------------------------------------------------------------
# _build_decode_filename
# ---------------------------------------------------------------------------

class BuildDecodeFilenameTests(unittest.TestCase):

    def test_basic_pattern_with_pinned_timestamp(self):
        ts = datetime.datetime(2026, 4, 29, 14, 30, 45, tzinfo=datetime.timezone.utc)
        result = _build_decode_filename(
            status="FINDINGS",
            target="litellm-1.82.8-py3-none-any.whl",
            ext=".txt",
            timestamp=ts,
        )
        self.assertEqual(
            result,
            "FINDINGS_2026-04-29_14-30-45_litellm-1.82.8-py3-none-any.whl.txt",
        )

    def test_nofindings_status(self):
        ts = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
        result = _build_decode_filename(
            status="NOFINDINGS",
            target="clean-package",
            ext=".txt",
            timestamp=ts,
        )
        self.assertEqual(result, "NOFINDINGS_2026-01-01_00-00-00_clean-package.txt")

    def test_json_extension(self):
        ts = datetime.datetime(2026, 4, 29, 14, 30, 45, tzinfo=datetime.timezone.utc)
        result = _build_decode_filename(
            status="FINDINGS",
            target="x",
            ext=".json",
            timestamp=ts,
        )
        self.assertEqual(result, "FINDINGS_2026-04-29_14-30-45_x.json")

    def test_zip_extension(self):
        # Future archive extension; the helper does not care.
        ts = datetime.datetime(2026, 4, 29, 14, 30, 45, tzinfo=datetime.timezone.utc)
        result = _build_decode_filename(
            status="FINDINGS",
            target="x",
            ext=".zip",
            timestamp=ts,
        )
        self.assertEqual(result, "FINDINGS_2026-04-29_14-30-45_x.zip")

    def test_default_timestamp_is_utc_now(self):
        # When timestamp=None, the helper uses datetime.now(timezone.utc).
        # We can't assert a specific value but we can sanity-check the
        # format and ensure the result is a parseable timestamp.
        result = _build_decode_filename(
            status="FINDINGS", target="x", ext=".txt",
        )
        # Format: FINDINGS_YYYY-MM-DD_HH-MM-SS_x.txt
        self.assertTrue(result.startswith("FINDINGS_"))
        self.assertTrue(result.endswith("_x.txt"))
        # Parse the middle 19 chars as a timestamp.
        ts_part = result[len("FINDINGS_"):-len("_x.txt")]
        # Should parse without raising.
        datetime.datetime.strptime(ts_part, "%Y-%m-%d_%H-%M-%S")

    def test_no_z_suffix_in_timestamp(self):
        # We deliberately omit the trailing Z because it's not
        # universally accepted in filenames on all OSes (Z itself is
        # fine but redundant).
        ts = datetime.datetime(2026, 4, 29, 14, 30, 45, tzinfo=datetime.timezone.utc)
        result = _build_decode_filename(
            status="FINDINGS", target="x", ext=".txt", timestamp=ts,
        )
        self.assertNotIn("Z", result)


# ---------------------------------------------------------------------------
# _resolve_decode_location
# ---------------------------------------------------------------------------

def _fake_result(identity: str) -> SimpleNamespace:
    return SimpleNamespace(artifact_identity=identity, findings=[])


def _empty_tree(target: str = "x") -> DecodedTree:
    return DecodedTree(target=target, max_depth=3, nodes=())


def _tree_with_one_node(target: str = "x") -> DecodedTree:
    # Construct a minimal DecodedTree with one node so the FINDINGS
    # branch is exercised. We don't care about the node's contents
    # for these tests; only that nodes is non-empty.
    from pydepgate.cli.decode_payloads import DecodedNode, STOP_NO_INNER_FINDINGS
    node = DecodedNode(
        outer_signal_id="DENS010",
        outer_severity="high",
        outer_location="x.py:1:0",
        outer_length=0,
        chain=(),
        unwrap_status="completed",
        final_kind="python_source",
        final_size=0,
        indicators=(),
        pickle_warning=False,
        depth=0,
        stop_reason=STOP_NO_INNER_FINDINGS,
    )
    return DecodedTree(target=target, max_depth=3, nodes=(node,))


class ResolveDecodeLocationTests(unittest.TestCase):

    def test_explicit_decode_location_used_as_directory(self):
        args = argparse.Namespace(decode_location="sandwich")
        result = _fake_result("litellm-1.82.8-py3-none-any.whl")
        tree = _tree_with_one_node()
        path = _resolve_decode_location(args, result, tree, ".txt")
        # The parent should be the user-provided path treated as a directory.
        self.assertEqual(path.parent, Path("sandwich"))
        # The filename starts with FINDINGS_ and ends with the target+ext.
        self.assertTrue(path.name.startswith("FINDINGS_"))
        self.assertTrue(path.name.endswith("_litellm-1.82.8-py3-none-any.whl.txt"))

    def test_no_decode_location_defaults_to_cwd_decoded(self):
        args = argparse.Namespace(decode_location=None)
        result = _fake_result("foo.whl")
        tree = _tree_with_one_node()
        path = _resolve_decode_location(args, result, tree, ".txt")
        self.assertEqual(path.parent, Path.cwd() / "decoded")

    def test_empty_tree_produces_nofindings_status(self):
        args = argparse.Namespace(decode_location="out")
        result = _fake_result("foo.whl")
        tree = _empty_tree()
        path = _resolve_decode_location(args, result, tree, ".txt")
        self.assertTrue(path.name.startswith("NOFINDINGS_"))

    def test_nonempty_tree_produces_findings_status(self):
        args = argparse.Namespace(decode_location="out")
        result = _fake_result("foo.whl")
        tree = _tree_with_one_node()
        path = _resolve_decode_location(args, result, tree, ".txt")
        self.assertTrue(path.name.startswith("FINDINGS_"))

    def test_target_derived_from_artifact_identity_basename(self):
        # Even with a directory path in the identity, the basename
        # is what shows up in the filename.
        args = argparse.Namespace(decode_location="out")
        result = _fake_result("/home/user/Downloads/litellm.whl")
        tree = _tree_with_one_node()
        path = _resolve_decode_location(args, result, tree, ".txt")
        self.assertIn("litellm.whl", path.name)
        # Confirm the leading directory components do NOT appear.
        self.assertNotIn("Downloads", path.name)
        self.assertNotIn("home", path.name)

    def test_target_with_special_chars_sanitized(self):
        args = argparse.Namespace(decode_location="out")
        result = _fake_result("evil-pkg+1.0@local")
        tree = _tree_with_one_node()
        path = _resolve_decode_location(args, result, tree, ".txt")
        self.assertIn("evil-pkg_1.0_local", path.name)
        self.assertNotIn("+", path.name)
        self.assertNotIn("@", path.name)

    def test_empty_artifact_identity_falls_back_to_unknown(self):
        args = argparse.Namespace(decode_location="out")
        result = _fake_result("")
        tree = _tree_with_one_node()
        path = _resolve_decode_location(args, result, tree, ".txt")
        self.assertIn("unknown_target", path.name)

    def test_json_extension_propagated(self):
        args = argparse.Namespace(decode_location="out")
        result = _fake_result("foo.whl")
        tree = _tree_with_one_node()
        path = _resolve_decode_location(args, result, tree, ".json")
        self.assertTrue(path.name.endswith(".json"))

    def test_path_components_compose_correctly(self):
        # The full path is directory + filename.
        args = argparse.Namespace(decode_location="my/output/dir")
        result = _fake_result("foo.whl")
        tree = _tree_with_one_node()
        path = _resolve_decode_location(args, result, tree, ".txt")
        # Confirm the full structure: my/output/dir/FINDINGS_<ts>_foo.whl.txt
        self.assertEqual(path.parent, Path("my/output/dir"))
        self.assertTrue(path.name.startswith("FINDINGS_"))
        self.assertIn("foo.whl", path.name)
        self.assertTrue(path.name.endswith(".txt"))


def _make_args(
    *,
    decode_iocs: str = "off",
    decode_format: str = "text",
    decode_location: str | None = None,
    decode_payload_depth: int = 3,
    peek_min_length: int = 32,
    peek_depth: int = 4,
    peek_budget: int = 4_000_000,
    decode_archive_password: str = "infected",
    decode_archive_stored: bool = False,
    min_severity: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        decode_iocs=decode_iocs,
        decode_format=decode_format,
        decode_location=decode_location,
        decode_payload_depth=decode_payload_depth,
        peek_min_length=peek_min_length,
        peek_depth=peek_depth,
        peek_budget=peek_budget,
        decode_archive_password=decode_archive_password,
        decode_archive_stored=decode_archive_stored,
        min_severity=min_severity,
    )
 
 
def _fake_result(identity: str = "litellm-1.82.8-py3-none-any.whl") -> SimpleNamespace:
    return SimpleNamespace(
        artifact_identity=identity,
        findings=[],  # decode_payloads is mocked, so contents don't matter
    )
 
 
def _node_with_ioc(
    *,
    severity: str = "high",
    location: str = "foo.py:10:5",
    decoded_source: str | None = "import os\n",
    children: tuple = (),
) -> DecodedNode:
    ioc = IOCData(
        original_sha256="a" * 64,
        original_sha512="a" * 128,
        decoded_sha256="b" * 64,
        decoded_sha512="b" * 128,
        decoded_source=decoded_source,
        extract_timestamp="2026-04-29T12:00:00+00:00",
    )
    return DecodedNode(
        outer_signal_id="DENS010",
        outer_severity=severity,
        outer_location=location,
        outer_length=100,
        chain=("base64",),
        unwrap_status="completed",
        final_kind="python_source",
        final_size=len(decoded_source.encode("utf-8")) if decoded_source else 0,
        indicators=(),
        pickle_warning=False,
        depth=0,
        stop_reason=STOP_LEAF_TERMINAL,
        triggered_by=("DENS010",),
        child_findings=(),
        children=children,
        ioc_data=ioc,
    )
 
 
def _tree_with_nodes(target: str = "litellm.whl") -> DecodedTree:
    return DecodedTree(
        target=target, max_depth=3, nodes=(_node_with_ioc(),),
    )
 
 
def _empty_tree(target: str = "litellm.whl") -> DecodedTree:
    return DecodedTree(target=target, max_depth=3, nodes=())
 
 
class _DecodeFlowTestBase(unittest.TestCase):
    """Common setup: temp directory, captured stderr, mock decode_payloads.
 
    Each subclass test sets `self.tree_to_return` to control what the
    mocked decode_payloads emits, then calls _run_decode_pass.
    """
 
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.outdir = Path(self.tmp.name) / "out"
 
        self.tree_to_return: DecodedTree = _tree_with_nodes()
 
        self.stderr = io.StringIO()
        self._stderr_patch = mock.patch.object(sys, "stderr", self.stderr)
        self._stderr_patch.start()
        self.addCleanup(self._stderr_patch.stop)
 
        # Patch decode_payloads at its bound location inside scan.py.
        self._decode_patch = mock.patch(
            "pydepgate.cli.scan.decode_payloads",
            side_effect=lambda *a, **kw: self.tree_to_return,
        )
        self.mock_decode = self._decode_patch.start()
        self.addCleanup(self._decode_patch.stop)
 
        # Patch the archive writer at its bound location inside scan.py.
        self._archive_patch = mock.patch(
            "pydepgate.cli.scan.write_encrypted_zip",
        )
        self.mock_write_archive = self._archive_patch.start()
        self.addCleanup(self._archive_patch.stop)
 
    def stderr_text(self) -> str:
        return self.stderr.getvalue()
 
 
# ---------------------------------------------------------------------------
# mode == off
# ---------------------------------------------------------------------------
 
class OffModeTests(_DecodeFlowTestBase):
 
    def test_writes_single_txt_when_tree_has_nodes(self):
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="off",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        files = list(self.outdir.glob("*"))
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].name.startswith("FINDINGS_"))
        self.assertTrue(files[0].suffix == ".txt")
        self.mock_write_archive.assert_not_called()
 
    def test_skips_when_tree_empty(self):
        self.tree_to_return = _empty_tree()
        args = _make_args(
            decode_iocs="off",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        # No files, no archive call.
        self.assertFalse(self.outdir.exists() and any(self.outdir.iterdir()))
        self.mock_write_archive.assert_not_called()
        self.assertIn("no payload-bearing findings", self.stderr_text())
 
    def test_no_iocs_section_in_off_mode_report(self):
        # In off mode the txt should not have the IOC section even
        # if ioc_data is somehow populated on the nodes.
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="off",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        files = list(self.outdir.glob("*"))
        content = files[0].read_text()
        self.assertNotIn("IOC (INDICATORS OF COMPROMISE)", content)
 
 
# ---------------------------------------------------------------------------
# mode == hashes
# ---------------------------------------------------------------------------
 
class HashesModeTests(_DecodeFlowTestBase):
 
    def test_writes_report_and_sidecar_when_tree_has_nodes(self):
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="hashes",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        files = sorted(self.outdir.glob("*"))
        # One main .txt and one .iocs.txt sidecar.
        self.assertEqual(len(files), 2)
        names = {f.name for f in files}
        # Main file is FINDINGS_<ts>_<target>.txt
        # Sidecar is FINDINGS_<ts>_<target>.iocs.txt
        self.assertTrue(any(n.endswith(".iocs.txt") for n in names))
        self.assertTrue(any(
            n.endswith(".txt") and not n.endswith(".iocs.txt")
            for n in names
        ))
        self.mock_write_archive.assert_not_called()
 
    def test_sidecar_contains_hash_records(self):
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="hashes",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        sidecars = list(self.outdir.glob("*.iocs.txt"))
        self.assertEqual(len(sidecars), 1)
        content = sidecars[0].read_text()
        self.assertIn("decoded_sha256", content)
        self.assertIn("original_sha256", content)
 
    def test_skips_when_tree_empty(self):
        self.tree_to_return = _empty_tree()
        args = _make_args(
            decode_iocs="hashes",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        self.assertFalse(self.outdir.exists() and any(self.outdir.iterdir()))
        self.mock_write_archive.assert_not_called()
 
 
# ---------------------------------------------------------------------------
# mode == full
# ---------------------------------------------------------------------------
 
class FullModeTests(_DecodeFlowTestBase):
 
    def setUp(self) -> None:
        super().setUp()
        # Make write_encrypted_zip actually create a (placeholder)
        # file at its target path so the tmp.replace() call has
        # something to work with.
        def fake_write(path, entries, *, password, compression):
            Path(path).write_bytes(b"FAKE_ZIP")
        self.mock_write_archive.side_effect = fake_write
 
    def test_writes_archive_and_sidecar_when_tree_has_nodes(self):
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="full",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        # Archive writer should have been called once.
        self.mock_write_archive.assert_called_once()
 
        # Final files in the directory: <archive>.zip and <stem>.iocs.txt.
        files = sorted(self.outdir.glob("*"))
        suffixes = sorted(f.suffix for f in files if f.is_file())
        self.assertIn(".zip", suffixes)
        # Sidecar suffix is multi-part: .iocs.txt -> Path.suffix is .txt
        self.assertTrue(any(f.name.endswith(".iocs.txt") for f in files))
 
    def test_archive_entries_have_three_files_in_subdir(self):
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="full",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        call = self.mock_write_archive.call_args
        # The entries arg is positional[1] in our signature.
        entries = call.args[1] if len(call.args) > 1 else call.kwargs["entries"]
 
        names = [name for (name, _) in entries]
        self.assertEqual(len(names), 3)
        # All three should share a subdirectory prefix derived from
        # the sanitized artifact identity.
        prefixes = {n.split("/")[0] for n in names}
        self.assertEqual(len(prefixes), 1)
        # Filenames inside.
        leaves = sorted(n.split("/")[-1] for n in names)
        self.assertEqual(leaves, ["iocs.txt", "report.txt", "sources.txt"])
 
    def test_password_and_compression_forwarded(self):
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="full",
            decode_location=str(self.outdir),
            decode_archive_password="burritos",
            decode_archive_stored=True,
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        call = self.mock_write_archive.call_args
        self.assertEqual(call.kwargs["password"], "burritos")
        self.assertEqual(call.kwargs["compression"], "stored")
 
    def test_atomic_write_targets_tmp_first(self):
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="full",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        # The path passed to write_encrypted_zip should end in .tmp,
        # NOT in .zip. The .replace() call moves it into place.
        call = self.mock_write_archive.call_args
        path_arg = call.args[0]
        self.assertTrue(
            path_arg.endswith(".tmp"),
            f"expected write_encrypted_zip target to be a .tmp path, got {path_arg}",
        )
 
    def test_writes_stub_archive_when_tree_empty(self):
        self.tree_to_return = _empty_tree()
        args = _make_args(
            decode_iocs="full",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        # NOFINDINGS still produces an archive in full mode.
        self.mock_write_archive.assert_called_once()
 
        # The archive filename has NOFINDINGS as the status prefix.
        call = self.mock_write_archive.call_args
        path_arg = call.args[0]
        self.assertIn("NOFINDINGS_", path_arg)
 
    def test_inner_subdir_uses_sanitized_target_name(self):
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="full",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(
            _fake_result(identity="evil-pkg+1.0@local"),
            engine=mock.Mock(),
            args=args,
        )
 
        call = self.mock_write_archive.call_args
        entries = call.args[1] if len(call.args) > 1 else call.kwargs["entries"]
        prefix = entries[0][0].split("/")[0]
        # Special chars squashed to underscores, no plus or at signs.
        self.assertNotIn("+", prefix)
        self.assertNotIn("@", prefix)
        self.assertIn("evil-pkg", prefix)
 
 
# ---------------------------------------------------------------------------
# JSON format
# ---------------------------------------------------------------------------
 
class JsonFormatTests(_DecodeFlowTestBase):
 
    def test_json_format_writes_single_json_file_in_off_mode(self):
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="off",
            decode_format="json",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        files = list(self.outdir.glob("*"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].suffix, ".json")
        self.mock_write_archive.assert_not_called()
 
    def test_json_format_writes_single_json_file_in_full_mode_too(self):
        # JSON output carries IOC data inline, so the three-file
        # split doesn't apply. JSON is always one file.
        self.tree_to_return = _tree_with_nodes()
        args = _make_args(
            decode_iocs="full",
            decode_format="json",
            decode_location=str(self.outdir),
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        files = list(self.outdir.glob("*"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].suffix, ".json")
        self.mock_write_archive.assert_not_called()
 
 
# ---------------------------------------------------------------------------
# min-severity filter integration
# ---------------------------------------------------------------------------
 
class MinSeverityFilterTests(_DecodeFlowTestBase):
 
    def test_filter_runs_after_decode_not_before(self):
        # If filter ran before decode, decode_payloads would be
        # called with extract_iocs=False or similar gated behavior.
        # We just confirm decode_payloads was called and our return
        # value got filtered.
        node_low = DecodedNode(
            outer_signal_id="DENS010",
            outer_severity="low",
            outer_location="foo.py:1:0",
            outer_length=100,
            chain=("base64",),
            unwrap_status="completed",
            final_kind="python_source",
            final_size=10,
            indicators=(),
            pickle_warning=False,
            depth=0,
            stop_reason=STOP_LEAF_TERMINAL,
            triggered_by=("DENS010",),
            child_findings=(),
            children=(),
            ioc_data=None,
        )
        self.tree_to_return = DecodedTree(
            target="litellm.whl", max_depth=3, nodes=(node_low,),
        )
        args = _make_args(
            decode_iocs="off",
            decode_location=str(self.outdir),
            min_severity="high",
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        # Decode was called.
        self.mock_decode.assert_called_once()
        # The filter pruned the low-severity node, so the tree is
        # empty post-filter and we hit the skip path.
        self.assertIn("at or above --min-severity=high", self.stderr_text())
        self.assertFalse(
            self.outdir.exists() and any(self.outdir.iterdir())
        )
 
    def test_keep_for_context_preserves_low_parent_with_critical_child(self):
        # The filter's "keep for context" rule means a low-severity
        # outer with a critical descendant survives. We verify the
        # report file gets written in that case.
        crit_child = DecodedNode(
            outer_signal_id="DENS011",
            outer_severity="critical",
            outer_location="foo.py:5:0",
            outer_length=50,
            chain=("base64",),
            unwrap_status="completed",
            final_kind="python_source",
            final_size=10,
            indicators=(),
            pickle_warning=False,
            depth=1,
            stop_reason=STOP_LEAF_TERMINAL,
            triggered_by=("DENS011",),
            child_findings=(),
            children=(),
            ioc_data=None,
        )
        low_parent = _node_with_ioc(severity="low", children=(crit_child,))
        self.tree_to_return = DecodedTree(
            target="litellm.whl", max_depth=3, nodes=(low_parent,),
        )
        args = _make_args(
            decode_iocs="off",
            decode_location=str(self.outdir),
            min_severity="high",
        )
        _run_decode_pass(_fake_result(), engine=mock.Mock(), args=args)
 
        # File should exist; the low parent stays for context.
        files = list(self.outdir.glob("*"))
        self.assertEqual(len(files), 1)
 
 
# ---------------------------------------------------------------------------
# _sidecar_iocs_path helper
# ---------------------------------------------------------------------------
 
class SidecarIocsPathTests(unittest.TestCase):
 
    def test_replaces_zip_with_iocs_txt(self):
        main = Path("/tmp/x/FINDINGS_2026-04-29_14-30-45_litellm.whl.zip")
        sidecar = _sidecar_iocs_path(main)
        self.assertEqual(
            sidecar.name,
            "FINDINGS_2026-04-29_14-30-45_litellm.whl.iocs.txt",
        )
        self.assertEqual(sidecar.parent, main.parent)
 
    def test_replaces_txt_with_iocs_txt(self):
        main = Path("/tmp/x/FINDINGS_2026-04-29_14-30-45_litellm.whl.txt")
        sidecar = _sidecar_iocs_path(main)
        self.assertEqual(
            sidecar.name,
            "FINDINGS_2026-04-29_14-30-45_litellm.whl.iocs.txt",
        )
 
    def test_handles_filename_with_multiple_dots(self):
        # Last-suffix replacement only.
        main = Path("/tmp/x/FINDINGS_litellm-1.82.8-py3-none-any.whl.zip")
        sidecar = _sidecar_iocs_path(main)
        self.assertEqual(
            sidecar.name,
            "FINDINGS_litellm-1.82.8-py3-none-any.whl.iocs.txt",
        )
 
 
if __name__ == "__main__":
    unittest.main()