"""
Tests for the 'scan --single' flag.

Two layers:
  1. Unit tests on the routing helpers (_file_kind_for_single,
     _dispatch_single) without subprocess overhead.
  2. End-to-end subprocess tests confirming the CLI accepts the flag
     and produces sensible output.

Critical invariant after the cleaner-engine refactor: every finding's
context.internal_path matches the real filesystem path the user gave
us, NOT a synthetic stand-in. Several tests below explicitly assert
that property.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

from pydepgate.cli.subcommands.scan import (
    _AS_KIND_TO_FILE_KIND,
    _dispatch_single,
    _file_kind_for_single,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import ArtifactKind, Severity
from pydepgate.traffic_control.triage import FileKind


def _run_cli(args, env=None):
    """Run pydepgate as a subprocess. Mirror of helper used elsewhere."""
    base_env = os.environ.copy()
    for k in list(base_env.keys()):
        if k.startswith("PYDEPGATE_") or k == "NO_COLOR":
            del base_env[k]
    if env:
        base_env.update(env)
    result = subprocess.run(
        [sys.executable, "-m", "pydepgate"] + list(args),
        capture_output=True,
        text=True,
        env=base_env,
        timeout=10,
    )
    return result.returncode, result.stdout, result.stderr


# =============================================================================
# Tier 1: FileKind autodetection
# =============================================================================

class FileKindAutodetectTests(unittest.TestCase):
    """_file_kind_for_single picks the right FileKind for each filename."""

    def test_pth_extension_is_pth(self):
        result = _file_kind_for_single(
            pathlib.Path("/tmp/foo.pth"), as_kind=None,
        )
        self.assertIs(result, FileKind.PTH)

    def test_setup_py_is_setup_py(self):
        result = _file_kind_for_single(
            pathlib.Path("/tmp/setup.py"), as_kind=None,
        )
        self.assertIs(result, FileKind.SETUP_PY)

    def test_init_py_is_init_py(self):
        result = _file_kind_for_single(
            pathlib.Path("/tmp/__init__.py"), as_kind=None,
        )
        self.assertIs(result, FileKind.INIT_PY)

    def test_sitecustomize_is_sitecustomize(self):
        result = _file_kind_for_single(
            pathlib.Path("/tmp/sitecustomize.py"), as_kind=None,
        )
        self.assertIs(result, FileKind.SITECUSTOMIZE)

    def test_usercustomize_is_usercustomize(self):
        result = _file_kind_for_single(
            pathlib.Path("/tmp/usercustomize.py"), as_kind=None,
        )
        self.assertIs(result, FileKind.USERCUSTOMIZE)

    def test_arbitrary_py_defaults_to_setup_py(self):
        # The iteration default: random "garbage_test.py" should be
        # treated as setup.py for maximum rule promotion.
        result = _file_kind_for_single(
            pathlib.Path("/tmp/garbage_test.py"), as_kind=None,
        )
        self.assertIs(result, FileKind.SETUP_PY)

    def test_no_extension_defaults_to_setup_py(self):
        result = _file_kind_for_single(
            pathlib.Path("/tmp/snippet"), as_kind=None,
        )
        self.assertIs(result, FileKind.SETUP_PY)


class FileKindOverrideTests(unittest.TestCase):
    """--as KIND wins over auto-detection."""

    def test_explicit_setup_py_override(self):
        # File is .pth but --as forces setup_py.
        result = _file_kind_for_single(
            pathlib.Path("/tmp/foo.pth"), as_kind="setup_py",
        )
        self.assertIs(result, FileKind.SETUP_PY)

    def test_explicit_init_py_override(self):
        result = _file_kind_for_single(
            pathlib.Path("/tmp/foo.py"), as_kind="init_py",
        )
        self.assertIs(result, FileKind.INIT_PY)

    def test_every_choice_has_a_mapping(self):
        # Every value in argparse's choices must map to a FileKind.
        for kind in ("setup_py", "init_py", "pth", "sitecustomize",
                     "usercustomize"):
            result = _file_kind_for_single(
                pathlib.Path("/tmp/anything"), as_kind=kind,
            )
            self.assertIs(result, _AS_KIND_TO_FILE_KIND[kind])

    def test_no_choice_maps_to_skip(self):
        # Sanity: none of the user-facing choices should resolve to
        # FileKind.SKIP, since the engine would reject it.
        for kind in _AS_KIND_TO_FILE_KIND.values():
            self.assertIsNot(kind, FileKind.SKIP)


# =============================================================================
# Tier 2: _dispatch_single end-to-end (no subprocess)
# =============================================================================

class DispatchSingleTests(unittest.TestCase):

    def setUp(self):
        self.engine = StaticEngine(analyzers=[
            EncodingAbuseAnalyzer(),
            CodeDensityAnalyzer(),
        ])

    def test_nonexistent_file_returns_diag(self):
        result = _dispatch_single(
            self.engine, "/nonexistent/garbage.py", as_kind=None,
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.diagnostics), 1)
        self.assertIn("not found", result.diagnostics[0])

    def test_directory_path_returns_diag(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _dispatch_single(self.engine, tmp, as_kind=None)
            self.assertEqual(result.findings, ())
            self.assertEqual(len(result.diagnostics), 1)
            self.assertIn("not a regular file", result.diagnostics[0])

    def test_arbitrary_py_file_gets_setup_py_treatment(self):
        # Iteration test: a random .py file in /tmp gets analyzed as
        # if it were setup.py, exercising the full rule path.
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage_test.py"
            path.write_bytes(source)
            result = _dispatch_single(self.engine, str(path), as_kind=None)
            self.assertGreater(len(result.findings), 0)
            critical = [f for f in result.findings
                        if f.severity == Severity.CRITICAL]
            self.assertGreater(len(critical), 0)

    def test_finding_context_carries_real_path(self):
        # THE bug the cleaner refactor fixed: findings used to
        # report context.internal_path == "setup.py" no matter what
        # file was scanned. Now they must carry the real path.
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "demo_fixture_42.py"
            path.write_bytes(source)
            result = _dispatch_single(self.engine, str(path), as_kind=None)
            self.assertGreater(len(result.findings), 0)
            for finding in result.findings:
                self.assertEqual(
                    finding.context.internal_path, str(path),
                    msg=("finding context should reference the real "
                         "path, not a synthetic stand-in"),
                )

    def test_artifact_identity_is_real_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage_test.py"
            path.write_bytes(b"x = 1\n")
            result = _dispatch_single(self.engine, str(path), as_kind=None)
            self.assertEqual(result.artifact_identity, str(path))

    def test_pth_content_is_analyzed_as_pth(self):
        content = (
            b"import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evil.pth"
            path.write_bytes(content)
            result = _dispatch_single(self.engine, str(path), as_kind=None)
            self.assertGreater(len(result.findings), 0)
            # And the path is preserved in the .pth path too.
            for finding in result.findings:
                self.assertEqual(finding.context.internal_path, str(path))

    def test_as_override_changes_severity(self):
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage.py"
            path.write_bytes(source)
            r_setup = _dispatch_single(
                self.engine, str(path), as_kind="setup_py",
            )
            r_init = _dispatch_single(
                self.engine, str(path), as_kind="init_py",
            )
        max_setup = max(f.severity for f in r_setup.findings)
        max_init = max(f.severity for f in r_init.findings)
        order = {Severity.LOW: 1, Severity.MEDIUM: 2,
                 Severity.HIGH: 3, Severity.CRITICAL: 4}
        self.assertGreater(order[max_setup], order[max_init])

    def test_unparseable_content_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage.py"
            path.write_bytes(b"def (\n@@@ this is not python\n")
            result = _dispatch_single(self.engine, str(path), as_kind=None)
            # No assertion on findings; just that a result came back.
            self.assertIsNotNone(result)


# =============================================================================
# Tier 3: CLI end-to-end (subprocess)
# =============================================================================

class CliSingleFlagTests(unittest.TestCase):
    """The flag actually wires through to the CLI."""

    def test_single_flag_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "snippet.py"
            path.write_bytes(b"x = 1\n")
            rc, out, err = _run_cli([
                "scan", "--single", str(path), "--format", "json",
            ])
            self.assertEqual(rc, 0, msg=f"stderr: {err}")
            payload = json.loads(out)
            self.assertIn("findings", payload)

    def test_single_flag_reports_real_path_in_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage_xyz.py"
            path.write_bytes(b"x = 1\n")
            rc, out, err = _run_cli([
                "scan", "--single", str(path), "--format", "json",
            ])
            payload = json.loads(out)
            self.assertEqual(payload["artifact"]["identity"], str(path))

    def test_single_flag_reports_real_path_in_findings(self):
        # The bug the cleaner refactor fixed, end-to-end via subprocess.
        # Findings should reference the actual file the user gave us.
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "demo_xyz.py"
            path.write_bytes(source)
            rc, out, err = _run_cli([
                "scan", "--single", str(path), "--format", "json",
            ])
            payload = json.loads(out)
            self.assertGreater(len(payload["findings"]), 0)
            for finding in payload["findings"]:
                # The JSON schema may carry the path under different
                # keys depending on reporter version; at minimum, the
                # real filename should appear somewhere in the
                # finding's serialized context.
                serialized = json.dumps(finding)
                self.assertIn(
                    str(path), serialized,
                    msg=f"real path missing from finding: {finding}",
                )

    def test_single_flag_finds_density_signal_in_garbage(self):
        # 128 chars of base64 alphabet, entropy ~6.0:
        payload_str = (
            "QWxsIHRoZSB3b3JsZCdzIGEgc3RhZ2UsQWxsIHRoZSBz" * 4
        )[:128]
        source = textwrap.dedent(f'''
            x = "{payload_str}"
        ''').encode()
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "test_data.py"
            path.write_bytes(source)
            rc, out, err = _run_cli([
                "scan", "--single", str(path), "--format", "json",
            ])
            self.assertIn(rc, (0, 1, 2),
                          msg=f"unexpected rc={rc}, stderr: {err}")
            payload = json.loads(out)
            ids = [f["signal_id"] for f in payload["findings"]]
            # At least one DENS signal should fire on this string.
            density_ids = [i for i in ids if i.startswith("DENS")]
            self.assertGreater(len(density_ids), 0,
                               msg=f"no density findings; got {ids}")

    def test_no_args_errors_clearly(self):
        rc, out, err = _run_cli(["scan"])
        self.assertNotEqual(rc, 0)
        self.assertIn("either", err.lower())

    def test_target_and_single_together_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "x.py"
            path.write_bytes(b"x = 1\n")
            rc, out, err = _run_cli([
                "scan", "pip", "--single", str(path),
            ])
            self.assertNotEqual(rc, 0)
            self.assertIn("cannot combine", err.lower())

    def test_as_without_single_errors(self):
        rc, out, err = _run_cli([
            "scan", "pip", "--as", "setup_py",
        ])
        self.assertNotEqual(rc, 0)
        self.assertIn("--as", err)

    def test_single_with_as_init_py(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "anything.py"
            path.write_bytes(b"x = 1\n")
            rc, out, err = _run_cli([
                "scan", "--single", str(path),
                "--as", "init_py",
                "--format", "json",
            ])
            self.assertEqual(rc, 0, msg=f"stderr: {err}")

    def test_single_with_nonexistent_file_returns_diagnostic(self):
        rc, out, err = _run_cli([
            "scan", "--single", "/nonexistent/garbage.py",
            "--format", "json",
        ])
        payload = json.loads(out)
        self.assertEqual(payload["findings"], [])
        self.assertGreater(len(payload["diagnostics"]), 0)
        self.assertIn("not found", payload["diagnostics"][0])


if __name__ == "__main__":
    unittest.main()