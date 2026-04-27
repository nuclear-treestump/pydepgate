"""
Tests for the 'scan --single' flag.

Two layers:
  1. Unit tests on the routing helpers (_internal_path_for_single,
     _dispatch_single) without subprocess overhead.
  2. End-to-end subprocess tests confirming the CLI accepts the flag
     and produces sensible output.
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
    _AS_KIND_TO_INTERNAL_PATH,
    _dispatch_single,
    _internal_path_for_single,
)
from pydepgate.engines.static import StaticEngine
from pydepgate.analyzers.density_analyzer import CodeDensityAnalyzer
from pydepgate.analyzers.encoding_abuse import EncodingAbuseAnalyzer
from pydepgate.engines.base import ArtifactKind, Severity


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
# Tier 1: internal_path autodetection
# =============================================================================

class InternalPathAutodetectTests(unittest.TestCase):
    """_internal_path_for_single picks a triage-acceptable path."""

    def test_pth_uses_real_filename(self):
        result = _internal_path_for_single(
            pathlib.Path("/tmp/foo.pth"), as_kind=None,
        )
        self.assertEqual(result, "foo.pth")

    def test_setup_py_uses_setup_py(self):
        result = _internal_path_for_single(
            pathlib.Path("/tmp/setup.py"), as_kind=None,
        )
        self.assertEqual(result, "setup.py")

    def test_init_py_gets_depth_fix(self):
        # A bare __init__.py at depth 0 would be classified as SKIP.
        # The helper must add a synthetic parent directory so triage
        # sees it at depth 1.
        result = _internal_path_for_single(
            pathlib.Path("/tmp/__init__.py"), as_kind=None,
        )
        self.assertEqual(result, "pkg/__init__.py")

    def test_sitecustomize_passthrough(self):
        result = _internal_path_for_single(
            pathlib.Path("/tmp/sitecustomize.py"), as_kind=None,
        )
        self.assertEqual(result, "sitecustomize.py")

    def test_usercustomize_passthrough(self):
        result = _internal_path_for_single(
            pathlib.Path("/tmp/usercustomize.py"), as_kind=None,
        )
        self.assertEqual(result, "usercustomize.py")

    def test_arbitrary_py_defaults_to_setup_py(self):
        # The whole point: random "garbage_test.py" should be
        # treated as setup.py for maximum rule promotion.
        result = _internal_path_for_single(
            pathlib.Path("/tmp/garbage_test.py"), as_kind=None,
        )
        self.assertEqual(result, "setup.py")

    def test_no_extension_defaults_to_setup_py(self):
        result = _internal_path_for_single(
            pathlib.Path("/tmp/snippet"), as_kind=None,
        )
        self.assertEqual(result, "setup.py")


class InternalPathOverrideTests(unittest.TestCase):
    """--as KIND wins over auto-detection."""

    def test_explicit_setup_py_override(self):
        result = _internal_path_for_single(
            pathlib.Path("/tmp/foo.pth"), as_kind="setup_py",
        )
        # Even though the file is .pth, --as setup_py forces setup.py.
        self.assertEqual(result, "setup.py")

    def test_explicit_init_py_override_includes_depth_fix(self):
        result = _internal_path_for_single(
            pathlib.Path("/tmp/foo.py"), as_kind="init_py",
        )
        self.assertEqual(result, "pkg/__init__.py")

    def test_every_choice_has_a_mapping(self):
        # Every value of _AS_KIND_CHOICES (the argparse choices) must
        # have a corresponding entry in _AS_KIND_TO_INTERNAL_PATH so
        # the helper never raises KeyError.
        for kind in ("setup_py", "init_py", "pth", "sitecustomize",
                     "usercustomize"):
            result = _internal_path_for_single(
                pathlib.Path("/tmp/anything"), as_kind=kind,
            )
            self.assertEqual(result, _AS_KIND_TO_INTERNAL_PATH[kind])


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
            self.engine,
            "/nonexistent/garbage.py",
            as_kind=None,
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
            # The encoding_abuse analyzer should fire on this content.
            self.assertGreater(len(result.findings), 0)
            # In setup.py context, ENC001 promotes to CRITICAL.
            critical = [f for f in result.findings
                        if f.severity == Severity.CRITICAL]
            self.assertGreater(len(critical), 0)

    def test_artifact_identity_is_real_path(self):
        # The report should identify the actual file the user gave us,
        # not the synthetic internal_path used internally.
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage_test.py"
            path.write_bytes(b"x = 1\n")
            result = _dispatch_single(self.engine, str(path), as_kind=None)
            self.assertEqual(result.artifact_identity, str(path))

    def test_pth_content_is_analyzed_as_pth(self):
        # A .pth file should be parsed as .pth (one line at a time),
        # not as Python source.
        content = (
            b"import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evil.pth"
            path.write_bytes(content)
            result = _dispatch_single(self.engine, str(path), as_kind=None)
            self.assertGreater(len(result.findings), 0)

    def test_as_override_changes_severity(self):
        # Same content scanned with --as setup_py vs --as init_py
        # should produce different severities (setup_py rule for ENC001
        # is CRITICAL, init_py rule is HIGH).
        source = (
            b"import base64\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage.py"
            path.write_bytes(source)
            r_setup = _dispatch_single(self.engine, str(path),
                                       as_kind="setup_py")
            r_init = _dispatch_single(self.engine, str(path),
                                      as_kind="init_py")
        # Both should produce findings, with different severities.
        self.assertGreater(len(r_setup.findings), 0)
        self.assertGreater(len(r_init.findings), 0)
        max_sev_setup = max(f.severity for f in r_setup.findings)
        max_sev_init = max(f.severity for f in r_init.findings)
        # CRITICAL > HIGH per the existing default rules.
        order = {Severity.LOW: 1, Severity.MEDIUM: 2,
                 Severity.HIGH: 3, Severity.CRITICAL: 4}
        self.assertGreater(order[max_sev_setup], order[max_sev_init])

    def test_unparseable_content_does_not_crash(self):
        # The whole point of iteration testing on garbage data: bad
        # input should produce a clean (possibly empty) result, not
        # a crash.
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage.py"
            path.write_bytes(b"def (\n@@@ this is not python\n")
            result = _dispatch_single(self.engine, str(path), as_kind=None)
            # No assertion on findings; just that we got a result.
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
            # rc=0 means the scan ran cleanly.
            self.assertEqual(rc, 0, msg=f"stderr: {err}")
            payload = json.loads(out)
            self.assertIn("findings", payload)

    def test_single_flag_reports_real_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "garbage_xyz.py"
            path.write_bytes(b"x = 1\n")
            rc, out, err = _run_cli([
                "scan", "--single", str(path), "--format", "json",
            ])
            payload = json.loads(out)
            self.assertEqual(payload["artifact"]["identity"], str(path))

    def test_single_flag_finds_density_signal_in_garbage(self):
        # A high-entropy string in a generic .py file should still
        # surface a density signal under --single (because the file
        # is treated as setup.py by default, which has a DENS010 rule).
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
        # Neither target nor --single -> error with helpful message.
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
        # Diagnostic recorded but the scan itself completed.
        payload = json.loads(out)
        self.assertEqual(payload["findings"], [])
        self.assertGreater(len(payload["diagnostics"]), 0)
        self.assertIn("not found", payload["diagnostics"][0])


if __name__ == "__main__":
    unittest.main()