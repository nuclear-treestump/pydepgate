"""Tests for the cvescan CLI subcommand."""

from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
import unittest
from types import SimpleNamespace
import zipfile
from pathlib import Path
from unittest import mock

from pydepgate.cli import exit_codes
from pydepgate.cli import main as cli_main
from pydepgate.cli.subcommands import cvescan
from pydepgate.dbs.cvedb import constants
from pydepgate.dbs.cvedb import schema
from pydepgate.package_tools.cvescanner import scanner


class CveScanCliTests(unittest.TestCase):
    def test_register_creates_cvescan_subcommand(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="subcommand")
        cvescan.register(subparsers)

        args = parser.parse_args(["cvescan", "demo-1.0.0-py3-none-any.whl"])

        self.assertEqual(args.subcommand, "cvescan")
        self.assertEqual(args.target, "demo-1.0.0-py3-none-any.whl")
        self.assertIs(args.func, cvescan.run)

    def test_main_parser_dispatches_cvescan(self):
        parser = cli_main.build_parser()
        args = parser.parse_args(["cvescan", "demo-1.0.0-py3-none-any.whl"])

        self.assertEqual(args.subcommand, "cvescan")
        self.assertIs(args.func, cvescan.run)

    def test_human_output_returns_blocking_for_high_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel_path = _make_wheel(root, "demo_pkg", "1.2.3")
            db_path = _make_db(root, severity="HIGH")
            args = _make_args(wheel_path, db_path, output_format="human")

            stdout = io.StringIO()
            with mock.patch.object(sys, "stdout", stdout):
                rc = cvescan.run(args)

            self.assertEqual(rc, exit_codes.FINDINGS_BLOCKING)
            output = stdout.getvalue()
            self.assertIn("CVE scan: demo-pkg 1.2.3", output)
            self.assertIn("CVE-2099-0001", output)
            self.assertIn("HIGH", output)
            self.assertIn(constants.OSV_DATA_SOURCE_NAME, output)

    def test_json_output_contains_finding_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel_path = _make_wheel(root, "demo_pkg", "1.2.3")
            db_path = _make_db(root, severity="LOW")
            args = _make_args(wheel_path, db_path, output_format="json")

            stdout = io.StringIO()
            with mock.patch.object(sys, "stdout", stdout):
                rc = cvescan.run(args)

            self.assertEqual(rc, exit_codes.FINDINGS_BELOW_BLOCKING)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["schema"], "pydepgate.cvescan.v1")
            self.assertEqual(payload["package_name"], "demo-pkg")
            self.assertEqual(payload["package_version"], "1.2.3")
            self.assertEqual(payload["total_findings"], 1)
            self.assertEqual(payload["findings"][0]["canonical_id"], "CVE-2099-0001")
            self.assertEqual(
                payload["artifact_metadata"]["identity_source"], "core-metadata"
            )

    def test_min_severity_filters_display_and_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel_path = _make_wheel(root, "demo_pkg", "1.2.3")
            db_path = _make_db(root, severity="LOW")
            args = _make_args(
                wheel_path,
                db_path,
                output_format="human",
                min_severity="high",
            )

            stdout = io.StringIO()
            with mock.patch.object(sys, "stdout", stdout):
                rc = cvescan.run(args)

            self.assertEqual(rc, exit_codes.CLEAN)
            self.assertIn("matched the current severity filter", stdout.getvalue())

    def test_strict_exit_uses_hidden_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel_path = _make_wheel(root, "demo_pkg", "1.2.3")
            db_path = _make_db(root, severity="LOW")
            args = _make_args(
                wheel_path,
                db_path,
                output_format="human",
                min_severity="high",
                strict_exit=True,
            )

            stdout = io.StringIO()
            with mock.patch.object(sys, "stdout", stdout):
                rc = cvescan.run(args)

            self.assertEqual(rc, exit_codes.FINDINGS_BELOW_BLOCKING)

    def test_missing_database_is_tool_error_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel_path = _make_wheel(root, "demo_pkg", "1.2.3")
            missing_db = root / "missing.db"
            args = _make_args(wheel_path, missing_db, output_format="human")

            stderr = io.StringIO()
            with mock.patch.object(sys, "stderr", stderr):
                rc = cvescan.run(args)

            self.assertEqual(rc, exit_codes.TOOL_ERROR)
            self.assertIn("CVE database not found", stderr.getvalue())
            self.assertIn("cvedb update", stderr.getvalue())

    def test_ignore_missing_database_returns_warning_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel_path = _make_wheel(root, "demo_pkg", "1.2.3")
            missing_db = root / "missing.db"
            args = _make_args(
                wheel_path,
                missing_db,
                output_format="json",
                ignore_missing_db=True,
            )

            stdout = io.StringIO()
            with mock.patch.object(sys, "stdout", stdout):
                rc = cvescan.run(args)

            self.assertEqual(rc, exit_codes.CLEAN)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["total_findings"], 0)
            self.assertTrue(
                any(
                    "cve-database-not-found" in warning
                    for warning in payload["warnings"]
                )
            )

    def test_sarif_output_is_rejected(self):
        args = _make_args(
            Path("demo-1.0.0-py3-none-any.whl"),
            Path("db.sqlite"),
            output_format="sarif",
        )

        stderr = io.StringIO()
        with mock.patch.object(sys, "stderr", stderr):
            rc = cvescan.run(args)

        self.assertEqual(rc, exit_codes.TOOL_ERROR)
        self.assertIn("does not support SARIF", stderr.getvalue())

    def test_run_invokes_internal_cve_runner_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel_path = _make_wheel(root, "demo_pkg", "1.2.3")
            db_path = root / "pypi_osv.db"
            args = _make_args(wheel_path, db_path, output_format="human")
            fake_result = scanner.CveScanResult(
                package_name="demo-pkg",
                normalized_package_name="demo-pkg",
                package_version="1.2.3",
                package_metadata=None,
                findings=(),
                unevaluated_ranges=(),
                warnings=(),
                attribution="test attribution",
                database_path=db_path,
                applied_policy_result=None,
            )
            fake_outcome = SimpleNamespace(
                result=fake_result,
                scan_completed_event_id="cve-completed-test",
            )

            stdout = io.StringIO()
            with (
                mock.patch.object(sys, "stdout", stdout),
                mock.patch.object(
                    cvescan, "execute_cve_scan", return_value=fake_outcome
                ) as execute_cve_scan,
            ):
                rc = cvescan.run(args)

            self.assertEqual(rc, exit_codes.CLEAN)
            execute_cve_scan.assert_called_once()
            request = execute_cve_scan.call_args.args[0]
            self.assertIsInstance(request, cvescan.CveScanRequest)
            self.assertEqual(request.ticket.scan_mode, "cve.artifact")
            self.assertEqual(request.ticket.allowed_actions, ("cve.scan",))
            self.assertEqual(request.ticket.target_kind, "wheel")
            self.assertEqual(request.ticket.target_identity, str(wheel_path))
            self.assertEqual(request.target_ref.kind, "wheel")
            self.assertEqual(request.target_ref.identity, str(wheel_path))
            self.assertEqual(request.target_ref.metadata["command"], "cvescan")
            self.assertTrue(request.require_database)
            self.assertEqual(request.db_path, str(db_path))

    def test_event_log_records_grant_cve_scan_and_completion_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel_path = _make_wheel(root, "demo_pkg", "1.2.3")
            db_path = _make_db(root, severity="LOW")
            event_log = root / "events.jsonl"
            args = _make_args(
                wheel_path,
                db_path,
                output_format="json",
                event_log=event_log,
            )

            stdout = io.StringIO()
            with mock.patch.object(sys, "stdout", stdout):
                rc = cvescan.run(args)

            self.assertEqual(rc, exit_codes.FINDINGS_BELOW_BLOCKING)
            events = [
                json.loads(line)
                for line in event_log.read_text(encoding="utf-8").splitlines()
            ]
            event_types = [event["event_type"] for event in events]
            self.assertEqual(
                event_types,
                [
                    "internal.scanner.scan_grant_issued",
                    "internal.scanner.cve_scan_started",
                    "internal.scanner.cve_scan_completed",
                    "internal.scanner.run_completed",
                ],
            )
            ticket_id = events[0]["ticket_id"]
            self.assertIsNotNone(ticket_id)
            self.assertTrue(all(event["ticket_id"] == ticket_id for event in events))
            self.assertEqual(events[0]["payload"]["scan_mode"], "cve.artifact")
            self.assertNotIn("ticket_nonce", events[0]["payload"])
            self.assertEqual(events[2]["payload"]["scan_mode"], "cve.artifact")
            self.assertEqual(events[2]["payload"]["target_kind"], "wheel")
            self.assertEqual(events[2]["payload"]["target_identity"], str(wheel_path))
            self.assertEqual(events[2]["payload"]["target_ref"]["kind"], "wheel")
            self.assertEqual(events[2]["payload"]["result_kind"], "cve")
            self.assertEqual(events[2]["payload"]["package_name"], "demo-pkg")
            self.assertEqual(events[2]["payload"]["finding_count"], 1)
            self.assertEqual(events[3]["payload"]["scan_mode"], "cve.artifact")
            self.assertEqual(events[3]["payload"]["target_kind"], "wheel")
            self.assertEqual(events[3]["payload"]["target_identity"], str(wheel_path))
            self.assertEqual(events[3]["payload"]["target_ref"]["kind"], "wheel")
            self.assertEqual(events[3]["payload"]["result_kind"], "cve")
            self.assertEqual(events[3]["payload"]["exit_code"], rc)


def _make_args(
    wheel_path: Path,
    db_path: Path,
    *,
    output_format: str,
    min_severity: str | None = None,
    strict_exit: bool = False,
    ignore_missing_db: bool = False,
    save_to_db: bool = False,
    event_log: Path | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        target=str(wheel_path),
        db_path=str(db_path),
        ignore_missing_db=ignore_missing_db,
        save_to_db=save_to_db,
        event_log=str(event_log) if event_log is not None else None,
        format=output_format,
        min_severity=min_severity,
        strict_exit=strict_exit,
    )


def _make_wheel(root: Path, distribution: str, version: str) -> Path:
    wheel_path = root / f"{distribution}-{version}-py3-none-any.whl"
    dist_info = f"{distribution}-{version}.dist-info"
    metadata = (
        "Metadata-Version: 2.1\n"
        "Name: demo-pkg\n"
        f"Version: {version}\n"
        "Summary: demo package\n"
    )
    wheel = (
        "Wheel-Version: 1.0\n"
        "Generator: test\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    )
    with zipfile.ZipFile(wheel_path, "w") as zf:
        zf.writestr(f"{dist_info}/METADATA", metadata)
        zf.writestr(f"{dist_info}/WHEEL", wheel)
    return wheel_path


def _make_db(root: Path, *, severity: str) -> Path:
    db_path = root / "pypi_osv.db"
    conn = schema.connect(db_path)
    try:
        with conn:
            schema.initialize_schema(conn)
            schema.write_metadata_dict(
                conn,
                {
                    schema.METADATA_KEY_DATA_SOURCE_NAME: constants.OSV_DATA_SOURCE_NAME,
                    schema.METADATA_KEY_DATA_SOURCE_URL: constants.OSV_DATA_SOURCE_URL,
                    schema.METADATA_KEY_DATA_LICENSE: constants.OSV_DATA_LICENSE,
                    schema.METADATA_KEY_DATA_LICENSE_URL: constants.OSV_DATA_LICENSE_URL,
                },
            )
            conn.execute(
                "INSERT INTO vulnerabilities "
                "(canonical_id, summary, details, published, modified, "
                "cvss_v3, cvss_v4, severity, versions_complete) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "CVE-2099-0001",
                    "Demo vulnerability",
                    "Demo details",
                    "2099-01-01T00:00:00Z",
                    "2099-01-02T00:00:00Z",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "",
                    severity,
                    1,
                ),
            )
            conn.execute(
                "INSERT INTO aliases (alias, canonical_id, alias_type) "
                "VALUES (?, ?, ?)",
                ("CVE-2099-0001", "CVE-2099-0001", "CVE"),
            )
            conn.execute(
                "INSERT INTO affected_versions "
                "(canonical_id, package_name, version) VALUES (?, ?, ?)",
                ("CVE-2099-0001", "demo-pkg", "1.2.3"),
            )
    finally:
        conn.close()
    return db_path


if __name__ == "__main__":
    unittest.main()
