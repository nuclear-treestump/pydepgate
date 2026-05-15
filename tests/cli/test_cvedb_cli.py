"""Tests for cvedb subcommand (v2)."""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from pydepgate.cli.subcommands import cvedb
from pydepgate.cli import exit_codes
from pydepgate.package_tools.cvedb import constants, fetcher, importer, schema


def _setuptools_record() -> dict:
    return {
        "schema_version": "1.7.3",
        "id": "PYSEC-2025-49",
        "published": "2025-05-17T16:15:19Z",
        "modified": "2026-05-11T00:26:34.671259971Z",
        "aliases": [
            "BIT-setuptools-2025-47273",
            "CVE-2025-47273",
            "GHSA-5rjg-fvgr-3xxf",
        ],
        "details": "setuptools path traversal.",
        "affected": [
            {
                "package": {"name": "setuptools", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "78.1.1"}],
                    }
                ],
                "versions": ["75.0.0", "78.0.1"],
            }
        ],
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/X"},
        ],
    }


def _make_test_zip(path: Path, records: list) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, record in records:
            zf.writestr(name, json.dumps(record))


def _make_head_info(content_length: int = 100 * 1024 * 1024) -> fetcher.HeadInfo:
    return fetcher.HeadInfo(
        url=constants.OSV_PYPI_ALL_ZIP_URL,
        status=200,
        content_type="application/zip",
        content_length=content_length,
        etag='"abc123"',
        last_modified="Wed, 14 May 2026 12:00:00 GMT",
    )


def _make_fetch_result(zip_path: Path) -> fetcher.FetchResult:
    return fetcher.FetchResult(
        path=zip_path,
        bytes_written=zip_path.stat().st_size if zip_path.exists() else 1000,
        sha256="deadbeef" * 8,
        content_type="application/zip",
        etag='"abc123"',
        last_modified="Wed, 14 May 2026 12:00:00 GMT",
    )


def _make_args(action: str, no_bar: bool = True) -> argparse.Namespace:
    return argparse.Namespace(action=action, no_bar=no_bar)


class TestRegister(unittest.TestCase):
    def test_register_creates_cvedb_subcommand(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="subcommand")
        cvedb.register(subparsers)
        self.assertIn("cvedb", subparsers.choices)

    def test_cvedb_accepts_valid_actions(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="subcommand")
        cvedb.register(subparsers)
        for action in ("update", "status", "path"):
            args = parser.parse_args(["cvedb", action])
            self.assertEqual(args.action, action)

    def test_cvedb_rejects_unknown_action(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="subcommand")
        cvedb.register(subparsers)
        with self.assertRaises(SystemExit):
            parser.parse_args(["cvedb", "delete-everything"])

    def test_cvedb_no_bar_flag(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="subcommand")
        cvedb.register(subparsers)
        args = parser.parse_args(["cvedb", "update", "--no-bar"])
        self.assertTrue(args.no_bar)

    def test_cvedb_no_bar_defaults_false(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="subcommand")
        cvedb.register(subparsers)
        args = parser.parse_args(["cvedb", "update"])
        self.assertFalse(args.no_bar)


class TestPathAction(unittest.TestCase):
    def test_path_prints_db_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                stdout = io.StringIO()
                with mock.patch.object(sys, "stdout", stdout):
                    rc = cvedb.run(_make_args("path"))
                self.assertEqual(rc, exit_codes.CLEAN)
                output = stdout.getvalue().strip()
                self.assertIn("pydepgate", output)
                self.assertIn("cvedb", output)
                self.assertIn("pypi_osv.db", output)


class TestStatusAction(unittest.TestCase):
    def test_status_when_db_does_not_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                stderr = io.StringIO()
                with mock.patch.object(sys, "stderr", stderr):
                    rc = cvedb.run(_make_args("status"))
                self.assertEqual(rc, exit_codes.TOOL_ERROR)
                self.assertIn("not found", stderr.getvalue())
                self.assertIn("cvedb update", stderr.getvalue())

    def test_status_with_populated_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                db_path = Path(tmp) / "pydepgate" / "cvedb" / constants.CVE_DB_FILENAME
                db_path.parent.mkdir(parents=True, exist_ok=True)
                conn = schema.connect(db_path)
                try:
                    schema.initialize_schema(conn)
                    schema.write_metadata_dict(
                        conn,
                        {
                            schema.METADATA_KEY_RECORDS_IMPORTED: "20000",
                            schema.METADATA_KEY_LAST_FULL_UPDATE: "2026-05-14T12:00:00Z",
                            schema.METADATA_KEY_LAST_SNAPSHOT_SHA256: "abc123" * 10,
                            schema.METADATA_KEY_LAST_IMPORT_RUN_UUID: "11111111-2222-4333-8444-555555555555",
                            schema.METADATA_KEY_DATA_SOURCE_NAME: constants.OSV_DATA_SOURCE_NAME,
                            schema.METADATA_KEY_DATA_LICENSE: constants.OSV_DATA_LICENSE,
                        },
                    )
                    # Add a synthetic range row so the live count is nonzero
                    conn.execute(
                        "INSERT INTO vulnerabilities (canonical_id) VALUES (?)",
                        ("CVE-TEST",),
                    )
                    conn.execute(
                        "INSERT INTO affected_ranges "
                        "(canonical_id, package_name, range_type, "
                        "introduced, fixed, last_affected) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        ("CVE-TEST", "pkg", "ECOSYSTEM", "1.0", "2.0", ""),
                    )
                    conn.commit()
                finally:
                    conn.close()

                stdout = io.StringIO()
                with mock.patch.object(sys, "stdout", stdout):
                    rc = cvedb.run(_make_args("status"))
                self.assertEqual(rc, exit_codes.CLEAN)
                output = stdout.getvalue()
                self.assertIn("20000", output)
                self.assertIn("2026-05-14", output)
                self.assertIn("Open Source Vulnerability", output)
                self.assertIn("CC-BY 4.0", output)
                # v2 additions
                self.assertIn("Range rows:", output)
                self.assertIn("Last import run:", output)
                self.assertIn("11111111-2222-4333-8444-555555555555", output)


class TestUpdateAction(unittest.TestCase):
    def test_update_happy_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                source_zip = Path(tmp) / "source.zip"
                _make_test_zip(
                    source_zip,
                    [
                        ("PYSEC-2025-49.json", _setuptools_record()),
                    ],
                )

                def fake_download(
                    url, dest, *, head_info=None, progress_callback=None, **kw
                ):
                    import shutil

                    shutil.copy(source_zip, dest)
                    return _make_fetch_result(dest)

                head_info = _make_head_info(content_length=source_zip.stat().st_size)

                stderr = io.StringIO()
                with (
                    mock.patch.object(fetcher, "head_check", return_value=head_info),
                    mock.patch.object(fetcher, "download", side_effect=fake_download),
                    mock.patch.object(sys, "stderr", stderr),
                ):
                    rc = cvedb.run(_make_args("update", no_bar=True))

                self.assertEqual(rc, exit_codes.CLEAN)

                db_path = Path(tmp) / "pydepgate" / "cvedb" / constants.CVE_DB_FILENAME
                self.assertTrue(db_path.exists())

                zip_path = (
                    Path(tmp)
                    / "pydepgate"
                    / "cvedb"
                    / constants.CVE_DB_IMPORT_ZIP_FILENAME
                )
                self.assertFalse(zip_path.exists())

                conn = schema.connect(db_path)
                try:
                    source_name = schema.read_metadata(
                        conn, schema.METADATA_KEY_DATA_SOURCE_NAME
                    )
                    self.assertEqual(source_name, constants.OSV_DATA_SOURCE_NAME)
                    license_url = schema.read_metadata(
                        conn, schema.METADATA_KEY_DATA_LICENSE_URL
                    )
                    self.assertEqual(license_url, constants.OSV_DATA_LICENSE_URL)
                    snap_sha = schema.read_metadata(
                        conn, schema.METADATA_KEY_LAST_SNAPSHOT_SHA256
                    )
                    self.assertIsNotNone(snap_sha)
                    pyver = schema.read_metadata(
                        conn, schema.METADATA_KEY_PYDEPGATE_VERSION
                    )
                    self.assertIsNotNone(pyver)
                    # v2: run UUID was written by the importer
                    run_uuid = schema.read_metadata(
                        conn,
                        schema.METADATA_KEY_LAST_IMPORT_RUN_UUID,
                    )
                    self.assertIsNotNone(run_uuid)
                    self.assertEqual(len(run_uuid), 36)
                finally:
                    conn.close()

                output = stderr.getvalue()
                self.assertIn("CC-BY 4.0", output)
                self.assertIn("osv.dev", output)
                # v2 summary lines present
                self.assertIn("Exact version rows:", output)
                self.assertIn("Range rows:", output)
                self.assertIn("Total:", output)

    def test_update_summary_total_is_sum(self):
        """The Total line equals the sum of the four counter lines."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                source_zip = Path(tmp) / "source.zip"
                _make_test_zip(
                    source_zip,
                    [
                        ("PYSEC-2025-49.json", _setuptools_record()),
                    ],
                )

                def fake_download(
                    url, dest, *, head_info=None, progress_callback=None, **kw
                ):
                    import shutil

                    shutil.copy(source_zip, dest)
                    return _make_fetch_result(dest)

                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        fetcher,
                        "head_check",
                        return_value=_make_head_info(
                            content_length=source_zip.stat().st_size
                        ),
                    ),
                    mock.patch.object(fetcher, "download", side_effect=fake_download),
                    mock.patch.object(sys, "stderr", stderr),
                ):
                    cvedb.run(_make_args("update", no_bar=True))

                output = stderr.getvalue()

                def _extract(label):
                    for line in output.splitlines():
                        line = line.strip()
                        if line.startswith(label):
                            return int(line.split(":")[1].strip())
                    self.fail(f"line not found: {label}")

                exact = _extract("Exact version rows:")
                ranges = _extract("Range rows:")
                aliases = _extract("Aliases:")
                parse_errors = _extract("Parse errors:")
                total = _extract("Total:")

                self.assertEqual(total, exact + ranges + aliases + parse_errors)

    def test_update_head_check_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        fetcher,
                        "head_check",
                        side_effect=fetcher.HeadCheckError("server says no"),
                    ),
                    mock.patch.object(sys, "stderr", stderr),
                ):
                    rc = cvedb.run(_make_args("update"))

                self.assertEqual(rc, exit_codes.TOOL_ERROR)
                self.assertIn("HEAD check failed", stderr.getvalue())
                self.assertIn("server says no", stderr.getvalue())

                db_path = Path(tmp) / "pydepgate" / "cvedb" / constants.CVE_DB_FILENAME
                self.assertFalse(db_path.exists())

    def test_update_size_limit_exceeded(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        fetcher,
                        "head_check",
                        side_effect=fetcher.SizeLimitExceeded("advertised 999 GB"),
                    ),
                    mock.patch.object(sys, "stderr", stderr),
                ):
                    rc = cvedb.run(_make_args("update"))

                self.assertEqual(rc, exit_codes.TOOL_ERROR)
                self.assertIn("999 GB", stderr.getvalue())
                self.assertIn("size range", stderr.getvalue())

    def test_update_download_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        fetcher,
                        "head_check",
                        return_value=_make_head_info(),
                    ),
                    mock.patch.object(
                        fetcher,
                        "download",
                        side_effect=fetcher.DownloadError("connection lost"),
                    ),
                    mock.patch.object(sys, "stderr", stderr),
                ):
                    rc = cvedb.run(_make_args("update"))

                self.assertEqual(rc, exit_codes.TOOL_ERROR)
                self.assertIn("download failed", stderr.getvalue())
                self.assertIn("connection lost", stderr.getvalue())

    def test_update_existing_db_preserved_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": tmp},
                clear=False,
            ):
                source_zip = Path(tmp) / "source.zip"
                _make_test_zip(
                    source_zip,
                    [
                        ("PYSEC-2025-49.json", _setuptools_record()),
                    ],
                )

                def fake_download_ok(url, dest, **kw):
                    import shutil

                    shutil.copy(source_zip, dest)
                    return _make_fetch_result(dest)

                with (
                    mock.patch.object(
                        fetcher,
                        "head_check",
                        return_value=_make_head_info(
                            content_length=source_zip.stat().st_size
                        ),
                    ),
                    mock.patch.object(
                        fetcher, "download", side_effect=fake_download_ok
                    ),
                    mock.patch.object(sys, "stderr", io.StringIO()),
                ):
                    rc = cvedb.run(_make_args("update", no_bar=True))

                self.assertEqual(rc, exit_codes.CLEAN)
                db_path = Path(tmp) / "pydepgate" / "cvedb" / constants.CVE_DB_FILENAME
                self.assertTrue(db_path.exists())
                first_size = db_path.stat().st_size

                bad_zip = Path(tmp) / "bad.zip"
                bad_zip.write_bytes(b"this is not a zip")

                def fake_download_bad(url, dest, **kw):
                    import shutil

                    shutil.copy(bad_zip, dest)
                    return _make_fetch_result(dest)

                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        fetcher,
                        "head_check",
                        return_value=_make_head_info(
                            content_length=bad_zip.stat().st_size
                        ),
                    ),
                    mock.patch.object(
                        fetcher, "download", side_effect=fake_download_bad
                    ),
                    mock.patch.object(sys, "stderr", stderr),
                ):
                    rc = cvedb.run(_make_args("update", no_bar=True))

                self.assertEqual(rc, exit_codes.TOOL_ERROR)
                self.assertTrue(db_path.exists())
                self.assertEqual(db_path.stat().st_size, first_size)


class TestDispatchDefensive(unittest.TestCase):
    def test_run_with_unknown_action_returns_tool_error(self):
        args = argparse.Namespace(action="bogus", no_bar=True)
        stderr = io.StringIO()
        with mock.patch.object(sys, "stderr", stderr):
            rc = cvedb.run(args)
        self.assertEqual(rc, exit_codes.TOOL_ERROR)
        self.assertIn("unknown cvedb action", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
