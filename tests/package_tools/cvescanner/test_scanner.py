"""tests.package_tools.cvescanner.test_scanner

Unit tests for package_tools.cvescanner.scanner.

The scanner tests build tiny cvedb SQLite fixtures directly through the
schema helpers. They do not download OSV data and they do not run the
file-content static scanner.
"""

from __future__ import annotations

import pickle
import tempfile
import unittest
import zipfile
from dataclasses import dataclass
from pathlib import Path

from pydepgate.package_tools import metadata as package_metadata
from pydepgate.package_tools.cvedb import constants
from pydepgate.package_tools.cvedb import importer
from pydepgate.package_tools.cvedb import lookup
from pydepgate.package_tools.cvedb import schema
from pydepgate.package_tools.cvescanner import scanner


@dataclass(frozen=True)
class FakeAppliedPolicyResult:
    """Small stand-in for the future AppliedPolicyResult type."""

    policy_name: str
    mode: str


class CveScannerTests(unittest.TestCase):
    """Tests for scanner result shaping and policy ingestion."""

    def test_scan_identity_returns_exact_match_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cvedb.sqlite"
            _build_db(
                db_path,
                vulnerabilities=(
                    _vulnerability_row(
                        canonical_id="CVE-2026-0001",
                        summary="bad example",
                        severity="high",
                    ),
                ),
                aliases=(
                    ("CVE-2026-0001", "CVE-2026-0001", "CVE"),
                    ("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", "GHSA"),
                ),
                affected_versions=(("CVE-2026-0001", "Example_Pkg", "1.0.0"),),
            )

            result = scanner.scan_identity(
                "example-pkg",
                "1.0.0",
                db_path=db_path,
            )

        self.assertTrue(result.has_findings)
        self.assertFalse(result.has_unevaluated_ranges)
        self.assertEqual(result.package_name, "example-pkg")
        self.assertEqual(result.normalized_package_name, "example-pkg")
        self.assertEqual(result.package_version, "1.0.0")
        self.assertEqual(result.database_path, db_path)
        self.assertEqual(result.attribution, constants.OSV_DATA_ATTRIBUTION_LINE)
        self.assertEqual(len(result.findings), 1)

        finding = result.findings[0]
        self.assertEqual(finding.canonical_id, "CVE-2026-0001")
        self.assertEqual(
            finding.aliases,
            ("CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"),
        )
        self.assertEqual(finding.database_package_name, "Example_Pkg")
        self.assertEqual(finding.database_version, "1.0.0")
        self.assertEqual(finding.match_type, lookup.MATCH_TYPE_EXACT_VERSION)
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.raw_severity, "high")
        self.assertTrue(finding.versions_complete)

    def test_scan_identity_returns_range_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cvedb.sqlite"
            _build_db(
                db_path,
                vulnerabilities=(_vulnerability_row(canonical_id="CVE-2026-0002"),),
                aliases=(("CVE-2026-0002", "CVE-2026-0002", "CVE"),),
                affected_ranges=(
                    (
                        "CVE-2026-0002",
                        "range-demo",
                        lookup.RANGE_TYPE_ECOSYSTEM,
                        "1.0.0",
                        "2.0.0",
                        "",
                    ),
                ),
            )

            result = scanner.scan_identity(
                "range-demo",
                "1.5.0",
                db_path=db_path,
            )

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.match_type, lookup.MATCH_TYPE_RANGE_FIXED)
        self.assertEqual(finding.range_type, lookup.RANGE_TYPE_ECOSYSTEM)
        self.assertEqual(finding.introduced, "1.0.0")
        self.assertEqual(finding.fixed, "2.0.0")
        self.assertEqual(finding.database_version, "")

    def test_scan_identity_preserves_unevaluated_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cvedb.sqlite"
            _build_db(
                db_path,
                vulnerabilities=(_vulnerability_row(canonical_id="CVE-2026-0003"),),
                aliases=(("CVE-2026-0003", "CVE-2026-0003", "CVE"),),
                affected_ranges=(
                    (
                        "CVE-2026-0003",
                        "git-range-demo",
                        "GIT",
                        "0",
                        "b5d1b965ead7d9f777a3216369b5baf23ec08999",
                        "",
                    ),
                ),
            )

            result = scanner.scan_identity(
                "git-range-demo",
                "1.0.0",
                db_path=db_path,
            )

        self.assertFalse(result.has_findings)
        self.assertTrue(result.has_unevaluated_ranges)
        self.assertIn(lookup.WARNING_RANGE_ROWS_UNEVALUATED, result.warnings)
        self.assertIn(scanner.WARNING_CVE_RANGES_UNEVALUATED, result.warnings)
        self.assertEqual(len(result.unevaluated_ranges), 1)
        note = result.unevaluated_ranges[0]
        self.assertEqual(note.canonical_id, "CVE-2026-0003")
        self.assertEqual(note.range_type, "GIT")
        self.assertEqual(
            note.reason,
            lookup.UNEVALUATED_REASON_UNSUPPORTED_RANGE_TYPE,
        )

    def test_scan_metadata_preserves_metadata_warnings(self) -> None:
        meta = _metadata(
            name="warning-demo",
            version=None,
            warnings=("wheel filename 'bad.whl' could not be parsed",),
        )

        result = scanner.scan_metadata(meta, db_path=Path("missing.sqlite"))

        self.assertFalse(result.has_findings)
        self.assertEqual(result.package_metadata, meta)
        self.assertEqual(result.package_name, "warning-demo")
        self.assertIsNone(result.package_version)
        self.assertIn("wheel filename 'bad.whl' could not be parsed", result.warnings)
        self.assertIn(scanner.WARNING_MISSING_PACKAGE_VERSION, result.warnings)

    def test_scan_artifact_reads_wheel_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            db_path = root / "cvedb.sqlite"
            wheel_path = root / "artifact_demo-1.0.0-py3-none-any.whl"
            _write_wheel(
                wheel_path,
                name="artifact-demo",
                version="1.0.0",
            )
            _build_db(
                db_path,
                vulnerabilities=(_vulnerability_row(canonical_id="CVE-2026-0004"),),
                aliases=(("CVE-2026-0004", "CVE-2026-0004", "CVE"),),
                affected_versions=(("CVE-2026-0004", "artifact-demo", "1.0.0"),),
            )

            result = scanner.scan_artifact(wheel_path, db_path=db_path)

        self.assertEqual(result.package_name, "artifact-demo")
        self.assertEqual(result.package_version, "1.0.0")
        self.assertIsNotNone(result.package_metadata)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].canonical_id, "CVE-2026-0004")

    def test_missing_database_is_warning_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "missing.sqlite"
            result = scanner.scan_identity(
                "example",
                "1.0.0",
                db_path=db_path,
            )

        self.assertFalse(result.has_findings)
        self.assertTrue(result.has_warnings)
        self.assertTrue(
            any(
                warning.startswith(scanner.WARNING_CVE_DATABASE_NOT_FOUND)
                for warning in result.warnings
            )
        )

    def test_missing_database_can_be_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "missing.sqlite"
            with self.assertRaises(lookup.CveDatabaseNotFound):
                scanner.scan_identity(
                    "example",
                    "1.0.0",
                    db_path=db_path,
                    require_database=True,
                )

    def test_applied_policy_result_is_preserved(self) -> None:
        policy = FakeAppliedPolicyResult(policy_name="quick", mode="audit")

        result = scanner.scan_identity(
            None,
            "1.0.0",
            db_path=Path("missing.sqlite"),
            applied_policy_result=policy,
        )

        self.assertIs(result.applied_policy_result, policy)
        self.assertIn(scanner.WARNING_MISSING_PACKAGE_NAME, result.warnings)

    def test_severity_unknown_for_empty_or_zero_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cvedb.sqlite"
            _build_db(
                db_path,
                vulnerabilities=(
                    _vulnerability_row(
                        canonical_id="MAL-2026-0005",
                        severity="0",
                    ),
                ),
                aliases=(("MAL-2026-0005", "MAL-2026-0005", "MAL"),),
                affected_versions=(
                    ("MAL-2026-0005", "mal-demo", importer.ALL_VERSIONS_SENTINEL),
                ),
            )

            result = scanner.scan_identity("mal-demo", "9.9.9", db_path=db_path)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, scanner.SEVERITY_UNKNOWN)
        self.assertEqual(result.findings[0].raw_severity, "0")
        self.assertEqual(result.findings[0].match_type, lookup.MATCH_TYPE_ALL_VERSIONS)

    def test_result_is_pickle_safe_when_policy_is_pickle_safe(self) -> None:
        policy = FakeAppliedPolicyResult(policy_name="medium", mode="enforce")
        result = scanner.scan_identity(
            None,
            None,
            applied_policy_result=policy,
        )

        restored = pickle.loads(pickle.dumps(result))

        self.assertEqual(restored.package_name, result.package_name)
        self.assertEqual(restored.warnings, result.warnings)
        self.assertEqual(restored.applied_policy_result, policy)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _build_db(
    path: Path,
    *,
    vulnerabilities: tuple[tuple, ...] = (),
    aliases: tuple[tuple, ...] = (),
    affected_versions: tuple[tuple, ...] = (),
    affected_ranges: tuple[tuple, ...] = (),
) -> None:
    """Create a tiny cvedb fixture."""
    conn = schema.connect(path)
    try:
        with conn:
            schema.initialize_schema(conn)
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_DATA_SOURCE_NAME,
                constants.OSV_DATA_SOURCE_NAME,
            )
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_DATA_SOURCE_URL,
                constants.OSV_DATA_SOURCE_URL,
            )
            schema.write_metadata(
                conn,
                schema.METADATA_KEY_DATA_LICENSE,
                constants.OSV_DATA_LICENSE,
            )
            conn.executemany(
                "INSERT INTO vulnerabilities "
                "(canonical_id, summary, details, published, modified, "
                "cvss_v3, cvss_v4, severity, versions_complete) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vulnerabilities,
            )
            conn.executemany(
                "INSERT INTO aliases (alias, canonical_id, alias_type) "
                "VALUES (?, ?, ?)",
                aliases,
            )
            conn.executemany(
                "INSERT INTO affected_versions "
                "(canonical_id, package_name, version) "
                "VALUES (?, ?, ?)",
                affected_versions,
            )
            conn.executemany(
                "INSERT INTO affected_ranges "
                "(canonical_id, package_name, range_type, introduced, fixed, "
                "last_affected) VALUES (?, ?, ?, ?, ?, ?)",
                affected_ranges,
            )
    finally:
        conn.close()


def _vulnerability_row(
    *,
    canonical_id: str,
    summary: str = "summary",
    details: str = "details",
    published: str = "2026-01-01T00:00:00Z",
    modified: str = "2026-01-02T00:00:00Z",
    cvss_v3: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvss_v4: str = "",
    severity: str = "MODERATE",
    versions_complete: int = 1,
) -> tuple:
    """Return a vulnerabilities table row."""
    return (
        canonical_id,
        summary,
        details,
        published,
        modified,
        cvss_v3,
        cvss_v4,
        severity,
        versions_complete,
    )


def _metadata(
    *,
    name: str | None,
    version: str | None,
    warnings: tuple[str, ...] = (),
) -> package_metadata.PackageMetadata:
    """Build a PackageMetadata fixture."""
    normalized = package_metadata.normalize_package_name(name) if name else None
    return package_metadata.PackageMetadata(
        artifact_type="wheel",
        artifact_path=Path("fixture.whl"),
        name=name,
        normalized_name=normalized,
        version=version,
        identity_source=package_metadata.IDENTITY_SOURCE_CORE_METADATA,
        metadata_name=name,
        metadata_version=version,
        filename_name=name,
        filename_version=version,
        dist_info_dir="fixture-1.0.0.dist-info",
        metadata_path="fixture-1.0.0.dist-info/METADATA",
        wheel_metadata_path="fixture-1.0.0.dist-info/WHEEL",
        wheel_version="1.0",
        wheel_generator="test",
        root_is_purelib=True,
        wheel_tags=("py3-none-any",),
        requires_python=None,
        requires_dist=(),
        provides_extra=(),
        project_urls=(),
        summary=None,
        direct_url=None,
        warnings=warnings,
    )


def _write_wheel(path: Path, *, name: str, version: str) -> None:
    """Write a tiny wheel metadata fixture."""
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n",
        )
        zf.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
            "Tag: py3-none-any\n",
        )
        zf.writestr(f"{dist_info}/RECORD", "")


if __name__ == "__main__":
    unittest.main()
