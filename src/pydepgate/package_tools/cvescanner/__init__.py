"""pydepgate.package_tools.cvescanner.__init__

Artifact-level CVE scanning for package identities.

The cvescanner package consumes package metadata, queries the local
cvedb subsystem, and returns frozen result records for callers that
need CVE data without running the file-content static scanner.

Public calls:

    scan_artifact(path, *, db_path=None, applied_policy_result=None)
        Read package metadata from an artifact and scan the resolved
        package identity against cvedb.

    scan_metadata(metadata, *, db_path=None, applied_policy_result=None)
        Scan an already extracted PackageMetadata object.

    scan_identity(package_name, version, *, db_path=None,
                  applied_policy_result=None)
        Scan a raw package identity. This is useful for tests and for
        future callers that already have resolved package facts.

Public records:

    CveFinding
        One definite vulnerability match returned by cvedb lookup and
        shaped for scanner consumers.

    CveUnevaluatedRange
        Advisory range evidence that could not be compared to the
        queried package version safely.

    CveScanResult
        Full scanner result, including package identity, findings,
        warnings, attribution, database path, and an optional applied
        policy result for future policy-aware scanning.
"""

from __future__ import annotations

from pydepgate.package_tools.cvescanner.scanner import CveFinding
from pydepgate.package_tools.cvescanner.scanner import CveScanResult
from pydepgate.package_tools.cvescanner.scanner import CveUnevaluatedRange
from pydepgate.package_tools.cvescanner.scanner import scan_artifact
from pydepgate.package_tools.cvescanner.scanner import scan_identity
from pydepgate.package_tools.cvescanner.scanner import scan_metadata

__all__ = (
    "CveFinding",
    "CveScanResult",
    "CveUnevaluatedRange",
    "scan_artifact",
    "scan_identity",
    "scan_metadata",
)
