"""pydepgate.package_tools.__init__

Subsystems that operate on Python packages as units of work rather
than on files inside packages. Static analyzers and enrichers under
pydepgate/analyzers and pydepgate/enrichers operate on file content;
the modules here operate on package identity, package metadata,
published vulnerabilities, and future artifact-level policy.

Currently houses:

  metadata      Artifact-level package identity and metadata
                extraction. Wheels are the first supported artifact
                type.

  cvedb/        OSV PyPI vulnerability database import, storage, and
                lookup.

  cvescanner/   Artifact-level CVE scanner. Consumes metadata and
                cvedb lookup results, and returns scanner-shaped
                package vulnerability findings.

A shared base class for package_tools should land only after the
scanner and future package-level tools prove the common contract. The
current split keeps file scanning, metadata extraction, cvedb storage,
and CVE scan policy in separate modules.
"""
