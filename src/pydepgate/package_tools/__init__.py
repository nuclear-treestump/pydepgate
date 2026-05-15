"""pydepgate.package_tools.__init__

Subsystems that operate on Python packages as units of work rather
than on files inside packages. Static analyzers and enrichers under
pydepgate/analyzers and pydepgate/enrichers operate on file content;
the modules here operate on package identity (name, version, declared
dependencies, published vulnerabilities).

Currently houses:

  cvedb/    OSV PyPI vulnerability database import, storage, and
            lookup. Backs the depscan CVE pass that lands in
            v0.6.0.

A shared base class for package_tools lands when the second
subsystem exists; until then the surface is too small to abstract
without guessing at requirements.

Base expectation would be a PackageTool class that intakes a
Metadata or PackageInfo object and produces a Finding object.
This DOES mean I will have to implement both V2, V3, and V4 of
CVSS math in the CVE pass, but that's a problem for future me.

TODO: Add a base class for package tools, and refactor cvedb to use it.

"""
