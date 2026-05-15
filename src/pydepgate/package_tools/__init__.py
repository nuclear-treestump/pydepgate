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
"""
