"""pydepgate.package_tools.cvedb.__init__

CVE database subsystem: import, storage, and lookup of OSV PyPI
vulnerability data.

Public modules:

  fetcher    HTTP layer. HEAD check and streaming download of the
             OSV PyPI all.zip and modified_id.csv resources.
             Stdlib-only. Picklable result types.

Future modules (not in this delivery):

  schema     SQLite DDL and migration logic for the CVE cache DB.
  importer   Zip extraction, JSON parsing, dedup, and DB load.
  lookup     Query API used by the depscan CVE pass.
  constants  OSV URLs and resource naming conventions.

The attribution requirement for OSV data (CC-BY 4.0) is handled at
two layers: the importer writes a db_metadata table with source
URL, license, and attribution string; the depscan reporter prints
an attribution footer when CVE findings are present in the output.
"""
