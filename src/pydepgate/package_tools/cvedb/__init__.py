"""pydepgate.package_tools.cvedb.__init__

CVE database subsystem: import, storage, and lookup of OSV PyPI
vulnerability data.

Public modules:

  constants  OSV URLs, cache filenames, schema version, and
             attribution strings.

  fetcher    HTTP layer. HEAD checks and streaming downloads of the
             OSV PyPI all.zip and modified_id.csv resources.
             Stdlib-only. Pickle-safe result types.

  schema     SQLite DDL, connection helpers, metadata helpers, and
             schema-version verification.

  importer   OSV PyPI snapshot ingestion. Reads a downloaded snapshot,
             parses records, deduplicates aliases, and writes the
             local cvedb SQLite cache.

  lookup     Query API used by the future cvescan pass. Looks up a
             package name and version against affected_versions rows,
             surfaces ALL-sentinel matches, and reports affected_ranges
             rows as unevaluated hints.

The attribution requirement for OSV data (CC-BY 4.0) is handled at
two layers: the importer and cvedb CLI write db_metadata rows with
source URL, license, and attribution context; consumers print an
attribution footer when CVE findings are present in user-visible
output.
"""
