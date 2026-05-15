"""pydepgate.package_tools.cvedb.constants

URLs, filenames, and attribution strings for the OSV PyPI
vulnerability dataset.

This module holds values that are static across runs but
specific to the OSV source. Keeping them in one place means a
future change to an OSV URL or to the attribution requirement
is a single-file edit, and the cvedb subsystem's coupling to
OSV is explicit rather than scattered across modules.

Attribution: the OSV dataset is licensed under CC-BY 4.0. The
importer writes the values below into the cvedb SQLite
db_metadata table at import time, and the depscan reporter
surfaces OSV_DATA_ATTRIBUTION_LINE in report footers when CVE
findings are present in the output.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Source URLs
# ---------------------------------------------------------------------------

# Full PyPI advisory snapshot. One JSON file per OSV record,
# zipped. Today's size is around 90MB, around 20,000 entries.
OSV_PYPI_ALL_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"

# Lightweight feed of (id, modified_timestamp) pairs. Used to
# detect changes between full snapshots. Today's size is well
# under 5MB.
OSV_PYPI_MODIFIED_ID_CSV_URL = (
    "https://osv-vulnerabilities.storage.googleapis.com/PyPI/modified_id.csv"
)


# ---------------------------------------------------------------------------
# Content-type and size expectations for HEAD validation
# ---------------------------------------------------------------------------

# The all.zip object is served as one of these. GCS chooses the
# specific value based on the object's content-type metadata,
# which can drift; accepting both removes a brittle dependency
# on GCS configuration.
OSV_PYPI_ALL_ZIP_ACCEPTED_CONTENT_TYPES: tuple[str, ...] = (
    "application/zip",
    "application/octet-stream",
)

# The modified_id.csv is served as text/csv, text/plain, or
# application/octet-stream depending on object metadata. All
# three are acceptable for a feed file.
OSV_PYPI_MODIFIED_ID_CSV_ACCEPTED_CONTENT_TYPES: tuple[str, ...] = (
    "text/csv",
    "text/plain",
    "application/octet-stream",
)

# Size sanity bounds for the modified_id.csv. Today's value is
# well under 5MB; these bounds give multiple-x headroom in
# either direction without leaving the door open for a runaway
# server response.
OSV_PYPI_MODIFIED_ID_CSV_MIN_SIZE = 10 * 1024
OSV_PYPI_MODIFIED_ID_CSV_MAX_SIZE = 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# Cache filenames
# ---------------------------------------------------------------------------

# The on-disk SQLite database. Lives at
# {pydepgate_cache_dir()}/cvedb/{CVE_DB_FILENAME}.
CVE_DB_FILENAME = "pypi_osv.db"

# The downloaded zip lives at this filename within the cvedb
# cache directory only for the duration of an import. After the
# DB is built successfully, the zip is removed and its SHA256 is
# recorded in db_metadata as the "last imported snapshot"
# fingerprint so a subsequent update knows what version of the
# upstream data the DB reflects.
CVE_DB_IMPORT_ZIP_FILENAME = "pypi_osv_import.zip"


# ---------------------------------------------------------------------------
# Schema and provenance
# ---------------------------------------------------------------------------

# Bumped when the cvedb table layout changes incompatibly. The
# importer compares this value against db_metadata.schema_version
# and refuses to operate on a database written by a different
# schema generation. A future migration system can use this as
# the source-of-truth target version.
CVE_DB_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Attribution (CC-BY 4.0 compliance)
# ---------------------------------------------------------------------------

OSV_DATA_SOURCE_NAME = "Open Source Vulnerability (OSV) Database"
OSV_DATA_SOURCE_URL = "https://osv.dev"
OSV_DATA_LICENSE = "CC-BY 4.0"
OSV_DATA_LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"

# One-line attribution for report footers. Kept short because it
# appears below the findings list when CVE findings are present.
# The full source name, source URL, and license URL are
# accessible via the cvedb db_metadata table and (in future) the
# `pydepgate cvedb status` subcommand.
OSV_DATA_ATTRIBUTION_LINE = (
    f"Vulnerability data: {OSV_DATA_SOURCE_NAME} "
    f"({OSV_DATA_SOURCE_URL}), {OSV_DATA_LICENSE}."
)
