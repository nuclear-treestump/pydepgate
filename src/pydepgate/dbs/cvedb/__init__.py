"""pydepgate.dbs.cvedb.__init__

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

  lookup     Storage-level query API. Looks up a package name and
             version against exact affected_versions rows, the ALL
             sentinel, and ECOSYSTEM affected_ranges rows that can be
             evaluated safely.

Public calls:

    lookup_package(conn, package_name, version)
        Query an already-open sqlite3.Connection.

    lookup_package_in_db(db_path, package_name, version)
        Open a cvedb SQLite file, query one package identity, and
        close the connection.

Private helpers:

  _pepver    Small stdlib-only PEP 440 helper used by lookup.py for
             affected_ranges checks. This is intentionally private to
             cvedb and should not be treated as a general packaging API.

The attribution requirement for OSV data (CC-BY 4.0) is handled at
two layers: the importer and cvedb CLI write db_metadata rows with
source URL, license, and attribution context; consumers print an
attribution footer when CVE findings are present in user-visible
output.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydepgate.dbs.cvedb.lookup import LookupResult


__all__ = (
    "lookup_package",
    "lookup_package_in_db",
)


def lookup_package(
    conn: sqlite3.Connection,
    package_name: str,
    version: str,
) -> "LookupResult":
    """Query an open cvedb connection for one package identity.

    This is the package-level public shim for lookup.lookup_package.
    Keeping the shim here gives callers one stable cvedb entrypoint
    without moving storage logic into __init__.py.
    """
    from pydepgate.dbs.cvedb import lookup

    return lookup.lookup_package(conn, package_name, version)


def lookup_package_in_db(
    db_path: str | Path,
    package_name: str,
    version: str,
) -> "LookupResult":
    """Open a cvedb SQLite file and query one package identity.

    This is the package-level public shim for
    lookup.lookup_package_in_db. Exceptions are raised by lookup.py so
    callers can continue importing the detailed exception hierarchy from
    pydepgate.package_tools.cvedb.lookup when they need it.
    """
    from pydepgate.dbs.cvedb import lookup

    return lookup.lookup_package_in_db(db_path, package_name, version)
