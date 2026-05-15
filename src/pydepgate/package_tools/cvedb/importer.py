"""pydepgate.package_tools.cvedb.importer

OSV PyPI snapshot importer.

Pipeline:
  1. Validate the downloaded zip (decompressed size caps).
  2. Read JSON entries from the zip (sequential; ZipFile is not
     thread-safe).
  3. Parse each entry in a thread pool. Each record yields a
     ParsedRecord or a ParseFailure.
  4. Merge ParsedRecords by canonical ID. Multi-record CVEs
     (CVE + GHSA + PYSEC for the same vulnerability) union
     their data.
  5. Drop and recreate the cvedb tables inside one BEGIN
     IMMEDIATE transaction. Batched executemany writes follow,
     then provenance metadata, then commit.

The importer is responsible only for ingesting OSV data. CC-BY
4.0 attribution constants are written by the CLI's update path,
not here, so the importer stays decoupled from licensing.
"""

from __future__ import annotations

import concurrent.futures
import json
import sqlite3
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from pydepgate.package_tools.cvedb import schema
from pydepgate import run_context

ProgressCallback = Callable[[int, int], None]
FinishCallback = Callable[[], None]


# ---------------------------------------------------------------------------
# Constants and tuning
# ---------------------------------------------------------------------------

DEFAULT_MAX_DECOMPRESSED_BYTES = 500 * 1024 * 1024
DEFAULT_MAX_PER_FILE_BYTES = 1 * 1024 * 1024
DEFAULT_MAX_WORKERS = 8

# Batch size for executemany during the write phase. Calibrated
# to balance progress-bar refresh granularity against per-batch
# overhead. With ~560k rows total and 1000 per batch, the bar
# updates ~560 times during write.
_WRITE_BATCH_SIZE = 1000

_KNOWN_ALIAS_PREFIXES: tuple[tuple[str, str], ...] = (
    ("CVE-", "CVE"),
    ("GHSA-", "GHSA"),
    ("PYSEC-", "PYSEC"),
    ("OSV-", "OSV"),
    ("BIT-", "BIT"),
    ("GO-", "GO"),
    ("DSA-", "DSA"),
    ("USN-", "USN"),
    ("RUSTSEC-", "RUSTSEC"),
    ("MAL-", "MAL"),
)

_CANONICAL_PRIORITY: tuple[str, ...] = ("CVE", "GHSA", "PYSEC")

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "MODERATE": 2,
    "LOW": 1,
    "INFO": 0,
}

PYPI_ECOSYSTEM = "PyPI"

# The sentinel version string written to affected_versions when
# a CVE applies to every version of a package. Queries can use
# `WHERE version = ? OR version = 'ALL'` to handle both exact-
# match and universal-coverage CVEs in one pass.
ALL_VERSIONS_SENTINEL = "ALL"

WARNING_NO_AFFECTED = "no_affected"
WARNING_NO_PYPI_AFFECTED = "no_pypi_affected"
WARNING_PARSE_ERROR = "parse_error"
WARNING_MISSING_ID = "missing_id"
WARNING_MALFORMED_RECORD = "malformed_record"
WARNING_NO_USABLE_DATA = "no_usable_data"


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class CvedbImportError(Exception):
    pass


class ZipValidationError(CvedbImportError):
    pass


class ImportFailedError(CvedbImportError):
    pass


# ---------------------------------------------------------------------------
# Progress callbacks bundle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProgressCallbacks:
    """Bundle of update + finish callbacks for the importer's three phases.

    Each phase has an update callback (called as work progresses)
    and a finish callback (called once when the phase completes).
    The finish callback writes a newline so the next phase's bar
    starts on a fresh line; without it, the next phase's update
    would overwrite the previous phase's line via the carriage-
    return prefix.

    Any field may be None to suppress that phase's bar. The CLI
    typically supplies all six; tests typically supply none.
    """

    read_update: ProgressCallback | None = None
    read_finish: FinishCallback | None = None
    parse_update: ProgressCallback | None = None
    parse_finish: FinishCallback | None = None
    write_update: ProgressCallback | None = None
    write_finish: FinishCallback | None = None


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImportResult:
    """Summary of a successful import."""

    records_imported: int
    records_with_parse_errors: int
    records_with_no_usable_data: int
    affected_version_rows: int
    affected_range_rows: int
    alias_rows: int
    elapsed_seconds: float


@dataclass(frozen=True)
class ParsedRecord:
    """One OSV record reduced to the fields the importer needs."""

    osv_id: str
    canonical_id: str
    canonical_id_type: str
    all_identifiers: tuple[tuple[str, str], ...]
    summary: str | None
    details: str | None
    published: str | None
    modified: str | None
    cvss_v3: str | None
    cvss_v4: str | None
    severity: str | None
    affected: tuple[tuple[str, str], ...]
    ranges: tuple[tuple[str, str, str, str, str], ...]
    all_versions_packages: tuple[str, ...]
    has_explicit_versions: bool


@dataclass(frozen=True)
class ParseFailure:
    filename: str
    osv_id: str | None
    reason: str
    detail: str


@dataclass
class MergedVulnerability:
    canonical_id: str
    summary: str | None = None
    details: str | None = None
    published: str | None = None
    modified: str | None = None
    cvss_v3: str | None = None
    cvss_v4: str | None = None
    severity: str | None = None
    has_explicit_versions: bool = False
    identifiers: set[tuple[str, str]] = field(default_factory=set)
    affected: set[tuple[str, str]] = field(default_factory=set)
    ranges: set[tuple[str, str, str, str, str]] = field(default_factory=set)
    all_versions_packages: set[str] = field(default_factory=set)

    def merge(self, record: ParsedRecord) -> None:
        if self.summary is None and record.summary:
            self.summary = record.summary
        if self.details is None and record.details:
            self.details = record.details
        if record.published:
            if self.published is None or record.published < self.published:
                self.published = record.published
        if record.modified:
            if self.modified is None or record.modified > self.modified:
                self.modified = record.modified
        if self.cvss_v3 is None and record.cvss_v3:
            self.cvss_v3 = record.cvss_v3
        if self.cvss_v4 is None and record.cvss_v4:
            self.cvss_v4 = record.cvss_v4
        if record.severity:
            current_rank = _SEVERITY_RANK.get((self.severity or "").upper(), -1)
            new_rank = _SEVERITY_RANK.get(record.severity.upper(), -1)
            if new_rank > current_rank:
                self.severity = record.severity
        if record.has_explicit_versions:
            self.has_explicit_versions = True
        for ident, alias_type in record.all_identifiers:
            self.identifiers.add((ident, alias_type))
        self.identifiers.add((self.canonical_id, _alias_type_for(self.canonical_id)))
        for entry in record.affected:
            self.affected.add(entry)
        for range_entry in record.ranges:
            self.ranges.add(range_entry)
        for pkg in record.all_versions_packages:
            self.all_versions_packages.add(pkg)


# ---------------------------------------------------------------------------
# Canonical ID and alias-type helpers
# ---------------------------------------------------------------------------


def _alias_type_for(identifier: str) -> str:
    for prefix, label in _KNOWN_ALIAS_PREFIXES:
        if identifier.startswith(prefix):
            return label
    return "OTHER"


def _derive_canonical_id(
    osv_id: str,
    aliases: Iterable[str],
) -> tuple[str, str]:
    candidates = [osv_id, *aliases]
    by_type: dict[str, list[str]] = {}
    for ident in candidates:
        atype = _alias_type_for(ident)
        by_type.setdefault(atype, []).append(ident)
    for preferred in _CANONICAL_PRIORITY:
        if preferred in by_type and by_type[preferred]:
            best = sorted(by_type[preferred])[0]
            return best, preferred
    return osv_id, _alias_type_for(osv_id)


# ---------------------------------------------------------------------------
# Range parsing helpers
# ---------------------------------------------------------------------------


def _parse_ranges_for_package(
    ranges_field: list,
) -> tuple[list[tuple[str, str, str, str]], bool]:
    """Walk the OSV ranges array as an events state machine.

    Returns (parsed_ranges, has_all):
      parsed_ranges is a list of (range_type, introduced, fixed,
      last_affected) tuples. fixed and last_affected are "" when
      not present in the source.

      has_all is True if any range qualifies as "every version
      affected" via the structural rule: an introduced=0 event
      with no fixed and no last_affected closing it.

    The OSV events list is a state machine:
      - "introduced" opens a new range with the given lower bound
      - "fixed" closes the current range with that upper bound
      - "last_affected" closes the current range inclusively
      - A trailing introduced with no closer is an open-ended
        range from that version onward
    """
    parsed: list[tuple[str, str, str, str]] = []
    has_all = False

    for range_entry in ranges_field:
        if not isinstance(range_entry, dict):
            continue
        range_type = range_entry.get("type", "ECOSYSTEM")
        if not isinstance(range_type, str) or not range_type:
            continue
        events = range_entry.get("events", [])
        if not isinstance(events, list):
            continue

        # State machine state: the introduced value awaiting its
        # closer (None means we're between ranges)
        current_introduced: str | None = None

        for event in events:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                val = event["introduced"]
                if not isinstance(val, str) or not val:
                    continue
                if current_introduced is not None:
                    # Previous introduced had no closer; emit it
                    # as open-ended before starting the new range.
                    parsed.append((range_type, current_introduced, "", ""))
                    if current_introduced == "0":
                        has_all = True
                current_introduced = val
            elif "fixed" in event:
                val = event["fixed"]
                if not isinstance(val, str) or not val:
                    continue
                if current_introduced is not None:
                    parsed.append((range_type, current_introduced, val, ""))
                    current_introduced = None
                # else: fixed without introduced is malformed; skip
            elif "last_affected" in event:
                val = event["last_affected"]
                if not isinstance(val, str) or not val:
                    continue
                if current_introduced is not None:
                    parsed.append((range_type, current_introduced, "", val))
                    current_introduced = None
                # else: last_affected without introduced is malformed

        # Tail: any introduced still awaiting a closer at end-of-
        # events is an open-ended range from that version onward.
        if current_introduced is not None:
            parsed.append((range_type, current_introduced, "", ""))
            if current_introduced == "0":
                has_all = True

    return parsed, has_all


# ---------------------------------------------------------------------------
# Zip validation and reading
# ---------------------------------------------------------------------------


def _validate_zip(
    zip_path: Path,
    *,
    max_decompressed_bytes: int,
    max_per_file_bytes: int,
) -> list[zipfile.ZipInfo]:
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infolist = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise ZipValidationError(f"not a valid zip file: {exc}") from exc

    total = 0
    for info in infolist:
        if info.file_size > max_per_file_bytes:
            raise ZipValidationError(
                f"entry {info.filename!r} decompresses to "
                f"{info.file_size} bytes, exceeds per-file limit "
                f"of {max_per_file_bytes}"
            )
        total += info.file_size
    if total > max_decompressed_bytes:
        raise ZipValidationError(
            f"zip would decompress to {total} bytes, exceeds "
            f"limit of {max_decompressed_bytes}"
        )
    return infolist


def _read_json_entries(
    zip_path: Path,
    infolist: list[zipfile.ZipInfo],
    progress_callback: ProgressCallback | None = None,
) -> list[tuple[str, bytes]]:
    """Read every JSON entry's decompressed bytes from the zip.

    Sequential because ZipFile is not thread-safe. Progress is
    reported per JSON entry; total is the JSON-file count.
    """
    json_infos = [
        i for i in infolist if i.filename.endswith(".json") and not i.is_dir()
    ]
    total = len(json_infos)

    if progress_callback is not None:
        try:
            progress_callback(0, total)
        except Exception:
            pass

    out: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(zip_path) as zf:
        for idx, info in enumerate(json_infos, 1):
            try:
                data = zf.read(info.filename)
            except (zipfile.BadZipFile, RuntimeError, OSError):
                # Bad entry; skip silently. Count of parsed records
                # reflects the gap.
                if progress_callback is not None:
                    try:
                        progress_callback(idx, total)
                    except Exception:
                        pass
                continue
            out.append((info.filename, data))
            if progress_callback is not None:
                try:
                    progress_callback(idx, total)
                except Exception:
                    pass
    return out


# ---------------------------------------------------------------------------
# Per-record JSON parsing
# ---------------------------------------------------------------------------


def _parse_entry(
    filename: str,
    data: bytes,
) -> ParsedRecord | ParseFailure:
    try:
        record = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return ParseFailure(
            filename=filename,
            osv_id=None,
            reason=WARNING_PARSE_ERROR,
            detail=f"{type(exc).__name__}: {exc}",
        )

    if not isinstance(record, dict):
        return ParseFailure(
            filename=filename,
            osv_id=None,
            reason=WARNING_MALFORMED_RECORD,
            detail="top-level JSON is not an object",
        )

    osv_id = record.get("id")
    if not isinstance(osv_id, str) or not osv_id:
        return ParseFailure(
            filename=filename,
            osv_id=None,
            reason=WARNING_MISSING_ID,
            detail="record has no usable 'id' field",
        )

    raw_aliases = record.get("aliases", [])
    if not isinstance(raw_aliases, list):
        raw_aliases = []
    aliases = tuple(a for a in raw_aliases if isinstance(a, str) and a)

    canonical_id, canonical_type = _derive_canonical_id(osv_id, aliases)

    all_idents_list: list[tuple[str, str]] = [
        (osv_id, _alias_type_for(osv_id)),
        (canonical_id, canonical_type),
    ]
    for alias in aliases:
        all_idents_list.append((alias, _alias_type_for(alias)))
    seen: set[str] = set()
    unique_idents: list[tuple[str, str]] = []
    for ident, atype in all_idents_list:
        if ident in seen:
            continue
        seen.add(ident)
        unique_idents.append((ident, atype))

    affected_field = record.get("affected", [])
    if not isinstance(affected_field, list):
        affected_field = []

    affected_entries: list[tuple[str, str]] = []
    range_entries: list[tuple[str, str, str, str, str]] = []
    all_versions_pkgs: list[str] = []
    saw_pypi = False
    saw_versions = False
    for entry in affected_field:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package", {})
        if not isinstance(package, dict):
            continue
        ecosystem = package.get("ecosystem")
        if ecosystem != PYPI_ECOSYSTEM:
            continue
        saw_pypi = True
        name = package.get("name")
        if not isinstance(name, str) or not name:
            continue

        # Explicit versions
        versions = entry.get("versions", [])
        if not isinstance(versions, list):
            versions = []
        for version in versions:
            if not isinstance(version, str) or not version:
                continue
            saw_versions = True
            affected_entries.append((name, version))

        # Ranges (v2 addition)
        ranges_field = entry.get("ranges", [])
        if not isinstance(ranges_field, list):
            ranges_field = []
        parsed_ranges, has_all = _parse_ranges_for_package(ranges_field)
        for range_type, intro, fixed, last_aff in parsed_ranges:
            range_entries.append((name, range_type, intro, fixed, last_aff))
        if has_all:
            all_versions_pkgs.append(name)

    if not saw_pypi:
        return ParseFailure(
            filename=filename,
            osv_id=osv_id,
            reason=WARNING_NO_PYPI_AFFECTED,
            detail="no PyPI ecosystem entries in affected array",
        )

    summary = record.get("summary")
    if not isinstance(summary, str):
        summary = None
    details = record.get("details")
    if not isinstance(details, str):
        details = None
    published = record.get("published")
    if not isinstance(published, str):
        published = None
    modified = record.get("modified")
    if not isinstance(modified, str):
        modified = None

    cvss_v3 = None
    cvss_v4 = None
    severity_field = record.get("severity", [])
    if isinstance(severity_field, list):
        for entry in severity_field:
            if not isinstance(entry, dict):
                continue
            sev_type = entry.get("type")
            score = entry.get("score")
            if not isinstance(score, str):
                continue
            if sev_type == "CVSS_V3" and cvss_v3 is None:
                cvss_v3 = score
            elif sev_type == "CVSS_V4" and cvss_v4 is None:
                cvss_v4 = score

    severity_label = None
    db_specific = record.get("database_specific", {})
    if isinstance(db_specific, dict):
        sev = db_specific.get("severity")
        if isinstance(sev, str) and sev:
            severity_label = sev.upper()

    unique_all_pkgs = tuple(sorted(set(all_versions_pkgs)))

    return ParsedRecord(
        osv_id=osv_id,
        canonical_id=canonical_id,
        canonical_id_type=canonical_type,
        all_identifiers=tuple(unique_idents),
        summary=summary,
        details=details,
        published=published,
        modified=modified,
        cvss_v3=cvss_v3,
        cvss_v4=cvss_v4,
        severity=severity_label,
        affected=tuple(affected_entries),
        ranges=tuple(range_entries),
        all_versions_packages=unique_all_pkgs,
        has_explicit_versions=saw_versions,
    )


# ---------------------------------------------------------------------------
# Parallel parse
# ---------------------------------------------------------------------------


def _parse_all(
    entries: list[tuple[str, bytes]],
    max_workers: int,
    progress_callback: ProgressCallback | None = None,
) -> tuple[list[ParsedRecord], list[ParseFailure]]:
    if not entries:
        return [], []

    total = len(entries)
    parsed: list[ParsedRecord] = []
    failures: list[ParseFailure] = []

    if progress_callback is not None:
        try:
            progress_callback(0, total)
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(_parse_entry, filename, data): filename
            for filename, data in entries
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_map):
            completed += 1
            try:
                result = future.result()
            except Exception as exc:
                filename = future_map[future]
                failures.append(
                    ParseFailure(
                        filename=filename,
                        osv_id=None,
                        reason=WARNING_PARSE_ERROR,
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                )
            else:
                if isinstance(result, ParsedRecord):
                    parsed.append(result)
                else:
                    failures.append(result)
            if progress_callback is not None:
                try:
                    progress_callback(completed, total)
                except Exception:
                    pass

    return parsed, failures


# ---------------------------------------------------------------------------
# Dedup and merge
# ---------------------------------------------------------------------------


def _merge_records(
    records: list[ParsedRecord],
) -> dict[str, MergedVulnerability]:
    merged: dict[str, MergedVulnerability] = {}
    for record in records:
        cid = record.canonical_id
        if cid not in merged:
            merged[cid] = MergedVulnerability(canonical_id=cid)
        merged[cid].merge(record)
    return merged


# ---------------------------------------------------------------------------
# DB write with batched executemany and write-phase progress
# ---------------------------------------------------------------------------


def _write_to_db(
    conn: sqlite3.Connection,
    merged: dict[str, MergedVulnerability],
    failures: list[ParseFailure],
    *,
    imported_at: str,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, int]:
    """Build all row batches, then batch-insert with progress callbacks.

    The batches are computed upfront so we know the total row
    count before any inserts begin; that lets the progress bar
    show a meaningful denominator from the first update.
    """
    # Build vulnerability rows
    vuln_rows = []
    for vuln in merged.values():
        vuln_rows.append(
            (
                vuln.canonical_id,
                vuln.summary,
                vuln.details,
                vuln.published,
                vuln.modified,
                vuln.cvss_v3,
                vuln.cvss_v4,
                vuln.severity,
                1 if vuln.has_explicit_versions else 0,
            )
        )

    # Build alias rows (deduplicated across canonicals)
    alias_rows = []
    seen_aliases: set[str] = set()
    for vuln in merged.values():
        for ident, atype in vuln.identifiers:
            if ident in seen_aliases:
                continue
            seen_aliases.add(ident)
            alias_rows.append((ident, vuln.canonical_id, atype))

    # Build affected_versions rows: explicit versions plus ALL
    # sentinel rows for packages flagged as "every version
    # affected" via structural detection at parse time.
    av_rows = []
    for vuln in merged.values():
        for package, version in vuln.affected:
            av_rows.append((vuln.canonical_id, package, version))
        for package in vuln.all_versions_packages:
            av_rows.append((vuln.canonical_id, package, ALL_VERSIONS_SENTINEL))

    # Build affected_ranges rows
    ar_rows = []
    for vuln in merged.values():
        for entry in vuln.ranges:
            package, range_type, intro, fixed, last_aff = entry
            ar_rows.append(
                (
                    vuln.canonical_id,
                    package,
                    range_type,
                    intro,
                    fixed,
                    last_aff,
                )
            )

    # Count canonicals with no usable data (no version rows, no
    # range rows, no ALL flag for any package). These get a
    # warning row.
    no_data_canonicals: list[str] = []
    for vuln in merged.values():
        if not vuln.affected and not vuln.ranges and not vuln.all_versions_packages:
            no_data_canonicals.append(vuln.canonical_id)

    # Build warning rows: parse failures plus no-usable-data flags
    warning_rows = []
    for failure in failures:
        warning_rows.append(
            (
                failure.osv_id,
                failure.reason,
                failure.detail,
                imported_at,
            )
        )
    for cid in no_data_canonicals:
        warning_rows.append(
            (
                cid,
                WARNING_NO_USABLE_DATA,
                "PyPI affected entry present but no versions and no ranges",
                imported_at,
            )
        )

    total_rows = (
        len(vuln_rows)
        + len(alias_rows)
        + len(av_rows)
        + len(ar_rows)
        + len(warning_rows)
    )
    written = 0

    if progress_callback is not None:
        try:
            progress_callback(0, total_rows)
        except Exception:
            pass

    def batch_insert(sql: str, rows: list) -> None:
        nonlocal written
        for i in range(0, len(rows), _WRITE_BATCH_SIZE):
            batch = rows[i : i + _WRITE_BATCH_SIZE]
            conn.executemany(sql, batch)
            written += len(batch)
            if progress_callback is not None:
                try:
                    progress_callback(written, total_rows)
                except Exception:
                    pass

    batch_insert(
        "INSERT INTO vulnerabilities "
        "(canonical_id, summary, details, published, modified, "
        "cvss_v3, cvss_v4, severity, versions_complete) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        vuln_rows,
    )
    batch_insert(
        "INSERT OR IGNORE INTO aliases "
        "(alias, canonical_id, alias_type) VALUES (?, ?, ?)",
        alias_rows,
    )
    batch_insert(
        "INSERT OR IGNORE INTO affected_versions "
        "(canonical_id, package_name, version) VALUES (?, ?, ?)",
        av_rows,
    )
    batch_insert(
        "INSERT OR IGNORE INTO affected_ranges "
        "(canonical_id, package_name, range_type, "
        "introduced, fixed, last_affected) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ar_rows,
    )
    batch_insert(
        "INSERT INTO import_warnings "
        "(osv_id, reason, detail, imported_at) "
        "VALUES (?, ?, ?, ?)",
        warning_rows,
    )

    return {
        "vulnerabilities": len(vuln_rows),
        "aliases": len(alias_rows),
        "affected_versions": len(av_rows),
        "affected_ranges": len(ar_rows),
        "no_usable_data": len(no_data_canonicals),
    }


def _write_provenance_metadata(
    conn: sqlite3.Connection,
    *,
    snapshot_sha256: str | None,
    imported_at: str,
    run_uuid: str,
    records_imported: int,
) -> None:
    """Write import provenance into db_metadata.

    Includes the run UUID so the DB knows which pydepgate
    invocation produced its current state.
    """
    payload: dict[str, str] = {
        schema.METADATA_KEY_LAST_FULL_UPDATE: imported_at,
        schema.METADATA_KEY_RECORDS_IMPORTED: str(records_imported),
        schema.METADATA_KEY_LAST_IMPORT_RUN_UUID: run_uuid,
    }
    if snapshot_sha256 is not None:
        payload[schema.METADATA_KEY_LAST_SNAPSHOT_SHA256] = snapshot_sha256
    schema.write_metadata_dict(conn, payload)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def import_from_zip(
    zip_path: Path,
    db_path: Path,
    *,
    snapshot_sha256: str | None = None,
    run_uuid: str | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
    max_per_file_bytes: int = DEFAULT_MAX_PER_FILE_BYTES,
    progress: ProgressCallbacks | None = None,
) -> ImportResult:
    """Import OSV PyPI data from a downloaded zip into a cvedb DB.

    Args:
        zip_path: Path to the OSV PyPI all.zip on disk.
        db_path: Path where the cvedb SQLite DB will live.
        snapshot_sha256: Optional SHA256 of the downloaded zip,
            written to metadata for future short-circuit checks.
        run_uuid: Optional explicit run UUID. When None, uses
            run_context.get_current_run_uuid(). Tests pass an
            explicit value; production callers pass nothing.
        max_workers: Thread pool size for the parse phase.
        max_decompressed_bytes: Aggregate decompressed-size cap.
        max_per_file_bytes: Per-entry decompressed-size cap.
        progress: Optional ProgressCallbacks bundle covering the
            three phases (read, parse, write). Each phase's
            finish callback is invoked after its work completes.

    Returns:
        ImportResult summarizing what was imported.
    """
    start = time.monotonic()

    if run_uuid is None:
        run_uuid = run_context.get_current_run_uuid()
    if progress is None:
        progress = ProgressCallbacks()

    infolist = _validate_zip(
        zip_path,
        max_decompressed_bytes=max_decompressed_bytes,
        max_per_file_bytes=max_per_file_bytes,
    )

    # Phase 1: read
    entries = _read_json_entries(zip_path, infolist, progress.read_update)
    if progress.read_finish is not None:
        try:
            progress.read_finish()
        except Exception:
            pass

    # Phase 2: parse
    parsed, failures = _parse_all(entries, max_workers, progress.parse_update)
    if progress.parse_finish is not None:
        try:
            progress.parse_finish()
        except Exception:
            pass

    # Phase 3: merge (in-memory only, no bar)
    merged = _merge_records(parsed)

    imported_at = datetime.now(timezone.utc).isoformat()

    # Phase 4: write
    conn = schema.connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            schema.drop_all_tables(conn)
            schema.initialize_schema(conn)
            counts = _write_to_db(
                conn,
                merged,
                failures,
                imported_at=imported_at,
                progress_callback=progress.write_update,
            )
            _write_provenance_metadata(
                conn,
                snapshot_sha256=snapshot_sha256,
                imported_at=imported_at,
                run_uuid=run_uuid,
                records_imported=len(merged),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    finally:
        conn.close()
        if progress.write_finish is not None:
            try:
                progress.write_finish()
            except Exception:
                pass

    elapsed = time.monotonic() - start
    return ImportResult(
        records_imported=len(merged),
        records_with_parse_errors=len(failures),
        records_with_no_usable_data=counts["no_usable_data"],
        affected_version_rows=counts["affected_versions"],
        affected_range_rows=counts["affected_ranges"],
        alias_rows=counts["aliases"],
        elapsed_seconds=elapsed,
    )
