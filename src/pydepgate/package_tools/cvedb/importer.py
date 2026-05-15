"""pydepgate.package_tools.cvedb.importer

Import OSV PyPI vulnerability data from a downloaded zip into a
cvedb SQLite database.

Public surface:

    import_from_zip(zip_path, db_path, ...) -> ImportResult
        Run the full import pipeline. Atomic at the DB level:
        prior data is preserved on any failure.

    ImportResult
        Frozen dataclass returned on successful import. Counts
        records imported, skipped, failed, plus elapsed time.

    ParsedRecord, ParseFailure
        Frozen, picklable result types from the per-record parse
        step. Exposed so the importer's intermediate stages can
        be tested in isolation.

    CvedbImportError, ZipValidationError, ImportFailedError
        Exception hierarchy.

    WARNING_* constants
        Reason strings used in the import_warnings table.

This module is stdlib-only.

Threading: JSON parsing happens in a ThreadPoolExecutor because
the json module's C implementation releases the GIL. SQLite
inserts happen serially in the main thread because SQLite is
single-writer. The producer-consumer boundary is the parsed list,
which is built in memory before the DB write phase begins.

Memory: peak around 400-600MB during the parse phase for the
real OSV dataset. Acceptable for a deliberate one-time-ish
operation. Callers that need lower memory ceilings can stream
through a smaller worker pool, but the simple full-load approach
gives the best wall-clock time for the expected input size.

Picklability: ParsedRecord, ParseFailure, and ImportResult are
frozen dataclasses with picklable fields, so a future
ProcessPoolExecutor variant of the parser would work without
refactoring the result types.

Atomicity: the DB write phase is one BEGIN IMMEDIATE / COMMIT
transaction wrapping drop_all_tables, initialize_schema, and
all batched executemany inserts. Any failure rolls back to the
prior DB state.
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

ProgressCallback = Callable[[int, int], None]


# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

# Maximum total decompressed size of the zip. The real OSV PyPI
# all.zip decompresses to roughly 300MB; 500MB gives headroom.
# The importer refuses larger archives as a defense against
# decompression bombs.
DEFAULT_MAX_DECOMPRESSED_BYTES = 500 * 1024 * 1024

# Maximum decompressed size of a single entry within the zip. No
# legitimate OSV record approaches this; an entry larger than
# this signals either corruption or a targeted bomb.
DEFAULT_MAX_PER_FILE_BYTES = 1 * 1024 * 1024

# Default worker count for the parallel parse phase. JSON parsing
# in CPython releases the GIL so threads provide real concurrency
# on multi-core hardware. The cap of 8 reflects diminishing
# returns past that count for the expected record sizes; callers
# on machines with substantially more cores can override.
DEFAULT_MAX_WORKERS = 8


# Identifier prefixes we recognize and their alias_type labels.
# Used both for canonical_id derivation and for populating the
# alias_type column. The order matters for derivation: prefixes
# earlier in the tuple are checked first, but selection of the
# canonical happens through _CANONICAL_PRIORITY below.
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

# Priority order for canonical_id selection. A CVE alias always
# wins. If no CVE is present, GHSA. Then PYSEC. If none of these,
# fall back to the record's own id with its discovered alias_type.
_CANONICAL_PRIORITY: tuple[str, ...] = ("CVE", "GHSA", "PYSEC")


# Rank for highest-wins severity merging. CRITICAL > HIGH > MEDIUM
# > LOW > INFO. MODERATE is GitHub's wording for MEDIUM, treated
# equivalently. Unknown labels rank below INFO so the first known
# label wins over them.
_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "MODERATE": 2,
    "LOW": 1,
    "INFO": 0,
}


# The ecosystem label used by OSV for PyPI records. Records with
# other ecosystem values are skipped (logged to import_warnings).
PYPI_ECOSYSTEM = "PyPI"


# Reason codes for the import_warnings table. Importer callers
# can filter or aggregate on these.
WARNING_NO_VERSIONS = "no_versions_list"
WARNING_NO_AFFECTED = "no_affected"
WARNING_NO_PYPI_AFFECTED = "no_pypi_affected"
WARNING_PARSE_ERROR = "parse_error"
WARNING_MISSING_ID = "missing_id"
WARNING_MALFORMED_RECORD = "malformed_record"


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class CvedbImportError(Exception):
    """Base class for cvedb importer failures."""


class ZipValidationError(CvedbImportError):
    """The zip failed pre-extraction safety checks.

    Raised when the archive is corrupt, exceeds the per-file
    size cap, or exceeds the aggregate decompressed-size cap.
    The DB is not touched when this is raised.
    """


class ImportFailedError(CvedbImportError):
    """The DB write phase could not complete.

    Raised when the SQLite write phase fails after parsing
    completed. The DB rollback has already happened by the
    time this is raised; the prior state is preserved.
    """


# ---------------------------------------------------------------------------
# Result types (picklable frozen dataclasses)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImportResult:
    """Summary of a successful import.

    Attributes:
        records_imported: Number of canonical vulnerabilities
            in the DB after the import. Equal to the number of
            distinct canonical_ids after dedup.
        records_skipped_no_versions: Subset of records_imported
            whose contributing records were all range-only and
            therefore produced no affected_versions rows.
        records_with_parse_errors: Number of zip entries that
            failed to parse or produced a non-importable record
            (no PyPI affected, malformed JSON, missing id).
        affected_version_rows: Total rows inserted into the
            affected_versions table.
        alias_rows: Total rows inserted into the aliases table.
        elapsed_seconds: Wall-clock duration of the import.
    """

    records_imported: int
    records_skipped_no_versions: int
    records_with_parse_errors: int
    affected_version_rows: int
    alias_rows: int
    elapsed_seconds: float


@dataclass(frozen=True)
class ParsedRecord:
    """One OSV record reduced to the fields the importer needs.

    Built by _parse_entry from raw JSON bytes. Frozen and
    picklable so future parallel-via-processes variants work
    without refactoring.

    Attributes:
        osv_id: The record's own id field (PYSEC-*, GHSA-*, etc).
        canonical_id: The selected canonical identifier after
            priority resolution (CVE > GHSA > PYSEC > osv_id).
        canonical_id_type: alias_type label for canonical_id.
        all_identifiers: Tuple of (identifier, alias_type) pairs
            covering osv_id, canonical_id, and every alias from
            the record's aliases array. Deduplicated by identifier.
        summary, details: From the OSV record. May be None.
        published, modified: ISO 8601 timestamps from the OSV
            record. May be None.
        cvss_v3, cvss_v4: CVSS vector strings from the severity
            array. Stored verbatim; no score computation.
        severity: The database_specific.severity label
            (CRITICAL, HIGH, MEDIUM, LOW). None when absent.
        affected: Tuple of (package_name, version) pairs for
            every explicit PyPI version mention in the record.
        has_explicit_versions: True if any (package, versions)
            entry in the affected array provided a non-empty
            versions list. False for range-only records.
    """

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
    has_explicit_versions: bool


@dataclass(frozen=True)
class ParseFailure:
    """Per-record parse or content failure.

    Logged into the import_warnings table at write time. The
    osv_id may be None when the failure occurred before the id
    could be extracted (e.g. malformed JSON).
    """

    filename: str
    osv_id: str | None
    reason: str
    detail: str


@dataclass
class MergedVulnerability:
    """In-memory accumulator for one canonical_id during dedup.

    Mutable (not frozen) because we accumulate across multiple
    contributing records. Never crosses process boundaries; only
    used in the main thread between the parse and write phases.
    """

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

    def merge(self, record: ParsedRecord) -> None:
        """Fold a ParsedRecord into this accumulator.

        Field semantics:
          summary, details, cvss_v3, cvss_v4: first non-empty wins
          published: earliest wins
          modified: latest wins
          severity: highest rank wins
          has_explicit_versions: OR across contributors
          identifiers: union
          affected: union
        """
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
        # Ensure the canonical_id is always present as a
        # self-alias even if no contributing record listed it
        # explicitly.
        self.identifiers.add((self.canonical_id, _alias_type_for(self.canonical_id)))
        for entry in record.affected:
            self.affected.add(entry)


# ---------------------------------------------------------------------------
# Private helpers: canonical ID and alias-type derivation
# ---------------------------------------------------------------------------


def _alias_type_for(identifier: str) -> str:
    """Classify an identifier by its prefix.

    Returns the alias_type label (CVE, GHSA, PYSEC, etc) for
    known prefixes, or "OTHER" for unknown shapes.
    """
    for prefix, label in _KNOWN_ALIAS_PREFIXES:
        if identifier.startswith(prefix):
            return label
    return "OTHER"


def _derive_canonical_id(
    osv_id: str,
    aliases: Iterable[str],
) -> tuple[str, str]:
    """Select the canonical_id from a record's id and aliases.

    Priority: CVE-* > GHSA-* > PYSEC-* > the record's own id.
    Ties within a priority class break alphabetically.

    Returns:
        (canonical_id, alias_type) tuple.
    """
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
# Private helpers: zip validation and entry reading
# ---------------------------------------------------------------------------


def _validate_zip(
    zip_path: Path,
    *,
    max_decompressed_bytes: int,
    max_per_file_bytes: int,
) -> list[zipfile.ZipInfo]:
    """Validate a zip against safety limits.

    Reads only the central directory (no entry contents). Returns
    the full infolist so the caller can avoid a second read of
    the central directory.

    Raises ZipValidationError if the zip is corrupt, if any
    single entry would decompress beyond max_per_file_bytes, or
    if the aggregate decompressed size would exceed
    max_decompressed_bytes.
    """
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
) -> list[tuple[str, bytes]]:
    """Read every JSON entry's decompressed bytes from the zip.

    Sequential because ZipFile is not thread-safe. Returns a
    list of (filename, bytes) tuples ready for the parallel
    parse phase. Entries that fail to read (corrupt member,
    OSError) are skipped silently; the parse phase will not
    receive them, and the absence shows up in the imported-
    versus-attempted record count.
    """
    out: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in infolist:
            if not info.filename.endswith(".json"):
                continue
            if info.is_dir():
                continue
            try:
                data = zf.read(info.filename)
            except (zipfile.BadZipFile, RuntimeError, OSError):
                continue
            out.append((info.filename, data))
    return out


# ---------------------------------------------------------------------------
# Private helpers: per-record JSON parsing
# ---------------------------------------------------------------------------


def _parse_entry(
    filename: str,
    data: bytes,
) -> ParsedRecord | ParseFailure:
    """Parse one OSV JSON record into a ParsedRecord or ParseFailure.

    Returns ParseFailure with an appropriate reason code when:
      * JSON parsing fails
      * top-level shape is not an object
      * the id field is missing or not a string
      * the affected array contains no PyPI ecosystem entries

    Otherwise returns a ParsedRecord. The returned ParsedRecord
    may have has_explicit_versions=False if every PyPI affected
    entry was range-only; that case is logged as a warning at
    write time rather than treated as a failure here, because
    the record is still useful in the DB (its canonical_id and
    aliases get stored).
    """
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

    # Build the full identifier set: record's own id, the
    # canonical (which may be the same), and every alias.
    # Deduplicate by identifier string while preserving the
    # alias_type per identifier.
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
        versions = entry.get("versions", [])
        if not isinstance(versions, list):
            versions = []
        for version in versions:
            if not isinstance(version, str) or not version:
                continue
            saw_versions = True
            affected_entries.append((name, version))

    if not saw_pypi:
        return ParseFailure(
            filename=filename,
            osv_id=osv_id,
            reason=WARNING_NO_PYPI_AFFECTED,
            detail="no PyPI ecosystem entries in affected array",
        )

    # Optional fields, type-checked individually so an unexpected
    # null or non-string value does not corrupt the record.
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

    # Severity vectors: take the first occurrence of each type.
    # Some records have CVSS_V3 only, some both V3 and V4, some
    # neither. Verbatim string storage; no score computation.
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

    # Severity label: from database_specific.severity when
    # present, normalized to upper-case. None otherwise.
    severity_label = None
    db_specific = record.get("database_specific", {})
    if isinstance(db_specific, dict):
        sev = db_specific.get("severity")
        if isinstance(sev, str) and sev:
            severity_label = sev.upper()

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
        has_explicit_versions=saw_versions,
    )


# ---------------------------------------------------------------------------
# Private helpers: parallel parse driver
# ---------------------------------------------------------------------------


def _parse_all(
    entries: list[tuple[str, bytes]],
    max_workers: int,
    progress_callback: ProgressCallback | None,
) -> tuple[list[ParsedRecord], list[ParseFailure]]:
    """Run _parse_entry across all entries with a thread pool.

    Returns (parsed_records, parse_failures). Progress callback
    is invoked once per completed task with (completed_count,
    total_count). The callback is also invoked with (0, total)
    before any task completes so the bar appears immediately on
    a TTY.
    """
    if not entries:
        return [], []

    total = len(entries)
    parsed: list[ParsedRecord] = []
    failures: list[ParseFailure] = []

    if progress_callback is not None:
        try:
            progress_callback(0, total)
        except Exception:
            # A buggy progress callback must not abort the import.
            # The same defensive principle applies as in the scan
            # engine's _safe_progress helper.
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
                # Should not happen, since _parse_entry catches
                # its own exceptions and returns ParseFailure.
                # Defensive in case a future change in
                # _parse_entry lets an exception escape.
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
# Private helpers: dedup and merge
# ---------------------------------------------------------------------------


def _merge_records(
    records: list[ParsedRecord],
) -> dict[str, MergedVulnerability]:
    """Group records by canonical_id and merge contributors.

    Returns a dict keyed by canonical_id. Each value is a
    MergedVulnerability with fields combined per the rules
    documented on MergedVulnerability.merge.
    """
    merged: dict[str, MergedVulnerability] = {}
    for record in records:
        cid = record.canonical_id
        if cid not in merged:
            merged[cid] = MergedVulnerability(canonical_id=cid)
        merged[cid].merge(record)
    return merged


# ---------------------------------------------------------------------------
# Private helpers: DB write
# ---------------------------------------------------------------------------


def _write_to_db(
    conn: sqlite3.Connection,
    merged: dict[str, MergedVulnerability],
    failures: list[ParseFailure],
    *,
    imported_at: str,
) -> dict[str, int]:
    """Insert merged vulnerabilities, aliases, versions, and warnings.

    Uses executemany for every batch so the per-row overhead of
    cursor execution is amortized. Returns a dict of counts the
    caller uses to build the ImportResult.

    Must be called inside an open transaction. Does not commit
    or rollback; the caller manages transaction boundaries.
    """
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
    conn.executemany(
        "INSERT INTO vulnerabilities "
        "(canonical_id, summary, details, published, modified, "
        "cvss_v3, cvss_v4, severity, versions_complete) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        vuln_rows,
    )

    # Aliases: deduplicate by alias string across all merged
    # vulnerabilities. If two distinct canonical_ids both claim
    # the same alias string (which would indicate upstream data
    # corruption), the first one wins via INSERT OR IGNORE.
    alias_rows = []
    seen_aliases: set[str] = set()
    for vuln in merged.values():
        for ident, atype in vuln.identifiers:
            if ident in seen_aliases:
                continue
            seen_aliases.add(ident)
            alias_rows.append((ident, vuln.canonical_id, atype))
    conn.executemany(
        "INSERT OR IGNORE INTO aliases "
        "(alias, canonical_id, alias_type) VALUES (?, ?, ?)",
        alias_rows,
    )

    av_rows = []
    for vuln in merged.values():
        for package, version in vuln.affected:
            av_rows.append((vuln.canonical_id, package, version))
    conn.executemany(
        "INSERT OR IGNORE INTO affected_versions "
        "(canonical_id, package_name, version) VALUES (?, ?, ?)",
        av_rows,
    )

    # Warnings: per-record parse failures plus per-canonical
    # range-only flags. The latter are emitted at write time
    # rather than during the merge so the count reflects the
    # final deduplicated state (one warning per affected
    # canonical, not per contributing record).
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
    skipped_no_versions = 0
    for vuln in merged.values():
        if not vuln.has_explicit_versions:
            skipped_no_versions += 1
            warning_rows.append(
                (
                    vuln.canonical_id,
                    WARNING_NO_VERSIONS,
                    "no explicit versions list for any PyPI package",
                    imported_at,
                )
            )
    if warning_rows:
        conn.executemany(
            "INSERT INTO import_warnings "
            "(osv_id, reason, detail, imported_at) "
            "VALUES (?, ?, ?, ?)",
            warning_rows,
        )

    return {
        "vulnerabilities": len(vuln_rows),
        "aliases": len(alias_rows),
        "affected_versions": len(av_rows),
        "skipped_no_versions": skipped_no_versions,
    }


def _write_provenance_metadata(
    conn: sqlite3.Connection,
    *,
    snapshot_sha256: str | None,
    imported_at: str,
    records_imported: int,
    records_skipped_no_versions: int,
) -> None:
    """Write import provenance into db_metadata.

    Records:
      * last_full_update: ISO 8601 timestamp of this import
      * last_snapshot_sha256: the zip's SHA256 (if provided by caller)
      * records_imported: count after dedup
      * records_skipped_no_versions: range-only count

    OSV attribution constants (data_source_name, license, etc)
    are written separately by the caller (typically the CLI
    subcommand) using values from
    pydepgate.package_tools.cvedb.constants.
    """
    payload: dict[str, str] = {
        schema.METADATA_KEY_LAST_FULL_UPDATE: imported_at,
        schema.METADATA_KEY_RECORDS_IMPORTED: str(records_imported),
        schema.METADATA_KEY_RECORDS_SKIPPED_NO_VERSIONS: str(
            records_skipped_no_versions
        ),
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
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
    max_per_file_bytes: int = DEFAULT_MAX_PER_FILE_BYTES,
    progress_callback: ProgressCallback | None = None,
) -> ImportResult:
    """Import OSV PyPI data from a downloaded zip into a cvedb DB.

    The import is atomic at the DB level: the entire write phase
    runs inside one BEGIN IMMEDIATE / COMMIT transaction. If
    anything fails after the transaction begins, ROLLBACK
    restores the prior DB state. The zip on disk is not modified.

    Pipeline phases:
      1. Validate the zip against safety limits (per-entry and
         aggregate decompressed size).
      2. Read every .json entry's bytes from the zip (sequential).
      3. Parse each entry in a thread pool. Failures are recorded
         to the import_warnings table at write time but do not
         abort the import.
      4. Group records by canonical_id and merge contributors.
      5. Drop and recreate the cvedb schema, then bulk-insert
         every vulnerability, alias, affected_version, and
         warning row. Commit the transaction.

    Args:
        zip_path: Path to the OSV PyPI all.zip on disk.
        db_path: Path where the cvedb SQLite DB will live. If
            the file does not exist it is created. If it does
            exist its previous contents are replaced atomically.
        snapshot_sha256: Optional SHA256 of the downloaded zip,
            typically taken from the fetcher's FetchResult.
            Written to db_metadata as last_snapshot_sha256 so
            future cvedb update calls can detect "same snapshot,
            no work needed."
        max_workers: Thread pool size for the parse phase.
            Defaults to DEFAULT_MAX_WORKERS (8). JSON parsing
            releases the GIL so threads provide real concurrency.
        max_decompressed_bytes: Aggregate decompressed-size cap
            for bomb protection. Defaults to 500MB.
        max_per_file_bytes: Per-entry decompressed-size cap.
            Defaults to 1MB.
        progress_callback: Optional Callable[[int, int], None]
            matching pydepgate.cli.progress.ProgressCallback.
            Invoked once per completed parse task plus one
            initial (0, total) call so the bar appears
            immediately on a TTY.

    Returns:
        ImportResult summarizing what was imported.

    Raises:
        ZipValidationError: zip is corrupt or violates safety
            limits. The DB is not touched.
        sqlite3.Error: a SQLite-level failure during the write
            phase. The transaction is rolled back before this
            propagates.
    """
    start = time.monotonic()

    infolist = _validate_zip(
        zip_path,
        max_decompressed_bytes=max_decompressed_bytes,
        max_per_file_bytes=max_per_file_bytes,
    )

    entries = _read_json_entries(zip_path, infolist)
    parsed, failures = _parse_all(entries, max_workers, progress_callback)
    merged = _merge_records(parsed)

    imported_at = datetime.now(timezone.utc).isoformat()

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
            )
            _write_provenance_metadata(
                conn,
                snapshot_sha256=snapshot_sha256,
                imported_at=imported_at,
                records_imported=len(merged),
                records_skipped_no_versions=counts["skipped_no_versions"],
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    finally:
        conn.close()

    elapsed = time.monotonic() - start
    return ImportResult(
        records_imported=len(merged),
        records_skipped_no_versions=counts["skipped_no_versions"],
        records_with_parse_errors=len(failures),
        affected_version_rows=counts["affected_versions"],
        alias_rows=counts["aliases"],
        elapsed_seconds=elapsed,
    )
