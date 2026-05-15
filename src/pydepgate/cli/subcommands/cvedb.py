"""pydepgate.cli.subcommands.cvedb

CLI subcommand: cvedb (update, status, path).

Manages the local CVE database derived from OSV PyPI snapshots.
Calls the importer for the actual ingestion; this file owns the
download flow, progress bars (four total: Downloading, Reading,
Parsing, Writing), CC-BY 4.0 attribution metadata writes, and
the human-readable summary and status output.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydepgate.cli import exit_codes
from pydepgate.cli import progress
from pydepgate.package_tools.cvedb import constants
from pydepgate.package_tools.cvedb import fetcher
from pydepgate.package_tools.cvedb import importer
from pydepgate.package_tools.cvedb import schema
from pydepgate.pdgplatform import paths
from pydepgate.cli.subcommands.version import get_version
from pydepgate.run_context import get_current_run_uuid

_ACTIONS = ("update", "status", "path")


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "cvedb",
        help="Manage the local CVE database",
        description=(
            "Manage pydepgate's local CVE database. The database "
            "is built from the OSV PyPI vulnerability feed "
            "(https://osv.dev) and powers vulnerability lookups for "
            "resolved Python dependencies. OSV data is licensed "
            "CC-BY 4.0; attribution is recorded in the local DB and "
            "surfaced in scan output that uses it.\n"
            "\n"
            "Actions:\n"
            "  update   Download and import the latest OSV PyPI snapshot.\n"
            "  status   Show local DB info (record counts, last update, hash).\n"
            "  path     Print the on-disk location of the local DB.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "action",
        choices=_ACTIONS,
        help="What to do",
    )
    parser.add_argument(
        "--no-bar",
        action="store_true",
        default=False,
        help="Suppress progress bars (also auto-suppressed when stderr is not a TTY)",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    if args.action == "update":
        return _run_update(args)
    if args.action == "status":
        return _run_status(args)
    if args.action == "path":
        return _run_path(args)
    sys.stderr.write(f"unknown cvedb action: {args.action}\n")
    return exit_codes.TOOL_ERROR


def _db_path() -> Path:
    return paths.pydepgate_cache_dir() / "cvedb" / constants.CVE_DB_FILENAME


def _run_path(args: argparse.Namespace) -> int:
    sys.stdout.write(f"{_db_path()}\n")
    return exit_codes.CLEAN


def _run_status(args: argparse.Namespace) -> int:
    db_path = _db_path()
    if not db_path.exists():
        sys.stderr.write(
            f"CVE database not found at {db_path}\n"
            f"Run 'pydepgate cvedb update' to download and import.\n"
        )
        return exit_codes.TOOL_ERROR

    try:
        conn = schema.connect(db_path)
    except Exception as exc:
        sys.stderr.write(f"error opening CVE database: {exc}\n")
        return exit_codes.TOOL_ERROR

    try:
        try:
            schema.check_schema_compatibility(conn)
        except schema.SchemaVersionMismatch as exc:
            sys.stderr.write(
                f"CVE database has incompatible schema: {exc}\n"
                f"Run 'pydepgate cvedb update' to rebuild.\n"
            )
            return exit_codes.TOOL_ERROR

        metadata = schema.read_all_metadata(conn)

        # Live table count for ranges; the metadata block holds
        # the canonical "vulnerabilities imported" count but not
        # the range row count.
        range_count = conn.execute("SELECT COUNT(*) FROM affected_ranges").fetchone()[0]

        sys.stdout.write(f"CVE database: {db_path}\n")
        sys.stdout.write(
            f"  Schema version:     "
            f"{metadata.get(schema.METADATA_KEY_SCHEMA_VERSION, 'unknown')}\n"
        )
        sys.stdout.write(
            f"  Records imported:   "
            f"{metadata.get(schema.METADATA_KEY_RECORDS_IMPORTED, 'unknown')}\n"
        )
        sys.stdout.write(f"  Range rows:         {range_count}\n")
        sys.stdout.write(
            f"  Last update:        "
            f"{metadata.get(schema.METADATA_KEY_LAST_FULL_UPDATE, 'never')}\n"
        )
        run_uuid = metadata.get(schema.METADATA_KEY_LAST_IMPORT_RUN_UUID)
        if run_uuid:
            sys.stdout.write(f"  Last import run:    {run_uuid}\n")
        sha = metadata.get(schema.METADATA_KEY_LAST_SNAPSHOT_SHA256)
        if sha:
            sys.stdout.write(f"  Snapshot SHA256:    {sha[:16]}...\n")

        source = metadata.get(
            schema.METADATA_KEY_DATA_SOURCE_NAME,
            constants.OSV_DATA_SOURCE_NAME,
        )
        license_name = metadata.get(
            schema.METADATA_KEY_DATA_LICENSE,
            constants.OSV_DATA_LICENSE,
        )
        sys.stdout.write(f"\nData source: {source}\n")
        sys.stdout.write(f"License:     {license_name}\n")

        return exit_codes.CLEAN
    finally:
        conn.close()


def _run_update(args: argparse.Namespace) -> int:
    db_path = _db_path()
    cache_dir = paths.ensure_directory(db_path.parent)
    zip_path = cache_dir / constants.CVE_DB_IMPORT_ZIP_FILENAME

    sys.stderr.write(f"Checking {constants.OSV_PYPI_ALL_ZIP_URL}\n")
    try:
        head_info = fetcher.head_check(
            constants.OSV_PYPI_ALL_ZIP_URL,
            accepted_content_types=constants.OSV_PYPI_ALL_ZIP_ACCEPTED_CONTENT_TYPES,
        )
    except fetcher.SizeLimitExceeded as exc:
        sys.stderr.write(f"error: {exc}\n")
        sys.stderr.write(
            "The OSV PyPI snapshot is outside the expected size range. "
            "If OSV has grown significantly, this limit may need updating "
            "in pydepgate's source.\n"
        )
        return exit_codes.TOOL_ERROR
    except fetcher.HeadCheckError as exc:
        sys.stderr.write(f"error: HEAD check failed: {exc}\n")
        return exit_codes.TOOL_ERROR
    except fetcher.DownloadError as exc:
        sys.stderr.write(f"error: network failure: {exc}\n")
        return exit_codes.TOOL_ERROR

    size_mb = head_info.content_length / 1024 / 1024
    sys.stderr.write(f"  ok ({size_mb:.1f} MB)\n")

    # Four bars: Downloading, Reading, Parsing, Writing.
    # Each is a (update, finish) pair from make_progress_callback.
    # The download bar fires during the fetcher call; the other
    # three are bundled into a ProgressCallbacks and handed to
    # the importer.
    download_update, download_finish = progress.make_progress_callback(
        no_bar=args.no_bar,
        label="Downloading",
    )
    read_update, read_finish = progress.make_progress_callback(
        no_bar=args.no_bar,
        label="Reading    ",
    )
    parse_update, parse_finish = progress.make_progress_callback(
        no_bar=args.no_bar,
        label="Parsing    ",
    )
    write_update, write_finish = progress.make_progress_callback(
        no_bar=args.no_bar,
        label="Writing    ",
    )

    def download_adapter(received: int, total) -> None:
        # Fetcher's callback receives (int, int | None); the
        # progress bar's update wants (int, int). When head_info
        # is supplied (which it always is here), total is never
        # None.
        if total is not None:
            download_update(received, total)

    try:
        fetch_result = fetcher.download(
            constants.OSV_PYPI_ALL_ZIP_URL,
            zip_path,
            head_info=head_info,
            progress_callback=download_adapter,
        )
    except fetcher.DownloadError as exc:
        download_finish()
        sys.stderr.write(f"error: download failed: {exc}\n")
        return exit_codes.TOOL_ERROR
    finally:
        download_finish()

    # Bundle the three importer-phase callbacks into a single
    # ProgressCallbacks. The importer calls each phase's finish
    # at the phase boundary so bars terminate cleanly before the
    # next bar starts.
    import_progress = importer.ProgressCallbacks(
        read_update=read_update,
        read_finish=read_finish,
        parse_update=parse_update,
        parse_finish=parse_finish,
        write_update=write_update,
        write_finish=write_finish,
    )

    try:
        result = importer.import_from_zip(
            zip_path,
            db_path,
            snapshot_sha256=fetch_result.sha256,
            progress=import_progress,
        )
    except importer.ZipValidationError as exc:
        sys.stderr.write(f"error: zip validation failed: {exc}\n")
        _cleanup_zip(zip_path)
        return exit_codes.TOOL_ERROR
    except Exception as exc:
        sys.stderr.write(f"error: import failed: {type(exc).__name__}: {exc}\n")
        _cleanup_zip(zip_path)
        return exit_codes.TOOL_ERROR
    finally:
        # Defensive: ensure all bars are terminated even if the
        # importer raised before reaching its own finish calls.
        # Each finish is idempotent (a no-op after the first call).
        read_finish()
        parse_finish()
        write_finish()

    # Write OSV attribution metadata. The importer wrote
    # provenance (timestamp, counts, hash, run_uuid); attribution
    # values come from constants.py and are composed here so the
    # importer stays decoupled from CC-BY 4.0 specifics.
    try:
        conn = schema.connect(db_path)
        try:
            with conn:
                schema.write_metadata_dict(
                    conn,
                    {
                        schema.METADATA_KEY_DATA_SOURCE_NAME: constants.OSV_DATA_SOURCE_NAME,
                        schema.METADATA_KEY_DATA_SOURCE_URL: constants.OSV_DATA_SOURCE_URL,
                        schema.METADATA_KEY_DATA_LICENSE: constants.OSV_DATA_LICENSE,
                        schema.METADATA_KEY_DATA_LICENSE_URL: constants.OSV_DATA_LICENSE_URL,
                        schema.METADATA_KEY_PYDEPGATE_VERSION: get_version(),
                    },
                )
        finally:
            conn.close()
    except Exception as exc:
        sys.stderr.write(
            f"warning: failed to write attribution metadata: "
            f"{type(exc).__name__}: {exc}\n"
            f"The import succeeded but attribution is missing from "
            f"the DB; rerun 'pydepgate cvedb update' to retry.\n"
        )

    # Summary with totals
    total = (
        result.affected_version_rows
        + result.affected_range_rows
        + result.alias_rows
        + result.records_with_parse_errors
    )
    sys.stderr.write("\n")
    sys.stderr.write(
        f"Imported {result.records_imported} vulnerabilities in "
        f"{result.elapsed_seconds:.1f}s\n"
    )
    sys.stderr.write(f"  Exact version rows:    {result.affected_version_rows}\n")
    sys.stderr.write(f"  Range rows:            {result.affected_range_rows}\n")
    sys.stderr.write(f"  Aliases:               {result.alias_rows}\n")
    sys.stderr.write(f"  Parse errors:          {result.records_with_parse_errors}\n")
    if result.records_with_no_usable_data:
        sys.stderr.write(
            f"  No usable data:        " f"{result.records_with_no_usable_data}\n"
        )
    sys.stderr.write(f"  Total:                 {total}\n")
    sys.stderr.write("\n")
    sys.stderr.write(f"Database: {db_path}\n")
    sys.stderr.write(f"Snapshot SHA256: {fetch_result.sha256}\n")
    sys.stderr.write(f"\n{constants.OSV_DATA_ATTRIBUTION_LINE}\n")
    sys.stderr.write(f"Your Run ID: {get_current_run_uuid()}\n")

    _cleanup_zip(zip_path)

    return exit_codes.CLEAN


def _cleanup_zip(zip_path: Path) -> None:
    """Best-effort removal of the downloaded zip."""
    try:
        zip_path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        sys.stderr.write(f"warning: could not remove {zip_path}: {exc}\n")
