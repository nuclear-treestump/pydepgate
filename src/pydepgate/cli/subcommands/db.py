"""pydepgate.cli.subcommands.db

The 'db' subcommand: inspect and query the pydepgate evidence database.

Actions:

  path          Print the database file path and exit. The database
                does not need to exist.

  status        Show record counts and metadata for the database.

  list-runs     List scan runs in reverse chronological order.

  query         Query the database for artifact records.
                  --package NAME [--version VER]
                  --artifact-sha512 SHA512

  explain       Show the full record for a single run.
                  --run-id UUID
"""

from __future__ import annotations

import argparse
import sys

from pydepgate.cli import exit_codes
from pydepgate.pdgplatform.paths import ensure_directory, pydepgate_data_dir

# ---------------------------------------------------------------------------
# Database path helper
# ---------------------------------------------------------------------------

_DB_SUBDIR = "pdgdb"
_DB_FILENAME = "evidence.db"


def _db_path():
    """Return the Path to the evidence database file.

    Does not create the directory or file. Callers that need the
    directory to exist pass the result through ensure_directory().
    """
    return pydepgate_data_dir() / _DB_SUBDIR / _DB_FILENAME


# ---------------------------------------------------------------------------
# Subcommand registration
# ---------------------------------------------------------------------------


def register(subparsers) -> None:
    """Register the db subcommand on the given subparsers object."""
    parser = subparsers.add_parser(
        "db",
        help="Inspect and query the pydepgate evidence database",
        description=(
            "Inspect and query the pydepgate evidence database. "
            "The database is populated by 'pydepgate scan --save-to-db' "
            "and 'pydepgate cvescan --save-to-db'."
        ),
    )
    action_subparsers = parser.add_subparsers(
        dest="db_action",
        title="actions",
        metavar="<action>",
    )
    action_subparsers.required = True

    # path
    action_subparsers.add_parser(
        "path",
        help="Print the database file path",
    )

    # status
    action_subparsers.add_parser(
        "status",
        help="Show record counts and database metadata",
    )

    # list-runs
    list_runs_parser = action_subparsers.add_parser(
        "list-runs",
        help="List scan runs in reverse chronological order",
    )
    list_runs_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        metavar="N",
        help="Maximum number of runs to show (default: 50, 0 for all)",
    )

    # query
    query_parser = action_subparsers.add_parser(
        "query",
        help="Query artifact records by package name or artifact hash",
    )
    query_group = query_parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument(
        "--package",
        metavar="NAME",
        help="Package name to query (case-insensitive, hyphens match underscores)",
    )
    query_group.add_argument(
        "--artifact-sha512",
        metavar="SHA512",
        help="Artifact SHA-512 hex string to query",
    )
    query_parser.add_argument(
        "--version",
        metavar="VERSION",
        default=None,
        help="Package version to filter by (only with --package)",
    )
    query_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        metavar="N",
        help="Maximum number of results to show (default: 50, 0 for all)",
    )

    # explain
    explain_parser = action_subparsers.add_parser(
        "explain",
        help="Show the full record for a single scan run",
    )
    explain_parser.add_argument(
        "--run-id",
        required=True,
        metavar="UUID",
        help="UUID of the run to explain",
    )
    explain_parser.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="Output format (default: human)",
    )

    action_subparsers.add_parser(
        "init",
        help="Create the evidence database",
    )

    parser.set_defaults(func=run)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    """Dispatch to the selected db action."""
    action = args.db_action
    if action == "path":
        return _run_path()
    if action == "status":
        return _run_status()
    if action == "list-runs":
        limit = None if args.limit == 0 else args.limit
        return _run_list_runs(limit=limit)
    if action == "query":
        limit = None if args.limit == 0 else args.limit
        return _run_query(args, limit=limit)
    if action == "explain":
        return _run_explain(args)
    if action == "init":
        return _run_init()
    sys.stderr.write(f"error: unknown db action: {action}\n")
    return exit_codes.TOOL_ERROR


# ---------------------------------------------------------------------------
# Action implementations
# ---------------------------------------------------------------------------


def _run_path() -> int:
    """Print the database file path."""
    print(_db_path())
    return exit_codes.CLEAN


def _run_init() -> int:
    """Create the evidence database, or report if it already exists."""
    from pydepgate.dbs.pdgdb import schema
    from pydepgate.pdgplatform.paths import ensure_directory

    db_path = _db_path()

    if db_path.exists():
        conn = schema.connect(db_path)
        try:
            last_modified = schema.read_metadata(
                conn, schema.METADATA_KEY_LAST_MODIFIED
            )
            created_at = schema.read_metadata(conn, schema.METADATA_KEY_CREATED_AT)
        finally:
            conn.close()
        timestamp = last_modified or created_at or "(unknown)"
        print(
            f"Evidence database already exists: {db_path}\n"
            f"Last modified: {timestamp}"
        )
        return exit_codes.CLEAN

    try:
        ensure_directory(db_path.parent)
        conn = schema.connect(db_path)
        try:
            schema.initialize_schema(conn)
        finally:
            conn.close()
    except OSError as exc:
        sys.stderr.write(
            f"error: could not create evidence database at {db_path}: {exc}\n"
        )
        return exit_codes.TOOL_ERROR

    print(f"Evidence database created: {db_path}")
    return exit_codes.CLEAN


def _open_db():
    """Open and return a compatible pdgdb connection.

    Returns (conn, None) on success or (None, error_message) on failure.
    The caller is responsible for closing conn.
    """
    from pydepgate.dbs.pdgdb import schema

    db_path = _db_path()
    if not db_path.exists():
        return None, (
            f"Evidence database does not exist: {db_path}\n"
            f"Run 'pydepgate scan --save-to-db <target>' to create it."
        )
    conn = schema.connect(db_path)
    try:
        schema.check_schema_compatibility(conn)
    except schema.SchemaVersionMismatch as exc:
        conn.close()
        return None, str(exc)
    return conn, None


def _run_status() -> int:
    """Display record counts and metadata."""
    from pydepgate.dbs.pdgdb.reader import get_db_status

    db_path = _db_path()
    conn, err = _open_db()
    if conn is None:
        sys.stderr.write(f"error: {err}\n")
        return exit_codes.TOOL_ERROR

    try:
        status = get_db_status(conn, str(db_path))
    finally:
        conn.close()

    print(f"Evidence database: {status.db_path}")
    print(f"  Schema version:     {status.schema_version}")
    print(f"  Created by:         {status.pydepgate_version or '(unknown)'}")
    print(f"  Created at:         {status.created_at or '(unknown)'}")
    print(f"  Last modified:      {status.last_modified or '(unknown)'}")
    print(f"  Scan runs:          {status.total_scan_runs}")
    print(f"  Scanned artifacts:  {status.total_scanned_artifacts}")
    print(f"  Static findings:    {status.total_static_findings}")
    print(f"  Decoded nodes:      {status.total_decoded_nodes}")
    print(f"  CVE findings:       {status.total_cve_findings}")
    return exit_codes.CLEAN


def _run_list_runs(*, limit: int | None) -> int:
    """List scan runs newest-first."""
    from pydepgate.dbs.pdgdb.reader import list_runs

    conn, err = _open_db()
    if conn is None:
        sys.stderr.write(f"error: {err}\n")
        return exit_codes.TOOL_ERROR

    try:
        rows = list_runs(conn, limit=limit)
    finally:
        conn.close()

    if not rows:
        print("No scan runs recorded.")
        return exit_codes.CLEAN

    # Header.
    print(
        f"{'RUN ID':<36}  {'CMD':<8}  {'VER':<8}  "
        f"{'ARTS':>4}  {'STATIC':>6}  {'CVE':>5}  STARTED"
    )
    print("-" * 86)
    for row in rows:
        print(
            f"{row.run_id:<36}  {row.command:<8}  {row.pydepgate_ver:<8}  "
            f"{row.artifact_count:>4}  {row.finding_count:>6}  "
            f"{row.cve_finding_count:>5}  {row.started_at}"
        )
    return exit_codes.CLEAN


def _run_query(args: argparse.Namespace, *, limit: int | None) -> int:
    """Query artifact records."""
    from pydepgate.dbs.pdgdb.reader import query_by_artifact_sha512, query_by_package

    conn, err = _open_db()
    if conn is None:
        sys.stderr.write(f"error: {err}\n")
        return exit_codes.TOOL_ERROR

    try:
        if args.package:
            if args.version and args.artifact_sha512:
                sys.stderr.write("error: --version only applies with --package.\n")
                return exit_codes.TOOL_ERROR
            rows = query_by_package(
                conn,
                args.package,
                package_version=args.version,
                limit=limit,
            )
        else:
            rows = query_by_artifact_sha512(
                conn,
                args.artifact_sha512,
                limit=limit,
            )
    finally:
        conn.close()

    if not rows:
        print("No matching artifacts.")
        return exit_codes.CLEAN

    for row in rows:
        pkg = (
            f"{row.package_name}=={row.package_version}"
            if row.package_name and row.package_version
            else row.package_name or "(no package metadata)"
        )
        sha = (
            (row.artifact_sha512 or "")[:16] + "..."
            if row.artifact_sha512
            else "(no hash)"
        )
        print(
            f"{row.run_id}  {row.artifact_kind:<12}  {pkg:<30}  "
            f"{row.finding_count:>4} static  {row.cve_finding_count:>4} CVE  "
            f"{sha}  {row.scanned_at}"
        )
    return exit_codes.CLEAN


def _run_explain(args: argparse.Namespace) -> int:
    """Show the full record for a single run."""
    import json as _json

    from pydepgate.dbs.pdgdb.reader import explain_run

    conn, err = _open_db()
    if conn is None:
        sys.stderr.write(f"error: {err}\n")
        return exit_codes.TOOL_ERROR

    try:
        explanation = explain_run(conn, args.run_id)
    finally:
        conn.close()

    if explanation is None:
        sys.stderr.write(f"error: run not found: {args.run_id}\n")
        return exit_codes.TOOL_ERROR

    explain_format = getattr(args, "format", "human")

    if explain_format == "json":
        _print_explain_json(explanation)
    else:
        _print_explain_human(explanation)

    return exit_codes.CLEAN


def _print_explain_human(explanation) -> None:
    """Render a RunExplanation as human-readable text."""
    print(f"Run ID:      {explanation.run_id}")
    print(f"Command:     {explanation.command}")
    print(f"Producer:    {explanation.producer_id}")
    print(f"Version:     {explanation.pydepgate_ver}")
    print(f"Started:     {explanation.started_at}")

    art = explanation.artifact
    if art:
        print()
        print(f"Artifact:    {art.artifact_identity}")
        print(f"Kind:        {art.artifact_kind}")
        if art.package_name:
            pkg = (
                f"{art.package_name}=={art.package_version}"
                if art.package_version
                else art.package_name
            )
            print(f"Package:     {pkg}")
        if art.artifact_sha512:
            print(f"SHA-512:     {art.artifact_sha512[:32]}...")
        print(f"Scanned at:  {art.scanned_at}")

    print()
    print(f"Findings ({len(explanation.findings)}):")
    if not explanation.findings:
        print("  (none)")
    else:
        for f in explanation.findings:
            print(
                f"  [{f.severity.upper():>8}]  {f.signal_id:<12}  "
                f"{f.internal_path}:{f.line}:{f.col}  {f.description}"
            )

    if explanation.decoded_nodes:
        print()
        print(f"Decoded nodes ({len(explanation.decoded_nodes)}):")
        for node in explanation.decoded_nodes:
            chain_str = " -> ".join(node.chain) if node.chain else "(none)"
            print(
                f"  depth={node.depth}  {node.outer_signal_id}  "
                f"{node.outer_location}  chain=[{chain_str}]  "
                f"final={node.final_kind}({node.final_size}b)  "
                f"stop={node.stop_reason}"
            )
            for cf in node.child_findings:
                print(
                    f"    [{cf.severity.upper():>8}]  {cf.signal_id:<12}  "
                    f"line {cf.line}:{cf.col}  {cf.description}"
                )

    if explanation.cve_findings:
        print()
        print(f"CVE findings ({len(explanation.cve_findings)}):")
        for cf in explanation.cve_findings:
            sev = (cf.severity or "UNKNOWN").upper()
            print(
                f"  [{sev:>8}]  {cf.canonical_id:<20}  {cf.match_kind}  {cf.summary or ''}"
            )
            if cf.cvss_v3:
                print(f"             CVSS v3: {cf.cvss_v3}")
            if cf.cvss_v4:
                print(f"             CVSS v4: {cf.cvss_v4}")


def _print_explain_json(explanation) -> None:
    """Render a RunExplanation as JSON."""
    import json as _json

    art = explanation.artifact
    doc = {
        "run_id": explanation.run_id,
        "command": explanation.command,
        "producer_id": explanation.producer_id,
        "pydepgate_ver": explanation.pydepgate_ver,
        "started_at": explanation.started_at,
        "artifact": (
            {
                "artifact_identity": art.artifact_identity,
                "artifact_kind": art.artifact_kind,
                "package_name": art.package_name,
                "package_version": art.package_version,
                "artifact_sha256": art.artifact_sha256,
                "artifact_sha512": art.artifact_sha512,
                "scanned_at": art.scanned_at,
                "finding_count": art.finding_count,
            }
            if art
            else None
        ),
        "findings": [
            {
                "signal_id": f.signal_id,
                "analyzer": f.analyzer,
                "severity": f.severity,
                "confidence": f.confidence,
                "scope": f.scope,
                "internal_path": f.internal_path,
                "line": f.line,
                "col": f.col,
                "description": f.description,
                "rule_id": f.rule_id,
                "producer_id": f.producer_id,
                "stored_at": f.stored_at,
            }
            for f in explanation.findings
        ],
        "cve_findings": [
            {
                "canonical_id": cf.canonical_id,
                "package_name": cf.package_name,
                "package_version": cf.package_version,
                "severity": cf.severity,
                "cvss_v3": cf.cvss_v3,
                "cvss_v4": cf.cvss_v4,
                "summary": cf.summary,
                "match_kind": cf.match_kind,
                "producer_id": cf.producer_id,
                "stored_at": cf.stored_at,
            }
            for cf in explanation.cve_findings
        ],
        "decoded_nodes": [
            {
                "id": node.id,
                "parent_node_id": node.parent_node_id,
                "outer_signal_id": node.outer_signal_id,
                "outer_severity": node.outer_severity,
                "outer_location": node.outer_location,
                "outer_length": node.outer_length,
                "chain": list(node.chain),
                "unwrap_status": node.unwrap_status,
                "final_kind": node.final_kind,
                "final_size": node.final_size,
                "indicators": list(node.indicators),
                "pickle_warning": node.pickle_warning,
                "depth": node.depth,
                "stop_reason": node.stop_reason,
                "containing_file_sha256": node.containing_file_sha256,
                "containing_file_sha512": node.containing_file_sha512,
                "child_findings": [
                    {
                        "signal_id": cf.signal_id,
                        "severity": cf.severity,
                        "line": cf.line,
                        "col": cf.col,
                        "description": cf.description,
                    }
                    for cf in node.child_findings
                ],
            }
            for node in explanation.decoded_nodes
        ],
    }
    print(_json.dumps(doc, indent=2))
