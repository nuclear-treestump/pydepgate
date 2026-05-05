"""pydepgate.reporters.scan_result.json

Machine-readable JSON output for pydepgate ScanResult.

Emits a single JSON object per ScanResult, with schema_version 3
as documented in the JSON output schema_version contract (see
CONTRIBUTING.md). The wire format is a public contract; any
shape change is a schema bump.

This module exposes a single public function: render(). Callers
import the module and dispatch via it:

    from pydepgate.reporters.scan_result import json as scan_json
    scan_json.render(result, sys.stdout)

The module name 'json' shadows the stdlib 'json' module in the
package's own namespace, but Python's absolute-import default
ensures that the local `import json` at the top of this file
resolves to the stdlib module. Callers who need stdlib json in
the same scope as this module should use module-import style
(as shown above) rather than `from pydepgate.reporters.scan_result.json
import render`.
"""

from __future__ import annotations

import json
from typing import TextIO

from pydepgate.engines.base import (
    Finding,
    ScanResult,
)


def render(result: ScanResult, stream: TextIO) -> None:
    """Render a ScanResult as a single JSON object on stdout."""
    payload = {
        "report_type": "pydepgate_scan_result",
        "schema_version": 3,
        "artifact": {
            "identity": result.artifact_identity,
            "kind": result.artifact_kind.value,
            "sha256": result.artifact_sha256,
            "sha512": result.artifact_sha512,
        },
        "findings": [_finding_to_dict(f) for f in result.findings],
        "suppressed_findings": [
            _suppressed_to_dict(s) for s in result.suppressed_findings
        ],
        "skipped": [
            {"path": s.internal_path, "reason": s.reason}
            for s in result.skipped
        ],
        "statistics": {
            "files_total": result.statistics.files_total,
            "files_scanned": result.statistics.files_scanned,
            "files_skipped": result.statistics.files_skipped,
            "files_failed_to_parse": result.statistics.files_failed_to_parse,
            "signals_emitted": result.statistics.signals_emitted,
            "analyzers_run": result.statistics.analyzers_run,
            "enrichers_run": result.statistics.enrichers_run,
            "duration_seconds": result.statistics.duration_seconds,
        },
        "diagnostics": list(result.diagnostics),
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")


def _suppressed_to_dict(sup) -> dict:
    """Convert a SuppressedFinding to a JSON-serializable dict."""
    return {
        "signal_id": sup.original_finding.signal.signal_id,
        "internal_path": sup.original_finding.context.internal_path,
        "description": sup.original_finding.signal.description,
        "suppressing_rule_id": sup.suppressing_rule_id,
        "suppressing_rule_source": sup.suppressing_rule_source,
        "would_have_been_severity": sup.would_have_been.severity.value,
    }


def _finding_to_dict(finding: Finding) -> dict:
    """Convert a Finding to a JSON-serializable dict."""
    sig = finding.signal
    return {
        "severity": finding.severity.value,
        "signal_id": sig.signal_id,
        "analyzer": sig.analyzer,
        "confidence": int(sig.confidence),
        "scope": sig.scope.name.lower() if hasattr(sig.scope, "name") else str(sig.scope),
        "description": sig.description,
        "location": {
            "internal_path": finding.context.internal_path,
            "line": sig.location.line,
            "column": sig.location.column,
        },
        "file_sha256": finding.context.file_sha256,
        "file_sha512": finding.context.file_sha512,
        "context": _serialize_context(sig.context),
    }


def _serialize_context(context: dict) -> dict:
    """Make a context dict JSON-safe by coercing tuples to lists.

    Underscore-prefixed keys are pipeline-internal (carrying data
    such as the stashed `_full_value` for enrichers) and are
    omitted from JSON output to keep the wire format lean and to
    avoid emitting raw payload bytes that consumers do not need.
    """
    out = {}
    for key, value in context.items():
        if key.startswith("_"):
            continue
        if isinstance(value, tuple):
            out[key] = list(value)
        elif isinstance(value, (str, int, float, bool, type(None), list, dict)):
            out[key] = value
        else:
            # Fallback: stringify anything else.
            out[key] = str(value)
    return out