from __future__ import annotations

"""pydepgate.reporters.sarif

SARIF 2.1.0 output for pydepgate scan results.

This package emits SARIF documents compatible with GitHub
code scanning's ingestion subset of the OASIS SARIF 2.1.0
standard. The implementation is split across submodules:

  - severity.py: pydepgate Severity to SARIF level
    mapping, GitHub security-severity numeric, and
    severity rank helpers.
  - uris.py: artifactLocation URI scheme decisions per
    path kind (real, artifact-internal, synthetic
    decoded).
  - fingerprints.py: partialFingerprints algorithm for
    GitHub alert deduplication across runs.
  - rules.py: rule descriptor generation from
    SIGNAL_EXPLANATIONS plus the default rule walk.
  - results.py: result entries from pydepgate findings,
    including codeFlows for findings reached via decoded
    payload chains.
  - document.py: full SARIF document assembly.
  - _constants.py: shared tool-identity constants.

The public entry point is render(result, decoded_tree,
stream, *, srcroot=None, scan_mode=None).

On clean assembly, render() writes a complete SARIF 2.1.0
document. On assembly failure, it logs to stderr and emits
a fallback document with executionSuccessful=False and a
notification carrying the exception text, so consumers
parse a valid document either way.
"""

import json
import sys
from typing import TYPE_CHECKING, TextIO

from pydepgate.reporters.sarif._constants import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_INFORMATION_URI,
    TOOL_NAME,
    TOOL_ORGANIZATION,
)
from pydepgate.reporters.sarif.document import (
    assemble_document,
    assemble_fallback_document,
)

if TYPE_CHECKING:
    from pydepgate.engines.base import ScanResult
    from pydepgate.enrichers.decode_payloads import DecodedTree


def render(
    result: "ScanResult",
    decoded_tree: "DecodedTree | None",
    stream: TextIO,
    *,
    srcroot: str | None = None,
    scan_mode: str | None = None,
) -> None:
    """Emit SARIF 2.1.0 output for a scan result.

    Args:
        result: the ScanResult from the main scan pass.
        decoded_tree: optional DecodedTree from the decode
            pass. None when decode is disabled.
        stream: a writable text stream. The function writes
            the SARIF document plus a trailing newline.
        srcroot: optional srcroot path. When provided,
            artifactLocation entries on real on-disk paths
            are tagged with uriBaseId=PROJECTROOT, and the
            originalUriBaseIds.PROJECTROOT entry in the
            document carries this value as its URI. Used
            by callers running in-repo scans where GitHub
            needs to resolve paths relative to a known
            root.
        scan_mode: optional override for the scan-mode
            segment of automationDetails.id. Defaults to
            ScanResult.artifact_kind.value when None.
            Callers with additional context (deep mode,
            custom scan modes) pass an explicit value.

    Behavior:
        On clean assembly, writes a complete SARIF 2.1.0
        document to the stream. On any exception during
        assembly, writes a fallback document with
        executionSuccessful=False and a notification
        carrying the exception text, and logs the failure
        to stderr. The function never raises; consumers
        always receive a parseable SARIF document.
    """
    try:
        document = assemble_document(
            result=result,
            decoded_tree=decoded_tree,
            srcroot=srcroot,
            scan_mode=scan_mode,
        )
    except Exception as exc:
        sys.stderr.write(f"pydepgate: SARIF assembly failed: {exc!r}\n")
        document = assemble_fallback_document(error_message=str(exc))

    json.dump(document, stream, indent=2)
    stream.write("\n")
