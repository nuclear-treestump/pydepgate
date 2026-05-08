from __future__ import annotations

"""pydepgate.reporters.sarif.__init__

SARIF 2.1.0 output for pydepgate scan results.

This package emits SARIF documents compatible with GitHub
code scanning's ingestion subset of the OASIS SARIF 2.1.0
standard. The implementation is split across submodules:

  - severity.py: pydepgate Severity to SARIF level mapping
    and GitHub security-severity numeric.
  - uris.py: artifactLocation URI scheme decisions per path
    kind (real, artifact-internal, synthetic decoded).
  - fingerprints.py: partialFingerprints algorithm for
    GitHub alert deduplication across runs.
  - rules.py: rule descriptor generation (Phase B,
    planned).
  - results.py: result generation including codeFlows for
    decoded payload chains 
  - document.py: full SARIF document assembly and emission.

The public entry point is render(result, decoded_tree,
stream).

The placeholder is intentionally valid SARIF rather than an
unstructured message so that consumers (CI pipelines,
upload-sarif actions) can ingest it without parse errors
even before real findings are emitted.
"""

import json
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from pydepgate.engines.base import ScanResult
    from pydepgate.enrichers.decode_payloads import DecodedTree


# Tool identity constants. Centralized here so the document
# assembly phase can import them rather than redefining.
TOOL_NAME = "pydepgate"
TOOL_INFORMATION_URI = "https://github.com/nuclear-treestump/pydepgate"
TOOL_ORGANIZATION = "Nuclear Treestump"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"


def render(
    result: "ScanResult",
    decoded_tree: "DecodedTree | None",
    stream: TextIO,
) -> None:
    """Emit SARIF 2.1.0 output for a scan result.

    Args:
        result: the ScanResult from the main scan pass.
        decoded_tree: optional DecodedTree from the decode
            pass.
        stream: a writable text stream. The function writes
            the SARIF document plus a trailing newline.

    """
    placeholder_document = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFORMATION_URI,
                        "organization": TOOL_ORGANIZATION,
                    },
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {
                                    "text": (
                                        "pydepgate SARIF emission is "
                                        "under development. This "
                                        "document is a placeholder; "
                                        "a future release will "
                                        "produce findings."
                                    ),
                                },
                            },
                        ],
                    },
                ],
            },
        ],
    }
    json.dump(placeholder_document, stream, indent=2)
    stream.write("\n")
